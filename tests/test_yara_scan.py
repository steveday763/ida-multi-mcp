"""Tests for YARA-backed scan tools."""

from __future__ import annotations

import builtins
import importlib
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
IDA_MCP_ROOT = SRC_ROOT / "ida_multi_mcp" / "ida_mcp"


class FakeStringInstance:
    def __init__(self, offset: int, data: bytes = b"\x01\x02\x03\x04"):
        self.offset = offset
        self.matched_data = data
        self.matched_length = len(data)


class FakeStringMatch:
    def __init__(self, identifier: str, instances: list[FakeStringInstance]):
        self.identifier = identifier
        self.instances = instances


class FakeMatch:
    def __init__(
        self,
        rule: str = "AES_SBOX",
        meta: dict | None = None,
        strings: list | None = None,
        tags: list[str] | None = None,
    ):
        self.rule = rule
        self.namespace = "default"
        self.tags = tags if tags is not None else ["crypto", "aes"]
        self.meta = meta if meta is not None else {
            "family": "aes",
            "algorithm": "AES",
            "confidence": "high",
        }
        self.strings = strings if strings is not None else [
            FakeStringMatch("$sbox", [FakeStringInstance(0x20, b"\x63\x7c\x77\x7b")])
        ]


class FakeRules:
    def __init__(self, matches: list[FakeMatch] | None = None, match_calls: list | None = None):
        self.matches = matches if matches is not None else [FakeMatch()]
        self.match_calls = match_calls

    def match(self, **kwargs):
        if self.match_calls is not None:
            self.match_calls.append(kwargs)
        return self.matches


@pytest.fixture
def api_yara_module(monkeypatch):
    """Load api_yara with IDA modules stubbed out."""
    import ida_multi_mcp

    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    idaapi = MagicMock()
    idaapi.SEGPERM_READ = 1
    idaapi.SEGPERM_WRITE = 2
    idaapi.SEGPERM_EXEC = 4
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    text_seg = SimpleNamespace(
        start_ea=0x1000,
        end_ea=0x1100,
        perm=idaapi.SEGPERM_READ,
        size=lambda: 0x100,
    )
    bss_seg = SimpleNamespace(
        start_ea=0x2000,
        end_ea=0x2100,
        perm=idaapi.SEGPERM_WRITE,
        size=lambda: 0x100,
    )
    idaapi.getseg.side_effect = lambda ea: text_seg if ea == 0x1000 else bss_seg
    idaapi.get_func.side_effect = lambda ea: (
        SimpleNamespace(start_ea=0x1050) if ea in (0x1055, 0x3000) else None
    )
    idaapi.get_name_ea.return_value = idaapi.BADADDR
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    ida_segment = MagicMock()
    ida_segment.get_segm_name.side_effect = lambda seg: ".text" if seg is text_seg else ".bss"
    monkeypatch.setitem(sys.modules, "ida_segment", ida_segment)

    ida_funcs = MagicMock()
    ida_funcs.get_func_name.return_value = "sub_1050"
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)

    ida_bytes = MagicMock()
    ida_bytes.get_bytes.return_value = bytes(range(0x100))
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)

    idautils = MagicMock()
    idautils.Segments.return_value = [0x1000, 0x2000]
    xref = SimpleNamespace(frm=0x1055, iscode=False)
    idautils.XrefsTo.return_value = [xref]
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")

    class IDAError(Exception):
        pass

    sync.IDAError = IDAError
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda _seconds: (lambda func: func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    utils.parse_address = lambda value: int(value, 0) if isinstance(value, str) else int(value)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    api_yara = importlib.import_module("ida_multi_mcp.ida_mcp.api_yara")
    return api_yara, ida_bytes, idautils


def install_fake_yara(
    monkeypatch,
    matches: list[FakeMatch] | None = None,
    match_calls: list | None = None,
):
    compile_calls = []

    def fake_compile(**kwargs):
        compile_calls.append(kwargs)
        return FakeRules(matches, match_calls)

    yara = types.ModuleType("yara")
    yara.compile = fake_compile
    monkeypatch.setitem(sys.modules, "yara", yara)
    return compile_calls


def test_yara_scan_missing_yara_returns_dependency_error(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    monkeypatch.delitem(sys.modules, "yara", raising=False)
    original_import = builtins.__import__

    def fail_yara_import(name, *args, **kwargs):
        if name == "yara":
            raise ImportError("No module named 'yara'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_yara_import)

    result = api_yara.yara_scan(rules_text='rule x { condition: true }')

    assert result["error"] == "dependency_missing"
    assert result["engine"] == "yara-python"


def test_yara_scan_requires_exactly_one_rule_source(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    install_fake_yara(monkeypatch)

    assert api_yara.yara_scan()["error"] == "invalid_rules"
    result = api_yara.yara_scan(
        rules_text='rule x { condition: true }',
        builtin_rules="crypto",
    )
    assert result["error"] == "invalid_rules"


def test_yara_scan_uses_yara_compile_with_includes_disabled(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    compile_calls = install_fake_yara(monkeypatch)

    result = api_yara.yara_scan(rules_text='rule x { condition: true }')

    assert result["error"] is None
    assert compile_calls[0]["source"] == 'rule x { condition: true }'
    assert compile_calls[0]["includes"] is False


def test_yara_scan_maps_offsets_to_ea(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    install_fake_yara(monkeypatch)

    result = api_yara.yara_scan(rules_text='rule x { condition: true }')

    evidence = result["matches"][0]["evidence"][0]
    assert evidence["addr"] == "0x1020"
    assert evidence["segment"] == ".text"
    assert evidence["offset_in_segment"] == 0x20


def test_yara_scan_passes_match_timeout(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    match_calls = []
    install_fake_yara(monkeypatch, match_calls=match_calls)

    api_yara.yara_scan(rules_text='rule x { condition: true }', timeout_sec=7)

    assert match_calls[0]["timeout"] == 7


def test_yara_scan_records_data_xrefs_and_functions(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    install_fake_yara(monkeypatch)

    result = api_yara.yara_scan(rules_text='rule x { condition: true }')

    xref = result["matches"][0]["evidence"][0]["xrefs"][0]
    assert xref["from"] == "0x1055"
    assert xref["type"] == "data"
    assert xref["function"] == {"addr": "0x1050", "name": "sub_1050"}


def test_crypto_scan_uses_builtin_crypto_rules_and_family_filter(api_yara_module, monkeypatch):
    api_yara, _ida_bytes, _idautils = api_yara_module
    matches = [
        FakeMatch(rule="AES_SBOX", meta={"family": "aes", "algorithm": "AES"}),
        FakeMatch(rule="SHA256_K", meta={"family": "sha2", "algorithm": "SHA-256"}),
    ]
    compile_calls = install_fake_yara(monkeypatch, matches)

    result = api_yara.crypto_scan(families="aes")

    assert "filepath" in compile_calls[0]
    assert [match["rule"] for match in result["matches"]] == ["AES_SBOX"]


def test_static_schema_includes_yara_tools():
    schemas = json.loads((SRC_ROOT / "ida_multi_mcp" / "ida_tool_schemas.json").read_text())
    names = {tool["name"] for tool in schemas}

    assert "yara_scan" in names
    assert "crypto_scan" in names


def test_builtin_crypto_rules_file_exists():
    rules_path = IDA_MCP_ROOT / "signatures" / "crypto.yar"

    text = rules_path.read_text()
    assert 'family = "aes"' in text
    assert 'algorithm = "AES"' in text
