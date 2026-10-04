"""The merged analyze_function: an array in, one result per address out.

It used to take a single address and return a single dict, with a separate
analyze_batch tool for the array form. Both called the same internal helper, so
they are one tool now — and the per-section toggles that only the batch form had
came along.
"""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


def load_api_composite(monkeypatch):
    import ida_multi_mcp

    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    for name in [
        "ida_hexrays", "ida_lines", "ida_funcs", "idaapi", "idautils",
        "ida_typeinf", "ida_nalt", "ida_kernwin", "ida_bytes", "ida_ida",
        "ida_xref", "ida_ua", "ida_name", "idc", "ida_auto", "ida_strlist",
        "ida_search", "ida_pro", "ida_segment", "ida_frame", "ida_loader",
    ]:
        monkeypatch.setitem(sys.modules, name, MagicMock(name=name))

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    class IDAError(Exception):
        pass

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.IDAError = IDAError
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda _seconds: (lambda func: func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    class _AutoUtils(types.ModuleType):
        """Answer every helper api_composite imports with a MagicMock, so this
        test does not have to track that import list."""

        def __getattr__(self, name):
            if name.startswith("__"):
                raise AttributeError(name)
            value = MagicMock(name=name)
            setattr(self, name, value)
            return value

    utils = _AutoUtils("ida_multi_mcp.ida_mcp.utils")
    utils.MAX_BATCH_SIZE = 500
    # These two must behave like themselves: the tool loops over their result.
    utils.normalize_list_input = (
        lambda value, **_kw: value if isinstance(value, list) else [value]
    )
    utils.parse_address = lambda value: int(value, 0)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    module = importlib.import_module("ida_multi_mcp.ida_mcp.api_composite")
    return module, IDAError


def _stub_internal(module, monkeypatch):
    calls = []

    def fake_internal(ea, include_asm=False):
        calls.append((ea, include_asm))
        return {
            "addr": hex(ea),
            "decompiled": "code",
            "decompile_truncated": False,
            "xrefs": [],
            "strings": [],
            "constants": [],
            "callees": [],
            "callers": [],
        }

    monkeypatch.setattr(module, "_analyze_function_internal", fake_internal)
    return calls


def _resolve_hex(module, monkeypatch):
    monkeypatch.setattr(module, "_resolve_addr", lambda value: int(value, 0))


def test_single_address_still_returns_a_one_element_array(monkeypatch):
    """Batch-first is this project's stated convention, so the old single-dict
    return is the thing that had to change."""
    module, _ = load_api_composite(monkeypatch)
    _resolve_hex(module, monkeypatch)
    calls = _stub_internal(module, monkeypatch)

    result = module.analyze_function(["0x1000"])

    assert isinstance(result, list)
    assert [item["addr"] for item in result] == ["0x1000"]
    assert calls == [(0x1000, False)]


def test_keeps_input_order_across_several_addresses(monkeypatch):
    module, _ = load_api_composite(monkeypatch)
    _resolve_hex(module, monkeypatch)
    calls = _stub_internal(module, monkeypatch)

    result = module.analyze_function(["0x3000", "0x1000", "0x2000"])

    assert [item["addr"] for item in result] == ["0x3000", "0x1000", "0x2000"]
    assert [ea for ea, _ in calls] == [0x3000, 0x1000, 0x2000]


def test_one_bad_address_does_not_lose_the_others(monkeypatch):
    module, IDAError = load_api_composite(monkeypatch)
    _stub_internal(module, monkeypatch)

    def resolve(value):
        if value == "nope":
            raise IDAError("no function at nope")
        return int(value, 0)

    monkeypatch.setattr(module, "_resolve_addr", resolve)

    result = module.analyze_function(["0x1000", "nope", "0x2000"])

    assert [item["addr"] for item in result] == ["0x1000", "nope", "0x2000"]
    assert result[1]["error"] == "no function at nope"
    assert "decompiled" in result[0] and "decompiled" in result[2]


def test_section_toggles_drop_only_their_own_fields(monkeypatch):
    """These toggles came from the deleted analyze_batch, which is the whole
    reason it was worth merging rather than dropping."""
    module, _ = load_api_composite(monkeypatch)
    _resolve_hex(module, monkeypatch)
    _stub_internal(module, monkeypatch)

    (result,) = module.analyze_function(
        ["0x1000"],
        include_decompile=False,
        include_xrefs=False,
        include_strings=False,
        include_callees=False,
    )

    for dropped in (
        "decompiled", "decompile_truncated", "xrefs",
        "strings", "constants", "callees", "callers",
    ):
        assert dropped not in result
    assert result["addr"] == "0x1000"


def test_rejects_oversized_batches(monkeypatch):
    module, IDAError = load_api_composite(monkeypatch)
    _resolve_hex(module, monkeypatch)
    _stub_internal(module, monkeypatch)

    with pytest.raises(IDAError, match="Batch too large"):
        module.analyze_function(["0x%x" % (0x1000 + i) for i in range(501)])
