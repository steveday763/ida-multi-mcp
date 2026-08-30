"""Regression tests for explicit text encodings in the IDA ``find`` tool."""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


def load_api_analysis(monkeypatch):
    """Import api_analysis with a minimal synthetic IDA Python surface."""
    import ida_multi_mcp

    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    for name in [
        "ida_hexrays",
        "ida_lines",
        "ida_funcs",
        "idaapi",
        "idautils",
        "ida_typeinf",
        "ida_nalt",
        "ida_kernwin",
        "ida_bytes",
        "ida_ida",
        "ida_entry",
        "ida_idaapi",
        "ida_xref",
        "ida_ua",
        "ida_name",
        "idc",
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

    compat = types.ModuleType("ida_multi_mcp.ida_mcp.compat")
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.compat", compat)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    for name in [
        "parse_address",
        "normalize_list_input",
        "normalize_dict_list",
        "paginate",
        "get_function",
        "get_prototype",
        "get_stack_frame_variables_internal",
        "decompile_function_safe",
        "compact_whitespace",
        "get_assembly_lines",
        "get_all_xrefs",
        "get_all_comments",
        "extract_function_strings",
        "Function",
        "Argument",
        "DisassemblyFunction",
        "Xref",
        "BasicBlock",
        "StructFieldQuery",
        "InsnPattern",
    ]:
        setattr(utils, name, MagicMock(name=name))
    utils.MAX_BATCH_SIZE = 1000
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    return importlib.import_module("ida_multi_mcp.ida_mcp.api_analysis"), IDAError


@pytest.mark.parametrize(
    ("encoding", "expected"),
    [
        ("utf-8", "74 65 73 74"),
        ("utf-16le", "74 00 65 00 73 00 74 00"),
        ("utf-16be", "00 74 00 65 00 73 00 74"),
    ],
)
def test_find_string_uses_selected_encoding(monkeypatch, encoding, expected):
    api_analysis, _ = load_api_analysis(monkeypatch)
    api_analysis.ida_ida.inf_get_min_ea.return_value = 0x1000
    api_analysis.ida_ida.inf_get_max_ea.return_value = 0x2000
    api_analysis.ida_kernwin.user_cancelled.return_value = False
    compiled_patterns = []

    def compile_pattern(pattern, start_ea):
        compiled_patterns.append((pattern, start_ea))
        return object()

    api_analysis._compile_binpat = compile_pattern
    api_analysis._search_compiled_pattern = lambda *args: (["0x1234"], False)

    result = api_analysis.find(type="string", targets="test", encoding=encoding)

    assert compiled_patterns == [(expected, 0x1000)]
    assert result[0]["matches"] == ["0x1234"]
    assert result[0]["error"] is None


def test_find_rejects_unknown_encoding(monkeypatch):
    api_analysis, IDAError = load_api_analysis(monkeypatch)

    with pytest.raises(IDAError, match="Unsupported string encoding"):
        api_analysis.find(type="string", targets="test", encoding="utf-16")


def test_find_rejects_non_utf8_encoding_for_non_string_search(monkeypatch):
    api_analysis, IDAError = load_api_analysis(monkeypatch)

    with pytest.raises(IDAError, match="only supported when type='string'"):
        api_analysis.find(type="immediate", targets=7, encoding="utf-16le")
