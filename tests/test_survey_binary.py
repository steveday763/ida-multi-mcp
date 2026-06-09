"""Tests for survey_binary detail levels."""

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


@pytest.fixture
def api_survey_module(monkeypatch):
    """Load api_survey with IDA modules stubbed out."""
    import ida_multi_mcp

    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    idaapi = MagicMock()
    idaapi.get_kernel_version.return_value = "9.3"
    idaapi.get_imagebase.return_value = 0x10000000
    idaapi.SEGPERM_READ = 1
    idaapi.SEGPERM_WRITE = 2
    idaapi.SEGPERM_EXEC = 4
    idaapi.getseg.return_value = SimpleNamespace(
        start_ea=0x1000,
        end_ea=0x2000,
        perm=idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC,
        size=lambda: 0x1000,
    )
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    ida_ida = MagicMock()
    ida_ida.inf_is_64bit.return_value = True
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)

    ida_entry = MagicMock()
    ida_entry.get_entry_qty.return_value = 1
    ida_entry.get_entry_ordinal.return_value = 0
    ida_entry.get_entry.return_value = 0x1234
    ida_entry.get_entry_name.return_value = "JNI_OnLoad"
    monkeypatch.setitem(sys.modules, "ida_entry", ida_entry)

    ida_nalt = MagicMock()
    ida_nalt.get_root_filename.return_value = "libUE4.so"
    ida_nalt.get_input_file_path.return_value = "/tmp/libUE4.so"
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)

    ida_segment = MagicMock()
    ida_segment.get_segm_name.return_value = ".text"
    monkeypatch.setitem(sys.modules, "ida_segment", ida_segment)

    idautils = MagicMock()
    idautils.Segments.return_value = [0x1000]
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    idc = MagicMock()
    idc.get_idb_path.return_value = "/tmp/libUE4.so.i64"
    monkeypatch.setitem(sys.modules, "idc", idc)

    api_core = types.ModuleType("ida_multi_mcp.ida_mcp.api_core")
    api_core._get_strings_cache = MagicMock(
        side_effect=AssertionError("probe must not build the strings cache")
    )
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.api_core", api_core)

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
    utils.get_image_size = lambda: 0x2000000
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    api_survey = importlib.import_module("ida_multi_mcp.ida_mcp.api_survey")
    return api_survey, api_core, idautils, sync


def test_survey_probe_avoids_expensive_paths(api_survey_module, monkeypatch):
    api_survey, api_core, idautils, _sync = api_survey_module
    idautils.Functions.side_effect = AssertionError("probe must not enumerate functions")
    open_mock = MagicMock(side_effect=AssertionError("probe must not hash input files"))
    monkeypatch.setattr(builtins, "open", open_mock)

    result = api_survey.survey_binary("probe")

    assert result["metadata"] == {
        "path": "/tmp/libUE4.so.i64",
        "module": "libUE4.so",
        "arch": "64",
        "base_address": "0x10000000",
        "image_size": "0x2000000",
    }
    assert result["segments"] == [
        {
            "name": ".text",
            "start": "0x1000",
            "end": "0x2000",
            "size": "0x1000",
            "permissions": "rx",
        }
    ]
    assert result["entrypoints"] == [{"addr": "0x1234", "name": "JNI_OnLoad", "ordinal": 0}]
    assert "statistics" not in result
    assert "md5" not in result["metadata"]
    assert "sha256" not in result["metadata"]
    idautils.Functions.assert_not_called()
    api_core._get_strings_cache.assert_not_called()
    open_mock.assert_not_called()


def test_survey_rejects_unknown_detail_level(api_survey_module):
    api_survey, _api_core, idautils, sync = api_survey_module

    with pytest.raises(sync.IDAError):
        api_survey.survey_binary("fast")

    idautils.Segments.assert_not_called()


def test_static_survey_schema_documents_detail_levels():
    schemas = json.loads((SRC_ROOT / "ida_multi_mcp" / "ida_tool_schemas.json").read_text())
    survey = next(tool for tool in schemas if tool["name"] == "survey_binary")

    description = survey["description"]
    level_description = survey["inputSchema"]["properties"]["detail_level"]["description"]
    assert "probe" in description
    assert "minimal" in description
    assert "standard" in description
    assert "libUE4.so" in level_description
    assert "does not enumerate functions or strings" in level_description
    assert "avoid it for large binaries" in level_description

    metadata_required = survey["outputSchema"]["properties"]["metadata"]["required"]
    assert "md5" not in metadata_required
    assert "sha256" not in metadata_required
