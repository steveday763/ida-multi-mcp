"""Regression tests for the lightweight IDB resource split."""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch


IDA_MCP_ROOT = Path(__file__).resolve().parents[1] / "src" / "ida_multi_mcp" / "ida_mcp"


def _load_api_resources(monkeypatch):
    import ida_multi_mcp

    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    package = types.ModuleType("ida_multi_mcp.ida_mcp")
    package.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", package)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", package, raising=False)

    for name in (
        "ida_funcs", "ida_nalt", "ida_segment", "ida_typeinf", "idaapi", "idautils", "idc"
    ):
        monkeypatch.setitem(sys.modules, name, MagicMock(name=name))

    compat = types.ModuleType("ida_multi_mcp.ida_mcp.compat")
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.compat", compat)

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.resource = lambda _uri: (lambda func: func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.idasync = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    utils.Metadata = lambda **values: values
    utils.Fingerprint = lambda **values: values
    utils.Segment = lambda **values: values
    utils.StructureDefinition = lambda **values: values
    utils.StructureMember = lambda **values: values
    utils.get_image_size = lambda: 0x2000
    utils.parse_address = lambda value: int(value, 0)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    return importlib.import_module("ida_multi_mcp.ida_mcp.api_resources")


def test_metadata_does_not_read_or_hash_the_input_file(monkeypatch):
    api_resources = _load_api_resources(monkeypatch)
    api_resources.idc.get_idb_path.return_value = "/tmp/test.i64"
    api_resources.ida_nalt.get_root_filename.return_value = "test.bin"
    api_resources.idaapi.get_imagebase.return_value = 0x1000

    with patch("builtins.open", side_effect=AssertionError("metadata read the input file")):
        result = api_resources.idb_metadata_resource()

    assert result == {
        "path": "/tmp/test.i64",
        "module": "test.bin",
        "base": "0x1000",
        "size": "0x2000",
    }
    api_resources.ida_nalt.retrieve_input_file_md5.assert_not_called()
    api_resources.ida_nalt.retrieve_input_file_sha256.assert_not_called()


def test_fingerprint_resource_owns_hash_fields(monkeypatch, tmp_path):
    api_resources = _load_api_resources(monkeypatch)
    input_path = tmp_path / "test.bin"
    input_path.write_bytes(b"binary")
    api_resources.ida_nalt.get_input_file_path.return_value = str(input_path)
    api_resources.ida_nalt.retrieve_input_file_md5.return_value = bytes.fromhex("ab" * 16)
    api_resources.ida_nalt.retrieve_input_file_sha256.return_value = bytes.fromhex("cd" * 32)

    result = api_resources.idb_fingerprint_resource()

    assert result == {
        "md5": "ab" * 16,
        "sha256": "cd" * 32,
        "filesize": "0x6",
    }
