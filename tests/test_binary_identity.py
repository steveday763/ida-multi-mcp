"""Binary identity check: shared normalization and IDA-side propagation.

The router forwards the registered binary name in the request _meta; the IDA
side exposes it to @idasync code and turns a mismatch into a JSON-RPC error.
"""

import json
import sys
import types
from pathlib import Path

import pytest

from ida_multi_mcp.binary_identity import (
    BINARY_MISMATCH_CODE,
    EXPECTED_BINARY_META_KEY,
    normalize_binary_name,
)


class TestNormalizeBinaryName:
    def test_windows_path_style_name(self):
        registered = r"D:\1_Project\ultra-codex\references\claude.exe"
        assert normalize_binary_name(registered) == normalize_binary_name("claude.exe")

    def test_case_insensitive(self):
        assert normalize_binary_name("CLAUDE.EXE") == normalize_binary_name("claude.exe")

    def test_different_names_differ(self):
        assert normalize_binary_name("a.exe") != normalize_binary_name("b.exe")

    @pytest.mark.parametrize("name", [None, "", "   ", "C:\\dir\\"])
    def test_empty_is_none(self, name):
        assert normalize_binary_name(name) is None


@pytest.fixture
def ida_zeromcp(monkeypatch):
    """The ida_mcp zeromcp copy, loaded without the IDA-dependent package __init__."""
    root = Path(__file__).resolve().parents[1] / "src" / "ida_multi_mcp" / "ida_mcp"
    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(root)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    for name in [n for n in sys.modules if n.startswith("ida_multi_mcp.ida_mcp.zeromcp")]:
        monkeypatch.delitem(sys.modules, name)
    from ida_multi_mcp.ida_mcp.zeromcp import jsonrpc, mcp
    return mcp, jsonrpc


def _call(server, method, params):
    return server.registry.dispatch({"jsonrpc": "2.0", "id": 7, "method": method, "params": params})


class TestIdaSidePropagation:
    def test_tool_sees_request_meta_only_during_the_call(self, ida_zeromcp):
        mcp, jsonrpc = ida_zeromcp
        server = mcp.McpServer("t")
        seen = {}

        @server.tool
        def probe() -> str:
            seen["meta"] = dict(jsonrpc.get_current_request_meta())
            return "ok"

        meta = {EXPECTED_BINARY_META_KEY: "test.exe"}
        resp = _call(server, "tools/call", {"name": "probe", "arguments": {}, "_meta": meta})

        assert resp["result"]["isError"] is False
        assert seen["meta"] == meta
        assert jsonrpc.get_current_request_meta() == {}

    def test_tool_mismatch_becomes_jsonrpc_error(self, ida_zeromcp):
        mcp, jsonrpc = ida_zeromcp
        server = mcp.McpServer("t")

        @server.tool
        def wrong_db() -> str:
            raise jsonrpc.JsonRpcException(BINARY_MISMATCH_CODE, "IDA is now analyzing 'b.exe'")

        resp = _call(server, "tools/call", {"name": "wrong_db", "arguments": {}})

        assert resp["error"]["code"] == BINARY_MISMATCH_CODE
        assert "b.exe" in resp["error"]["message"]
        assert jsonrpc.get_current_request_meta() == {}

    def test_other_tool_errors_stay_tool_results(self, ida_zeromcp):
        mcp, _ = ida_zeromcp
        server = mcp.McpServer("t")

        @server.tool
        def broken() -> str:
            raise mcp.McpToolError("bad address")

        resp = _call(server, "tools/call", {"name": "broken", "arguments": {}})

        assert resp["result"]["isError"] is True

    def test_resource_mismatch_becomes_jsonrpc_error(self, ida_zeromcp):
        mcp, jsonrpc = ida_zeromcp
        server = mcp.McpServer("t")
        seen = {}

        @server.resource("ida://idb/metadata")
        def metadata() -> dict:
            seen["meta"] = dict(jsonrpc.get_current_request_meta())
            raise jsonrpc.JsonRpcException(BINARY_MISMATCH_CODE, "IDA is now analyzing 'b.exe'")

        meta = {EXPECTED_BINARY_META_KEY: "a.exe"}
        resp = _call(server, "resources/read", {"uri": "ida://idb/metadata", "_meta": meta})

        assert seen["meta"] == meta
        assert resp["error"]["code"] == BINARY_MISMATCH_CODE
        assert jsonrpc.get_current_request_meta() == {}
