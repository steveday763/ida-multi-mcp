"""Tests for the IDA-side MCP server used by GUI/idalib workers."""

import importlib.util
import json
from pathlib import Path
import sys
import threading
import types


def _load_ida_side_mcp_module():
    """Load ida_mcp/zeromcp without importing ida_multi_mcp.ida_mcp.

    The package __init__ imports idaapi, which is unavailable in unit tests.
    """
    package_name = "_ida_side_zeromcp_test"
    package_dir = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "ida_multi_mcp"
        / "ida_mcp"
        / "zeromcp"
    )

    package = types.ModuleType(package_name)
    package.__path__ = [str(package_dir)]
    sys.modules[package_name] = package

    for module_name in ("jsonrpc", "mcp"):
        full_name = f"{package_name}.{module_name}"
        spec = importlib.util.spec_from_file_location(
            full_name,
            package_dir / f"{module_name}.py",
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)

    return sys.modules[f"{package_name}.mcp"]


ida_mcp = _load_ida_side_mcp_module()


def _dispatch(server, method, params=None, request_id=1):
    request = {"jsonrpc": "2.0", "method": method, "id": request_id}
    if params is not None:
        request["params"] = params
    return server.registry.dispatch(request)


class _FakeHTTPServer:
    instances = []

    def __init__(self, server_address, request_handler, bind_and_activate=False):
        self.server_address = server_address
        self.request_handler = request_handler
        self.bind_and_activate = bind_and_activate
        self.allow_reuse_address = False
        self.allow_reuse_port = False
        _FakeHTTPServer.instances.append(self)

    def server_bind(self):
        pass

    def server_activate(self):
        pass

    def server_close(self):
        pass

    def serve_forever(self):
        pass


class _FakeThreadingHTTPServer(_FakeHTTPServer):
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _FakeThreadingHTTPServer.instances.append(self)


def test_foreground_serve_can_use_threaded_http(monkeypatch):
    monkeypatch.setattr(ida_mcp, "HTTPServer", _FakeHTTPServer)
    monkeypatch.setattr(ida_mcp, "ThreadingHTTPServer", _FakeThreadingHTTPServer)
    _FakeHTTPServer.instances.clear()
    _FakeThreadingHTTPServer.instances.clear()

    server = ida_mcp.McpServer("test")
    server.serve("127.0.0.1", 0, background=False, threaded=True)

    assert len(_FakeThreadingHTTPServer.instances) == 1
    assert len(_FakeHTTPServer.instances) == 1


def test_tools_call_returns_busy_while_another_tool_is_running():
    server = ida_mcp.McpServer("test")
    entered = threading.Event()
    release = threading.Event()

    @server.tool
    def slow() -> str:
        entered.set()
        assert release.wait(5)
        return "done"

    @server.tool
    def fast() -> str:
        return "fast"

    slow_response = {}

    def run_slow():
        slow_response.update(
            _dispatch(
                server,
                "tools/call",
                {"name": "slow", "arguments": {}},
                request_id=1,
            )
        )

    thread = threading.Thread(target=run_slow)
    thread.start()
    assert entered.wait(5)

    busy = _dispatch(
        server,
        "tools/call",
        {"name": "fast", "arguments": {}},
        request_id=2,
    )

    release.set()
    thread.join(5)

    busy_result = busy["result"]
    assert busy_result["isError"] is True
    assert "busy processing tool 'slow'" in busy_result["content"][0]["text"]

    slow_result = slow_response["result"]
    assert slow_result["isError"] is False
    assert json.loads(slow_result["content"][0]["text"]) == "done"
