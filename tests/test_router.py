"""Tests for router.py — Request routing with mock HTTP."""

import json
from unittest.mock import patch, MagicMock

import pytest

from ida_multi_mcp.binary_identity import BINARY_MISMATCH_CODE, EXPECTED_BINARY_META_KEY
from ida_multi_mcp.registry import InstanceRegistry
from ida_multi_mcp.router import InstanceRouter


@pytest.fixture
def router_env(tmp_path):
    """Return (registry, router, instance_id) with one registered instance."""
    reg = InstanceRegistry(str(tmp_path / "inst.json"))
    iid = reg.register(
        pid=42, port=7000, idb_path="/test.i64",
        binary_name="test.exe", host="127.0.0.1",
    )
    router = InstanceRouter(reg)
    return reg, router, iid


class TestMissingInstanceId:
    def test_error_with_single_instance(self, router_env):
        """With 1 instance, missing instance_id should still error."""
        reg, router, iid = router_env
        resp = router.route_request("tools/call", {"arguments": {}})
        assert "error" in resp
        assert "instance_id" in resp["error"]
        assert resp["available_instances"] == [{"id": iid, "binary_name": "test.exe"}]

    def test_error_with_multiple_instances(self, tmp_path):
        """With 2+ instances, missing instance_id should error."""
        reg = InstanceRegistry(str(tmp_path / "inst.json"))
        reg.register(pid=42, port=7000, idb_path="/a.i64",
                     binary_name="a.exe", host="127.0.0.1")
        reg.register(pid=43, port=7001, idb_path="/b.i64",
                     binary_name="b.exe", host="127.0.0.1")
        router = InstanceRouter(reg)
        resp = router.route_request("tools/call", {"arguments": {}})
        assert "error" in resp
        assert "instance_id" in resp["error"]

    def test_resource_read_requires_instance_id(self, router_env):
        _, router, _ = router_env
        resp = router.route_request("resources/read", {"uri": "ida://idb/metadata"})
        assert "error" in resp
        assert "instance_id" in resp["error"]


class TestNonexistentInstance:
    def test_nonexistent_instance_error(self, router_env):
        _, router, _ = router_env
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": "nope"}})
        assert "error" in resp
        assert "not found" in resp["error"]


class TestExpiredInstance:
    def test_expired_with_reason_and_replacements(self, router_env):
        reg, router, iid = router_env
        # Register a replacement then expire the original
        iid2 = reg.register(pid=43, port=7001, idb_path="/test2.i64",
                            binary_name="test.exe", host="127.0.0.1")
        reg.expire_instance(iid, reason="binary_changed", replaced_by=iid2)
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": iid}})
        assert "error" in resp
        assert resp["reason"] == "binary_changed"
        assert any(r["id"] == iid2 for r in resp.get("replacements", []))


class TestSendRequest:
    def test_resource_read_strips_instance_id(self, router_env):
        _, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": {"contents": []},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router.route_request("resources/read", {
                "instance_id": iid,
                "uri": "ida://idb/metadata",
            })

        assert resp == {"contents": []}
        body = json.loads(mock_conn.request.call_args[0][2])
        assert body["method"] == "resources/read"
        assert body["params"] == {
            "uri": "ida://idb/metadata",
            "_meta": {EXPECTED_BINARY_META_KEY: "test.exe"},
        }

    def test_strips_instance_id(self, router_env):
        _, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": {"data": "ok"},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router.route_request("tools/call", {
                "arguments": {"instance_id": iid, "addr": "0x1000"}
            })

        # Verify instance_id was stripped from the forwarded request
        call_args = mock_conn.request.call_args
        body = json.loads(call_args[0][2])
        assert "instance_id" not in body["params"]["arguments"]

    def test_request_ids_are_unique(self, router_env):
        """IDA keys in-flight tools/call by JSON-RPC id; a constant id let
        concurrent requests from several hubs overwrite each other there."""
        _, router, iid = router_env
        mock_conn = _mock_conn({"jsonrpc": "2.0", "result": {"ok": True}, "id": 1})
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            for _ in range(2):
                router.route_request("tools/call", {
                    "name": "decompile",
                    "arguments": {"instance_id": iid},
                })

        ids = [json.loads(c[0][2])["id"] for c in mock_conn.request.call_args_list]
        assert len(ids) == 2 and ids[0] != ids[1]

    def test_ssrf_blocked(self, router_env):
        _, router, _ = router_env
        resp = router._send_request(
            {"host": "10.0.0.1", "port": 80}, "tools/call", {})
        assert "error" in resp
        assert "refused" in resp["error"]

    def test_connection_failure(self, router_env):
        _, router, iid = router_env
        with patch("http.client.HTTPConnection",
                   side_effect=ConnectionRefusedError):
            resp = router.route_request("tools/call", {
                "arguments": {"instance_id": iid}
            })
        assert "error" in resp

    def test_method_not_found_gets_actionable_hint(self, router_env):
        _, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method 'py_eval' not found"},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router.route_request("tools/call", {
                "name": "py_eval",
                "arguments": {"instance_id": iid, "code": "1 + 1"},
            })

        assert resp["error"] == "Method 'py_eval' not found"
        assert "config page" in resp["hint"]
        assert "restart" in resp["hint"]
    def test_connection_closed_on_error(self, router_env):
        """The socket must be released even when the request raises."""
        _, router, _ = router_env
        mock_conn = MagicMock()
        mock_conn.request.side_effect = OSError("boom")
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router._send_request(
                {"host": "127.0.0.1", "port": 7000}, "tools/call", {})
        assert "error" in resp
        mock_conn.close.assert_called_once()

    def test_connection_closed_on_success(self, router_env):
        _, router, _ = router_env
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"result": {"ok": True}}).encode()
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router._send_request(
                {"host": "127.0.0.1", "port": 7000}, "tools/call", {})
        assert resp == {"ok": True}
        mock_conn.close.assert_called_once()


def _mock_conn(payload: dict) -> MagicMock:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(payload).encode()
    mock_conn = MagicMock()
    mock_conn.getresponse.return_value = mock_response
    return mock_conn


class TestBinaryVerificationForwarding:
    """The binary check runs inside IDA's execution of the request itself.

    A separate metadata round-trip queued behind a busy IDA main thread, timed
    out after 5s, and left IDA writing to an abandoned connection.
    """

    def test_tool_call_carries_expected_binary(self, router_env):
        _, router, iid = router_env
        mock_conn = _mock_conn({"jsonrpc": "2.0", "result": {"ok": True}, "id": 1})
        with patch("http.client.HTTPConnection", return_value=mock_conn) as conn_cls:
            router.route_request("tools/call", {
                "name": "decompile",
                "arguments": {"instance_id": iid, "addr": "0x1000"},
            })

        body = json.loads(mock_conn.request.call_args[0][2])
        assert body["params"]["_meta"] == {EXPECTED_BINARY_META_KEY: "test.exe"}
        # One request per call: no metadata pre-query ahead of the tool.
        assert conn_cls.call_count == 1
        assert mock_conn.request.call_count == 1

    def test_mismatch_maps_to_stale_instance_error(self, router_env):
        _, router, iid = router_env
        mock_conn = _mock_conn({
            "jsonrpc": "2.0",
            "error": {
                "code": BINARY_MISMATCH_CODE,
                "message": "IDA is now analyzing 'other.exe', not the registered 'test.exe'",
            },
            "id": 1,
        })
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router.route_request("tools/call", {
                "name": "decompile",
                "arguments": {"instance_id": iid},
            })

        assert "other.exe" in resp["error"]
        assert "stale" in resp["error"]
        assert "list_instances" in resp["hint"]

