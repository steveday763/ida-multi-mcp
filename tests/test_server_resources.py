"""Tests for federated IDA resources exposed by the central server."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from ida_multi_mcp.tools import management
from ida_multi_mcp.server import IdaMultiMcpServer


def _call(server, method, params=None):
    request = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params is not None:
        request["params"] = params
    return server.server.registry.dispatch(request)


@pytest.fixture
def server(tmp_path):
    with patch("ida_multi_mcp.server.rediscover_instances", return_value=[]):
        with patch("ida_multi_mcp.server.cleanup_stale_instances", return_value=[]):
            srv = IdaMultiMcpServer(registry_path=str(tmp_path / "instances.json"))
            srv._refresh_tools()
            yield srv


def _register(server):
    return server.registry.register(
        pid=42,
        port=7000,
        idb_path="/tmp/test.i64",
        binary_name="test.exe",
        host="127.0.0.1",
    )


def test_resources_list_namespaces_each_instance(server):
    instance_id = _register(server)
    discovered = {
        "resources": [{
            "uri": "ida://idb/metadata",
            "name": "idb_metadata_resource",
            "description": "Get metadata",
            "mimeType": "application/json",
        }, {
            "uri": "ida://idb/fingerprint",
            "name": "idb_fingerprint_resource",
            "description": "Get fingerprint",
            "mimeType": "application/json",
        }],
        "resourceTemplates": [{
            "uriTemplate": "ida://struct/{name}",
            "name": "struct_name_resource",
            "description": "Get a structure",
            "mimeType": "application/json",
        }],
    }
    with patch.object(server, "_discover_ida_resources", return_value=discovered):
        resources = _call(server, "resources/list")["result"]["resources"]
        templates = _call(server, "resources/templates/list")["result"]["resourceTemplates"]

    assert resources[0]["uri"] == f"ida://instance/{instance_id}/idb/metadata"
    assert resources[0]["name"] == f"{instance_id}:idb_metadata_resource"
    assert resources[1]["uri"] == f"ida://instance/{instance_id}/idb/fingerprint"
    assert templates[0]["uriTemplate"] == f"ida://instance/{instance_id}/struct/{{name}}"
    assert templates[0]["name"] == f"{instance_id}:struct_name_resource"


def test_resource_discovery_reads_resources_and_templates(server):
    responses = [
        {"result": {"resources": [{"uri": "ida://cursor", "name": "cursor"}]}},
        {"result": {"resourceTemplates": [{"uriTemplate": "ida://import/{name}"}]}},
    ]

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def read(self):
            return json.dumps(self.payload).encode()

    class FakeConnection:
        def __init__(self, *_args, **_kwargs):
            self.response = responses.pop(0)

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return FakeResponse(self.response)

        def close(self):
            pass

    with patch("http.client.HTTPConnection", side_effect=FakeConnection):
        result = server._discover_ida_resources({"host": "127.0.0.1", "port": 7000})

    assert result == {
        "resources": [{"uri": "ida://cursor", "name": "cursor"}],
        "resourceTemplates": [{"uriTemplate": "ida://import/{name}"}],
    }


def test_resources_read_routes_and_rewrites_uri(server):
    instance_id = _register(server)
    routed = {}

    def fake_route(method, params):
        routed["method"] = method
        routed["params"] = params
        return {
            "contents": [{
                "uri": "ida://idb/metadata",
                "mimeType": "application/json",
                "text": json.dumps({"module": "test.exe"}),
            }]
        }

    public_uri = f"ida://instance/{instance_id}/idb/metadata"
    with patch.object(server.router, "route_request", side_effect=fake_route):
        result = _call(server, "resources/read", {"uri": public_uri})["result"]

    assert routed == {
        "method": "resources/read",
        "params": {"instance_id": instance_id, "uri": "ida://idb/metadata"},
    }
    assert result["contents"][0]["uri"] == public_uri
    assert json.loads(result["contents"][0]["text"]) == {"module": "test.exe"}


def test_resource_template_read_decodes_parameter(server):
    instance_id = _register(server)
    routed = {}

    def fake_route(method, params):
        routed.update(method=method, params=params)
        return {"contents": [{"uri": params["uri"], "text": "{}"}]}

    public_uri = f"ida://instance/{instance_id}/struct/Foo%20Bar"
    with patch.object(server.router, "route_request", side_effect=fake_route):
        _call(server, "resources/read", {"uri": public_uri})

    assert routed["params"]["uri"] == "ida://struct/Foo Bar"


def test_resources_read_rejects_non_federated_uri(server):
    result = _call(server, "resources/read", {"uri": "ida://idb/metadata"})["result"]

    assert result["isError"] is True
    assert "federated form" in result["contents"][0]["text"]


def test_removed_survey_is_not_advertised(server):
    names = [tool["name"] for tool in _call(server, "tools/list")["result"]["tools"]]

    assert "survey_binary" not in names


def test_compare_binaries_reads_resources(server):
    instance_a = _register(server)
    instance_b = server.registry.register(
        pid=43,
        port=7001,
        idb_path="/tmp/other.i64",
        binary_name="other.exe",
        host="127.0.0.1",
    )

    snapshots = {
        instance_a: {
            "ida://idb/metadata": {"module": "test.exe"},
            "ida://idb/segments": [{"name": ".text"}],
            "ida://idb/entrypoints": [{"name": "main"}],
        },
        instance_b: {
            "ida://idb/metadata": {"module": "other.exe"},
            "ida://idb/segments": [{"name": ".data"}],
            "ida://idb/entrypoints": [{"name": "start"}],
        },
    }

    def fake_route(method, params):
        assert method == "resources/read"
        value = snapshots[params["instance_id"]][params["uri"]]
        return {
            "contents": [{
                "uri": params["uri"],
                "text": json.dumps(value),
            }]
        }

    with patch.object(server.router, "route_request", side_effect=fake_route):
        result = management.compare_binaries({
            "instance_id_a": instance_a,
            "instance_id_b": instance_b,
        })

    assert result["instance_a"]["module"] == "test.exe"
    assert result["instance_b"]["module"] == "other.exe"
    assert result["segments"]["only_a"] == [".text"]
    assert result["segments"]["only_b"] == [".data"]
    assert result["entrypoints"]["only_a"] == ["main"]
    assert result["entrypoints"]["only_b"] == ["start"]
