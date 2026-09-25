"""Request routing for ida-multi-mcp.

Routes MCP requests to the appropriate IDA instance with fallback verification.
"""

import json
import http.client
from typing import Any

from .binary_identity import BINARY_MISMATCH_CODE, EXPECTED_BINARY_META_KEY
from .registry import InstanceRegistry, ALLOWED_HOSTS


class InstanceRouter:
    """Routes MCP tool requests to IDA instances.

    Handles instance_id extraction, fallback verification, and error handling.
    """

    def __init__(self, registry: InstanceRegistry):
        """Initialize the router.

        Args:
            registry: The instance registry
        """
        self.registry = registry

    def route_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Route a tool request to the appropriate IDA instance.

        Args:
            method: MCP method name (e.g., "tools/call")
            params: Method parameters (may include instance_id)

        Returns:
            Response dict from the IDA instance
        """
        # Tool calls carry instance_id inside arguments. Resource reads use the
        # federated URI at the proxy boundary, so the server passes the routed
        # instance_id alongside the standard resources/read params.
        if method == "resources/read":
            instance_id = params.get("instance_id")
        else:
            instance_id = params.get("arguments", {}).get("instance_id")

        if not instance_id:
            instances = self.registry.list_instances()
            return {
                "error": "Missing required parameter 'instance_id'.",
                "hint": (
                    "Call list_instances() and pass instance_id explicitly."
                    if len(instances) != 0
                    else "No IDA instances registered. Start IDA with the MCP plugin first."
                ),
                "available_instances": [
                    {"id": id, "binary_name": info.get("binary_name", "unknown")}
                    for id, info in instances.items()
                ],
            }

        # Get instance info
        instance_info = self.registry.get_instance(instance_id)

        # Check if instance exists
        if instance_info is None:
            # Check if it was expired
            expired_info = self.registry.get_expired(instance_id)
            if expired_info is not None:
                return self._handle_expired_instance(instance_id, expired_info)
            else:
                return self._handle_missing_instance(instance_id)

        # Remove the proxy-only instance_id before forwarding to IDA.
        forward_params = params.copy()
        if method == "resources/read":
            forward_params.pop("instance_id", None)
        elif "arguments" in forward_params:
            forward_args = forward_params["arguments"].copy()
            forward_args.pop("instance_id", None)
            forward_params["arguments"] = forward_args
        # IDA verifies this against the loaded database on its main thread, in
        # the same execution as the request (hook-failure / port-reuse fallback).
        forward_params["_meta"] = {EXPECTED_BINARY_META_KEY: instance_info.get("binary_name")}

        # Route the request
        return self._send_request(instance_info, method, forward_params)

    def _send_request(self, instance_info: dict, method: str, params: dict) -> dict[str, Any]:
        """Send HTTP request to IDA instance.

        Args:
            instance_info: Instance metadata
            method: MCP method name
            params: Method parameters

        Returns:
            Response dict
        """
        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")

        # Security: validate host is localhost only (prevent SSRF)
        if host not in ALLOWED_HOSTS:
            return {"error": "Connection refused: only localhost instances allowed"}

        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=300.0)
            request_body = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1
            })
            conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            response_data = json.loads(response.read().decode())

            # Return result or error
            if "result" in response_data:
                return response_data["result"]
            elif "error" in response_data:
                error = response_data["error"]
                if isinstance(error, dict) and error.get("code") == BINARY_MISMATCH_CODE:
                    return {
                        "error": f"Instance binary changed: {error.get('message')}. Instance may be stale.",
                        "hint": "Use list_instances() to see current instances.",
                    }
                if isinstance(error, dict) and error.get("code") == -32601:
                    tool_name = params.get("name") if method == "tools/call" else method
                    message = str(error.get("message", "Method not found"))
                    return {
                        "error": message,
                        "hint": (
                            f"Target instance does not expose tool '{tool_name}'. "
                            "Enable the tool in the IDA plugin config page, or restart "
                            "the IDA plugin so it loads the same ida-multi-mcp version "
                            "as the router."
                        ),
                    }
                return {"error": error}
            else:
                return response_data

        except Exception as e:
            # Security: don't leak host/port in error messages
            return {
                "error": f"Failed to connect to instance: {type(e).__name__}",
            }
        finally:
            if conn is not None:
                conn.close()  # always release the socket, even on error

    def _handle_expired_instance(self, instance_id: str, expired_info: dict) -> dict[str, Any]:
        """Handle request for an expired instance.

        Args:
            instance_id: Expired instance ID
            expired_info: Expired instance metadata

        Returns:
            Error response with replacement suggestions
        """
        # Find replacement: same binary name
        binary_name = expired_info.get("binary_name", "")
        instances = self.registry.list_instances()
        replacements = [
            (id, info) for id, info in instances.items()
            if info.get("binary_name") == binary_name
        ]

        reason = expired_info.get("reason", expired_info.get("expire_reason", "unknown"))
        if replacements:
            return {
                "error": f"Instance '{instance_id}' expired at {expired_info.get('expired_at')}",
                "reason": reason,
                "replacements": [
                    {"id": id, "binary_name": info.get("binary_name")}
                    for id, info in replacements
                ],
                "hint": f"Use instance_id='{replacements[0][0]}' for subsequent calls."
            }
        else:
            return {
                "error": f"Instance '{instance_id}' expired and no replacement found.",
                "reason": reason,
                "available_instances": list(instances.keys())
            }

    def _handle_missing_instance(self, instance_id: str) -> dict[str, Any]:
        """Handle request for a missing instance.

        Args:
            instance_id: Missing instance ID

        Returns:
            Error response with available instances
        """
        instances = self.registry.list_instances()
        return {
            "error": f"Instance '{instance_id}' not found.",
            "available_instances": [
                {"id": id, "binary_name": info.get("binary_name", "unknown")}
                for id, info in instances.items()
            ],
            "hint": "Use list_instances() to see all available instances."
        }
