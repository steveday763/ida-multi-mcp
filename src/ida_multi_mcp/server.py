"""MCP server for ida-multi-mcp.

Aggregates tools from multiple IDA instances and routes requests.
"""

import os
import re
import sys
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from .vendor.zeromcp import McpServer
from .registry import InstanceRegistry
from .router import InstanceRouter
from .health import cleanup_stale_instances, rediscover_instances
from .idalib_manager import IdalibManager
from .tools import management, idalib as idalib_tools
from .cache import get_cache, DEFAULT_MAX_OUTPUT_CHARS
from .schema_text import compact_resource_schema, compact_tool_schema

# Static IDA tool schemas (loaded once at import time)
_STATIC_IDA_TOOLS_PATH = Path(__file__).parent / "ida_tool_schemas.json"
_STATIC_IDA_TOOLS: list[dict] | None = None


def _federate_resource_uri(instance_id: str, remote_uri: str) -> str | None:
    """Prefix an IDA resource URI with the routed instance identifier."""
    parsed = urlsplit(remote_uri)
    if parsed.scheme != "ida" or not parsed.netloc:
        return None

    suffix = parsed.netloc + parsed.path
    if parsed.query:
        suffix += f"?{parsed.query}"
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return f"ida://instance/{quote(instance_id, safe='')}/{suffix.lstrip('/')}"


def _unfederate_resource_uri(uri: str) -> tuple[str, str] | None:
    """Return ``(instance_id, IDA-side URI)`` for a federated resource URI."""
    parsed = urlsplit(uri)
    if parsed.scheme != "ida" or parsed.netloc != "instance" or not parsed.path:
        return None

    parts = parsed.path.lstrip("/").split("/", 2)
    if len(parts) < 2:
        return None
    instance_id = unquote(parts[0])
    authority = parts[1]
    path = parts[2] if len(parts) == 3 else ""
    if not authority:
        return None

    remote_uri = f"ida://{unquote(authority)}"
    if path:
        remote_uri += f"/{unquote(path)}"
    if parsed.query:
        remote_uri += f"?{parsed.query}"
    if parsed.fragment:
        remote_uri += f"#{parsed.fragment}"
    return instance_id, remote_uri


def _load_static_ida_tools() -> list[dict]:
    """Load static IDA tool schemas from bundled JSON file."""
    global _STATIC_IDA_TOOLS
    if _STATIC_IDA_TOOLS is None:
        try:
            with open(_STATIC_IDA_TOOLS_PATH, "r", encoding="utf-8") as f:
                _STATIC_IDA_TOOLS = json.load(f)
        except Exception as e:
            print(f"[ida-multi-mcp] Warning: failed to load static tool schemas: {e}",
                  file=sys.stderr)
            _STATIC_IDA_TOOLS = []
    return _STATIC_IDA_TOOLS


_SERVER_INSTRUCTIONS = """\
ida-multi-mcp routes calls to one or more IDA Pro instances.

- Call `list_instances()` first and pass `instance_id` to IDA tools.
- Call `analysis_wait(instance_id=...)` before analysis on a newly opened IDB;
  results are INCOMPLETE until analysis settles.
- Prefer batch and `*_query` tools; paginate large results.
- Renames, type changes, and comments persist only after `idb_save()`.
- Routed resources use `ida://instance/<instance_id>/...`.
"""


# Tools whose results are silently wrong on a partially analysed IDB.
# Deliberately not every tool: the warning has to stay rare enough to be read.
_ANALYSIS_SENSITIVE_TOOLS = frozenset({
    "list_funcs", "func_query", "classify_functions",
    "lookup_funcs", "list_globals",
    "callgraph", "callees", "xref_query", "xrefs_to_field",
    "analyze_component", "analyze_function",
})
_ANALYSIS_STATE_TTL_SEC = 10.0


def _json_text(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def _schema_preserving_preview(value: Any, max_chars: int) -> Any:
    """Return a smaller value of the same JSON type (str/list/dict) when huge."""
    if max_chars <= 0:
        return value
    try:
        if len(_json_text(value)) <= max_chars:
            return value
    except Exception:
        return value

    if isinstance(value, str):
        return value[:max_chars]

    if isinstance(value, list):
        # Accumulate serialized length per item instead of re-serializing
        # the whole prefix each iteration (which is quadratic).
        out: list[Any] = []
        used = 2  # "[" and "]"
        for item in value:
            try:
                item_len = len(_json_text(item))
            except Exception:
                break
            used += item_len + (1 if out else 0)  # +1 for comma separator
            if used > max_chars:
                break
            out.append(item)
        return out

    if isinstance(value, dict):
        def _truncate(v: Any, depth: int = 0) -> Any:
            if depth > 6:
                return v
            if isinstance(v, str) and len(v) > 1000:
                return v[:1000] + f"... [{len(v)} chars total]"
            if isinstance(v, list):
                return [_truncate(x, depth + 1) for x in v[:50]]
            if isinstance(v, dict):
                return {k: _truncate(x, depth + 1) for k, x in v.items()}
            return v

        return _truncate(value)

    return value


class IdaMultiMcpServer:
    """MCP server that aggregates multiple IDA Pro instances.

    Discovers IDA capabilities from registered instances and routes requests
    to the appropriate instance.
    """

    def __init__(
        self,
        registry_path: str | None = None,
        idalib_python: str | None = None,
    ):
        """Initialize the multi-instance MCP server.

        Args:
            registry_path: Path to registry JSON file (default: ~/.ida-mcp/instances.json)
            idalib_python: Python executable with idapro installed (for headless sessions)
        """
        self.registry = InstanceRegistry(registry_path)
        self.router = InstanceRouter(self.registry)
        self.server = McpServer(
            "ida-multi-mcp", version="1.0.0", instructions=_SERVER_INSTRUCTIONS
        )

        # idalib lifecycle manager
        self.idalib_manager = IdalibManager(self.registry, python_executable=idalib_python)

        # Tool cache. Rebound wholesale by _refresh_tools rather than mutated,
        # so concurrent readers on stdio worker threads always see a complete map.
        self._tool_cache: dict[str, dict] = {}
        self._cache_valid = False
        self._refresh_lock = threading.Lock()
        # instance_id -> (analysis_incomplete, monotonic timestamp)
        self._analysis_state_cache: dict[str, tuple[bool, float]] = {}
        self._analysis_state_lock = threading.Lock()

        # Set up management tools
        management.set_registry(self.registry)
        management.set_router(self.router)
        idalib_tools.set_manager(self.idalib_manager)

        # Register handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP protocol handlers."""

        def _is_result_wrapper_schema(schema: Any) -> bool:
            if not isinstance(schema, dict):
                return False
            if schema.get("type") != "object":
                return False
            props = schema.get("properties")
            if not isinstance(props, dict) or "result" not in props:
                return False
            # Treat {result: <T>} as wrapper only when it is the ONLY property
            return set(props.keys()) == {"result"}

        def _coerce_structured_for_schema(tool_name: str, structured: Any) -> Any:
            """Ensure structuredContent matches the tool's advertised outputSchema.

            Some servers advertise an object wrapper {result: ...} for non-object returns.
            Others advertise raw arrays/scalars. We adapt based on cached tool schema.
            """
            schema = self._tool_cache.get(tool_name, {}).get("outputSchema")

            # If schema expects wrapper, always wrap non-wrapper values.
            if _is_result_wrapper_schema(schema):
                if isinstance(structured, dict) and set(structured.keys()) == {"result"}:
                    return structured
                return {"result": structured}

            # If schema does NOT expect wrapper, unwrap legacy {result: ...}.
            if isinstance(structured, dict) and set(structured.keys()) == {"result"}:
                return structured.get("result")

            return structured

        # Override tools/list to return cached tools

        def custom_tools_list(cursor: str | None = None, _meta: dict | None = None) -> dict:
            """List all available tools (management + IDA tools)."""
            # Ensure tool cache is fresh
            if not self._cache_valid:
                self._refresh_tools()

            # Return all cached tools (cursor ignored - no pagination needed)
            return {"tools": list(self._tool_cache.values())}

        def custom_resources_list(cursor: str | None = None, _meta: dict | None = None) -> dict:
            """List resources exposed by each registered IDA instance."""
            return {"resources": self._list_federated_resources()[0]}

        def custom_resource_templates_list(
            cursor: str | None = None, _meta: dict | None = None
        ) -> dict:
            """List parameterized resources exposed by each registered IDA instance."""
            return {"resourceTemplates": self._list_federated_resources()[1]}

        def custom_resources_read(uri: str, _meta: dict | None = None) -> dict:
            """Read a namespaced resource from its routed IDA instance."""
            parsed = _unfederate_resource_uri(uri)
            if parsed is None:
                return self._resource_error(
                    uri,
                    "Resource URI must use the federated form ida://instance/<instance_id>/<resource-authority>/<resource-path>.",
                )

            instance_id, remote_uri = parsed
            response = self.router.route_request(
                "resources/read",
                {"instance_id": instance_id, "uri": remote_uri},
            )
            if not isinstance(response, dict):
                return self._resource_error(uri, "Invalid resource response")
            if "error" in response:
                return self._resource_error(uri, response)

            # The remote server returns its local URI. Rewrite it so clients can
            # continue to address the resource through this aggregator.
            contents = response.get("contents")
            if isinstance(contents, list):
                rewritten = []
                for item in contents:
                    if not isinstance(item, dict):
                        rewritten.append(item)
                        continue
                    item_copy = item.copy()
                    item_copy["uri"] = uri
                    rewritten.append(item_copy)
                return {**response, "contents": rewritten}
            return response

        self.server.registry.methods["tools/list"] = custom_tools_list
        self.server.registry.methods["resources/list"] = custom_resources_list
        self.server.registry.methods["resources/templates/list"] = custom_resource_templates_list
        self.server.registry.methods["resources/read"] = custom_resources_read

        # Override tools/call to route requests
        def custom_tools_call(name: str, arguments: dict[str, Any] | None = None, _meta: dict | None = None) -> dict:
            """Route tool call to appropriate handler."""
            if arguments is None:
                arguments = {}

            # Management tools (local)
            if name == "list_instances":
                result = management.list_instances()
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": False
                }

            elif name == "get_cached_output":
                cache = get_cache()
                cache_id = arguments.get("cache_id", "")
                offset = arguments.get("offset", 0)
                size = arguments.get("size", DEFAULT_MAX_OUTPUT_CHARS)

                try:
                    result = cache.get(cache_id, offset, size)
                    return {
                        "content": [{"type": "text", "text": result["chunk"]}],
                        "structuredContent": result,
                        "isError": False
                    }
                except KeyError as e:
                    return {
                        "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                        "isError": True
                    }

            elif name == "analysis_wait":
                result = management.analysis_wait(arguments)
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": "error" in result,
                }

            elif name == "list_cached_outputs":
                cache = get_cache()
                result = {"entries": cache.list_entries(), **cache.stats()}
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": False,
                }

            elif name == "decompile_to_file":
                result = self._handle_decompile_to_file(arguments)
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": "error" in result
                }

            # idalib management tools (local)
            elif name in ("idalib_open", "idalib_close", "idalib_list", "idalib_status"):
                handler = getattr(idalib_tools, name)
                result = handler(arguments)
                is_error = "error" in result
                # After idalib_open succeeds, refresh tools so the new instance's
                # tools become available immediately.
                if name == "idalib_open" and not is_error:
                    self._refresh_tools()
                return {
                    "content": [{"type": "text", "text": _json_text(result)}],
                    "structuredContent": result,
                    "isError": is_error,
                }

            # IDA tools (proxied)
            else:
                # Check if any IDA instance is available before proxying
                active = self.registry.get_active()
                if not active:
                    # Try auto-discovery before giving up
                    discovered = rediscover_instances(self.registry)
                    if discovered:
                        active = self.registry.get_active()
                if not active:
                    return {
                        "content": [{"type": "text", "text": (
                            f"Error: No IDA Pro instance is connected. "
                            f"Cannot execute tool '{name}'.\n\n"
                            f"To fix this:\n"
                            f"1. Open IDA Pro and load a binary\n"
                            f"2. Press Ctrl+M (or start the MCP plugin manually)\n"
                            f"3. The plugin will auto-register with this server\n"
                            f"4. Use 'list_instances' to verify the connection"
                        )}],
                        "isError": True,
                    }

                # Extract max_output_chars if provided (0 = unlimited)
                max_output = arguments.pop("max_output_chars", DEFAULT_MAX_OUTPUT_CHARS)

                ida_response = self.router.route_request("tools/call", {
                    "name": name,
                    "arguments": arguments
                })

                # Format response
                if "error" in ida_response:
                    return {
                        "content": [{"type": "text", "text": f"Error: {_json_text(ida_response)}"}],
                        "isError": True
                    }

                # IDA instance should return an MCP tool result envelope already.
                content = ida_response.get("content") if isinstance(ida_response, dict) else None
                is_error = bool(ida_response.get("isError")) if isinstance(ida_response, dict) else False
                structured = ida_response.get("structuredContent") if isinstance(ida_response, dict) else None

                if structured is None and isinstance(content, list) and content:
                    # Best-effort: parse JSON text content as structured output
                    try:
                        structured = json.loads(content[0].get("text", ""))
                    except Exception:
                        structured = None

                structured = _coerce_structured_for_schema(name, structured)

                # If IDA didn't provide content, generate a readable one.
                if not content:
                    content = [{"type": "text", "text": _json_text(structured)}]

                # Results from a still-analysing IDB are silently partial. A
                # description telling the caller to gate on analysis_wait() only
                # helps if they read it first, so say it again here, attached to
                # the incomplete answer itself.
                #
                # Appended to every return path below, not once here: the
                # truncation branch builds a fresh content list, and that branch
                # is the one a big half-analysed binary always takes.
                analysis_note: list[dict] = []
                if name in _ANALYSIS_SENSITIVE_TOOLS and self._analysis_incomplete(
                    arguments.get("instance_id")
                ):
                    analysis_note = [{
                        "type": "text",
                        "text": (
                            "\n[ida-multi-mcp] WARNING: IDA auto-analysis has NOT finished on "
                            "this instance. Functions, xrefs, strings and decompiler output are "
                            "incomplete, and this result is very likely missing data. Call "
                            "analysis_wait(instance_id=...) and then repeat this call before "
                            "drawing any conclusions."
                        ),
                    }]

                # If the tool has an output schema, Factory requires structuredContent.
                # Even on errors, keep the structured payload if present.
                if is_error:
                    return {
                        "content": list(content) + analysis_note,
                        **({"structuredContent": structured} if structured is not None else {}),
                        "isError": True,
                    }

                # Serialize structured for size checks
                structured_text = _json_text(structured)
                total_chars = len(structured_text)

                # Check if truncation needed (max_output=0 means unlimited)
                if max_output > 0 and total_chars > max_output:
                    # Cache full response text for humans (get_cached_output)
                    cache = get_cache()
                    instance_id = arguments.get("instance_id") or "unknown"
                    cache_id = cache.store(structured_text, tool_name=name, instance_id=instance_id)

                    preview_structured = _schema_preserving_preview(structured, max_output)
                    preview_text = _json_text(preview_structured)

                    truncation_notice = (
                        f"\n\n--- TRUNCATED ---\n"
                        f"Showing ~{max_output:,} of {total_chars:,} chars ({total_chars - max_output:,} remaining)\n"
                        f"cache_id: {cache_id}\n"
                        f"To get more: get_cached_output(cache_id='{cache_id}', offset={max_output})"
                    )

                    return {
                        "content": [
                            {"type": "text", "text": preview_text[:max_output] + truncation_notice}
                        ] + analysis_note,
                        "structuredContent": preview_structured,
                        "isError": False,
                    }

                return {
                    "content": list(content) + analysis_note,
                    "structuredContent": structured,
                    "isError": False,
                }

        self.server.registry.methods["tools/call"] = custom_tools_call

    def _resource_error(self, uri: str, error: Any) -> dict:
        """Build an MCP resources/read error result without leaking transport details."""
        if isinstance(error, dict):
            payload = error
        else:
            payload = {"error": str(error)}
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": _json_text(payload),
            }],
            "isError": True,
        }

    def _list_federated_resources(self) -> tuple[list[dict], list[dict]]:
        """Discover and namespace resources from all registered IDA instances."""
        instances = self.registry.list_instances()
        if not instances:
            discovered = rediscover_instances(self.registry)
            if discovered:
                instances = self.registry.list_instances()

        resources: list[dict] = []
        templates: list[dict] = []
        for instance_id in sorted(instances):
            info = instances.get(instance_id)
            if not info:
                continue
            discovered = self._discover_ida_resources(info)
            for resource in discovered.get("resources", []):
                remote_uri = resource.get("uri") if isinstance(resource, dict) else None
                if not isinstance(remote_uri, str):
                    continue
                public_uri = _federate_resource_uri(instance_id, remote_uri)
                if public_uri is None:
                    continue
                entry = compact_resource_schema(resource)
                entry["uri"] = public_uri
                entry["name"] = f"{instance_id}:{resource.get('name', remote_uri)}"
                description = entry.get("description", "")
                entry["description"] = f"[instance_id={instance_id}] {description}".strip()
                resources.append(entry)

            for template in discovered.get("resourceTemplates", []):
                remote_template = (
                    template.get("uriTemplate") if isinstance(template, dict) else None
                )
                if not isinstance(remote_template, str):
                    continue
                public_template = _federate_resource_uri(instance_id, remote_template)
                if public_template is None:
                    continue
                entry = compact_resource_schema(template)
                entry["uriTemplate"] = public_template
                entry["name"] = f"{instance_id}:{template.get('name', remote_template)}"
                description = entry.get("description", "")
                entry["description"] = f"[instance_id={instance_id}] {description}".strip()
                templates.append(entry)

        return resources, templates

    def _discover_ida_resources(self, instance_info: dict) -> dict[str, list[dict]]:
        """Fetch resource and resource-template catalogs from one IDA instance."""
        import http.client

        from .registry import ALLOWED_HOSTS

        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")
        if host not in ALLOWED_HOSTS:
            return {"resources": [], "resourceTemplates": []}

        result: dict[str, list[dict]] = {"resources": [], "resourceTemplates": []}
        for method, key in (
            ("resources/list", "resources"),
            ("resources/templates/list", "resourceTemplates"),
        ):
            conn = None
            try:
                conn = http.client.HTTPConnection(host, port, timeout=10.0)
                request_body = json.dumps({
                    "jsonrpc": "2.0",
                    "method": method,
                    "id": 1,
                })
                conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
                response = conn.getresponse()
                response_data = json.loads(response.read().decode())
                remote_result = response_data.get("result")
                if isinstance(remote_result, dict) and isinstance(remote_result.get(key), list):
                    result[key] = remote_result[key]
            except Exception as e:
                print(
                    f"[ida-multi-mcp] Failed to discover IDA {method}: {type(e).__name__}",
                    file=sys.stderr,
                )
            finally:
                if conn is not None:
                    conn.close()
        return result

    def _analysis_incomplete(self, instance_id: str | None) -> bool:
        """Whether the instance is still auto-analysing.

        Cached briefly: this runs on every analysis-sensitive call, and the
        answer only ever flips once per database. Anything unknown (no instance,
        probe failed) reports False — a spurious warning on every result would
        train the caller to ignore it.
        """
        if not instance_id:
            return False
        now = time.monotonic()
        with self._analysis_state_lock:
            entry = self._analysis_state_cache.get(instance_id)
            if entry is not None and now - entry[1] < _ANALYSIS_STATE_TTL_SEC:
                return entry[0]

        try:
            resp = self.router.route_request(
                "tools/call",
                {"name": "analysis_status", "arguments": {"instance_id": instance_id}},
            )
            structured = resp.get("structuredContent") if isinstance(resp, dict) else None
            if not isinstance(structured, dict) or "finished" not in structured:
                return False
            incomplete = not bool(structured["finished"])
        except Exception:
            return False

        with self._analysis_state_lock:
            self._analysis_state_cache[instance_id] = (incomplete, now)
        return incomplete

    def _handle_decompile_to_file(self, arguments: dict) -> dict:
        """Decompile functions and save results to local files.

        Orchestrates list_funcs + decompile calls via IDA, writes to disk locally.
        """
        decompile_all = arguments.get("all", False)
        addrs = arguments.get("addrs", [])
        output_dir = arguments.get("output_dir", ".")
        mode = arguments.get("mode", "single")
        allow_outside_cwd = arguments.get("allow_outside_cwd", False)
        instance_id = arguments.get("instance_id")
        if not instance_id:
            return {
                "error": "Missing required parameter 'instance_id'.",
                "hint": "Call list_instances() and pass instance_id explicitly.",
            }

        # Security: validate output_dir to prevent path traversal
        resolved_dir = os.path.realpath(output_dir)
        # Reject absolute paths that escape CWD unless they are subdirectories
        if ".." in os.path.normpath(output_dir).split(os.sep):
            return {"error": "output_dir must not contain '..' path components"}
        # Security: confine output to the current working directory by default.
        # Tool arguments here are LLM-generated, so an injected absolute path
        # (e.g. a system directory) must not silently receive written files.
        # Callers can opt out explicitly with allow_outside_cwd=true.
        if not allow_outside_cwd:
            cwd = os.path.realpath(os.getcwd())
            if resolved_dir != cwd and not resolved_dir.startswith(cwd + os.sep):
                return {
                    "error": (
                        "output_dir must be within the current working directory. "
                        "Pass allow_outside_cwd=true to write elsewhere."
                    ),
                    "cwd": cwd,
                }
        output_dir = resolved_dir

        # addr → name mapping (populated by list_funcs when using 'all')
        addr_names: dict[str, str] = {}

        # Fetch all function addresses via paginated list_funcs calls
        if decompile_all:
            addrs = []
            offset = 0
            page_size = 500
            while True:
                list_result = self.router.route_request("tools/call", {
                    "name": "list_funcs",
                    "arguments": {
                        "queries": [{"count": page_size, "offset": offset}],
                        "instance_id": instance_id,
                    }
                })
                if "error" in list_result:
                    return {"error": f"Failed to list functions: {list_result['error']}"}

                try:
                    content = list_result.get("content", [])
                    if not content:
                        break
                    raw = json.loads(content[0]["text"])
                    if not isinstance(raw, list) or not raw:
                        break
                    page_data = raw[0].get("data", [])
                    if not page_data:
                        break
                    for f in page_data:
                        if "addr" in f:
                            addrs.append(f["addr"])
                            if "name" in f:
                                addr_names[f["addr"]] = f["name"]
                    # Check if there are more pages
                    next_offset = raw[0].get("next_offset")
                    if next_offset is None or len(page_data) < page_size:
                        break
                    offset = next_offset
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    return {"error": "Failed to parse list_funcs response"}

            if not addrs:
                return {"error": "No functions found in binary"}

        if not addrs:
            return {"error": "No addresses provided. Pass 'addrs' array or set 'all' to true."}

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        success = 0
        failed = 0
        failed_addrs = []
        files_written = []

        def _call_decompile(addr: str) -> dict:
            """Call decompile and parse MCP content wrapper."""
            raw = self.router.route_request("tools/call", {
                "name": "decompile",
                "arguments": {
                    "addr": addr,
                    "instance_id": instance_id,
                }
            })
            # Router returns {"content": [{"text": "{\"addr\":...,\"code\":...}"}]}
            try:
                content = raw.get("content", [])
                if content:
                    return json.loads(content[0]["text"])
            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                pass
            return raw

        if mode == "merged":
            merged_path = os.path.join(output_dir, "decompiled.c")
            with open(merged_path, "w", encoding="utf-8") as f:
                for addr in addrs:
                    decomp = _call_decompile(addr)
                    code = decomp.get("code")
                    if code:
                        name = addr_names.get(addr) or decomp.get("name") or addr
                        f.write(f"// {name} @ {addr}\n")
                        f.write(code)
                        f.write("\n\n")
                        success += 1
                    else:
                        failed += 1
                        failed_addrs.append(addr)
            files_written.append("decompiled.c")
        else:
            # single mode: one file per function
            for addr in addrs:
                decomp = _call_decompile(addr)
                code = decomp.get("code")
                if code:
                    name = addr_names.get(addr) or decomp.get("name") or addr
                    safe_name = re.sub(r'[<>:"/\\|?*]', "_", name)
                    # Security: strip '..' path traversal sequences from function names
                    safe_name = safe_name.replace("..", "_")
                    # Include address to avoid collisions across duplicate function names.
                    addr_suffix = re.sub(r"[^0-9A-Fa-fx]", "_", str(addr))
                    filename = f"{safe_name}_{addr_suffix}.c"
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(f"// {name} @ {addr}\n")
                        f.write(code)
                        f.write("\n")
                    files_written.append(filename)
                    success += 1
                else:
                    failed += 1
                    failed_addrs.append(addr)

        return {
            "output_dir": output_dir,
            "mode": mode,
            "total": len(addrs),
            "success": success,
            "failed": failed,
            "failed_addrs": failed_addrs[:50],
            "files": files_written[:50],
            "files_total": len(files_written),
        }

    def _refresh_tools(self) -> int:
        """Refresh tool cache from IDA instances.

        Discovery does HTTP round-trips per instance and takes real time, so the
        new cache is built into a local dict and swapped in at the end rather
        than mutated in place. The lock keeps two concurrent refreshes (e.g. a
        tools/list miss racing the one idalib_open triggers) from duplicating
        that work.

        Returns:
            Number of tools discovered
        """
        with self._refresh_lock:
            return self._build_tool_cache()

    def _build_tool_cache(self) -> int:
        cache = {}

        # Add management tools
        cache["list_instances"] = compact_tool_schema({
            "name": "list_instances",
            "description": "List registered IDA instances.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "instances": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "type": {"type": "string", "description": "gui or idalib"},
                                "binary_name": {"type": "string"},
                                "binary_path": {"type": "string"},
                                "arch": {"type": "string"},
                                "host": {"type": "string"},
                                "port": {"type": "integer"},
                                "pid": {"type": "integer"},
                                "registered_at": {"type": "string"}
                            },
                            "required": ["id", "type", "binary_name", "binary_path", "arch", "host", "port", "pid", "registered_at"]
                        }
                    }
                },
                "required": ["count", "instances"]
            }
        })

        cache["analysis_wait"] = compact_tool_schema({
            "name": "analysis_wait",
            "description": (
                "Wait for IDA auto-analysis; timeout returns current state. "
                "finished is a snapshot; functions_added helps confirm completion."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "IDA instance ID"},
                    "timeout_sec": {
                        "type": "number",
                        "description": "Wait seconds (default 120; max 600)",
                    },
                },
                "required": ["instance_id"],
            },
        })

        cache["list_cached_outputs"] = compact_tool_schema({
            "name": "list_cached_outputs",
            "description": "List cached truncated outputs.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        })

        cache["get_cached_output"] = compact_tool_schema({
            "name": "get_cached_output",
            "description": "Read a cached truncated output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cache_id": {
                        "type": "string",
                        "description": "Cache ID"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Character offset (default 0)"
                    },
                    "size": {
                        "type": "integer",
                        "description": "Character count (default 20000; 0=rest)"
                    }
                },
                "required": ["cache_id"]
            }
        })

        cache["decompile_to_file"] = compact_tool_schema({
            "name": "decompile_to_file",
            "description": "Decompile functions to files; large sets may take time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "addrs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Function addresses; required unless all=true"
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Decompile all; ignores addrs"
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output directory"
                    },
                    "mode": {
                        "type": "string",
                        "description": "Mode: single|merged"
                    },
                    "allow_outside_cwd": {
                        "type": "boolean",
                        "description": "Allow output outside cwd"
                    },
                    "instance_id": {
                        "type": "string",
                        "description": "IDA instance ID"
                    }
                },
                "required": ["output_dir", "instance_id"]
            }
        })

        # Register idalib management tool schemas (only if IDA Pro with idalib is available)
        from .idalib_manager import is_idalib_available
        if is_idalib_available():
            for schema in idalib_tools.IDALIB_TOOL_SCHEMAS:
                compacted = compact_tool_schema(schema)
                cache[compacted["name"]] = compacted

        # Always load static IDA tool schemas so tools are visible even
        # when no IDA instance is connected.
        for tool_schema in _load_static_ida_tools():
            if tool_schema.get("name") == "survey_binary":
                # Older bundled catalogs can outlive the removed IDA tool.
                continue
            schema = compact_tool_schema(tool_schema)

            # Require explicit instance_id for all IDA tools (avoid global active instance contention).
            input_schema = schema.get("inputSchema", {}) or {}
            properties = input_schema.get("properties", {}) or {}
            required = input_schema.get("required", []) or []
            properties["instance_id"] = {
                "type": "string",
                "description": "IDA instance ID"
            }
            if "instance_id" not in required:
                required.append("instance_id")
            input_schema["properties"] = properties
            input_schema["required"] = required
            schema["inputSchema"] = input_schema

            cache[schema["name"]] = schema

        # Discover IDA tools from any available instance (rediscover if needed).
        instances = self.registry.list_instances()
        if not instances:
            discovered = rediscover_instances(self.registry)
            if discovered:
                print(
                    f"[ida-multi-mcp] Auto-discovered {len(discovered)} IDA instance(s) during refresh",
                    file=sys.stderr,
                )
            instances = self.registry.list_instances()

        if instances:
            # Copy tool schemas from the first responsive instance. Routing always requires instance_id.
            ida_tools: list[dict] = []
            for candidate_id in sorted(instances.keys()):
                instance_info = self.registry.get_instance(candidate_id)
                if not instance_info:
                    continue
                ida_tools = self._discover_ida_tools(instance_info)
                if ida_tools:
                    break

            for tool in ida_tools:
                if tool.get("name") == "survey_binary":
                    continue
                tool_schema = compact_tool_schema(tool)
                input_schema = tool_schema.get("inputSchema", {}) or {}
                properties = input_schema.get("properties", {}) or {}
                required = input_schema.get("required", []) or []

                # Add instance_id parameter (required)
                properties["instance_id"] = {
                    "type": "string",
                    "description": "IDA instance ID"
                }
                if "instance_id" not in required:
                    required.append("instance_id")

                input_schema["properties"] = properties
                input_schema["required"] = required
                tool_schema["inputSchema"] = input_schema

                cache[tool_schema["name"]] = tool_schema

        # MCP spec expects outputSchema to be an object schema.
        # Some clients validate all advertised tools; keep schemas conservative.
        for tool_schema in cache.values():
            os = tool_schema.get("outputSchema")
            if not os:
                tool_schema["outputSchema"] = {"type": "object"}
                continue
            if os.get("type") != "object":
                tool_schema["outputSchema"] = {
                    "type": "object",
                    "properties": {"result": os},
                    "required": ["result"],
                }

        # Publish in one rebind. Readers (tools/list, _coerce_structured_for_schema)
        # run on stdio worker threads, so they must never observe a partially
        # populated cache: they either see the whole old dict or the whole new one.
        self._tool_cache = cache
        self._cache_valid = True
        return len(cache)

    def _discover_ida_tools(self, instance_info: dict) -> list[dict]:
        """Discover tools from an IDA instance.

        Args:
            instance_info: Instance metadata

        Returns:
            List of tool schemas
        """
        import http.client

        from .registry import ALLOWED_HOSTS

        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")

        # Security: only connect to localhost instances
        if host not in ALLOWED_HOSTS:
            return []

        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=10.0)
            request_body = json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            })
            conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            response_data = json.loads(response.read().decode())

            if "result" in response_data:
                tools = response_data["result"].get("tools", [])
                return tools
            else:
                return []

        except Exception as e:
            print(f"[ida-multi-mcp] Failed to discover tools from instance: {e}", file=sys.stderr)
            return []
        finally:
            if conn is not None:
                conn.close()  # always release the socket, even on error

    def run(self):
        """Run the MCP server with stdio transport."""
        # Clean up dead instances on startup
        removed = cleanup_stale_instances(self.registry)
        if removed:
            print(f"[ida-multi-mcp] Cleaned up {len(removed)} dead instances on startup",
                  file=sys.stderr)

        # Auto-discover IDA instances if registry is empty
        if not self.registry.list_instances():
            discovered = rediscover_instances(self.registry)
            if discovered:
                print(f"[ida-multi-mcp] Auto-discovered {len(discovered)} IDA instance(s)",
                      file=sys.stderr)
            else:
                print("[ida-multi-mcp] No IDA instances found (start IDA with MCP plugin first)",
                      file=sys.stderr)

        # Refresh tools
        self._refresh_tools()
        print(f"[ida-multi-mcp] Server starting with {len(self._tool_cache)} tools",
              file=sys.stderr)

        # Run server with stdio transport (idalib cleanup via atexit in IdalibManager)
        self.server.stdio()


def serve(registry_path: str | None = None, idalib_python: str | None = None):
    """Start the ida-multi-mcp server.

    Args:
        registry_path: Optional custom registry path
        idalib_python: Python executable with idapro installed (for headless)
    """
    server = IdaMultiMcpServer(registry_path, idalib_python=idalib_python)
    server.run()
