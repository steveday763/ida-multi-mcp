"""Management tools for ida-multi-mcp.

These tools are implemented directly in the MCP server (not proxied to IDA).
They manage instance lifecycle and cross-instance operations.
"""

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..registry import InstanceRegistry

# Module-level registry reference, set by server.py on startup
_registry: "InstanceRegistry | None" = None


def set_registry(registry: "InstanceRegistry") -> None:
    """Set the registry instance for management tools."""
    global _registry
    _registry = registry


def _get_registry() -> "InstanceRegistry":
    if _registry is None:
        raise RuntimeError("Registry not initialized")
    return _registry


def list_instances() -> dict:
    """List all registered IDA Pro instances with their metadata.

    Returns instance ID, binary name, path, architecture, host, port,
    and registration time for each running IDA Pro instance.
    """
    registry = _get_registry()
    instances = registry.list_instances()
    result = []
    for id, info in instances.items():
        result.append({
            "id": id,
            "type": info.get("type", "gui"),
            "binary_name": info.get("binary_name", "unknown"),
            "binary_path": info.get("binary_path", "unknown"),
            "arch": info.get("arch", "unknown"),
            "host": info.get("host", "127.0.0.1"),
            "port": info.get("port", 0),
            "pid": info.get("pid", 0),
            "registered_at": info.get("registered_at", ""),
        })
    return {
        "count": len(result),
        "instances": result,
    }


# Module-level router reference for compare_binaries
_router = None


def set_router(router) -> None:
    global _router
    _router = router


def _read_resource(instance_id: str, uri: str) -> object | None:
    """Read one IDA resource through the shared router."""
    if _router is None:
        return None
    response = _router.route_request(
        "resources/read",
        {"instance_id": instance_id, "uri": uri},
    )
    if not isinstance(response, dict) or response.get("isError") or "error" in response:
        return None

    contents = response.get("contents")
    if not isinstance(contents, list) or not contents:
        return None
    text = contents[0].get("text") if isinstance(contents[0], dict) else None
    if not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def compare_binaries(arguments: dict) -> dict:
    """Compare metadata, segments, and entrypoints from two IDA instances."""
    id_a = arguments.get("instance_id_a", "")
    id_b = arguments.get("instance_id_b", "")
    if not id_a or not id_b:
        return {"error": "Both instance_id_a and instance_id_b are required"}
    if id_a == id_b:
        return {"error": "instance_id_a and instance_id_b must be different"}
    if _router is None:
        return {"error": "Router not initialized"}

    def _snapshot(instance_id: str) -> dict | None:
        metadata = _read_resource(instance_id, "ida://idb/metadata")
        segments = _read_resource(instance_id, "ida://idb/segments")
        entrypoints = _read_resource(instance_id, "ida://idb/entrypoints")
        if not isinstance(metadata, dict):
            return None
        if not isinstance(segments, list) or not isinstance(entrypoints, list):
            return None
        return {
            "metadata": metadata,
            "segments": segments,
            "entrypoints": entrypoints,
        }

    snapshot_a = _snapshot(id_a)
    snapshot_b = _snapshot(id_b)
    if snapshot_a is None:
        return {"error": f"Failed to read resources from instance {id_a}"}
    if snapshot_b is None:
        return {"error": f"Failed to read resources from instance {id_b}"}

    def _diff_sets(items_a: list[str], items_b: list[str]) -> dict:
        set_a, set_b = set(items_a), set(items_b)
        return {
            "only_a": sorted(set_a - set_b)[:200],
            "only_b": sorted(set_b - set_a)[:200],
            "common": len(set_a & set_b),
            "total_a": len(set_a),
            "total_b": len(set_b),
        }

    # Extract entry point names
    entries_a = [e.get("name", "") for e in snapshot_a["entrypoints"]]
    entries_b = [e.get("name", "") for e in snapshot_b["entrypoints"]]

    # Extract segment names
    segs_a = [s.get("name", "") for s in snapshot_a["segments"]]
    segs_b = [s.get("name", "") for s in snapshot_b["segments"]]

    return {
        "instance_a": {"id": id_a, "module": snapshot_a["metadata"].get("module", "?")},
        "instance_b": {"id": id_b, "module": snapshot_b["metadata"].get("module", "?")},
        "metadata": {"a": snapshot_a["metadata"], "b": snapshot_b["metadata"]},
        "entrypoints": _diff_sets(entries_a, entries_b),
        "segments": _diff_sets(segs_a, segs_b),
    }


# Bounded above the router's per-request socket timeout so a wait can never
# come back to the caller as a transport error instead of finished=false.
ANALYSIS_WAIT_MAX_SEC = 600.0
_ANALYSIS_POLL_INTERVAL_SEC = 1.0
# How long each IDA-side driving slice may hold the main thread.
_ANALYSIS_STEP_SEC = 5.0


def analysis_wait(arguments: dict) -> dict:
    """Poll an instance's analysis_status until analysis finishes or we time out.

    Implemented here rather than inside IDA on purpose. The obvious version --
    call ida_auto.auto_wait() under @idasync -- does not work:

      * auto_wait() is one blocking call that runs until the queues drain. It
        ignores any deadline we hand it, so `timeout_sec` was not enforced at
        all; measured live, a requested 30s wait ran 261s.
      * set_cancelled() does not reliably break it out (auto_wait's cancel path
        expects a wait box), so a Timer cannot bound it either.
      * Worst of all it holds IDA's main thread for the whole analysis, which
        blocks every other caller of that instance for minutes.

    Polling a cheap analysis_status instead gives a real timeout, and leaves the
    main thread free between polls -- both for the analyser itself and for other
    tool calls.
    """
    import time

    instance_id = arguments.get("instance_id")
    if not instance_id:
        return {
            "error": "Missing required parameter 'instance_id'.",
            "hint": "Call list_instances() and pass instance_id explicitly.",
        }

    try:
        requested = float(arguments.get("timeout_sec", 120.0))
    except (TypeError, ValueError):
        requested = 120.0
    budget = max(0.0, min(requested, ANALYSIS_WAIT_MAX_SEC))

    router = _router
    if router is None:
        return {"error": "Router unavailable"}

    def probe(tool: str, extra: dict | None = None) -> dict:
        args = {"instance_id": instance_id}
        if extra:
            args.update(extra)
        resp = router.route_request("tools/call", {"name": tool, "arguments": args})
        if not isinstance(resp, dict):
            return {}
        if "error" in resp:
            return {"_error": resp["error"]}
        body = resp.get("structuredContent")
        return body if isinstance(body, dict) else {}

    def status() -> dict:
        return probe("analysis_status")

    def drive(seconds: float) -> dict:
        # Driving, not just watching: IDA's background analysis plateaus short
        # of completion and auto_is_ok() never flips on its own.
        return probe("analysis_step", {"max_sec": seconds})

    t0 = time.monotonic()
    first = status()
    if "_error" in first:
        return {"error": f"Could not reach instance '{instance_id}': {first['_error']}"}
    if not first:
        return {"error": f"Instance '{instance_id}' did not report analysis status."}

    before = first.get("function_count", 0)
    last = first
    deadline = t0 + budget
    while not last.get("finished") and time.monotonic() < deadline:
        slice_sec = max(0.0, min(_ANALYSIS_STEP_SEC, deadline - time.monotonic()))
        if slice_sec <= 0:
            break
        stepped = drive(slice_sec)
        if stepped and "_error" not in stepped:
            last = stepped
        else:
            polled = status()
            if polled and "_error" not in polled:
                last = polled
            time.sleep(min(_ANALYSIS_POLL_INTERVAL_SEC, max(0.0, deadline - time.monotonic())))

    finished = bool(last.get("finished"))
    after = last.get("function_count", before)
    return {
        "finished": finished,
        "waited_sec": round(time.monotonic() - t0, 2),
        "function_count": after,
        "functions_added": after - before,
        "state": last.get("state", "unknown"),
        "note": (
            # Honest about what finished=True means. auto_is_ok() is a snapshot
            # of "queues empty right now", not a latch: observed live returning
            # True here and False on the very next analysis_status against the
            # same idle instance. functions_added is the more durable signal --
            # once it reaches 0 across successive calls, analysis has settled.
            "Analysis queues drained. This is a snapshot rather than a "
            "guarantee; if functions_added is 0 here and on a repeat call, "
            "the database has settled."
            if finished
            else f"Waited {budget:.0f}s and analysis is still running - "
                 f"call analysis_wait() again to continue."
        ),
    }
