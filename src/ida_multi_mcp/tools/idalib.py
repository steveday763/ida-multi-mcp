"""idalib management tools — exposed through the router MCP server.

These four tools let MCP clients open/close/list/inspect headless idalib
sessions.  Each session is a subprocess managed by :class:`IdalibManager`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..idalib_manager import IdalibManager

_manager: IdalibManager | None = None


def set_manager(manager: IdalibManager) -> None:
    """Inject the :class:`IdalibManager` instance (called by server.py on startup)."""
    global _manager
    _manager = manager


def _get_manager() -> IdalibManager:
    if _manager is None:
        raise RuntimeError("IdalibManager not initialized")
    return _manager


# ------------------------------------------------------------------
# Tool functions (called from custom_tools_call in server.py)
# ------------------------------------------------------------------


def idalib_open(arguments: dict) -> dict:
    """Open a binary in a new headless idalib session.

    Required args:
        input_path (str): Path to the binary or IDB file.
    Optional args:
        timeout (int): Seconds to wait for analysis (default 120).
        save_on_close (bool): Save the database when closing the worker
            (default false).
    """
    mgr = _get_manager()
    input_path = arguments.get("input_path", "")
    if not input_path:
        return {"error": "Missing required argument 'input_path'"}
    timeout = int(arguments.get("timeout", 120))
    save_on_close = bool(arguments.get("save_on_close", False))
    return mgr.spawn_session(
        input_path,
        timeout=timeout,
        save_on_close=save_on_close,
    )


def idalib_close(arguments: dict) -> dict:
    """Close a headless idalib session and terminate its worker process.

    Required args:
        instance_id (str): Instance ID of the idalib session.
    """
    mgr = _get_manager()
    instance_id = arguments.get("instance_id", "")
    if not instance_id:
        return {"error": "Missing required argument 'instance_id'"}
    return mgr.close_session(instance_id)


def idalib_list(arguments: dict) -> dict:
    """List registered idalib sessions and mark current-server ownership."""
    mgr = _get_manager()
    sessions = mgr.list_sessions()
    return {"count": len(sessions), "sessions": sessions}


def idalib_status(arguments: dict) -> dict:
    """Health / readiness check for a specific idalib session.

    Required args:
        instance_id (str): Instance ID to check.
    """
    mgr = _get_manager()
    instance_id = arguments.get("instance_id", "")
    if not instance_id:
        return {"error": "Missing required argument 'instance_id'"}
    return mgr.get_status(instance_id)


# ------------------------------------------------------------------
# Tool schemas (registered in server._refresh_tools)
# ------------------------------------------------------------------

IDALIB_TOOL_SCHEMAS: list[dict] = [
    {
        "name": "idalib_open",
        "description": (
            "Open a binary or IDB in a new headless idalib session. "
            "Binary paths follow IDA's normal database selection, so an "
            "existing adjacent IDB such as libfoo.so.i64 may be loaded instead "
            "of starting a fresh analysis. Spawns a background process that "
            "loads the input via idalib, "
            "waits for auto-analysis to complete, then registers as a regular "
            "IDA instance. Use list_instances() to see it alongside GUI instances. "
            "Requires idapro Python package on the configured Python."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": (
                        "Path to the binary or IDB file to open. Binary paths "
                        "use IDA's default behavior and may reuse an existing "
                        "adjacent .i64/.idb database."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": "Seconds to wait for analysis to complete (default 120)",
                },
                "save_on_close": {
                    "type": "boolean",
                    "description": (
                        "Save the IDB when the idalib worker closes (default false). "
                        "False means this session's changes are not written on "
                        "normal close; it does not force a fresh database or "
                        "prevent IDA from loading an existing adjacent IDB. "
                        "Use idb_save for explicit saves during a session."
                    ),
                },
            },
            "required": ["input_path"],
        },
    },
    {
        "name": "idalib_close",
        "description": (
            "Close a headless idalib session and terminate its worker process. "
            "The instance is removed from the registry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID of the idalib session to close",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "idalib_list",
        "description": (
            "List registered headless idalib sessions with pid, port, binary info, "
            "and whether the current MCP server manages the worker process."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "idalib_status",
        "description": (
            "Health and readiness check for a specific idalib session. "
            "Reports whether the worker process is alive and reachable via HTTP."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID of the idalib session to check",
                },
            },
            "required": ["instance_id"],
        },
    },
]
