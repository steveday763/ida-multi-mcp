import logging
import queue
import functools
import os
import sys
import threading
import time
from enum import IntEnum
import idaapi
import ida_kernwin
import ida_nalt
import idc
from ..binary_identity import BINARY_MISMATCH_CODE, EXPECTED_BINARY_META_KEY, normalize_binary_name
from .rpc import McpToolError
from .zeromcp.jsonrpc import (
    JsonRpcException,
    RequestCancelledError,
    get_current_cancel_event,
    get_current_request_meta,
)

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""
    pass


class BinaryMismatchError(JsonRpcException):
    def __init__(self, expected: str, current: str):
        super().__init__(
            BINARY_MISMATCH_CODE,
            f"IDA is now analyzing '{current}', not the registered '{expected}'",
        )


def _verify_binary(expected_binary: str) -> None:
    current = ida_nalt.get_root_filename()
    if normalize_binary_name(current) != normalize_binary_name(expected_binary):
        raise BinaryMismatchError(expected_binary, current)


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 15.0

# After the deadline fires ida_kernwin.set_cancelled(), how long a tool may keep
# running so it can notice the flag and format a partial response before
# IDASyncError is raised.
#
# This does extend the worst case to timeout + grace. It only buys anything for
# work that actually polls user_cancelled() (the C SDK calls); a pure-Python
# loop just runs longer. Set to 0 to enforce the timeout strictly.
_NATIVE_CANCEL_GRACE_ENV = "IDA_MCP_CANCEL_GRACE_SEC"
_DEFAULT_NATIVE_CANCEL_GRACE_SEC = 5.0


def _get_native_cancel_grace_seconds() -> float:
    value = os.getenv(_NATIVE_CANCEL_GRACE_ENV, "").strip()
    if value == "":
        return _DEFAULT_NATIVE_CANCEL_GRACE_SEC
    try:
        return max(0.0, float(value))
    except ValueError:
        return _DEFAULT_NATIVE_CANCEL_GRACE_SEC


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC



# Names of @idasync functions running on the IDA main thread. Only runned()
# touches it and runned() always executes on the main thread, so a plain list.
call_stack: list[str] = []


def _sync_wrapper(ff, expected_binary: str | None = None):
    """Call a function ff with a specific IDA safety_mode.

    expected_binary is checked on the main thread in the same execution as ff,
    so no other request can switch the database between the check and the call.
    """

    res_container = queue.Queue()

    def runned():
        if call_stack:
            # Report through res_container instead of raising: execute_sync
            # swallows the exception, and the res_container.get() below would
            # then block the requesting thread forever on an empty queue.
            # Peek only: the entry belongs to the call that is still running,
            # and removing it would let the next reentrant call run unchecked.
            res_container.put(IDASyncError(
                f"Call stack is not empty while calling the function "
                f"{ff.__name__} from {call_stack[-1]}"
            ))
            return

        call_stack.append(ff.__name__)
        # Batch mode must be toggled on the IDA main thread. Doing it in
        # sync_wrapper() ran idc.batch() on the requesting HTTP worker thread.
        old_batch = idc.batch(1)
        try:
            if expected_binary is not None:
                _verify_binary(expected_binary)
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        except BaseException as x:
            # SystemExit and friends must not escape into execute_sync: IDA
            # then stops serving (observed: that request and every later one
            # hang), and nothing reaches res_container for the requester.
            res_container.put(IDAError(f"{ff.__name__} raised {type(x).__name__}: {x}"))
        finally:
            idc.batch(old_batch)
            call_stack.pop()

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Batch mode is handled inside _sync_wrapper so that idc.batch() runs on the
    IDA main thread rather than on the calling HTTP worker thread.
    """
    # Capture request context from thread-local before execute_sync
    cancel_event = get_current_cancel_event()
    expected_binary = get_current_request_meta().get(EXPECTED_BINARY_META_KEY)

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:
        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Native cancellation: clear any stale flag and schedule a
            # set_cancelled() at the deadline. The sys.setprofile hook below
            # only fires between Python bytecodes, so it cannot preempt a
            # pure-C SDK call — a slow scan holds the IDA main thread well
            # past the timeout and every later tool call queues behind it.
            #
            # Many SDK calls already poll user_cancelled() and bail within one
            # poll cycle: ida_search.find_* (unless SEARCH_NOBRK),
            # ida_bytes.find_bytes/bin_search (unless BIN_SEARCH_NOBREAK),
            # ida_hexrays.decompile*, ida_strlist.build_strlist,
            # ida_auto.auto_wait. set_cancelled() is THREAD_SAFE, so firing it
            # from a Timer thread is safe.
            ida_kernwin.clr_cancelled()
            grace = _get_native_cancel_grace_seconds()
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:
                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()

                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                # Check request-level cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                # If native cancel just fired, give the tool a short grace
                # period to format a partial response rather than racing the
                # IDASyncError. Beyond that we still raise to bound the
                # response time.
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + grace:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                if native_timer is not None:
                    native_timer.cancel()
                # Sticky flag: clear unconditionally so the next tool starts
                # with a clean state. Without this, every subsequent
                # user_cancelled() returns True forever.
                ida_kernwin.clr_cancelled()

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, expected_binary)
    return _sync_wrapper(ff, expected_binary)


def idasync(f):
    """Run the function on the IDA main thread in write mode.
    
    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


# Backwards compatibility aliases
idaread = idasync
idawrite = idasync


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """
    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func
    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    
    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets
    
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
