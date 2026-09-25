from typing import Annotated
import ast
import io
import sys
import threading
import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref

from .rpc import tool
from .sync import idasync
from .utils import parse_address, get_function

# ============================================================================
# Python Evaluation
# ============================================================================


class _ThreadCapture(io.TextIOBase):
    """Stand-in for sys.stdout/stderr while py_eval runs.

    The swap is process-wide, but only the py_eval thread's output belongs to
    the result: HTTP handler threads keep logging other requests meanwhile, and
    their lines would otherwise leak into this response and vanish from IDA's
    output window.

    One instance per stream lives for the whole process. print() holds only a
    borrowed reference to sys.stdout, so a per-call object freed when py_eval
    restores the stream could still be written to by a handler thread in the
    middle of its print() (use-after-free).
    """

    def __init__(self):
        self._owner = None
        self._original = None
        self._buffer = io.StringIO()

    def begin(self, original) -> None:
        self._original = original
        self._buffer = io.StringIO()
        self._owner = threading.get_ident()

    def end(self) -> None:
        self._owner = None

    def write(self, s):
        if threading.get_ident() == self._owner:
            return self._buffer.write(s)
        return self._original.write(s)

    def flush(self):
        if threading.get_ident() != self._owner:
            self._original.flush()

    def getvalue(self) -> str:
        return self._buffer.getvalue()


_STDOUT_CAPTURE = _ThreadCapture()
_STDERR_CAPTURE = _ThreadCapture()


def _execute_py_eval_code(code: str, exec_globals: dict) -> str | None:
    """AST-based execution: single expression -> eval; trailing expression ->
    exec prefix then eval the last expression once; pure statements -> exec.

    The previous try-eval-then-exec pattern re-evaluated the last line as an
    expression after already executing it via exec(), so a side-effecting last
    line (e.g. ``list.append``) ran twice. Parsing the AST first lets the
    trailing expression be evaluated exactly once.
    """
    tree = ast.parse(code, mode="exec")

    def _eval_expr(expr_node: ast.expr) -> str | None:
        expr = ast.Expression(expr_node)
        ast.fix_missing_locations(expr)
        value = eval(compile(expr, "<py_eval>", "eval"), exec_globals)
        # None renders as "" via the caller's `result_value or ""` contract.
        return None if value is None else str(value)

    if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
        return _eval_expr(tree.body[0].value)

    before_keys = set(exec_globals.keys())
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        prefix = ast.Module(body=tree.body[:-1], type_ignores=tree.type_ignores)
        ast.fix_missing_locations(prefix)
        if prefix.body:
            exec(compile(prefix, "<py_eval>", "exec"), exec_globals)
        return _eval_expr(tree.body[-1].value)

    exec(compile(tree, "<py_eval>", "exec"), exec_globals)
    if "result" in exec_globals:
        return str(exec_globals["result"])

    new_keys = [
        key
        for key in exec_globals.keys()
        if key not in before_keys and not key.startswith("__")
    ]
    if new_keys:
        return str(exec_globals[new_keys[-1]])
    return None


@tool
@idasync
def py_eval(
    code: Annotated[str, "Python code"],
) -> dict:
    """Execute Python code in IDA context.
    Returns dict with result/stdout/stderr.
    Has access to normal Python builtins/imports and IDA API modules.
    Supports Jupyter-style evaluation."""
    # Capture stdout/stderr
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    stdout_capture = _STDOUT_CAPTURE
    stderr_capture = _STDERR_CAPTURE
    stdout_capture.begin(old_stdout)
    stderr_capture.begin(old_stderr)

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # Create execution context with IDA modules (lazy import to avoid errors)
        def lazy_import(module_name, globals=None, locals=None, fromlist=(), level=0):
            try:
                return __import__(module_name, globals, locals, fromlist, level)
            except Exception:
                return None

        exec_globals = {
            "idaapi": idaapi,
            "idc": idc,
            "idautils": lazy_import("idautils"),
            "ida_allins": lazy_import("ida_allins"),
            "ida_auto": lazy_import("ida_auto"),
            "ida_bitrange": lazy_import("ida_bitrange"),
            "ida_bytes": ida_bytes,
            "ida_dbg": ida_dbg,
            "ida_dirtree": lazy_import("ida_dirtree"),
            "ida_diskio": lazy_import("ida_diskio"),
            "ida_entry": ida_entry,
            "ida_expr": lazy_import("ida_expr"),
            "ida_fixup": lazy_import("ida_fixup"),
            "ida_fpro": lazy_import("ida_fpro"),
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_gdl": lazy_import("ida_gdl"),
            "ida_graph": lazy_import("ida_graph"),
            "ida_hexrays": ida_hexrays,
            "ida_ida": ida_ida,
            "ida_idd": lazy_import("ida_idd"),
            "ida_idp": lazy_import("ida_idp"),
            "ida_ieee": lazy_import("ida_ieee"),
            "ida_kernwin": ida_kernwin,
            "ida_libfuncs": lazy_import("ida_libfuncs"),
            "ida_lines": ida_lines,
            "ida_loader": lazy_import("ida_loader"),
            "ida_merge": lazy_import("ida_merge"),
            "ida_mergemod": lazy_import("ida_mergemod"),
            "ida_moves": lazy_import("ida_moves"),
            "ida_nalt": ida_nalt,
            "ida_name": ida_name,
            "ida_netnode": lazy_import("ida_netnode"),
            "ida_offset": lazy_import("ida_offset"),
            "ida_pro": lazy_import("ida_pro"),
            "ida_problems": lazy_import("ida_problems"),
            "ida_range": lazy_import("ida_range"),
            "ida_regfinder": lazy_import("ida_regfinder"),
            "ida_registry": lazy_import("ida_registry"),
            "ida_search": lazy_import("ida_search"),
            "ida_segment": ida_segment,
            "ida_segregs": lazy_import("ida_segregs"),
            "ida_srclang": lazy_import("ida_srclang"),
            "ida_strlist": lazy_import("ida_strlist"),
            "ida_struct": lazy_import("ida_struct"),
            "ida_tryblks": lazy_import("ida_tryblks"),
            "ida_typeinf": ida_typeinf,
            "ida_ua": lazy_import("ida_ua"),
            "ida_undo": lazy_import("ida_undo"),
            "ida_xref": ida_xref,
            "ida_enum": lazy_import("ida_enum"),
            "parse_address": parse_address,
            "get_function": get_function,
        }

        result_value = _execute_py_eval_code(code, exec_globals)

        # Collect output
        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": result_value or "",
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        import traceback

        return {
            "result": "",
            "stdout": "",
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        stdout_capture.end()
        stderr_capture.end()
