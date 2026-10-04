"""Core API Functions - IDB metadata and basic queries"""

import bisect
import re
import time
from typing import Annotated, Optional

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_loader
import ida_kernwin
import ida_strlist
import idaapi
import idautils
import ida_nalt
import ida_typeinf
import ida_segment
import idc

from . import compat
from .rpc import tool
from .sync import idasync, tool_timeout

# Cached strings list: [(ea, text, encoding), ...]
_strings_cache: list[tuple[int, str, str]] | None = None

# Cached function list: [Function(...), ...] and its index-aligned lowercased
# names. Assigned only in _get_funcs_index and cleared only in
# invalidate_funcs_cache, so _funcs_lower[i] always belongs to _funcs_cache[i].
_funcs_cache: list["Function"] | None = None
_funcs_lower: list[str] | None = None

# Cached function query metadata: [{addr, name, size, size_int, has_type}, ...]
_funcs_query_cache: list[dict] | None = None

# Cached globals list: [Global(...), ...] plus its name column, same pairing
# and same single-producer rule as the function cache.
_globals_cache: list["Global"] | None = None
_globals_lower: list[str] | None = None


def _string_encoding_label(strtype: int) -> str:
    """Name the storage form of one string-list entry.

    get_strtype_bpu gives bytes per character; the list mixes 1-byte and 2-byte
    entries (wide strings are ~21% of a UE4 dump's table), and this label is
    what lets a caller tell a UTF-16 hit from a UTF-8 one."""
    try:
        bpu = ida_nalt.get_strtype_bpu(strtype)
    except Exception:
        return "unknown"
    return {1: "utf-8", 2: "utf-16", 4: "utf-32"}.get(bpu, f"{bpu}-byte")


def _string_list_bounds() -> dict:
    """The filters IDA's string list currently applies.

    They come from the IDB's saved Strings-window options and silently bound
    what find_regex can ever match — a target shorter than `min_length` returns
    nothing, indistinguishable from "not present". Reported with each search so
    a miss is explainable, and never mutated here: changing them would rewrite
    the user's Strings window settings."""
    try:
        opts = ida_strlist.get_strlist_options()
    except Exception:
        return {}
    return {"min_length": opts.minlen, "only_7bit": bool(opts.only_7bit)}


def _get_strings_cache() -> list[tuple[int, str, str]]:
    """Materialize the IDA string list as (ea, text, encoding), once.

    Read through ida_strlist rather than idautils.Strings: the latter's
    constructor calls build_strlist(), which re-scans the whole binary — ~70s on
    a 1.6M-function database, far past the tool timeout, so a find_regex built
    on it could never return at all. Reading the list IDA has already built
    costs ~4s for 842K entries.

    An empty list means IDA never built one; that is reported to the caller
    instead of being mistaken for "no matches"."""
    global _strings_cache
    if _strings_cache is None:
        rows: list[tuple[int, str, str]] = []
        info = ida_strlist.string_info_ex_t()
        for index in range(ida_strlist.get_strlist_qty()):
            if not ida_strlist.get_strlist_item_ex(info, index):
                continue
            raw = ida_bytes.get_strlit_contents(info.ea, info.length, info.type)
            rows.append(
                (
                    info.ea,
                    raw.decode("UTF-8", "replace") if raw else "",
                    _string_encoding_label(info.type),
                )
            )
        _strings_cache = rows
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def _get_funcs_index() -> tuple[list["Function"], list[str]]:
    """The function cache plus its index-aligned lowercased-name column.

    Both lists are assigned only here and cleared only by
    invalidate_funcs_cache, so lower[i] always belongs to rows[i]. Filtering
    runs on the name column: on a 1.6M-function binary the per-row field
    lookup and `.lower()` were essentially the entire cost of a query.

    Rebuilds when the cache is empty or its count is stale (e.g. after a fresh
    analysis pass added functions)."""
    global _funcs_cache, _funcs_lower, _funcs_query_cache
    current_qty = None
    try:
        qty = ida_funcs.get_func_qty()
        if isinstance(qty, int):
            current_qty = qty
    except Exception:
        pass

    if _funcs_cache is None or (
        current_qty is not None and len(_funcs_cache) != current_qty
    ):
        rows = [get_function(addr) for addr in idautils.Functions()]
        _funcs_cache = rows
        _funcs_lower = [row["name"].lower() for row in rows]
        # Derived from the rows above, so it must not outlive them.
        _funcs_query_cache = None
    return _funcs_cache, _funcs_lower


def _get_funcs_cache() -> list["Function"]:
    return _get_funcs_index()[0]


def _get_funcs_query_index() -> tuple[list[dict], list[str]]:
    """Lightweight func_query rows plus the name column they align with.

    Reuses _funcs_index (addr/name/size) and only adds size_int, so it does
    NO per-function IDA calls and stays fast even on 100K+ function binaries.
    has_type is intentionally NOT precomputed here (a get_tinfo() per function
    would re-introduce a full scan that times out); func_query computes it
    lazily only for the rows it actually returns or filters on.

    Returns the same lowercased-name column as _get_funcs_index because the
    rows are derived in that order; invalidated together with it.
    """
    global _funcs_query_cache
    rows, lower = _get_funcs_index()
    if _funcs_query_cache is None:
        built: list[dict] = []
        for fn in rows:
            try:
                size_int = int(fn["size"], 16)
            except (KeyError, ValueError, TypeError):
                size_int = 0
            built.append({
                "addr": fn["addr"], "name": fn["name"],
                "size": fn["size"], "size_int": size_int,
            })
        _funcs_query_cache = built
    return _funcs_query_cache, lower


def invalidate_funcs_cache():
    """Clear the function caches and their name column (call after function
    changes). The three are only ever cleared here."""
    global _funcs_cache, _funcs_lower, _funcs_query_cache
    _funcs_cache = None
    _funcs_lower = None
    _funcs_query_cache = None


def _get_globals_index() -> tuple[list["Global"], list[str]]:
    """The globals cache plus its index-aligned lowercased-name column.

    Same single-producer rule as _get_funcs_index: both lists are assigned
    only here and cleared only by invalidate_globals_cache."""
    global _globals_cache, _globals_lower
    if _globals_cache is None:
        rows: list["Global"] = []
        for addr, name in idautils.Names():
            if not idaapi.get_func(addr) and name is not None:
                rows.append(Global(addr=hex(addr), name=name))
        _globals_cache = rows
        _globals_lower = [row["name"].lower() for row in rows]
    return _globals_cache, _globals_lower


def _get_globals_cache() -> list["Global"]:
    return _get_globals_index()[0]


def invalidate_globals_cache():
    """Clear the globals cache and its name column (call after data changes)."""
    global _globals_cache, _globals_lower
    _globals_cache = None
    _globals_lower = None


def _patch_cached_name(
    rows: list, lower: list[str], ea: int, name: str
) -> bool:
    """Re-point one cached row at a new name. False when `ea` has no row.

    The rows are address-ordered, so the row is located by bisect — O(log n)
    key calls rather than the O(n) of rebuilding."""
    idx = bisect.bisect_left(rows, ea, key=lambda row: int(row["addr"], 16))
    if idx >= len(rows) or int(rows[idx]["addr"], 16) != ea:
        return False
    rows[idx]["name"] = name
    lower[idx] = name.lower()
    return True


def update_cached_func_name(ea: int, name: str) -> bool:
    """Record a successfully renamed function without dropping the cache.

    A rename changes neither the function set nor any address, so everything
    except this one row still holds — and a rebuild would cost ~9.5s on a
    1.6M-function database for a single string. `ea` must be the function start
    the cache keys on.

    Returns False when the cache does not hold `ea` (nothing cached, or the
    address is not a cached function start); the caller then invalidates."""
    global _funcs_query_cache
    if _funcs_cache is None or _funcs_lower is None:
        return False
    if not _patch_cached_name(_funcs_cache, _funcs_lower, ea, name):
        return False
    if _funcs_query_cache is not None:
        # Derived in the same order as _funcs_cache, so the same row.
        idx = bisect.bisect_left(
            _funcs_query_cache, ea, key=lambda row: int(row["addr"], 16)
        )
        if idx < len(_funcs_query_cache) and int(
            _funcs_query_cache[idx]["addr"], 16
        ) == ea:
            _funcs_query_cache[idx]["name"] = name
    return True


def update_cached_global_name(ea: int, name: str) -> bool:
    """Record a renamed global, or report that a rebuild is needed.

    Unlike a function rename, naming a previously unnamed data address *adds*
    a row, which patching cannot express — so the caller invalidates when this
    returns False."""
    if _globals_cache is None or _globals_lower is None:
        return False
    return _patch_cached_name(_globals_cache, _globals_lower, ea, name)


def init_caches():
    """Build caches on plugin startup."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1-t0)*1000:.0f}ms")

    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    print(f"[MCP] Cached {len(funcs)} functions in {(t2-t1)*1000:.0f}ms")

    globals_ = _get_globals_cache()
    t3 = time.perf_counter()
    print(f"[MCP] Cached {len(globals_)} globals in {(t3-t2)*1000:.0f}ms")


@tool
@idasync
@tool_timeout(120.0)
def refresh_caches() -> dict:
    """Force-refresh all caches (strings, functions, globals)."""
    invalidate_strings_cache()
    invalidate_funcs_cache()
    invalidate_globals_cache()

    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    globals_ = _get_globals_cache()
    t3 = time.perf_counter()

    return {
        "strings": len(strings),
        "functions": len(funcs),
        "globals": len(globals_),
        "time_ms": round((t3 - t0) * 1000),
    }


from .utils import (
    Metadata,
    Function,
    ConvertedNumber,
    Global,
    Import,
    String,
    Segment,
    Page,
    NumberConversion,
    ListQuery,
    get_image_size,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    paginate,
    pattern_filter,
    pattern_filter_indexed,
)
from .sync import IDAError


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str], "Array of addresses or names"],
) -> list[dict]:
    """Resolve functions by address or by name; the form is auto-detected.

    Accepts 0x-prefixed addresses, sub_XXXX names, or real symbol names. Use
    this to turn a name from decompiler output into an address to work with."""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery],
        "Array of function filters with pagination",
    ],
) -> list[Page[Function]]:
    """List functions in the binary, paginated.

    Requires auto-analysis to be finished — call analysis_wait() first on a
    freshly opened binary or this returns a partial list. On large binaries use
    count/offset rather than fetching everything; count=0 with a glob filter is
    a full scan."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_functions, names_lower = _get_funcs_index()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter_indexed(
            all_functions, names_lower, filter_pattern, "name"
        )
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery],
        "Array of global-variable filters with pagination",
    ],
) -> list[Page[Global]]:
    """List global variables (non-function named addresses), paginated.

    Requires auto-analysis to be finished — call analysis_wait() first on a
    freshly opened binary or names will still be missing."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals, names_lower = _get_globals_index()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter_indexed(
            all_globals, names_lower, filter_pattern, "name"
        )
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
    filter: Annotated[str, "Optional glob/regex filter on the imported name"] = "",
    module: Annotated[str, "Optional glob/regex filter on the source module"] = "",
) -> Page[Import]:
    """List imported functions grouped by source module, optionally filtered.

    Useful early: the import set is a fast signal of what a binary can do
    (networking, crypto, process injection) before you decompile anything.
    Example: {module: 'kernel32', filter: '*File*'} finds all kernel32 file I/O
    imports."""
    filtered = _collect_imports()
    if filter:
        filtered = pattern_filter(filtered, filter, "imported_name")
    if module:
        filtered = pattern_filter(filtered, module, "module")
    return paginate(filtered, offset, count)


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings with case-insensitive regex patterns.

    Searches IDA's string list, which IDA bounds by minimum length and 7-bit
    only by default — a short or non-ASCII target can therefore miss. Those
    bounds are echoed in `string_list`, and find(type="string") is the unbounded
    byte search to use when they get in the way. Each match reports whether it
    is stored as UTF-8 or UTF-16."""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    # Security: limit regex pattern length to prevent ReDoS
    if len(pattern) > 500:
        from .sync import IDAError
        raise IDAError("Regex pattern too long: maximum 500 characters")

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        from .sync import IDAError
        raise IDAError(f"Invalid regex pattern: {e}")

    strings = _get_strings_cache()
    bounds = _string_list_bounds()

    if not strings:
        # Distinguish "IDA has no string list" from "no match": the caller can
        # act on the former (use find(type="string"), which needs no list).
        return {
            "n": 0,
            "matches": [],
            "cursor": {"done": True},
            "string_list": {**bounds, "built": False},
            "error": (
                "IDA has no string list built for this database; "
                "find(type='string') searches raw bytes and needs none"
            ),
        }

    matches = []
    skipped = 0
    more = False
    for ea, text, encoding in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text, "encoding": encoding})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
        "string_list": {**bounds, "built": True, "size": len(strings)},
    }


# ============================================================================
# Server Health & Warmup
# ============================================================================


_SERVER_START_TIME = time.time()


def _build_health_payload() -> dict:
    """Build health/readiness snapshot."""
    path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
    module = ida_nalt.get_root_filename() or ""
    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _SERVER_START_TIME, 1),
        "idb_path": path,
        "module": module,
        # auto_is_ok() is "are all queues empty", i.e. True once analysis has
        # finished. This was negated, so the field reported the opposite of the
        # truth in both directions and agents proceeded on a half-analysed IDB.
        "auto_analysis_ready": bool(ida_auto.auto_is_ok()),
        "hexrays_ready": bool(ida_hexrays.init_hexrays_plugin()),
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache else 0,
    }


_AUTO_STATE_NAMES = {
    "AU_NONE": "idle",
    "AU_UNK": "reanalysing unexplored bytes",
    "AU_CODE": "converting to instructions",
    "AU_WEAK": "converting to instructions (weak)",
    "AU_PROC": "creating functions",
    "AU_TAIL": "adding function tails",
    "AU_FCHUNK": "finding function chunks",
    "AU_USED": "reanalysing dependent instructions",
    "AU_TYPE": "applying type information",
    "AU_LIBF": "identifying library functions",
    "AU_CHLB": "identifying library functions (delayed)",
    "AU_FINAL": "final analysis pass",
}


def _auto_state_label(finished: bool) -> str:
    """Human-readable name of whatever the autoanalyser is doing right now.

    Note this runs on the IDA main thread, which is exactly what IDA borrows
    back from the analyser to service our request — so get_auto_state() very
    often reads AU_NONE even with work still queued. Report that as "queued"
    rather than "idle", which would contradict finished=False.
    """
    if finished:
        return "idle"
    try:
        state = ida_auto.get_auto_state()
    except Exception:
        return "unknown"
    if state == getattr(ida_auto, "AU_NONE", 0):
        return "queued (paused while servicing this request)"
    for const, label in _AUTO_STATE_NAMES.items():
        if const == "AU_NONE":
            continue
        value = getattr(ida_auto, const, None)
        if value is not None and state == value:
            return label
    return f"running (state={state})"


@tool
@idasync
def analysis_status() -> dict:
    """Check whether IDA's auto-analysis has work outstanding. Non-blocking.

    On a freshly opened binary, analysis runs in the background and the function
    list, xrefs, strings and decompiler output are all INCOMPLETE until it
    settles. Check this before drawing conclusions from a first pass, and use
    analysis_wait() to drive it to completion.

    `queue_empty` is a SNAPSHOT, not a latch. It reports IDA's auto_is_ok() at
    this instant — "are the analysis queues empty right now". IDA re-queues work
    as it goes, so the value can read True and then False again moments later;
    observed live on a 23MB DLL. Read it as:

      queue_empty=False -> definitely still working, do not trust results yet
      queue_empty=True  -> nothing queued at this instant; combine with a stable
                           function_count across calls before treating analysis
                           as done

    `finished` is kept as an alias of `queue_empty` for compatibility and
    carries the same caveat."""
    queue_empty = bool(ida_auto.auto_is_ok())
    return {
        "queue_empty": queue_empty,
        # Alias: same snapshot value, same caveat. Not a completion latch.
        "finished": queue_empty,
        "state": _auto_state_label(queue_empty),
        "function_count": ida_funcs.get_func_qty(),
        "hint": (
            "No analysis queued at this instant. This is a snapshot, not a "
            "guarantee — confirm function_count has stopped changing before "
            "treating the database as fully analysed."
            if queue_empty
            else "Analysis still has work queued — call analysis_wait() before relying on results."
        ),
    }


@tool
@idasync
@tool_timeout(300.0)
def analysis_step(
    max_sec: Annotated[float, "Seconds to spend driving analysis (default 5, max 30)"] = 5.0,
) -> dict:
    """Drive IDA's auto-analysis queue for a bounded slice, then return.

    Prefer analysis_wait(), which calls this in a loop with a real timeout.

    IDA's background analysis stalls short of completion: measured on a 23MB
    DLL it climbed to 73,928 functions on its own and then sat there, never
    flipping auto_is_ok(). Something has to drain the residual queue.

    Stepping one address at a time keeps each call bounded by max_sec, so the
    instance stays responsive through the long bulk phase. Once the range is
    drained this makes one closing auto_wait() call, which is unbounded and is
    the only thing that actually flips auto_is_ok() — see the comment below.
    That final slice therefore runs past max_sec.
    """
    budget = max(0.0, min(float(max_sec), 30.0))
    lo, hi = compat.inf_get_min_ea(), compat.inf_get_max_ea()
    before = ida_funcs.get_func_qty()
    t0 = time.perf_counter()
    deadline = time.monotonic() + budget

    steps = 0
    drained = False
    finalized = False
    while time.monotonic() < deadline:
        if ida_auto.auto_is_ok():
            break
        if not ida_auto.auto_make_step(lo, hi):
            # Range drained, but auto_is_ok() can still be False: there is a
            # closing pass that only auto_wait() performs. Measured on a 23MB
            # DLL, stepping produced all 73,929 functions and left the flag
            # False; one auto_wait() then took 34.5s, added zero functions, and
            # flipped it. So the last slice runs long by design — it is the only
            # way to reach a genuine "analysis finished".
            drained = True
            ida_auto.auto_wait()
            finalized = True
            break
        steps += 1

    finished = bool(ida_auto.auto_is_ok())
    after = ida_funcs.get_func_qty()
    return {
        "finished": finished,
        "steps": steps,
        "drained_range": drained,
        "finalized": finalized,
        "elapsed_sec": round(time.perf_counter() - t0, 2),
        "function_count": after,
        "functions_added": after - before,
        "state": _auto_state_label(finished),
    }


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> dict:
    """Warm up IDA subsystems to reduce first-call latency. Call after
    connecting to a new instance to ensure analysis is complete and caches
    are populated before running tools."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append({"step": "auto_wait", "ok": True,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append({"step": "init_caches", "ok": True,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step: dict = {"step": "init_hexrays", "ok": ok,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)}
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(s.get("ok")) for s in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


# ============================================================================
# Rich Queries
# ============================================================================


def _collect_imports() -> list[dict]:
    """Collect all imports into a flat list for filtering."""
    rv: list[dict] = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
        collected: list[tuple[int, str]] = []

        def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
            name = symbol_name if symbol_name else f"#{ordinal}"
            collected.append((ea, name))
            return True

        ida_nalt.enum_import_names(i, imp_cb)
        for ea, name in collected:
            rv.append({"addr": hex(ea), "imported_name": name, "module": module_name})
    return rv


@tool
@idasync
@tool_timeout(60.0)
def func_query(
    queries: Annotated[list[dict],
        "Array of function queries: filter, name_regex, min_size, max_size, has_type, sort_by, descending, offset, count"],
) -> list[dict]:
    """Query functions with richer filtering than list_funcs. Supports regex
    name filter, size range, type filter, sort by size/name/addr, and pagination.
    Example: {name_regex: 'crypt', min_size: 100, sort_by: 'size', descending: true}"""
    queries = normalize_dict_list(queries)

    # Shared, cached metadata — must not be mutated in place below.
    all_functions, names_lower = _get_funcs_query_index()

    # has_type is resolved lazily: a get_tinfo() per function over the whole
    # binary would time out on 100K+ function targets. Reuse one tinfo_t.
    _tif = ida_typeinf.tinfo_t()

    def _has_type(row: dict) -> bool:
        try:
            return bool(ida_nalt.get_tinfo(_tif, int(row["addr"], 16)))
        except (ValueError, TypeError):
            return False

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            # Still the full set here, so the name column stays aligned.
            filtered = pattern_filter_indexed(
                filtered, names_lower, name_filter, "name"
            )

        name_regex = query.get("name_regex", "")
        if name_regex:
            try:
                compiled = re.compile(name_regex)
                filtered = [f for f in filtered if compiled.search(f["name"])]
            except re.error:
                pass

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]
        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        # has_type filter: compute only for the already name/size-narrowed set.
        if "has_type" in query:
            want = bool(query["has_type"])
            filtered = [f for f in filtered if _has_type(f) is want]

        # The cache rows come from idautils.Functions(), which enumerates in
        # ascending address order, and a narrowed subset keeps that order — so
        # sorting by address would only re-derive it, at one int(addr, 16)
        # parse per row.
        needs_sort = sort_by != "addr" or descending

        # Copy before sorting in place when no filter narrowed the shared cache.
        if needs_sort and filtered is all_functions:
            filtered = list(filtered)

        if needs_sort:
            if sort_by == "name":
                filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
            elif sort_by == "size":
                filtered.sort(key=lambda f: f["size_int"], reverse=descending)
            else:
                filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        # Resolve has_type only for the returned page (≤ count rows).
        page["data"] = [
            {**{k: v for k, v in item.items() if k != "size_int"},
             "has_type": _has_type(item)}
            for item in page["data"]
        ]
        results.append(page)

    return results


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> dict:
    """Save active IDB to disk, with no dialogs. Call after renaming, retyping,
    or commenting to persist changes. Optionally specify a custom output path
    to write a copy instead, leaving the open database untouched."""
    try:
        requested = path.strip() if path else ""
        current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        save_path = requested or current
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        try:
            is_gui = bool(ida_kernwin.is_idaq())
        except Exception:
            is_gui = False

        saving_copy = bool(requested) and requested != current

        if saving_copy:
            # Explicit different destination: write a compressed snapshot and
            # leave the live working files alone.
            flags = getattr(ida_loader, "DBFL_COMP", 0)
            ok = bool(ida_loader.save_database(save_path, flags))
        elif is_gui:
            # In the GUI the open database is backed by loose .id0/.id1/.id2/
            # .nam/.til files that IDA is actively using. Pass None for the
            # in-place save IDA itself performs on Ctrl+W; handing it an
            # explicit path takes the save-as route instead.
            ok = bool(ida_loader.save_database(None, 0))
        else:
            # Headless: nothing else holds the working files, so pack into one
            # compressed database.
            flags = getattr(ida_loader, "DBFL_KILL", 0) | getattr(ida_loader, "DBFL_COMP", 0)
            ok = bool(ida_loader.save_database(save_path, flags))

        result: dict = {
            "ok": ok,
            "path": save_path,
            "mode": "copy" if saving_copy else ("gui-in-place" if is_gui else "headless-packed"),
        }
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}
