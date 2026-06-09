"""Binary survey tool — complete triage in one call.

Ported from upstream `ida-pro-mcp` `api_survey.py` (v2.0.0). Adapted to this
project's conventions:
- No `compat.py` shim: uses `ida_nalt` / `ida_ida` directly (IDA 8.3+).
- Reuses `_get_strings_cache()` from `api_core` and `get_image_size()` from `utils`.
"""

from __future__ import annotations

import hashlib
import re
from itertools import islice
from typing import Annotated, NotRequired, TypedDict

import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

from . import compat
from .api_core import _get_strings_cache
from .rpc import tool
from .sync import IDAError, idasync, tool_timeout
from .utils import get_image_size


class SurveyMetadata(TypedDict):
    path: str
    module: str
    arch: str
    base_address: str
    image_size: str
    md5: NotRequired[str]
    sha256: NotRequired[str]


class SurveySegmentInfo(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


class SurveyEntrypoint(TypedDict):
    addr: str
    name: str
    ordinal: int


class SurveyStatistics(TypedDict):
    total_functions: int
    named_functions: int
    library_functions: int
    unnamed_functions: int
    total_strings: int
    total_segments: int


class SurveyInterestingString(TypedDict):
    addr: str
    string: str
    xref_count: int


class SurveyInterestingFunction(TypedDict):
    addr: str
    name: str
    size: int
    xref_count: int
    callee_count: int
    type: str


class SurveyImportEntry(TypedDict):
    addr: str
    name: str
    module: str


class SurveyImportsByCategory(TypedDict):
    crypto: list[SurveyImportEntry]
    network: list[SurveyImportEntry]
    file_io: list[SurveyImportEntry]
    process: list[SurveyImportEntry]
    registry: list[SurveyImportEntry]
    other: list[SurveyImportEntry]


class SurveyCallGraphSummary(TypedDict):
    total_edges: int
    max_depth_estimate: None
    root_functions: list[str]
    leaf_functions_count: int


class SurveyBinaryResult(TypedDict, total=False):
    metadata: SurveyMetadata
    statistics: SurveyStatistics
    segments: list[SurveySegmentInfo]
    entrypoints: list[SurveyEntrypoint]
    interesting_strings: list[SurveyInterestingString]
    interesting_functions: list[SurveyInterestingFunction]
    imports_by_category: SurveyImportsByCategory
    call_graph_summary: SurveyCallGraphSummary
    _note: str


_MAX_FUNC_ITER = 10_000
_MAX_STRING_ITER = 5_000
_MAX_XREFS_PER_STRING = 200

# First-match-wins import classifier.
_IMPORT_CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    ("crypto", re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|\bssl\b|\btls\b|\bcert", re.IGNORECASE)),
    ("network", re.compile(r"socket|connect|send|recv|http|url|internet|ws2|winsock", re.IGNORECASE)),
    ("process", re.compile(r"process|thread|terminate|execute|shell|pipe|virtual", re.IGNORECASE)),
    ("registry", re.compile(r"reg|registry|hkey", re.IGNORECASE)),
    ("file_io", re.compile(r"file|path|directory|fopen|fclose|fread|fwrite|readfile|writefile|deletefile|createfile", re.IGNORECASE)),
]


def _classify_import(name: str) -> str:
    for category, pattern in _IMPORT_CATEGORIES:
        if pattern.search(name):
            return category
    return "other"


def _build_metadata(*, include_hashes: bool) -> SurveyMetadata:
    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())
    is_64 = compat.inf_is_64bit()

    metadata: SurveyMetadata = {
        "path": path,
        "module": module,
        "arch": "64" if is_64 else "32",
        "base_address": base,
        "image_size": size,
    }

    if include_hashes:
        input_path = ida_nalt.get_input_file_path()
        try:
            md5_h = hashlib.md5()
            sha256_h = hashlib.sha256()
            with open(input_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    md5_h.update(chunk)
                    sha256_h.update(chunk)
            metadata["md5"] = md5_h.hexdigest()
            metadata["sha256"] = sha256_h.hexdigest()
        except Exception:
            metadata["md5"] = metadata["sha256"] = "unavailable"

    return metadata


def _build_segments() -> list[SurveySegmentInfo]:
    segments: list[SurveySegmentInfo] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        perms = []
        if seg.perm & idaapi.SEGPERM_READ:
            perms.append("r")
        if seg.perm & idaapi.SEGPERM_WRITE:
            perms.append("w")
        if seg.perm & idaapi.SEGPERM_EXEC:
            perms.append("x")
        segments.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.size()),
            "permissions": "".join(perms) or "---",
        })
    return segments


def _build_entrypoints() -> list[SurveyEntrypoint]:
    entrypoints: list[SurveyEntrypoint] = []
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        name = compat.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


def _build_statistics(
    func_eas: list[int], string_count: int, segment_count: int
) -> SurveyStatistics:
    total = len(func_eas)
    named = 0
    library = 0
    unnamed = 0

    for ea in func_eas:
        name = idc.get_name(ea, 0) or ""
        func = idaapi.get_func(ea)
        flags = func.flags if func else 0

        if name.startswith("sub_"):
            unnamed += 1
        elif flags & idaapi.FUNC_LIB:
            library += 1
        else:
            named += 1

    return {
        "total_functions": total,
        "named_functions": named,
        "library_functions": library,
        "unnamed_functions": unnamed,
        "total_strings": string_count,
        "total_segments": segment_count,
    }


def _build_interesting_strings() -> list[SurveyInterestingString]:
    strings = _get_strings_cache()
    if len(strings) > _MAX_STRING_ITER:
        strings = strings[:_MAX_STRING_ITER]

    scored: list[tuple[int, int, str]] = []
    for ea, s in strings:
        count = sum(1 for _ in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_STRING))
        if count == 0:
            continue
        scored.append((count, ea, s))

    scored.sort(key=lambda t: t[0], reverse=True)
    return [
        {"addr": hex(ea), "string": s, "xref_count": xref_count}
        for xref_count, ea, s in scored[:15]
    ]


def _classify_func(func, callee_count: int) -> str:
    """thunk / wrapper / leaf / dispatcher / complex."""
    flags = func.flags
    size = func.end_ea - func.start_ea
    if flags & idaapi.FUNC_THUNK or size <= 8:
        return "thunk"
    if callee_count == 1 and size < 100:
        return "wrapper"
    if callee_count == 0:
        return "leaf"
    if callee_count > 10:
        return "dispatcher"
    return "complex"


def _build_interesting_functions(func_eas: list[int]) -> list[SurveyInterestingFunction]:
    candidates: list[tuple[int, int, str, int]] = []

    for ea in func_eas:
        func = idaapi.get_func(ea)
        if not func:
            continue
        flags = func.flags
        if flags & idaapi.FUNC_LIB:
            continue
        name = idc.get_name(ea, 0) or ""
        xref_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
        candidates.append((xref_count, ea, name, func.size()))

    candidates.sort(key=lambda t: t[0], reverse=True)
    top = candidates[:15]

    result: list[SurveyInterestingFunction] = []
    for xref_count, ea, name, size in top:
        func = idaapi.get_func(ea)
        callee_count = 0
        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    callee_count += 1

        result.append({
            "addr": hex(ea),
            "name": name,
            "size": size,
            "xref_count": xref_count,
            "callee_count": callee_count,
            "type": _classify_func(func, callee_count),
        })
    return result


def _build_imports_by_category() -> SurveyImportsByCategory:
    categories: SurveyImportsByCategory = {
        "crypto": [],
        "network": [],
        "file_io": [],
        "process": [],
        "registry": [],
        "other": [],
    }

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
            cat = _classify_import(name)
            categories[cat].append({
                "addr": hex(ea),
                "name": name,
                "module": module_name,
            })

    return categories


def _build_call_graph_summary(func_eas: list[int]) -> SurveyCallGraphSummary:
    total_edges = 0
    root_functions: list[str] = []
    leaf_count = 0

    for ea in func_eas:
        has_callers = False
        has_callees = False

        for xref in idautils.XrefsTo(ea, 0):
            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                has_callers = True
                break

        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    total_edges += 1
                    has_callees = True

        if not has_callers:
            name = idaapi.get_name(ea) or hex(ea)
            root_functions.append(name)
        if not has_callees:
            leaf_count += 1

    return {
        "total_edges": total_edges,
        "max_depth_estimate": None,
        "root_functions": root_functions[:100],
        "leaf_functions_count": leaf_count,
    }


@tool
@idasync
@tool_timeout(120.0)
def survey_binary(
    detail_level: Annotated[
        str,
        (
            "Detail level: 'probe', 'minimal', or 'standard'. "
            "'probe' is the only low-cost mode for very large binaries such as libUE4.so: "
            "metadata without hashes, segments, and entrypoints only; it does not enumerate "
            "functions or strings. 'minimal' keeps legacy summary statistics and hashes, "
            "but still enumerates all functions and builds the full strings cache, so avoid "
            "it for large binaries unless those counts are required. 'standard' also performs "
            "xref-based string/function triage, import categorization, and call graph summary; "
            "use it only after deciding the binary is small enough or the broad triage cost is acceptable."
        ),
    ] = "standard",
) -> SurveyBinaryResult:
    """Get a binary overview in one call.

    Modes:
    - probe: cheap readiness/shape probe for very large binaries such as libUE4.so.
      Returns metadata without md5/sha256, segment layout, and entrypoints only. It
      does not enumerate functions or strings.
    - minimal: legacy compact overview. Returns metadata with md5/sha256, segment
      layout, entrypoints, and statistics, but still enumerates all functions and
      materializes the full strings cache. Avoid as the first call on large binaries.
    - standard: full triage. Adds top 15 strings/functions ranked by xref count,
      import categories, and call graph summary. Avoid on large binaries unless the
      broad triage cost is acceptable."""
    if detail_level not in {"probe", "minimal", "standard"}:
        raise IDAError("detail_level must be one of: probe, minimal, standard")

    segments = _build_segments()

    if detail_level == "probe":
        return {
            "metadata": _build_metadata(include_hashes=False),
            "segments": segments,
            "entrypoints": _build_entrypoints(),
        }

    all_func_eas = list(idautils.Functions())
    truncated = len(all_func_eas) > _MAX_FUNC_ITER
    strings = _get_strings_cache()

    result: SurveyBinaryResult = {
        "metadata": _build_metadata(include_hashes=True),
        "statistics": _build_statistics(all_func_eas, len(strings), len(segments)),
        "segments": segments,
        "entrypoints": _build_entrypoints(),
    }

    if detail_level == "standard":
        func_eas = all_func_eas[:_MAX_FUNC_ITER] if truncated else all_func_eas
        result["interesting_strings"] = _build_interesting_strings()
        result["interesting_functions"] = _build_interesting_functions(func_eas)
        result["imports_by_category"] = _build_imports_by_category()
        result["call_graph_summary"] = _build_call_graph_summary(func_eas)

    if detail_level == "standard" and truncated:
        result["_note"] = (
            f"Binary has {len(all_func_eas)} functions; "
            f"xref analysis was limited to the first {_MAX_FUNC_ITER} for performance."
        )

    return result
