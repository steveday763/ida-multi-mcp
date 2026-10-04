"""Compact descriptions exposed in MCP schemas.

Descriptions are part of the model context. Keep them short and put detailed
semantics in the argument/output schema instead of repeating operational advice
in every tool entry.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


TOOL_DESCRIPTIONS: dict[str, str] = {
    "list_instances": "List registered IDA instances.",
    "analysis_wait": (
        "Wait for IDA auto-analysis; timeout returns current state. "
        "`finished` is a snapshot; `functions_added` helps confirm completion."
    ),
    "list_cached_outputs": "List cached truncated outputs.",
    "get_cached_output": "Read a cached truncated output.",
    "decompile_to_file": "Decompile functions to files; large sets may take time.",
    "idalib_open": "Open a binary or IDB in a headless IDA session.",
    "idalib_close": "Close a headless IDA session.",
    "idalib_list": "List headless IDA sessions.",
    "idalib_status": "Check a headless IDA session.",
    "lookup_funcs": "Resolve functions by address or name.",
    "list_funcs": "List functions; paginate large binaries.",
    "list_globals": "List global variables.",
    "refresh_caches": "Refresh IDA query caches.",
    "imports": "List imports.",
    "find_regex": "Search strings with a regular expression.",
    "decompile": "Decompile one function.",
    "disasm": "Disassemble one function.",
    "xrefs_to_field": "Find cross-references to struct fields.",
    "callees": "Find functions called by functions.",
    "find_bytes": "Search bytes (`??` is a wildcard).",
    "yara_scan": "Scan loaded IDA ranges with YARA; requires yara-python.",
    "basic_blocks": "Get function basic blocks.",
    "find": "Search strings, immediates, or references; encoding supports UTF-8/UTF-16LE/UTF-16BE.",
    "export_funcs": "Export function data in bulk.",
    "callgraph": "Build a call graph from root functions.",
    "get_bytes": "Read bytes as space-separated hex without `0x`.",
    "get_int": "Read integers.",
    "get_string": "Read NUL-terminated strings.",
    "get_global_value": "Read a global value by address or name.",
    "patch": "Write byte patches.",
    "put_int": "Write integers.",
    "declare_type": "Declare C types.",
    "read_struct": "Read a struct layout and instance values.",
    "search_structs": "Search structs by name.",
    "set_type": "Apply a type to a function or variable.",
    "infer_types": "Infer function or variable types.",
    "set_comments": "Set comments at addresses.",
    "patch_asm": "Write assembly patches.",
    "rename": "Rename functions or variables.",
    "define_func": "Define functions at addresses.",
    "define_code": "Convert bytes to code instructions.",
    "undefine": "Undefine items and restore raw bytes.",
    "stack_frame": "List stack variables.",
    "declare_stack": "Create stack variables.",
    "delete_stack": "Delete stack variables.",
    "py_eval": "Execute Python in IDA; runs on IDA's main thread.",
    "analyze_function": "Summarize one function.",
    "analyze_component": "Analyze related functions as a group.",
    "diff_before_after": "Apply a rename/type/comment action and compare decompilation.",
    "trace_data_flow": "Trace multi-hop data flow through cross-references.",
    "analysis_status": "Check auto-analysis status (non-blocking); `queue_empty` is a snapshot.",
    "analysis_step": "Advance auto-analysis for a bounded time slice.",
    "analyze_batch": "Analyze multiple functions in one call.",
    "classify_functions": "Classify functions by structure.",
    "enum_upsert": "Create or update local enums.",
    "func_query": "Query functions by filters and sort order.",
    "idb_save": "Save the active IDB.",
    "insn_query": "Search instructions by mnemonic or operands.",
    "server_warmup": "Warm IDA analysis and caches.",
    "xref_query": "Query cross-references by direction and type.",
}


RESOURCE_DESCRIPTIONS: dict[str, str] = {
    "idb_metadata_resource": "Get IDB metadata.",
    "idb_fingerprint_resource": "Get the input-file fingerprint.",
    "idb_segments_resource": "Get memory segments.",
    "idb_entrypoints_resource": "Get entry points.",
    "cursor_resource": "Get the current cursor position.",
    "selection_resource": "Get the current selection.",
    "types_resource": "Get local types.",
    "structs_resource": "Get structs and unions.",
    "struct_name_resource": "Get a struct definition.",
    "import_name_resource": "Get import details.",
    "export_name_resource": "Get export details.",
    "xrefs_from_resource": "Get outgoing cross-references.",
}


# These are repeated schema phrases, normalized before lookup so docstrings
# with line wrapping receive the same compact text.
PARAM_DESCRIPTIONS: dict[str, str] = {
    "Array of addresses or names": "Address/name array",
    "Number string to convert": "Number string",
    "Byte size for conversion (omit for auto)": "Byte size; omit to auto",
    "Array of numbers to convert to hex, decimal, binary, or ASCII": "Numbers to convert",
    "Optional glob pattern to filter results": "Optional glob filter",
    "Starting index (default: 0)": "Offset (default 0)",
    "Maximum number of results (default: 50, 0 for all)": "Max results (default 50; 0=all)",
    "Array of function filters with pagination": "Function filters",
    "Array of global-variable filters with pagination": "Global filters",
    "Offset": "Offset",
    "Count (0=all)": "Count (0=all)",
    "Regex pattern to search for in strings": "String regex",
    "Max matches (default: 30, max: 500)": "Max matches (default 30; max 500)",
    "Skip first N matches (default: 0)": "Skip matches (default 0)",
    "Function address to decompile": "Function address",
    "Function address to disassemble": "Function address",
    "Max instructions per function (default: 5000, max: 50000)": "Max instructions (default 5000; max 50000)",
    "Skip first N instructions (default: 0)": "Skip instructions (default 0)",
    "Compute total instruction count (default: false)": "Compute instruction count",
    "Array of addresses to find cross-references to": "Address array",
    "Max xrefs per address (default: 100, max: 1000)": "Max xrefs (default 100; max 1000)",
    "Structure name": "Struct name",
    "Field name": "Field name",
    "Array of function addresses to get callees for": "Function address array",
    "Max callees per function (default: 200, max: 500)": "Max callees (default 200; max 500)",
    "Array of byte patterns to search for (e.g. '48 8B ?? ??')": "Byte-pattern array",
    "Max matches per pattern (default: 1000, max: 10000)": "Max matches (default 1000; max 10000)",
    "Array of function addresses to get basic blocks for": "Function address array",
    "Max basic blocks per function (default: 1000, max: 10000)": "Max blocks (default 1000; max 10000)",
    "Skip first N blocks (default: 0)": "Skip blocks (default 0)",
    "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'": "Search type",
    "Max matches per target (default: 1000, max: 10000)": "Max matches (default 1000; max 10000)",
    "Text encoding for type='string' (default: 'utf-8'): 'utf-8', 'utf-16le', or 'utf-16be'": "Encoding: utf-8|utf-16le|utf-16be",
    "Array of function addresses to export": "Function address array",
    "Export format: json (default), c_header, or prototypes": "Export format",
    "Array of root function addresses to start call graph traversal from": "Root function addresses",
    "Maximum depth for call graph traversal": "Max traversal depth",
    "Max nodes across the graph (default: 1000, max: 100000)": "Max graph nodes (default 1000; max 100000)",
    "Max edges across the graph (default: 5000, max: 200000)": "Max graph edges (default 5000; max 200000)",
    "Max edges per function (default: 200, max: 5000)": "Max edges/function (default 200; max 5000)",
    "Address to read from (hex or decimal)": "Address",
    "Number of bytes to read": "Byte count",
    "Array of addresses to read strings from": "Address array",
    "Array of global variable addresses or names to read values from": "Global address/name array",
    "Address to patch (hex or decimal)": "Address",
    "Hex data to write (space-separated bytes)": "Hex bytes",
    "Address to write to (hex or decimal)": "Address",
    "Integer class (i8/u64/i16le/i16be/etc)": "Integer type",
    "Integer value as string (decimal or 0x..; negatives allowed for signed)": "Integer value",
    "Array of C type declarations": "C declarations",
    "Memory address (hex or decimal)": "Address",
    "Structure name (optional, auto-detect if omitted)": "Optional struct name",
    "Case-insensitive substring to search for in structure names": "Struct name filter",
    "Memory address": "Address",
    "Variable/function name": "Variable/function name",
    "Type name or declaration": "Type name or declaration",
    "Type of entity (auto-detected if omitted)": "Entity type",
    "Function signature (for kind=function)": "Function signature",
    "Local variable name (for kind=local)": "Local variable name",
    "Array of addresses to infer types for": "Address array",
    "Address (hex or decimal)": "Address",
    "Comment text": "Comment text",
    "Assembly instruction(s), semicolon-separated": "Assembly instructions",
    "Function address (hex or decimal)": "Function address",
    "New function name": "New function name",
    "Current variable name": "Current variable name",
    "New variable name": "New variable name",
    "Function address containing the local variable": "Containing function address",
    "Function address containing the stack variable": "Containing function address",
    "Comment text to append": "Comment text",
    "auto|func|line (default: auto)": "Scope: auto|func|line",
    "Skip if exact text already exists (default: true)": "Skip duplicate text",
    "Address to define (hex or decimal)": "Address",
    "Optional end address for explicit bounds": "Optional end address",
    "Address to undefine (hex or decimal)": "Address",
    "Optional end address": "Optional end address",
    "Optional size in bytes": "Optional byte count",
    "Address(es)": "Address array",
    "Function address": "Function address",
    "Frame-structure offset reported by stack_frame": "Stack-frame offset",
    "Variable name": "Variable name",
    "Type name": "Type name",
    "Seconds to spend driving analysis (default 5, max 30)": "Analysis seconds (default 5; max 30)",
    "Wait for auto analysis queue": "Wait for auto-analysis",
    "Build core caches (currently strings)": "Build core caches",
    "Initialize Hex-Rays decompiler plugin": "Initialize Hex-Rays",
    "Max functions to profile for expensive sorts (default: 10000, max: 100000)": "Profile scan limit",
    "Sort key: size, complexity, xref_count, callee_count, name (default: size)": "Sort key",
    "Sort descending (default: true)": "Descending sort",
    "Optional segment name filter": "Optional segment filter",
    "Optional start address for clipped scan range": "Optional start address",
    "Optional end address for clipped scan range": "Optional end address",
    "Maximum bytes scanned this call (default 64 MiB, cap 256 MiB)": "Scan byte limit",
    "Maximum rule matches returned (default 200, cap 1000)": "Rule-match limit",
    "Maximum string instances kept per rule (default 20)": "String instances/rule limit",
    "Maximum xrefs sampled per matched address (default 10)": "Xref sample limit",
    "Matched data preview bytes in hex (default 32, cap 256)": "Preview byte limit",
    "YARA match timeout per scanned range in seconds (default 10, cap 60)": "YARA timeout",
    "Array of crypto families to keep; use ['*'] for all": "Crypto families; ['*']=all",
    "YARA source text. Provide exactly one of rules_text, rules_path, or builtin_rules.": "Exactly one YARA source",
    "Path to a local .yar file. Includes are disabled.": "Local .yar path",
    "Builtin rule set name; currently only 'crypto'.": "Builtin rule set",
    "Cache ID from the _truncated metadata of a previous response": "Cache ID",
    "Starting character position (default: 0)": "Character offset (default 0)",
    "Number of characters to return (default: 20000, 0 = all remaining)": "Character count (default 20000; 0=rest)",
    "Function addresses to decompile (e.g. ['0x1800011A0', '0x180004B20']). Required unless 'all' is true.": "Function addresses; required unless all=true",
    "Decompile all functions in the binary (default: false). Uses paginated queries to avoid blocking IDA. When true, 'addrs' is ignored.": "Decompile all; ignores addrs",
    "Directory to save decompiled files. Must be within the current working directory unless allow_outside_cwd is true.": "Output directory",
    "Output mode: 'single' = one .c file per function (default), 'merged' = all in one file": "Mode: single|merged",
    "Permit output_dir outside the current working directory (default: false).": "Allow output outside cwd",
    "Seconds to wait before returning (default 120, max 600)": "Wait seconds (default 120; max 600)",
    "Target IDA instance ID (required)": "IDA instance ID",
    "First instance ID": "First instance ID",
    "Second instance ID": "Second instance ID",
    "Target IDA instance": "IDA instance ID",
    "Force rebuild (default false)": "Force rebuild",
    "Build in background (default true)": "Build in background",
    "Instance holding the query function": "Query instance ID",
    "Query function address or name": "Query function",
    "Max results (default 20)": "Max results (default 20)",
    "binary | instances | all (default binary)": "Scope: binary|instances|all",
    "Gallery instances when scope=instances": "Gallery instance IDs",
    "Minimum score filter (default 0)": "Minimum score",
    "Include the query itself (default false)": "Include query function",
    "{instance_id, func}": "Function reference",
    "Path to the binary or IDB file to open. Binary paths use IDA's default behavior and may reuse an existing adjacent .i64/.idb database.": "Binary or IDB path",
    "Optional path where to write the database (.i64) instead of next to the input. Use this when the input's directory is not writable (e.g. System32).": "Optional IDB output path",
    "Seconds to wait for analysis to complete (default 120)": "Analysis wait seconds (default 120)",
    "Save the IDB when the idalib worker closes (default false). False means this session's changes are not written on normal close; it does not force a fresh database or prevent IDA from loading an existing adjacent IDB. Use idb_save for explicit saves during a session.": "Save IDB on close (default false)",
    "Instance ID of the idalib session to close": "Idalib instance ID",
    "Instance ID of the idalib session to check": "Idalib instance ID",
}


def _normalized(value: Any) -> str:
    return " ".join(str(value).split())


_NORMALIZED_PARAM_DESCRIPTIONS = {
    _normalized(key): value for key, value in PARAM_DESCRIPTIONS.items()
}


def compact_tool_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Return a schema with compact tool and parameter descriptions."""
    result = deepcopy(schema)
    name = result.get("name")
    if name in TOOL_DESCRIPTIONS:
        result["description"] = TOOL_DESCRIPTIONS[name]

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            description = node.get("description")
            if description is not None:
                replacement = _NORMALIZED_PARAM_DESCRIPTIONS.get(_normalized(description))
                if replacement is not None:
                    node["description"] = replacement
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(result.get("inputSchema"))
    visit(result.get("outputSchema"))
    return result


def compact_resource_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Return a resource entry with a compact description."""
    result = deepcopy(schema)
    name = result.get("name")
    if name in RESOURCE_DESCRIPTIONS:
        result["description"] = RESOURCE_DESCRIPTIONS[name]
    return result
