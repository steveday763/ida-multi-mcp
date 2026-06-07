from itertools import islice
import struct
from typing import Annotated, Optional
import ida_hexrays
import ida_lines
import ida_funcs
import idaapi
import idautils
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_entry
import ida_idaapi
import ida_xref
import ida_ua
import ida_name
import idc
from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    paginate,
    get_function,
    get_prototype,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    compact_whitespace,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    extract_function_strings,
    Function,
    Argument,
    DisassemblyFunction,
    Xref,
    BasicBlock,
    StructFieldQuery,
    InsnPattern,
)

# ============================================================================
# Instruction Helpers
# ============================================================================

def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _next_head(ea: int, end_ea: int) -> int:
    return ida_bytes.next_head(ea, end_ea)


def _operand_value(insn: ida_ua.insn_t, i: int) -> int | None:
    op = insn.ops[i]
    if op.type == ida_ua.o_void:
        return None
    if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
        return op.addr
    return op.value


def _operand_type(insn: ida_ua.insn_t, i: int) -> int:
    return insn.ops[i].type


def _insn_mnem(insn: ida_ua.insn_t) -> str:
    try:
        return insn.get_canon_mnem().lower()
    except Exception:
        return ""


def _value_candidates_for_immediate(value: int) -> list[tuple[int, int, bytes]]:
    candidates: list[tuple[int, int, bytes]] = []

    def add(size: int, signed_val: int):
        if size == 4:
            masked = signed_val & 0xFFFFFFFF
            if not (-0x80000000 <= signed_val <= 0x7FFFFFFF):
                return
            b = struct.pack("<I", masked)
        else:
            masked = signed_val & 0xFFFFFFFFFFFFFFFF
            if not (-0x8000000000000000 <= signed_val <= 0x7FFFFFFFFFFFFFFF):
                return
            b = struct.pack("<Q", masked)
        candidates.append((masked, size, b))

    add(4, value)
    add(8, value)
    return candidates


def _parse_optional_int(value, field_name: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc


def _bin_search_ea(result) -> int:
    """Normalize IDA 8/9 bin_search return values to an ea."""
    if isinstance(result, tuple):
        if not result:
            return idaapi.BADADDR
        result = result[0]
    if result is None:
        return idaapi.BADADDR
    return int(result)


def _compile_binpat(pattern: str, start_ea: int) -> ida_bytes.compiled_binpat_vec_t:
    compiled = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(compiled, start_ea, pattern, 16)
    if err:
        raise ValueError(str(err))
    return compiled


def _bytes_to_binpat(data: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


def _search_compiled_pattern(
    compiled: ida_bytes.compiled_binpat_vec_t,
    start_ea: int,
    end_ea: int,
    limit: int,
    offset: int,
) -> tuple[list[str], bool]:
    matches: list[str] = []
    skipped = 0
    more = False
    ea = start_ea
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    while ea != idaapi.BADADDR and ea < end_ea:
        found = _bin_search_ea(ida_bytes.bin_search(ea, end_ea, compiled, flags))
        if found == idaapi.BADADDR:
            break
        if skipped < offset:
            skipped += 1
        else:
            matches.append(hex(found))
            if len(matches) >= limit:
                next_ea = _bin_search_ea(
                    ida_bytes.bin_search(found + 1, end_ea, compiled, flags)
                )
                more = next_ea != idaapi.BADADDR
                break
        ea = found + 1
    return matches, more


def _normalized_immediate_values(value: int) -> set[int]:
    values = {value}
    for normalized, _size, _pattern_bytes in _value_candidates_for_immediate(value):
        values.add(normalized)
    return values


def _find_immediate_matches(
    value: int,
    limit: int,
    offset: int,
    max_scan_insns: int = 2_000_000,
) -> tuple[list[str], bool, int, bool]:
    target_values = _normalized_immediate_values(value)
    matches: list[str] = []
    skipped = 0
    scanned = 0
    truncated = False

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue

        ea = seg.start_ea
        while ea != idaapi.BADADDR and ea < seg.end_ea:
            if scanned >= max_scan_insns:
                return matches, True, scanned, True

            insn = _decode_insn_at(ea)
            if insn is None:
                next_ea = _next_head(ea, seg.end_ea)
                if next_ea == idaapi.BADADDR or next_ea <= ea:
                    break
                ea = next_ea
                continue

            scanned += 1
            matched = False
            for i in range(8):
                if _operand_type(insn, i) == ida_ua.o_void:
                    break
                if _operand_type(insn, i) != ida_ua.o_imm:
                    continue
                op_val = _operand_value(insn, i)
                if op_val in target_values:
                    matched = True
                    break

            if matched:
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) >= limit:
                        return matches, True, scanned, truncated

            next_ea = _next_head(ea, seg.end_ea)
            if next_ea == idaapi.BADADDR or next_ea <= ea:
                ea += max(getattr(insn, "size", 1), 1)
            else:
                ea = next_ea

    return matches, False, scanned, truncated


_CALL_XREF_TYPES = {ida_xref.fl_CF, ida_xref.fl_CN}


def _iter_call_xrefs(func: ida_funcs.func_t):
    for item_ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item_ea, 0):
            if not xref.iscode or xref.type not in _CALL_XREF_TYPES:
                continue
            yield item_ea, xref.to

# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idasync
@tool_timeout(90.0)
def decompile(
    addr: Annotated[str, "Function address to decompile"],
) -> dict:
    """Decompile function to pseudocode"""
    try:
        start = parse_address(addr)
        code = decompile_function_safe(start)
        if code is None:
            return {"addr": addr, "code": None, "error": "Decompilation failed"}
        return {"addr": addr, "code": code}
    except Exception as e:
        return {"addr": addr, "code": None, "error": str(e)}


@tool
@idasync
@tool_timeout(90.0)
def disasm(
    addr: Annotated[str, "Function address to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
    include_total: Annotated[
        bool, "Compute total instruction count (default: false)"
    ] = False,
) -> dict:
    """Disassemble function to assembly instructions"""

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000
    if offset < 0:
        offset = 0


    try:
        start = parse_address(addr)
        func = idaapi.get_func(start)

        # Get segment info
        seg = idaapi.getseg(start)
        if not seg:
            return {
                "addr": addr,
                "asm": None,
                "error": "No segment found",
                "cursor": {"done": True},
            }

        segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

        if func:
            # Function exists: disassemble function items starting from requested address
            func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
            header_addr = start  # Use requested address, not function start
        else:
            # No function: disassemble sequentially from start address
            func_name = "<no function>"
            header_addr = start

        lines = []
        seen = 0
        total_count = 0
        more = False

        def _maybe_add(ea: int) -> bool:
            nonlocal seen, total_count, more
            if include_total:
                total_count += 1
            if seen < offset:
                seen += 1
                return True
            if len(lines) < max_instructions:
                line = ida_lines.generate_disasm_line(ea, 0)
                instruction = ida_lines.tag_remove(line) if line else ""
                lines.append(f"{ea:x}  {compact_whitespace(instruction)}")
                seen += 1
                return True
            more = True
            seen += 1
            return include_total

        if func:
            for ea in idautils.FuncItems(func.start_ea):
                if ea == idaapi.BADADDR:
                    continue
                if ea < start:
                    continue
                if not _maybe_add(ea):
                    break
        else:
            ea = start
            while ea < seg.end_ea:
                if ea == idaapi.BADADDR:
                    break
                if _decode_insn_at(ea) is None:
                    break
                if not _maybe_add(ea):
                    break
                ea = _next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        if include_total and not more:
            more = total_count > offset + max_instructions

        lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
        if lines:
            lines_str += "\n" + "\n".join(lines)

        rettype = None
        args: Optional[list[Argument]] = None
        stack_frame = None

        if func:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    rettype = str(ftd.rettype)
                    args = [
                        Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                        for i, a in enumerate(ftd)
                    ]
            stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

        out: DisassemblyFunction = {
            "name": func_name,
            "start_ea": hex(header_addr),
            "lines": lines_str,
        }
        if stack_frame:
            out["stack_frame"] = stack_frame
        if rettype:
            out["return_type"] = rettype
        if args is not None:
            out["arguments"] = args

        return {
            "addr": addr,
            "asm": out,
            "instruction_count": len(lines),
            "total_instructions": total_count if include_total else None,
            "cursor": (
                {"next": offset + max_instructions}
                if more
                else {"done": True}
            ),
        }
    except Exception as e:
        return {
            "addr": addr,
            "asm": None,
            "error": str(e),
            "cursor": {"done": True},
        }


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idasync
def xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
    limit: Annotated[int, "Max xrefs per address (default: 100, max: 1000)"] = 100,
) -> list[dict]:
    """Get cross-references to specified addresses"""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 1000:
        limit = 1000

    results = []

    for addr in addrs:
        try:
            xrefs = []
            more = False
            for xref in idautils.XrefsTo(parse_address(addr)):
                if len(xrefs) >= limit:
                    more = True
                    break
                xrefs.append(
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                )
            results.append({"addr": addr, "xrefs": xrefs, "more": more})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@tool
@idasync
def xrefs_from(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references from"],
    limit: Annotated[int, "Max xrefs per address (default: 100, max: 1000)"] = 100,
) -> list[dict]:
    """Get cross-references from specified addresses (symmetric with xrefs_to).
    Returns outgoing code and data references for each address."""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 1000:
        limit = 1000

    results = []

    for addr in addrs:
        try:
            xrefs = []
            more = False
            for xref in idautils.XrefsFrom(parse_address(addr)):
                if len(xrefs) >= limit:
                    more = True
                    break
                xrefs.append(
                    Xref(
                        addr=hex(xref.to),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.to, raise_error=False),
                    )
                )
            results.append({"addr": addr, "xrefs": xrefs, "more": more})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@tool
@idasync
def xrefs_to_field(queries: list[StructFieldQuery] | StructFieldQuery) -> list[dict]:
    """Get cross-references to structure fields"""
    if isinstance(queries, dict):
        queries = [queries]

    # Security: limit batch size
    from .utils import MAX_BATCH_SIZE
    if len(queries) > MAX_BATCH_SIZE:
        from .sync import IDAError
        raise IDAError(f"Batch too large: maximum {MAX_BATCH_SIZE} queries per request")

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                    }
                )
                continue

            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"struct": struct_name, "field": field_name, "xrefs": xrefs})
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idasync
def callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
    limit: Annotated[int, "Max callees per function (default: 200, max: 500)"] = 200,
) -> list[dict]:
    """Get functions called by the specified functions"""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 500:
        limit = 500

    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            callees_dict = {}
            more = False
            for call_ea, target in _iter_call_xrefs(func):
                if len(callees_dict) >= limit:
                    more = True
                    break
                callee_func = idaapi.get_func(target)
                target_key = callee_func.start_ea if callee_func else target
                if target_key in callees_dict:
                    continue
                func_type = "internal" if callee_func is not None else "external"
                func_name = (
                    ida_funcs.get_func_name(target_key)
                    if callee_func is not None
                    else ida_name.get_name(target)
                ) or ida_name.get_name(target) or ""
                callees_dict[target_key] = {
                    "addr": hex(target_key),
                    "name": func_name,
                    "type": func_type,
                    "callsite": hex(call_ea),
                }

            results.append({
                "addr": fn_addr,
                "callees": list(callees_dict.values()),
                "more": more,
            })
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idasync
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for byte patterns in the binary (supports wildcards with ??)"""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        matches = []
        more = False
        error = None
        try:
            start_ea = ida_ida.inf_get_min_ea()
            compiled = _compile_binpat(pattern, start_ea)
            matches, more = _search_compiled_pattern(
                compiled, start_ea, ida_ida.inf_get_max_ea(), limit, offset
            )
        except Exception as exc:
            error = str(exc)

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "n": len(matches),
                "cursor": {"next": offset + limit} if more else {"done": True},
                "error": error,
            }
        )
    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idasync
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[dict]:
    """Get control flow graph basic blocks for functions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            flowchart = idaapi.FlowChart(func)
            all_blocks = []

            for block in flowchart:
                all_blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset : offset + max_blocks]
            more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if more else {"done": True}
                    ),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "error": str(e),
                    "blocks": [],
                    "cursor": {"done": True},
                }
            )
    return results


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idasync
def find(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for patterns in the binary (strings, immediate values, or references)"""
    if not isinstance(targets, list):
        targets = [targets]

    # Security: limit batch size
    from .utils import MAX_BATCH_SIZE
    if len(targets) > MAX_BATCH_SIZE:
        from .sync import IDAError
        raise IDAError(f"Batch too large: maximum {MAX_BATCH_SIZE} targets per request")

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Raw byte search for UTF-8 substrings across the binary
        for pattern in targets:
            pattern_str = str(pattern)
            pattern_bytes = pattern_str.encode("utf-8")
            if not pattern_bytes:
                results.append(
                    {
                        "query": pattern_str,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": "Empty pattern",
                    }
                )
                continue

            matches = []
            more = False
            error = None
            try:
                start_ea = ida_ida.inf_get_min_ea()
                compiled = _compile_binpat(_bytes_to_binpat(pattern_bytes), start_ea)
                matches, more = _search_compiled_pattern(
                    compiled, start_ea, ida_ida.inf_get_max_ea(), limit, offset
                )
            except Exception as exc:
                error = str(exc)

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": error,
                }
            )

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    results.append(
                        {
                            "query": value,
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": "Invalid immediate",
                        }
                    )
                    continue

            matches = []
            more = False
            scanned = 0
            truncated = False
            error = None
            try:
                matches, more, scanned, truncated = _find_immediate_matches(
                    int(value), limit, offset
                )
            except Exception as exc:
                error = str(exc)

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": error,
                    "scanned": scanned,
                    "truncated": truncated,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.DataRefsTo(target))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.CodeRefsTo(target, 0))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    else:
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}",
            }
        )

    return results


def _resolve_insn_scan_ranges(pattern: dict, allow_broad: bool) -> tuple[list[tuple[int, int]], str | None]:
    func_addr = pattern.get("func")
    segment_name = pattern.get("segment")
    start_s = pattern.get("start")
    end_s = pattern.get("end")

    exec_segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC):
            exec_segments.append(seg)

    if func_addr is not None:
        try:
            ea = parse_address(func_addr)
            func = idaapi.get_func(ea)
            if not func:
                return [], f"Function not found at {func_addr}"
            return [(func.start_ea, func.end_ea)], None
        except Exception as e:
            return [], str(e)

    if segment_name is not None:
        for seg in exec_segments:
            if idaapi.get_segm_name(seg) == segment_name:
                return [(seg.start_ea, seg.end_ea)], None
        return [], f"Executable segment not found: {segment_name}"

    if start_s is not None or end_s is not None:
        if start_s is None:
            return [], "start is required when end is set"
        try:
            start_ea = parse_address(start_s)
            end_ea = parse_address(end_s) if end_s is not None else None
        except Exception as e:
            return [], str(e)

        if not exec_segments:
            return [], "No executable segments found"

        if end_ea is None:
            seg = idaapi.getseg(start_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                return [], "start address not in executable segment"
            end_ea = seg.end_ea

        if end_ea <= start_ea:
            return [], "end must be greater than start"

        ranges = []
        for seg in exec_segments:
            seg_start = max(seg.start_ea, start_ea)
            seg_end = min(seg.end_ea, end_ea)
            if seg_end > seg_start:
                ranges.append((seg_start, seg_end))

        if not ranges:
            return [], "No executable ranges within start/end"

        return ranges, None

    if not allow_broad:
        return [], "Scope required: set func/segment/start/end or allow_broad=true"

    if not exec_segments:
        return [], "No executable segments found"

    return [(seg.start_ea, seg.end_ea) for seg in exec_segments], None


def _scan_insn_ranges(
    ranges: list[tuple[int, int]],
    mnem: str,
    op0_val: int | None,
    op1_val: int | None,
    op2_val: int | None,
    any_val: int | None,
    limit: int,
    offset: int,
    max_scan_insns: int,
) -> tuple[list[str], bool, int, bool, int | None]:
    matches: list[str] = []
    skipped = 0
    scanned = 0
    more = False
    truncated = False
    next_start: int | None = None

    for start_ea, end_ea in ranges:
        ea = start_ea
        while ea < end_ea:
            if scanned >= max_scan_insns:
                truncated = True
                next_start = ea
                break

            scanned += 1

            insn = _decode_insn_at(ea)
            if insn is None:
                ea = _next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            if mnem and _insn_mnem(insn) != mnem:
                ea = _next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            match = True
            if op0_val is not None and _operand_value(insn, 0) != op0_val:
                match = False
            if op1_val is not None and _operand_value(insn, 1) != op1_val:
                match = False
            if op2_val is not None and _operand_value(insn, 2) != op2_val:
                match = False

            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if _operand_type(insn, i) == ida_ua.o_void:
                        break
                    if _operand_value(insn, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) > limit:
                        more = True
                        matches = matches[:limit]
                        break

            ea = _next_head(ea, end_ea)
            if ea == idaapi.BADADDR:
                break

        if more or truncated:
            break

    return matches, more, scanned, truncated, next_start


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idasync
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
) -> dict:
    """Export function data in various formats"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by ida-multi-mcp", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idasync
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
    max_nodes: Annotated[int, "Max nodes across the graph (default: 1000, max: 100000)"] = 1000,
    max_edges: Annotated[int, "Max edges across the graph (default: 5000, max: 200000)"] = 5000,
    max_edges_per_func: Annotated[
        int, "Max edges per function (default: 200, max: 5000)"
    ] = 200,
) -> list[dict]:
    """Build call graph starting from root functions"""
    roots = normalize_list_input(roots)
    if max_depth < 0:
        max_depth = 0
    if max_nodes <= 0 or max_nodes > 100000:
        max_nodes = 100000
    if max_edges <= 0 or max_edges > 200000:
        max_edges = 200000
    if max_edges_per_func <= 0 or max_edges_per_func > 5000:
        max_edges_per_func = 5000
    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                    }
                )
                continue

            nodes = {}
            edges = []
            visited = set()
            truncated = False
            per_func_capped = False
            limit_reason = None

            def hit_limit(reason: str):
                nonlocal truncated, limit_reason
                truncated = True
                limit_reason = reason

            def traverse(addr, depth):
                nonlocal per_func_capped
                if truncated:
                    return
                if depth > max_depth or addr in visited:
                    return
                if len(nodes) >= max_nodes:
                    hit_limit("nodes")
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

                edges_added = 0
                seen_edges: set[tuple[int, int]] = set()
                for _call_ea, target in _iter_call_xrefs(f):
                    if truncated:
                        break
                    if edges_added >= max_edges_per_func:
                        per_func_capped = True
                        break
                    callee_func = idaapi.get_func(target)
                    if callee_func:
                        edge_key = (f.start_ea, callee_func.start_ea)
                        if edge_key in seen_edges:
                            continue
                        seen_edges.add(edge_key)
                        if len(edges) >= max_edges:
                            hit_limit("edges")
                            break
                        edges.append(
                            {
                                "from": hex(addr),
                                "to": hex(callee_func.start_ea),
                                "type": "call",
                            }
                        )
                        edges_added += 1
                        traverse(callee_func.start_ea, depth + 1)

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "truncated": truncated,
                    "limit_reason": limit_reason,
                    "max_nodes": max_nodes,
                    "max_edges": max_edges,
                    "max_edges_per_func": max_edges_per_func,
                    "per_func_capped": per_func_capped,
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

    return results


# ============================================================================
# xref_query — unified xref query with direction + type filter
# ============================================================================


@tool
@idasync
def xref_query(
    queries: Annotated[list[dict] | dict,
        "Xref query: addr, direction (to/from/both), type_filter (code/data/all), offset, count"],
) -> list[dict]:
    """Query cross-references with direction and type filters.
    direction='to' finds refs TO addr, 'from' finds refs FROM addr, 'both' finds all.
    type_filter='code' shows only code xrefs, 'data' only data, 'all' shows both.
    Supports dedup and pagination."""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        addr_str = query.get("addr", "")
        direction = query.get("direction", "to")
        type_filter = query.get("type_filter", "all")
        offset = query.get("offset", 0)
        count = query.get("count", 100)

        try:
            ea = parse_address(addr_str)
            xrefs_raw: list[dict] = []
            seen: set[tuple] = set()

            if direction in ("to", "both"):
                for xref in idautils.XrefsTo(ea, 0):
                    key = ("to", xref.frm, ea, xref.iscode)
                    if key in seen:
                        continue
                    seen.add(key)
                    xtype = "code" if xref.iscode else "data"
                    if type_filter != "all" and xtype != type_filter:
                        continue
                    xrefs_raw.append({
                        "direction": "to", "from": hex(xref.frm), "to": hex(ea),
                        "type": xtype,
                        "fn": get_function(xref.frm, raise_error=False),
                    })

            if direction in ("from", "both"):
                for xref in idautils.XrefsFrom(ea, 0):
                    key = ("from", ea, xref.to, xref.iscode)
                    if key in seen:
                        continue
                    seen.add(key)
                    xtype = "code" if xref.iscode else "data"
                    if type_filter != "all" and xtype != type_filter:
                        continue
                    xrefs_raw.append({
                        "direction": "from", "from": hex(ea), "to": hex(xref.to),
                        "type": xtype,
                        "fn": get_function(xref.to, raise_error=False),
                    })

            page = paginate(xrefs_raw, offset, count)
            results.append({"addr": addr_str, **page})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


# ============================================================================
# insn_query — instruction search by mnemonic/operand
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def insn_query(
    queries: Annotated[list[dict] | dict,
        "Instruction pattern: mnem, op0, op1, op2, op_any, func, segment, offset, count"],
) -> list[dict]:
    """Search instructions by mnemonic and/or operand values within a function,
    segment, or global scope. Uses existing scan infrastructure.
    Example: {mnem: 'call', func: '0x401000'} or {mnem: 'syscall'}"""
    queries = normalize_dict_list(queries)
    results = []

    for pattern in queries:
        mnem = str(pattern.get("mnem", "")).strip().lower()
        offset = pattern.get("offset", 0)
        count = min(pattern.get("count", 500), 5000)

        try:
            op0 = _parse_optional_int(pattern.get("op0"), "op0")
            op1 = _parse_optional_int(pattern.get("op1"), "op1")
            op2 = _parse_optional_int(pattern.get("op2"), "op2")
            op_any = _parse_optional_int(pattern.get("op_any"), "op_any")
            allow_broad = bool(pattern.get("allow_broad", bool(mnem)))
            ranges, range_error = _resolve_insn_scan_ranges(
                pattern, allow_broad=allow_broad
            )
            if range_error:
                results.append({"pattern": pattern, "error": range_error, "matches": []})
                continue

            matched_addrs, more, scanned, capped, next_start = _scan_insn_ranges(
                ranges, mnem, op0, op1, op2, op_any,
                limit=count, offset=offset, max_scan_insns=500_000,
            )

            matches = []
            for addr_hex in matched_addrs:
                ea = int(addr_hex, 16)
                matches.append({
                    "addr": addr_hex,
                    "disasm": compact_whitespace(idc.GetDisasm(ea)) if idaapi.is_loaded(ea) else None,
                    "fn": get_function(ea, raise_error=False),
                })

            results.append({
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "more": more,
                "scanned": scanned,
                "truncated": capped,
                "next_start": hex(next_start) if next_start is not None else None,
            })
        except Exception as e:
            results.append({"pattern": pattern, "error": str(e), "matches": []})

    return results


# ============================================================================
# analyze_batch — multi-function analysis in one call
# ============================================================================


@tool
@idasync
@tool_timeout(180.0)
def analyze_batch(
    addrs: Annotated[list[str] | str, "Function addresses to analyze"],
    include_decompile: Annotated[bool, "Include pseudocode (default: true)"] = True,
    include_asm: Annotated[bool, "Include disassembly (default: false)"] = False,
    include_xrefs: Annotated[bool, "Include xrefs (default: true)"] = True,
    include_strings: Annotated[bool, "Include strings (default: true)"] = True,
    include_callees: Annotated[bool, "Include callees (default: true)"] = True,
) -> list[dict]:
    """Analyze multiple functions in one call. Selectively include decompilation,
    disassembly, xrefs, strings, and callees per function. More efficient than
    calling analyze_function N times — single IDA round-trip."""
    addrs = normalize_list_input(addrs)

    from .api_composite import _analyze_function_internal

    results = []
    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            result = _analyze_function_internal(ea, include_asm=include_asm)

            if not include_decompile:
                result.pop("decompiled", None)
                result.pop("decompile_truncated", None)
            if not include_xrefs:
                result.pop("xrefs", None)
            if not include_strings:
                result.pop("strings", None)
                result.pop("constants", None)
            if not include_callees:
                result.pop("callees", None)
                result.pop("callers", None)

            results.append(result)
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


# ============================================================================
# classify_functions — batch function classification
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def classify_functions(
    addrs: Annotated[list[str] | str, "Function addresses (or '*' for all non-library functions)"] = "*",
    offset: Annotated[int, "Skip first N results (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 500, max: 5000)"] = 500,
) -> dict:
    """Classify functions as thunk/wrapper/leaf/dispatcher/complex based on
    size, callee count, and flags. Use '*' (default) for all non-library
    functions. Returns paginated results sorted by address."""
    from .api_survey import _classify_func

    if count > 5000:
        count = 5000

    if isinstance(addrs, str) and addrs.strip() == "*":
        func_eas = [ea for ea in idautils.Functions()
                    if not (idaapi.get_func(ea) and idaapi.get_func(ea).flags & idaapi.FUNC_LIB)]
    else:
        addrs_list = normalize_list_input(addrs)
        func_eas = [parse_address(a) for a in addrs_list]

    classified = []
    for ea in func_eas:
        func = idaapi.get_func(ea)
        if not func:
            continue
        callee_count = 0
        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    callee_count += 1
        classified.append({
            "addr": hex(ea),
            "name": idaapi.get_func_name(ea) or "",
            "size": func.end_ea - func.start_ea,
            "type": _classify_func(func, callee_count),
        })

    page = paginate(classified, offset, count)
    page["total_classified"] = len(classified)
    return page


# ============================================================================
# func_profile — per-function metrics for analysis prioritization
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def func_profile(
    addrs: Annotated[list[str] | str, "Function addresses (or '*' for all)"] = "*",
    offset: Annotated[int, "Skip first N (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 100, max: 1000)"] = 100,
    sort_by: Annotated[str, "Sort key: size, complexity, xref_count, callee_count, name (default: size)"] = "size",
    descending: Annotated[bool, "Sort descending (default: true)"] = True,
) -> dict:
    """Per-function profile: size, basic block count, cyclomatic complexity,
    callee/caller counts, and string count. Useful for prioritizing which
    functions to analyze deeply. Fills the gap between list_funcs (too little
    info) and analyze_function (too expensive per call)."""
    if count > 1000:
        count = 1000

    if isinstance(addrs, str) and addrs.strip() == "*":
        func_eas = list(idautils.Functions())
    else:
        addrs_list = normalize_list_input(addrs)
        func_eas = [parse_address(a) for a in addrs_list]

    profiles = []
    for ea in func_eas:
        func = idaapi.get_func(ea)
        if not func:
            continue

        fc = idaapi.FlowChart(func)
        bb_count = 0
        edge_count = 0
        for block in fc:
            bb_count += 1
            for _ in block.succs():
                edge_count += 1
        complexity = edge_count - bb_count + 2

        xref_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
        callee_count = 0
        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    callee_count += 1
        caller_count = sum(1 for x in idautils.XrefsTo(ea, 0)
                          if x.type in (idaapi.fl_CF, idaapi.fl_CN))

        string_count = len(extract_function_strings(ea))

        profiles.append({
            "addr": hex(ea),
            "name": idaapi.get_func_name(ea) or "",
            "size": func.end_ea - func.start_ea,
            "basic_blocks": bb_count,
            "complexity": complexity,
            "xref_count": xref_count,
            "callee_count": callee_count,
            "caller_count": caller_count,
            "string_count": string_count,
        })

    sort_keys = {"size": "size", "complexity": "complexity", "xref_count": "xref_count",
                 "callee_count": "callee_count", "name": "name"}
    key = sort_keys.get(sort_by, "size")
    if key == "name":
        profiles.sort(key=lambda p: p["name"].lower(), reverse=descending)
    else:
        profiles.sort(key=lambda p: p.get(key, 0), reverse=descending)

    page = paginate(profiles, offset, count)
    page["total_profiled"] = len(profiles)
    return page
