"""Stack frame operations for ida-multi-mcp.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated
import ida_typeinf
import ida_frame
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    StackVarDecl,
    StackVarDelete,
    get_stack_frame_variables_internal,
)


# ============================================================================
# Stack Frame Operations
# ============================================================================


def _parse_stack_frame_offset(raw) -> int:
    try:
        offset = int(str(raw), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("offset must be an integer frame-structure offset") from exc
    if offset < 0:
        raise ValueError("offset must be the non-negative offset reported by stack_frame")
    return offset


def _frame_member_name_at(func, offset: int) -> str | None:
    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        return None
    udt = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(udt):
        return None
    for udm in udt:
        if udm.is_gap():
            continue
        if udm.offset // 8 == offset:
            return udm.name
    return None


@tool
@idasync
def stack_frame(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Get stack vars"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            vars = get_stack_frame_variables_internal(ea, True)
            results.append({"addr": addr, "vars": vars})
        except Exception as e:
            results.append({"addr": addr, "vars": None, "error": str(e)})

    return results


@tool
@idasync
def declare_stack(
    items: list[StackVarDecl] | StackVarDecl,
):
    """Create stack vars"""
    items = normalize_dict_list(items)
    results = []
    for item in items:
        fn_addr = item.get("addr", "")
        offset = item.get("offset", "")
        var_name = item.get("name", "")
        type_name = item.get("ty", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            tif = get_type_by_name(type_name)
            struct_offset = _parse_stack_frame_offset(offset)
            frame_offset = ida_frame.soff_to_fpoff(func, struct_offset)
            if frame_offset == idaapi.BADADDR:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "offset": hex(struct_offset),
                        "error": "Failed to convert stack frame offset",
                    }
                )
                continue

            if not ida_frame.define_stkvar(func, var_name, frame_offset, tif):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to define"}
                )
                continue

            actual_name = _frame_member_name_at(func, struct_offset)
            if actual_name != var_name:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "offset": hex(struct_offset),
                        "frame_offset": hex(frame_offset),
                        "error": (
                            f"Stack variable not defined at requested offset; "
                            f"found {actual_name!r}"
                        ),
                    }
                )
                continue

            results.append(
                {
                    "addr": fn_addr,
                    "name": var_name,
                    "offset": hex(struct_offset),
                    "frame_offset": hex(frame_offset),
                    "ok": True,
                }
            )
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


@tool
@idasync
def delete_stack(
    items: list[StackVarDelete] | StackVarDelete,
):
    """Delete stack vars"""

    items = normalize_dict_list(items)
    results = []
    for item in items:
        fn_addr = item.get("addr", "")
        var_name = item.get("name", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            idx, udm = frame_tif.get_udm(var_name)
            if not udm:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} not found",
                    }
                )
                continue

            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is special frame member",
                    }
                )
                continue

            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8
            size = udm.size // 8
            if ida_frame.is_funcarg_off(func, offset):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is argument member",
                    }
                )
                continue

            if not ida_frame.delete_frame_members(func, offset, offset + size):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to delete"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results
