"""YARA-backed scan tools for IDA ranges.

The scanner is intentionally YARA-only. If yara-python is missing from the IDA
Python environment, tools return a dependency error instead of falling back to a
hand-written byte scanner.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import os
from pathlib import Path
from typing import Annotated, Any

import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils

from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import parse_address


_RULES_TEXT_MAX_BYTES = 1 * 1024 * 1024
_RULES_FILE_MAX_BYTES = 4 * 1024 * 1024
_MAX_SCAN_BYTES_CAP = 256 * 1024 * 1024
_DEFAULT_SCAN_BYTES = 64 * 1024 * 1024
_MAX_LIMIT = 1000
_DEFAULT_LIMIT = 200
_MAX_STRINGS_PER_RULE = 1000
_DEFAULT_STRINGS_PER_RULE = 20
_MAX_XREFS_PER_MATCH = 100
_DEFAULT_XREFS_PER_MATCH = 10
_MAX_DATA_PREVIEW_BYTES = 256
_DEFAULT_DATA_PREVIEW_BYTES = 32
_MAX_TIMEOUT_SEC = 60
_DEFAULT_TIMEOUT_SEC = 10
_BUILTIN_RULES = {"crypto": "crypto.yar"}


@dataclass(frozen=True)
class ScanRange:
    start: int
    end: int
    segment_start: int
    segment_name: str

    @property
    def size(self) -> int:
        return self.end - self.start


def _dependency_error(tool_name: str) -> dict:
    return {
        "error": "dependency_missing",
        "message": f"{tool_name} requires yara-python in the IDA Python environment",
        "engine": "yara-python",
    }


def _import_yara(tool_name: str) -> tuple[Any | None, dict | None]:
    try:
        import yara  # type: ignore

        return yara, None
    except Exception:
        return None, _dependency_error(tool_name)


def _exactly_one(values: list[Any]) -> bool:
    return sum(1 for value in values if value not in (None, "")) == 1


def _builtin_rules_path(name: str) -> Path | None:
    filename = _BUILTIN_RULES.get(name)
    if filename is None:
        return None
    try:
        return Path(resources.files(__package__).joinpath("signatures", filename))
    except Exception:
        return Path(__file__).resolve().parent / "signatures" / filename


def _compile_yara_rules(
    *,
    tool_name: str,
    rules_text: str | None,
    rules_path: str | None,
    builtin_rules: str | None,
) -> tuple[Any | None, dict | None, str | None]:
    yara, error = _import_yara(tool_name)
    if error is not None:
        return None, error, None

    if not _exactly_one([rules_text, rules_path, builtin_rules]):
        return None, {
            "error": "invalid_rules",
            "message": "Provide exactly one of rules_text, rules_path, or builtin_rules",
            "engine": "yara-python",
        }, None

    try:
        if rules_text not in (None, ""):
            encoded = str(rules_text).encode("utf-8")
            if len(encoded) > _RULES_TEXT_MAX_BYTES:
                return None, {
                    "error": "invalid_rules",
                    "message": f"rules_text exceeds {_RULES_TEXT_MAX_BYTES} bytes",
                    "engine": "yara-python",
                }, None
            return yara.compile(source=str(rules_text), includes=False), None, "text"

        if rules_path not in (None, ""):
            path = Path(os.path.realpath(str(rules_path)))
            if not path.is_file():
                return None, {
                    "error": "invalid_rules",
                    "message": f"rules_path is not a regular file: {rules_path}",
                    "engine": "yara-python",
                }, None
            size = path.stat().st_size
            if size > _RULES_FILE_MAX_BYTES:
                return None, {
                    "error": "invalid_rules",
                    "message": f"rules_path exceeds {_RULES_FILE_MAX_BYTES} bytes",
                    "engine": "yara-python",
                }, None
            return yara.compile(filepath=str(path), includes=False), None, f"file:{path}"

        builtin = str(builtin_rules)
        path = _builtin_rules_path(builtin)
        if path is None:
            return None, {
                "error": "invalid_rules",
                "message": f"Unknown builtin_rules value: {builtin}",
                "engine": "yara-python",
            }, None
        if not path.is_file():
            return None, {
                "error": "invalid_rules",
                "message": f"Builtin YARA rules not found: {builtin}",
                "engine": "yara-python",
            }, None
        return yara.compile(filepath=str(path), includes=False), None, f"builtin:{builtin}"
    except Exception as exc:
        return None, {
            "error": "compile_failed",
            "message": str(exc),
            "engine": "yara-python",
        }, None


def _bounded_int(value: int, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except Exception:
        return default
    if number < minimum:
        return minimum
    if number > maximum:
        return maximum
    return number


def _select_scan_ranges(
    *,
    segment: str | None,
    start: str | None,
    end: str | None,
    max_scan_bytes: int,
) -> tuple[list[ScanRange], list[dict], bool, str | None, dict | None]:
    ranges: list[ScanRange] = []
    skipped: list[dict] = []
    truncated = False
    next_start: str | None = None

    start_ea: int | None = None
    end_ea: int | None = None
    try:
        if start not in (None, ""):
            start_ea = parse_address(start)
        if end not in (None, ""):
            end_ea = parse_address(end)
    except Exception as exc:
        return [], skipped, False, None, {
            "error": "invalid_range",
            "message": str(exc),
            "engine": "yara-python",
        }
    if end_ea is not None and start_ea is None:
        return [], skipped, False, None, {
            "error": "invalid_range",
            "message": "start is required when end is set",
            "engine": "yara-python",
        }
    if start_ea is not None and end_ea is not None and end_ea <= start_ea:
        return [], skipped, False, None, {
            "error": "invalid_range",
            "message": "end must be greater than start",
            "engine": "yara-python",
        }

    remaining = max_scan_bytes
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            skipped.append({"segment": hex(seg_ea), "reason": "missing_segment"})
            continue

        name = ida_segment.get_segm_name(seg) or ""
        if segment not in (None, "") and name != segment:
            continue
        if not (seg.perm & idaapi.SEGPERM_READ):
            skipped.append({"segment": name or hex(seg.start_ea), "reason": "not_readable"})
            continue

        seg_start = int(seg.start_ea)
        seg_end = int(seg.end_ea)
        if seg_end <= seg_start:
            skipped.append({"segment": name or hex(seg_start), "reason": "empty"})
            continue

        range_start = max(seg_start, start_ea) if start_ea is not None else seg_start
        range_end = min(seg_end, end_ea) if end_ea is not None else seg_end
        if range_end <= range_start:
            continue

        size = range_end - range_start
        if remaining <= 0:
            truncated = True
            next_start = hex(range_start)
            break

        if size > remaining:
            ranges.append(ScanRange(range_start, range_start + remaining, seg_start, name))
            truncated = True
            next_start = hex(range_start + remaining)
            break

        ranges.append(ScanRange(range_start, range_end, seg_start, name))
        remaining -= size

    if not ranges and not skipped:
        skipped.append({"segment": segment or "*", "reason": "no_matching_ranges"})

    return ranges, skipped, truncated, next_start, None


def _read_range(scan_range: ScanRange) -> bytes | None:
    try:
        data = ida_bytes.get_bytes(scan_range.start, scan_range.size)
    except Exception:
        return None
    if data is None:
        return None
    return bytes(data)


def _function_at(ea: int) -> dict | None:
    try:
        func = idaapi.get_func(ea)
    except Exception:
        return None
    if not func:
        return None
    name = ida_funcs.get_func_name(func.start_ea) or ""
    return {"addr": hex(func.start_ea), "name": name}


def _xref_sample(ea: int, max_xrefs: int) -> list[dict]:
    out: list[dict] = []
    try:
        refs = idautils.XrefsTo(ea, 0)
    except Exception:
        return out

    for xref in refs:
        if len(out) >= max_xrefs:
            break
        frm = int(xref.frm)
        out.append({
            "from": hex(frm),
            "type": "code" if getattr(xref, "iscode", False) else "data",
            "function": _function_at(frm),
        })
    return out


def _preview_hex(data: bytes | str | None, max_bytes: int) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="replace")
    else:
        raw = bytes(data)
    return raw[:max_bytes].hex()


def _iter_string_hits(match: Any):
    for item in getattr(match, "strings", []) or []:
        # yara-python >= 4.3: StringMatch with instances.
        if hasattr(item, "instances"):
            identifier = str(getattr(item, "identifier", ""))
            for inst in getattr(item, "instances", []) or []:
                offset = int(getattr(inst, "offset"))
                data = getattr(inst, "matched_data", None)
                length = int(getattr(inst, "matched_length", len(data) if data is not None else 0))
                yield identifier, offset, data, length
            continue

        # Older yara-python: (offset, identifier, data) tuple.
        if isinstance(item, tuple) and len(item) >= 3:
            offset, identifier, data = item[:3]
            yield str(identifier), int(offset), data, len(data) if data is not None else 0


def _normalize_family_filter(families: list[str] | str | None) -> set[str] | None:
    if families in (None, "", "*"):
        return None
    if isinstance(families, str):
        values = [part.strip() for part in families.split(",")]
    else:
        values = [str(part).strip() for part in families]
    result = {value.casefold() for value in values if value}
    return result or None


def _run_yara_scan(
    *,
    tool_name: str,
    rules_text: str | None,
    rules_path: str | None,
    builtin_rules: str | None,
    segment: str | None,
    start: str | None,
    end: str | None,
    max_scan_bytes: int,
    limit: int,
    max_strings_per_rule: int,
    max_xrefs_per_match: int,
    data_preview_bytes: int,
    timeout_sec: int,
    family_filter: set[str] | None = None,
) -> dict:
    rules, error, source_label = _compile_yara_rules(
        tool_name=tool_name,
        rules_text=rules_text,
        rules_path=rules_path,
        builtin_rules=builtin_rules,
    )
    if error is not None:
        return error

    max_scan_bytes = _bounded_int(
        max_scan_bytes,
        default=_DEFAULT_SCAN_BYTES,
        minimum=1,
        maximum=_MAX_SCAN_BYTES_CAP,
    )
    limit = _bounded_int(limit, default=_DEFAULT_LIMIT, minimum=1, maximum=_MAX_LIMIT)
    max_strings_per_rule = _bounded_int(
        max_strings_per_rule,
        default=_DEFAULT_STRINGS_PER_RULE,
        minimum=1,
        maximum=_MAX_STRINGS_PER_RULE,
    )
    max_xrefs_per_match = _bounded_int(
        max_xrefs_per_match,
        default=_DEFAULT_XREFS_PER_MATCH,
        minimum=0,
        maximum=_MAX_XREFS_PER_MATCH,
    )
    data_preview_bytes = _bounded_int(
        data_preview_bytes,
        default=_DEFAULT_DATA_PREVIEW_BYTES,
        minimum=0,
        maximum=_MAX_DATA_PREVIEW_BYTES,
    )
    timeout_sec = _bounded_int(
        timeout_sec,
        default=_DEFAULT_TIMEOUT_SEC,
        minimum=1,
        maximum=_MAX_TIMEOUT_SEC,
    )

    ranges, skipped, range_truncated, next_start, range_error = _select_scan_ranges(
        segment=segment,
        start=start,
        end=end,
        max_scan_bytes=max_scan_bytes,
    )
    if range_error is not None:
        return range_error

    matches_by_key: dict[tuple[str, str], dict] = {}
    scanned_bytes = 0
    output_truncated = False

    for scan_range in ranges:
        blob = _read_range(scan_range)
        if blob is None:
            skipped.append({"segment": scan_range.segment_name, "reason": "unloaded"})
            continue
        scanned_bytes += len(blob)

        try:
            yara_matches = rules.match(data=blob, timeout=timeout_sec)
        except Exception as exc:
            return {
                "error": "match_failed",
                "message": str(exc),
                "engine": "yara-python",
            }

        for match in yara_matches:
            meta = dict(getattr(match, "meta", {}) or {})
            family = str(meta.get("family", "")).casefold()
            if family_filter is not None and family not in family_filter:
                continue

            namespace = str(getattr(match, "namespace", "default"))
            rule = str(getattr(match, "rule", ""))
            key = (namespace, rule)
            if key not in matches_by_key:
                if len(matches_by_key) >= limit:
                    output_truncated = True
                    break
                matches_by_key[key] = {
                    "rule": rule,
                    "namespace": namespace,
                    "tags": list(getattr(match, "tags", []) or []),
                    "meta": meta,
                    "evidence": [],
                    "evidence_truncated": False,
                }

            normalized = matches_by_key[key]
            evidence = normalized["evidence"]
            for string_id, offset, data, matched_length in _iter_string_hits(match):
                if len(evidence) >= max_strings_per_rule:
                    normalized["evidence_truncated"] = True
                    continue
                ea = scan_range.start + offset
                evidence.append({
                    "string_id": string_id,
                    "addr": hex(ea),
                    "segment": scan_range.segment_name,
                    "offset_in_segment": ea - scan_range.segment_start,
                    "matched_length": matched_length,
                    "data_preview": _preview_hex(data, data_preview_bytes),
                    "function": _function_at(ea),
                    "xrefs": _xref_sample(ea, max_xrefs_per_match),
                })

        if output_truncated:
            break

    truncated = bool(range_truncated or output_truncated)
    return {
        "error": None,
        "engine": "yara-python",
        "rule_source": source_label,
        "matches": list(matches_by_key.values()),
        "count": len(matches_by_key),
        "scanned_bytes": scanned_bytes,
        "truncated": truncated,
        "next_start": next_start,
        "skipped_segments": skipped,
    }


@tool
@idasync
@tool_timeout(120.0)
def yara_scan(
    rules_text: Annotated[str | None, "YARA source text. Provide exactly one of rules_text, rules_path, or builtin_rules."] = None,
    rules_path: Annotated[str | None, "Path to a local .yar file. Includes are disabled."] = None,
    builtin_rules: Annotated[str | None, "Builtin rule set name; currently only 'crypto'."] = None,
    segment: Annotated[str | None, "Optional segment name filter"] = None,
    start: Annotated[str | None, "Optional start address for clipped scan range"] = None,
    end: Annotated[str | None, "Optional end address for clipped scan range"] = None,
    max_scan_bytes: Annotated[int, "Maximum bytes scanned this call (default 64 MiB, cap 256 MiB)"] = _DEFAULT_SCAN_BYTES,
    limit: Annotated[int, "Maximum rule matches returned (default 200, cap 1000)"] = _DEFAULT_LIMIT,
    max_strings_per_rule: Annotated[int, "Maximum string instances kept per rule (default 20)"] = _DEFAULT_STRINGS_PER_RULE,
    max_xrefs_per_match: Annotated[int, "Maximum xrefs sampled per matched address (default 10)"] = _DEFAULT_XREFS_PER_MATCH,
    data_preview_bytes: Annotated[int, "Matched data preview bytes in hex (default 32, cap 256)"] = _DEFAULT_DATA_PREVIEW_BYTES,
    timeout_sec: Annotated[int, "YARA match timeout per scanned range in seconds (default 10, cap 60)"] = _DEFAULT_TIMEOUT_SEC,
) -> dict:
    """Scan IDA loaded/readable ranges with YARA and map matches back to EA/xrefs.

    This scans IDA memory/ranges, not the original whole input file layout.
    """
    return _run_yara_scan(
        tool_name="yara_scan",
        rules_text=rules_text,
        rules_path=rules_path,
        builtin_rules=builtin_rules,
        segment=segment,
        start=start,
        end=end,
        max_scan_bytes=max_scan_bytes,
        limit=limit,
        max_strings_per_rule=max_strings_per_rule,
        max_xrefs_per_match=max_xrefs_per_match,
        data_preview_bytes=data_preview_bytes,
        timeout_sec=timeout_sec,
    )


@tool
@idasync
@tool_timeout(120.0)
def crypto_scan(
    families: Annotated[list[str] | str, "Crypto families to keep, e.g. '*', 'aes', or ['aes','sha2']"] = "*",
    segment: Annotated[str | None, "Optional segment name filter"] = None,
    start: Annotated[str | None, "Optional start address for clipped scan range"] = None,
    end: Annotated[str | None, "Optional end address for clipped scan range"] = None,
    max_scan_bytes: Annotated[int, "Maximum bytes scanned this call (default 64 MiB, cap 256 MiB)"] = _DEFAULT_SCAN_BYTES,
    limit: Annotated[int, "Maximum rule matches returned (default 200, cap 1000)"] = _DEFAULT_LIMIT,
    max_strings_per_rule: Annotated[int, "Maximum string instances kept per rule (default 20)"] = _DEFAULT_STRINGS_PER_RULE,
    max_xrefs_per_match: Annotated[int, "Maximum xrefs sampled per matched address (default 10)"] = _DEFAULT_XREFS_PER_MATCH,
    data_preview_bytes: Annotated[int, "Matched data preview bytes in hex (default 32, cap 256)"] = _DEFAULT_DATA_PREVIEW_BYTES,
    timeout_sec: Annotated[int, "YARA match timeout per scanned range in seconds (default 10, cap 60)"] = _DEFAULT_TIMEOUT_SEC,
) -> dict:
    """FindCrypto-style scan using builtin crypto YARA signatures."""
    return _run_yara_scan(
        tool_name="crypto_scan",
        rules_text=None,
        rules_path=None,
        builtin_rules="crypto",
        segment=segment,
        start=start,
        end=end,
        max_scan_bytes=max_scan_bytes,
        limit=limit,
        max_strings_per_rule=max_strings_per_rule,
        max_xrefs_per_match=max_xrefs_per_match,
        data_preview_bytes=data_preview_bytes,
        timeout_sec=timeout_sec,
        family_filter=_normalize_family_filter(families),
    )
