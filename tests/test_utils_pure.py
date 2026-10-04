"""Tests for ida_mcp/utils.py — Pure Python helpers (IDA modules stubbed).

The utils module lives inside ida_multi_mcp.ida_mcp, whose __init__.py
eagerly imports many IDA-dependent submodules.  We pre-populate sys.modules
with MagicMock stubs for every IDA and internal module so that only the pure
Python helpers in utils.py actually execute.
"""

import importlib
import itertools
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Build stubs BEFORE any ida_multi_mcp.ida_mcp import
# ---------------------------------------------------------------------------

_IDA_MODULES = [
    "ida_bytes", "ida_funcs", "ida_hexrays", "ida_kernwin", "ida_nalt", "ida_typeinf",
    "ida_ida", "ida_lines", "idaapi", "idautils", "idc",
]

for _name in _IDA_MODULES:
    if _name not in sys.modules:
        sys.modules[_name] = MagicMock()

# Stub the ida_mcp sub-package and all its submodules that __init__.py imports.
_PKG = "ida_multi_mcp.ida_mcp"
_SUBMODULES = [
    "rpc", "http", "framework",
    "api_core", "api_analysis", "api_memory", "api_types",
    "api_modify", "api_stack", "api_python", "api_resources",
    "api_composite", "api_yara", "compat",
]

# Create a real sync stub with IDAError
class IDAError(Exception):
    pass

_sync_stub = types.ModuleType(f"{_PKG}.sync")
_sync_stub.IDAError = IDAError
_sync_stub.IDASyncError = type("IDASyncError", (Exception,), {})
_sync_stub.CancelledError = type("CancelledError", (Exception,), {})
_sync_stub.idasync = lambda f: f  # no-op decorator
_sync_stub.ida_major = 9
sys.modules[f"{_PKG}.sync"] = _sync_stub

for _sub in _SUBMODULES:
    fqn = f"{_PKG}.{_sub}"
    if fqn not in sys.modules:
        sys.modules[fqn] = MagicMock()

# Now we can safely import utils — it will resolve its `from .sync import IDAError`
# through our real _sync_stub above, and all ida_* modules are MagicMocks.
# The __init__.py imports of api_* etc. will hit our MagicMock stubs harmlessly.
from ida_multi_mcp.ida_mcp.utils import (
    compact_whitespace,
    get_function,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    looks_like_address,
    pattern_filter,
    pattern_filter_indexed,
    _substring_needle,
    paginate,
    read_bytes_bss_safe,
    read_int_bss_safe,
)
import ida_multi_mcp.ida_mcp.utils as utils

utils.idaapi.BADADDR = -1
utils.idaapi.get_name_ea.side_effect = lambda _badaddr, _name: -1


# ---------------------------------------------------------------------------
# parse_address
# ---------------------------------------------------------------------------

class TestParseAddress:
    def test_hex_string(self):
        assert parse_address("0x1000") == 0x1000

    def test_bare_hex_rejected(self):
        """Bare hex without 0x prefix should raise."""
        with pytest.raises(IDAError, match="missing 0x prefix"):
            parse_address("DEADBEEF")

    def test_int_passthrough(self):
        assert parse_address(42) == 42

    def test_symbol_name_resolution(self):
        utils.idaapi.get_name_ea.side_effect = None
        utils.idaapi.get_name_ea.return_value = 0x401000

        assert parse_address("main") == 0x401000
        utils.idaapi.get_name_ea.assert_called_with(-1, "main")

        utils.idaapi.get_name_ea.reset_mock()
        utils.idaapi.get_name_ea.side_effect = lambda _badaddr, _name: -1

    def test_invalid_raises(self):
        with pytest.raises(IDAError, match="Not found"):
            parse_address("not_an_address")

    def test_out_of_range(self):
        with pytest.raises(IDAError, match="out of range"):
            parse_address(-1)

class TestBssSafeReads:
    def test_read_bytes_bss_safe_zero_fills_unloaded(self):
        load_map = {0x1000: True, 0x1001: False, 0x1002: True, 0x1003: False}
        value_map = {0x1000: 0x41, 0x1002: 0x43}

        # Region has a BSS gap → bulk get_bytes returns None → slow path.
        utils.ida_bytes.get_bytes.return_value = None
        utils.ida_bytes.is_loaded.side_effect = lambda ea: load_map.get(ea, False)
        utils.ida_bytes.get_byte.side_effect = lambda ea: value_map[ea]

        assert read_bytes_bss_safe(0x1000, 4) == b"A\x00C\x00"

    def test_read_bytes_bss_safe_fast_path_when_loaded(self):
        # Whole range loaded → single get_bytes call, no per-byte loop.
        utils.ida_bytes.get_bytes.side_effect = None
        utils.ida_bytes.get_bytes.return_value = b"ABCD"
        utils.ida_bytes.get_byte.side_effect = AssertionError("slow path used")

        assert read_bytes_bss_safe(0x1000, 4) == b"ABCD"

    def test_read_bytes_bss_safe_zero_size(self):
        assert read_bytes_bss_safe(0x1000, 0) == b""

    def test_read_int_bss_safe_returns_zero_for_unloaded_start(self):
        utils.ida_bytes.is_loaded.side_effect = lambda ea: False

        assert read_int_bss_safe(0x2000, 1) == 0
        assert read_int_bss_safe(0x2000, 2) == 0
        assert read_int_bss_safe(0x2000, 4) == 0
        assert read_int_bss_safe(0x2000, 8) == 0

    def test_read_int_bss_safe_uses_sized_reader_when_loaded(self):
        utils.ida_bytes.is_loaded.side_effect = lambda ea: True
        utils.ida_bytes.get_qword.return_value = 0x1122334455667788

        assert read_int_bss_safe(0x3000, 8) == 0x1122334455667788
        utils.ida_bytes.get_qword.assert_called_once_with(0x3000)


class TestGetFunction:
    def test_mid_function_address_returns_canonical_start(self):
        fn = MagicMock()
        fn.start_ea = 0x401000
        fn.end_ea = 0x401080
        fn.get_name.return_value = "sub_401000"
        utils.idaapi.get_func.return_value = fn

        result = get_function(0x401034)  # address inside the function body

        assert result["addr"] == "0x401000"
        assert result["size"] == "0x80"

    def test_missing_function_returns_none_when_not_raising(self):
        utils.idaapi.get_func.return_value = None
        assert get_function(0xDEAD, raise_error=False) is None

    def test_missing_function_raises_by_default(self):
        utils.idaapi.get_func.return_value = None
        with pytest.raises(IDAError, match="No function found"):
            get_function(0xDEAD)


class TestCompactWhitespace:
    def test_collapses_internal_spaces(self):
        assert compact_whitespace("mov     eax,     ebx") == "mov eax, ebx"

    def test_preserves_string_literals(self):
        assert compact_whitespace('db "a   b",    0') == 'db "a   b", 0'

    def test_preserves_leading_indent(self):
        assert compact_whitespace("    if   (x)\t\treturn  1;") == "    if (x) return 1;"


# ---------------------------------------------------------------------------
# normalize_list_input
# ---------------------------------------------------------------------------

class TestNormalizeListInput:
    def test_list_passthrough(self):
        assert normalize_list_input(["a", "b"]) == ["a", "b"]

    def test_comma_string(self):
        assert normalize_list_input("a, b, c") == ["a", "b", "c"]

    def test_exceeds_max(self):
        with pytest.raises(ValueError, match="Batch too large"):
            normalize_list_input(list(range(10)), max_items=5)


# ---------------------------------------------------------------------------
# normalize_dict_list
# ---------------------------------------------------------------------------

class TestNormalizeDictList:
    def test_single_dict(self):
        assert normalize_dict_list({"a": 1}) == [{"a": 1}]

    def test_json_string(self):
        result = normalize_dict_list('{"x": 1}')
        assert result == [{"x": 1}]

    def test_list_of_dicts(self):
        data = [{"a": 1}, {"b": 2}]
        assert normalize_dict_list(data) == data

    def test_exceeds_max(self):
        with pytest.raises(ValueError, match="Batch too large"):
            normalize_dict_list([{"x": i} for i in range(10)], max_items=5)


# ---------------------------------------------------------------------------
# looks_like_address
# ---------------------------------------------------------------------------

class TestLooksLikeAddress:
    def test_0x_prefix(self):
        assert looks_like_address("0x1234") is True

    def test_long_hex(self):
        assert looks_like_address("DEADBEEF") is True

    def test_short_string(self):
        assert looks_like_address("AB") is False

    def test_non_hex(self):
        assert looks_like_address("hello") is False


# ---------------------------------------------------------------------------
# pattern_filter
# ---------------------------------------------------------------------------

class TestPatternFilter:
    def test_glob(self):
        data = [{"name": "foo_bar"}, {"name": "baz_qux"}]
        result = pattern_filter(data, "foo*", "name")
        assert len(result) == 1
        assert result[0]["name"] == "foo_bar"

    def test_regex(self):
        data = [{"name": "func_123"}, {"name": "func_abc"}]
        result = pattern_filter(data, "/func_\\d+/", "name")
        assert len(result) == 1
        assert result[0]["name"] == "func_123"

    def test_substring(self):
        data = [{"name": "hello_world"}, {"name": "goodbye"}]
        result = pattern_filter(data, "ello", "name")
        assert len(result) == 1

    def test_max_length_rejection(self):
        with pytest.raises(IDAError, match="Pattern too long"):
            pattern_filter([], "x" * 600, "name")


# ---------------------------------------------------------------------------
# paginate
# ---------------------------------------------------------------------------

class TestPaginate:
    def test_basic_offset_count(self):
        data = list(range(10))
        page = paginate(data, offset=2, count=3)
        assert page["data"] == [2, 3, 4]
        assert page["next_offset"] == 5

    def test_end_of_data(self):
        data = list(range(5))
        page = paginate(data, offset=3, count=10)
        assert page["data"] == [3, 4]
        assert page["next_offset"] is None


# ---------------------------------------------------------------------------
# pattern_filter — differential coverage against the pre-rewrite implementation
# ---------------------------------------------------------------------------

def _reference_pattern_filter(data, pattern, key):
    """Verbatim copy of pattern_filter as it was before the matcher rewrite.

    The rewrite (hoisted normalization, `*text*` substring fast path, no
    per-row helper calls) is only acceptable if it selects the same rows, so
    every case below compares the two implementations."""
    import fnmatch
    import re

    if not pattern:
        return data

    if len(pattern) > 500:
        raise IDAError(f"Pattern too long: maximum 500 characters")

    regex = None
    use_glob = False

    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1 :]

        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL

        try:
            regex = re.compile(body, flags or re.IGNORECASE)
        except re.error:
            regex = None
    elif "*" in pattern or "?" in pattern:
        use_glob = True

    def get_value(item):
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)

    def matches(item):
        text = get_value(item)
        if regex is not None:
            return bool(regex.search(text))
        if use_glob:
            return fnmatch.fnmatch(text.lower(), pattern.lower())
        return pattern.lower() in text.lower()

    return [item for item in data if matches(item)]


class _AttrRow:
    """Same data shape as the dict rows, reached through attributes instead."""

    def __init__(self, name):
        self.name = name


_META_CHARS = ["*", "?", "[", "]", "!", "/", "a", "b"]
_NAME_CHARS = ["a", "b", "A", "B", "*", "[", "]", "/", ".", "0"]


def _all_patterns():
    out = [""]
    for n in range(1, 4):
        out.extend("".join(c) for c in itertools.product(_META_CHARS, repeat=n))
    out += ["*ab*", "*[ab]*", "*a?b*", "**", "*", "*a*", "/a/", "/a/i", "/[a/", "*.", "*/*"]
    return out


def _all_names():
    out = [""]
    for n in range(1, 4):
        out.extend("".join(c) for c in itertools.product(_NAME_CHARS, repeat=n))
    out += ["func_123", "A" * 40, "a/b", "a.b", "Namespace::Thing", "_Z3foov"]
    return out


_ROWS = [{"name": n} for n in _all_names()]
_LOWER = [r["name"].lower() for r in _ROWS]


class TestPatternFilterEquivalence:
    """Exhaustive over the metacharacter alphabet — that is where the risk is
    (`?`, `[seq]` and `[!seq]` must not take the substring shortcut), and the
    space is small enough to enumerate rather than sample."""

    @pytest.mark.parametrize("pattern", _all_patterns())
    def test_matches_reference(self, pattern):
        assert pattern_filter(_ROWS, pattern, "name") == _reference_pattern_filter(
            _ROWS, pattern, "name"
        )

    @pytest.mark.parametrize("pattern", _all_patterns())
    def test_indexed_matches_reference(self, pattern):
        assert pattern_filter_indexed(
            _ROWS, _LOWER, pattern, "name"
        ) == _reference_pattern_filter(_ROWS, pattern, "name")

    @pytest.mark.parametrize("pattern", _all_patterns())
    def test_attribute_rows_match_reference(self, pattern):
        rows = [_AttrRow(n) for n in _all_names()]
        assert pattern_filter(rows, pattern, "name") == _reference_pattern_filter(
            rows, pattern, "name"
        )

    def test_none_valued_field_reads_as_empty(self):
        rows = [{"name": None}, {"name": "x"}]
        for pattern in ("*", "x", "none", ""):
            assert pattern_filter(rows, pattern, "name") == _reference_pattern_filter(
                rows, pattern, "name"
            )

    def test_missing_key_falls_back_to_attribute_lookup(self):
        rows = [_AttrRow("alpha"), {"name": "beta"}]
        assert pattern_filter(rows, "alpha", "name") == [rows[0]]
        assert pattern_filter(rows, "beta", "name") == [rows[1]]

    def test_malformed_regex_falls_through_to_substring(self):
        rows = [{"name": "x/a(/y"}, {"name": "xay"}]
        assert pattern_filter(rows, "/a(/", "name") == _reference_pattern_filter(
            rows, "/a(/", "name"
        )

    def test_case_sensitive_regex_is_not_lowercased(self):
        rows = [{"name": "Foo"}, {"name": "foo"}]
        lower = [r["name"].lower() for r in rows]
        assert pattern_filter(rows, "/Foo/m", "name") == [rows[0]]
        assert pattern_filter_indexed(rows, lower, "/Foo/m", "name") == [rows[0]]

    def test_empty_pattern_returns_input_identity(self):
        assert pattern_filter(_ROWS, "", "name") is _ROWS
        assert pattern_filter_indexed(_ROWS, _LOWER, "", "name") is _ROWS


class TestSubstringShortcut:
    """The `*text*` shortcut is what makes a large-cache filter cheap, so pin
    the guard that decides when it applies.

    Getting this wrong is silent: the result set stays correct either way, and
    only the cost changes — it falls back to a regex match per row, which on
    1.6M rows is ~1.07s against ~0.045s."""

    def test_plain_star_wrapped_is_the_common_case(self):
        assert _substring_needle("*gworld*") == "gworld"
        assert _substring_needle("*") is None
        assert _substring_needle("**") is None

    def test_interior_star_still_needs_a_glob(self):
        assert _substring_needle("*a*b*") is None

    def test_other_metacharacters_still_need_a_glob(self):
        assert _substring_needle("*a?*") is None
        assert _substring_needle("*[ab]*") is None
        assert _substring_needle("*a]b*") is None

    def test_one_sided_star_still_needs_a_glob(self):
        assert _substring_needle("*abc") is None
        assert _substring_needle("abc*") is None
