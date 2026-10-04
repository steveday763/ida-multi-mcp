"""Pure tests for lazy cache initialization in ida_mcp api_core/api_modify."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
IDA_MCP_ROOT = SRC_ROOT / "ida_multi_mcp" / "ida_mcp"



def _stub_string_list(api_core, items):
    """Stub IDA's already-built string list.

    `_get_strings_cache` reads ida_strlist directly rather than going through
    idautils.Strings, whose constructor rebuilds the list across the whole
    binary (tens of seconds on a large database)."""
    class _Info:
        def __init__(self):
            self.ea = 0
            self.length = 0
            self.type = 0

    api_core.ida_strlist.string_info_ex_t.return_value = _Info()
    api_core.ida_strlist.get_strlist_qty.return_value = len(items)
    api_core.ida_strlist.get_strlist_item_ex.side_effect = (
        lambda info, index: (
            setattr(info, "ea", items[index][0]),
            setattr(info, "length", len(items[index][1])),
            setattr(info, "type", items[index][2] if len(items[index]) > 2 else 0),
            True,
        )[-1]
    )
    api_core.ida_bytes.get_strlit_contents.side_effect = (
        lambda ea, _length, _type: dict((it[0], it[1]) for it in items).get(ea)
    )


@pytest.fixture
def ida_mcp_modules(monkeypatch):
    """Load api_core/api_modify with IDA modules stubbed out."""
    import ida_multi_mcp

    # Remove any prior imports so this fixture gets a clean module state.
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    ida_module_names = [
        "ida_auto",
        "ida_funcs",
        "ida_hexrays",
        "ida_kernwin",
        "ida_ida",
        "ida_loader",
        "idaapi",
        "idautils",
        "ida_nalt",
        "ida_typeinf",
        "ida_segment",
        "idc",
        "ida_bytes",
        "ida_strlist",
        "ida_dirtree",
        "ida_frame",
        "ida_ua",
    ]
    for name in ida_module_names:
        monkeypatch.setitem(sys.modules, name, MagicMock())

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")

    class IDAError(Exception):
        pass

    sync.IDAError = IDAError
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda seconds: (lambda func: setattr(func, "__ida_mcp_timeout_sec__", seconds) or func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    utils.Metadata = dict
    utils.Function = dict
    utils.ConvertedNumber = dict
    utils.Global = dict
    utils.Import = dict
    utils.String = dict
    utils.Segment = dict
    utils.Page = dict
    utils.NumberConversion = dict
    utils.ListQuery = dict
    utils.CommentOp = dict
    utils.CommentAppendOp = dict
    utils.AsmPatchOp = dict
    utils.DefineOp = dict
    utils.UndefineOp = dict
    utils.FunctionRename = dict
    utils.GlobalRename = dict
    utils.LocalRename = dict
    utils.StackRename = dict
    utils.RenameBatch = dict
    utils.get_image_size = lambda *_args, **_kwargs: 0
    utils.parse_address = lambda value: int(value, 0) if isinstance(value, str) and value else value
    utils.normalize_list_input = lambda value, max_items=500: value
    utils.normalize_dict_list = (
        lambda value, str_to_dict=None, max_items=500:
        value if isinstance(value, list) else [value if not isinstance(value, str) else str_to_dict(value)]
    )
    utils.get_function = lambda addr, **_kw: {"addr": hex(addr), "name": f"sub_{addr:x}", "size": "0x40"}
    utils.paginate = lambda data, offset, count: {
        "data": data[offset:] if count == 0 else data[offset:offset + count],
        "next_offset": None,
    }
    utils.pattern_filter = lambda data, _pattern, _field: data
    utils.pattern_filter_indexed = lambda data, _names_lower, _pattern, _field: data
    utils.decompile_checked = lambda _ea: None
    utils.refresh_decompiler_ctext = lambda _ea: None
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    api_core = importlib.import_module("ida_multi_mcp.ida_mcp.api_core")
    api_modify = importlib.import_module("ida_multi_mcp.ida_mcp.api_modify")
    return api_core, api_modify


class TestApiCoreLazyCaches:
    def test_list_funcs_builds_cache_once(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._funcs_cache = None
        api_core.idautils.Functions.return_value = [0x1000, 0x2000]

        first = api_core.list_funcs({"offset": 0, "count": 50, "filter": ""})
        second = api_core.list_funcs({"offset": 0, "count": 50, "filter": ""})

        assert api_core.idautils.Functions.call_count == 1
        assert first == second
        assert [item["name"] for item in first[0]["data"]] == ["sub_1000", "sub_2000"]

    def test_list_funcs_rebuilds_when_cached_count_is_stale(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._funcs_cache = []
        api_core.ida_funcs.get_func_qty.return_value = 2
        api_core.idautils.Functions.return_value = [0x1000, 0x2000]

        result = api_core.list_funcs({"offset": 0, "count": 50, "filter": ""})

        assert [item["name"] for item in result[0]["data"]] == ["sub_1000", "sub_2000"]

    def test_list_globals_builds_cache_once(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._globals_cache = None
        api_core.idautils.Names.return_value = [
            (0x1000, "sub_1000"),
            (0x2000, "g_data"),
            (0x3000, None),
        ]
        api_core.idaapi.get_func.side_effect = lambda ea: object() if ea == 0x1000 else None

        first = api_core.list_globals({"offset": 0, "count": 50, "filter": ""})
        second = api_core.list_globals({"offset": 0, "count": 50, "filter": ""})

        assert api_core.idautils.Names.call_count == 1
        assert first == second
        assert first[0]["data"] == [{"addr": "0x2000", "name": "g_data"}]

    def test_refresh_caches_rebuilds_all_caches(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._strings_cache = [(0xdead, "stale", "utf-8")]
        api_core._funcs_cache = [{"addr": "0xdead", "name": "stale_func"}]
        api_core._globals_cache = [{"addr": "0xbeef", "name": "stale_global"}]

        _stub_string_list(api_core, [(0x10, b"a"), (0x20, b"b")])
        api_core.idautils.Functions.return_value = [0x1000]
        api_core.idautils.Names.return_value = [(0x2000, "g_value")]
        api_core.idaapi.get_func.return_value = None

        result = api_core.refresh_caches()

        assert result["strings"] == 2
        assert result["functions"] == 1
        assert result["globals"] == 1
        assert result["time_ms"] >= 0

    def test_refresh_caches_has_extended_timeout(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules

        assert getattr(api_core.refresh_caches, "__ida_mcp_timeout_sec__", None) == 120.0

    def test_func_query_builds_cache_once(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._funcs_cache = None
        api_core._funcs_query_cache = None
        api_core.idautils.Functions.return_value = [0x1000, 0x2000]
        api_core.ida_nalt.get_tinfo.return_value = False

        first = api_core.func_query({"offset": 0, "count": 50})
        second = api_core.func_query({"offset": 0, "count": 50})

        # Functions() iterated once (via the funcs cache); second call reuses it.
        assert api_core.idautils.Functions.call_count == 1
        assert first == second
        assert first[0]["data"][0]["addr"] == "0x1000"
        # size_int is stripped from output; has_type is resolved per-row.
        assert "size_int" not in first[0]["data"][0]
        assert first[0]["data"][0]["has_type"] is False

    def test_func_query_does_not_scan_types_when_unfiltered(self, ida_mcp_modules):
        """has_type must be resolved only for returned rows, not all functions."""
        api_core, _ = ida_mcp_modules
        api_core._funcs_cache = None
        api_core._funcs_query_cache = None
        api_core.idautils.Functions.return_value = list(range(0x1000, 0x1000 + 100))
        api_core.ida_nalt.get_tinfo.reset_mock()
        api_core.ida_nalt.get_tinfo.return_value = False

        api_core.func_query({"offset": 0, "count": 5})

        # Only the 5 returned rows get a get_tinfo call, not all 100 functions.
        assert api_core.ida_nalt.get_tinfo.call_count == 5

    def test_func_query_cache_invalidated_with_funcs_cache(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._funcs_query_cache = [{"addr": "0xdead", "name": "x",
                                        "size": "0x1", "size_int": 1}]
        api_core.invalidate_funcs_cache()
        assert api_core._funcs_query_cache is None

    def test_func_query_sort_does_not_mutate_cache(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._funcs_cache = None
        api_core._funcs_query_cache = None
        api_core.idautils.Functions.return_value = [0x2000, 0x1000]
        api_core.ida_nalt.get_tinfo.return_value = False

        api_core.func_query({"sort_by": "addr"})
        # Cache must remain in original Functions() order, not sorted order.
        assert [r["addr"] for r in api_core._funcs_query_cache] == ["0x2000", "0x1000"]


class TestApiModifyCacheInvalidation:
    def _prepare(self, api_modify):
        api_modify.invalidate_funcs_cache = MagicMock()
        api_modify.invalidate_globals_cache = MagicMock()
        api_modify.parse_address = lambda _value: 0x1000
        api_modify.refresh_decompiler_ctext = MagicMock()
        api_modify.idaapi.SN_CHECK = 0
        api_modify.idaapi.BADADDR = -1
        api_modify.idaapi.get_flags.return_value = 0
        api_modify.idaapi.has_user_name.return_value = True
        api_modify.idaapi.set_name.return_value = True
        api_modify.idaapi.get_func.return_value = SimpleNamespace(start_ea=0x1000)
        api_modify.idaapi.get_name_ea.return_value = 0x2000

    def test_rename_falls_back_to_invalidation_when_nothing_is_cached(
        self, ida_mcp_modules
    ):
        """The caches are only patched when they hold the row; a cold cache has
        nothing to patch and must not silently miss the rename."""
        api_core, api_modify = ida_mcp_modules
        api_core._funcs_cache = None
        api_core._globals_cache = None
        self._prepare(api_modify)

        result = api_modify.rename(
            {
                "func": {"addr": "0x1000", "name": "main"},
                "data": {"old": "g_old", "new": "g_new"},
            }
        )

        assert result["func"][0]["ok"] is True
        assert result["data"][0]["ok"] is True
        api_modify.invalidate_funcs_cache.assert_called_once()
        api_modify.invalidate_globals_cache.assert_called_once()

    def test_rename_patches_the_warm_cache_instead_of_dropping_it(
        self, ida_mcp_modules
    ):
        """A rebuild is ~9.5s on a 1.6M-function database; a rename changes one
        row, so the warm caches must survive it."""
        api_core, api_modify = ida_mcp_modules
        api_core._funcs_cache = [
            {"addr": "0x1000", "name": "sub_1000", "size": "0x40"},
            {"addr": "0x2000", "name": "sub_2000", "size": "0x40"},
        ]
        api_core._funcs_lower = ["sub_1000", "sub_2000"]
        api_core._funcs_query_cache = [
            {"addr": "0x1000", "name": "sub_1000", "size": "0x40", "size_int": 64},
            {"addr": "0x2000", "name": "sub_2000", "size": "0x40", "size_int": 64},
        ]
        api_core._globals_cache = [{"addr": "0x2000", "name": "g_old"}]
        api_core._globals_lower = ["g_old"]
        self._prepare(api_modify)
        # The helper re-reads the row through the cache build's own accessor, so
        # the stub must report the name IDA settled on after the rename.
        api_modify.get_function = lambda addr, **_kw: {
            "addr": hex(addr),
            "name": "main" if addr == 0x1000 else f"sub_{addr:x}",
            "size": "0x40",
        }

        result = api_modify.rename(
            {
                "func": {"addr": "0x1000", "name": "main"},
                "data": {"old": "g_old", "new": "g_new"},
            }
        )

        assert result["func"][0]["ok"] is True
        assert result["data"][0]["ok"] is True
        api_modify.invalidate_funcs_cache.assert_not_called()
        api_modify.invalidate_globals_cache.assert_not_called()

        # Name column stays aligned with the rows it describes.
        assert api_core._funcs_lower == ["main", "sub_2000"]
        assert api_core._globals_lower == ["g_new"]
        assert [r["name"] for r in api_core._funcs_query_cache] == [
            "main",
            "sub_2000",
        ]
        assert [r["name"] for r in api_core._funcs_cache] == ["main", "sub_2000"]

    def test_define_func_invalidates_caches_on_success(self, ida_mcp_modules):
        _, api_modify = ida_mcp_modules
        api_modify.invalidate_funcs_cache = MagicMock()
        api_modify.invalidate_globals_cache = MagicMock()
        api_modify.idaapi.BADADDR = -1
        api_modify.idaapi.is_loaded.return_value = True
        api_modify.parse_address = lambda value: -1 if value == "" else int(value, 0)
        api_modify.idaapi.get_func.side_effect = [
            None,
            SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        ]
        api_modify.ida_funcs.add_func.return_value = True

        result = api_modify.define_func({"addr": "0x1000"})

        assert result[0]["start"] == "0x1000"
        assert result[0]["end"] == "0x1010"
        api_modify.invalidate_funcs_cache.assert_called_once()
        api_modify.invalidate_globals_cache.assert_called_once()


class TestNameIndexAlignment:
    """`lower[i]` must always belong to `rows[i]`.

    The lowercased-name column exists so filters scan a `list[str]` instead of
    the rows — that scan is the whole cost of list_funcs on a large binary.
    Two parallel lists are a correctness hazard the moment anything can build,
    rebuild or clear them separately, so the invariant is pinned across every
    path that touches them.
    """

    def _seed(self, api_core, addrs):
        api_core._funcs_cache = None
        api_core._funcs_query_cache = None
        api_core._funcs_lower = None
        api_core.ida_funcs.get_func_qty.return_value = len(addrs)
        api_core.idautils.Functions.return_value = list(addrs)

    def test_funcs_column_matches_rows_after_staleness_rebuild(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        self._seed(api_core, [0x1000, 0x2000])

        rows, lower = api_core._get_funcs_index()
        assert lower == [row["name"].lower() for row in rows]

        # A fresh analysis pass adds a function: count mismatch forces a rebuild.
        api_core.ida_funcs.get_func_qty.return_value = 3
        api_core.idautils.Functions.return_value = [0x1000, 0x2000, 0x3000]

        rows, lower = api_core._get_funcs_index()
        assert len(rows) == len(lower) == 3
        assert lower == [row["name"].lower() for row in rows]

    def test_staleness_rebuild_drops_the_derived_query_rows(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        self._seed(api_core, [0x1000, 0x2000])
        api_core._get_funcs_query_index()

        api_core.ida_funcs.get_func_qty.return_value = 3
        api_core.idautils.Functions.return_value = [0x1000, 0x2000, 0x3000]

        rows, lower = api_core._get_funcs_query_index()
        assert len(rows) == len(lower) == 3
        assert lower == [row["name"].lower() for row in rows]
        # ... and the column still describes the function rows, not the old ones.
        assert lower == [r["name"].lower() for r in api_core._get_funcs_cache()]

    def test_invalidate_clears_both_lists(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        self._seed(api_core, [0x1000])
        api_core.idautils.Names.return_value = [(0x2000, "g_data")]
        api_core.idaapi.get_func.return_value = None

        api_core._get_funcs_index()
        api_core._get_globals_index()
        api_core.invalidate_funcs_cache()
        api_core.invalidate_globals_cache()

        assert api_core._funcs_cache is None and api_core._funcs_lower is None
        assert api_core._globals_cache is None and api_core._globals_lower is None

    def test_globals_column_matches_rows(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core._globals_cache = None
        api_core._globals_lower = None
        api_core.idautils.Names.return_value = [
            (0x1000, "sub_1000"),
            (0x2000, "G_Data"),
            (0x3000, "g_other"),
        ]
        api_core.idaapi.get_func.side_effect = lambda ea: object() if ea == 0x1000 else None

        rows, lower = api_core._get_globals_index()

        assert lower == ["g_data", "g_other"]
        assert lower == [row["name"].lower() for row in rows]


class TestFindRegexStringList:
    """find_regex reads IDA's string list — and must not rebuild it.

    idautils.Strings()'s constructor calls build_strlist(), which re-scans the
    whole binary: on a 1.6M-function database that is far past the tool
    timeout, so a find_regex built on it could never return at all."""

    def _seed(self, api_core):
        api_core._strings_cache = None
        _stub_string_list(
            api_core,
            [
                (0x1000, b"GetWorld", 0),        # 1 byte/char -> utf-8
                (0x2000, b"GetWorld", 0x2000001),  # 2 bytes/char -> utf-16
                (0x3000, b"Other", 0),
            ],
        )
        api_core.ida_nalt.get_strtype_bpu.side_effect = (
            lambda t: 2 if t == 0x2000001 else 1
        )
        api_core.ida_strlist.get_strlist_options.return_value = SimpleNamespace(
            minlen=5, only_7bit=1
        )

    def test_never_rebuilds_the_string_list(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        self._seed(api_core)

        api_core.find_regex("getworld")

        assert api_core.idautils.Strings.call_count == 0

    def test_reports_each_match_encoding(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        self._seed(api_core)

        result = api_core.find_regex("getworld")

        assert result["matches"] == [
            {"addr": "0x1000", "string": "GetWorld", "encoding": "utf-8"},
            {"addr": "0x2000", "string": "GetWorld", "encoding": "utf-16"},
        ]

    def test_reports_the_active_string_list_bounds(self, ida_mcp_modules):
        """A short target can never match, so the bound is echoed back rather
        than leaving an empty result looking like 'not present'."""
        api_core, _ = ida_mcp_modules
        self._seed(api_core)

        result = api_core.find_regex("getworld")

        assert result["string_list"] == {
            "min_length": 5,
            "only_7bit": True,
            "built": True,
            "size": 3,
        }

    def test_unbuilt_string_list_is_reported_not_mistaken_for_no_match(
        self, ida_mcp_modules
    ):
        api_core, _ = ida_mcp_modules
        api_core._strings_cache = None
        _stub_string_list(api_core, [])
        api_core.ida_strlist.get_strlist_options.return_value = SimpleNamespace(
            minlen=5, only_7bit=1
        )

        result = api_core.find_regex("getworld")

        assert result["n"] == 0
        assert result["string_list"]["built"] is False
        assert "find(type='string')" in result["error"]


class TestAnalysisStatusLabels:
    """analysis_status is pure reporting, so nothing exercised it and two
    module-level helpers it depends on were deleted without any test noticing.
    These calls execute the real code path."""

    def test_reports_idle_when_the_queue_is_empty(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core.ida_auto.auto_is_ok.return_value = True
        api_core.ida_auto.get_auto_state.return_value = 0
        api_core.ida_auto.is_auto_enabled.return_value = False

        result = api_core.analysis_status()

        assert result["finished"] is True
        assert result["queue_empty"] is True
        assert result["state"] == "idle"

    def test_reports_queued_while_the_analyser_is_paused_for_us(self, ida_mcp_modules):
        """get_auto_state() reads AU_NONE while the main thread is borrowed to
        serve this very request, so it must not be reported as idle."""
        api_core, _ = ida_mcp_modules
        api_core.ida_auto.auto_is_ok.return_value = False
        api_core.ida_auto.get_auto_state.return_value = getattr(
            api_core.ida_auto, "AU_NONE", 0
        )
        api_core.ida_auto.is_auto_enabled.return_value = True

        result = api_core.analysis_status()

        assert result["finished"] is False
        assert "queued" in result["state"]

    def test_maps_a_real_analysis_state_to_its_label(self, ida_mcp_modules):
        api_core, _ = ida_mcp_modules
        api_core.ida_auto.auto_is_ok.return_value = False
        api_core.ida_auto.get_auto_state.return_value = api_core.ida_auto.AU_CODE
        api_core.ida_auto.is_auto_enabled.return_value = True

        result = api_core.analysis_status()

        assert "instructions" in result["state"]
