from __future__ import annotations

import importlib
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock


REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


def load_api_python(monkeypatch):
    import ida_multi_mcp

    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)
    monkeypatch.setattr(ida_multi_mcp, "ida_mcp", pkg, raising=False)

    ida_module_names = [
        "idaapi",
        "idc",
        "ida_bytes",
        "ida_dbg",
        "ida_entry",
        "ida_frame",
        "ida_funcs",
        "ida_hexrays",
        "ida_ida",
        "ida_kernwin",
        "ida_lines",
        "ida_nalt",
        "ida_name",
        "ida_segment",
        "ida_typeinf",
        "ida_xref",
    ]
    for name in ida_module_names:
        monkeypatch.setitem(sys.modules, name, MagicMock())

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.idasync = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    utils.parse_address = lambda value: int(value, 0) if isinstance(value, str) else value
    utils.get_function = lambda addr: {"addr": hex(addr), "name": f"sub_{addr:x}"}
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    return importlib.import_module("ida_multi_mcp.ida_mcp.api_python")


def test_py_eval_allows_standard_imports_and_open(monkeypatch, tmp_path):
    api_python = load_api_python(monkeypatch)
    output_path = tmp_path / "py-eval-output.json"

    result = api_python.py_eval(
        "\n".join(
            [
                "import json",
                "import os",
                f"path = {str(output_path)!r}",
                "payload = {'basename': os.path.basename(path), 'ok': True}",
                "with open(path, 'w', encoding='utf-8') as f:",
                "    json.dump(payload, f, sort_keys=True)",
                "with open(path, 'r', encoding='utf-8') as f:",
                "    result = json.load(f)['basename']",
            ]
        )
    )

    assert result == {"result": output_path.name, "stdout": "", "stderr": ""}
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "basename": output_path.name,
        "ok": True,
    }
