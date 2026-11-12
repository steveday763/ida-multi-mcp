"""Every @tool function must declare a return type annotation.

The failure chain this pins (set_comments was broken by it in practice):
zeromcp's _generate_tool_schema emits an outputSchema only when the tool has
a return annotation. The proxy (server.py) then fills the missing outputSchema
with {"type": "object"} for every advertised tool. A list-returning tool thus
sends a JSON array as structuredContent against an advertised object schema,
and clients that validate tool output per the MCP spec reject the response —
the call looks broken even though the write succeeded inside IDA.

Tools returning a dict pass by accident; tools returning a list (set_comments,
declare_stack, delete_stack at the time of writing this test) fail every call.
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


def _tool_functions(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                name = dec.id if isinstance(dec, ast.Name) else getattr(dec, "attr", "")
                if name == "tool":
                    yield node
                    break


def test_every_tool_declares_a_return_annotation():
    missing = [
        f"{path.name}:{fn.lineno} {fn.name}"
        for path in sorted(IDA_MCP_ROOT.glob("api_*.py"))
        for fn in _tool_functions(path)
        if fn.returns is None
    ]
    assert not missing, (
        "a tool without a return annotation is advertised as "
        'outputSchema {"type": "object"} by the proxy, so a non-dict return '
        "fails client-side output validation: " + ", ".join(missing)
    )
