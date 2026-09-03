# 06. Tool Discovery and Schema Federation

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Sources
- Static schema: `src/ida_multi_mcp/ida_tool_schemas.json`
- Management tools: 4 built into the server
- Dynamic schema: `tools/list` from the connected IDA instance

## Federation Rules
- Inject `instance_id` as a required field into every IDA tool's inputSchema
- Add a single-thread warning to descriptions of `py_eval` and `list_funcs`
- If outputSchema is not an object, wrap with `{result: T}` to force object shape

## Visibility Strategy
- Tools remain visible via the static schema even without IDA
- On IDA connection, reflect the latest schema from the first responsive instance
- Resources are federated separately from tools. The central server discovers
  `resources/list` and `resources/templates/list` from every registered instance
  and namespaces each URI as `ida://instance/<instance_id>/<resource-authority>/<resource-path>`.
- `resources/read` parses that namespace, routes to the selected instance, and
  rewrites the returned content URI back to the federated URI.
- IDB metadata is intentionally lightweight; hashes are read from the separate
  `ida://idb/fingerprint` resource so metadata discovery does not read the whole
  input file.
- Resource federation is implemented in `src/ida_multi_mcp/server.py` and uses
  `src/ida_multi_mcp/router.py` for instance validation and transport routing.

## Extension Tools
- `api_debug` is extension-gated via `@ext("dbg")`
- Debug tools can be hidden from the default usage flow
