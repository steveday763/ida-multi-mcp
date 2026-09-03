# Tool Federation Contract

Last updated: 2026-02-17
Version: v1

## Authority
This contract defines the central MCP server's tool schema federation and large-response handling rules.

## Schema Rules
- IDA tools expose `instance_id` as a required input.
- For client compatibility, the output schema must be object-compatible.

## Output Rules
- Large outputs may be served as preview + cache pagination.
- Cache retrieval is performed via `get_cached_output` using offset/size.

## Resource Federation Rules
- The IDA-side resource catalog is exposed through the central MCP endpoint.
- Each resource URI is namespaced as
  `ida://instance/<instance_id>/<resource-authority>/<resource-path>` so multiple IDA instances
  remain addressable without an implicit active instance.
- `ida://idb/metadata` is lightweight and must not materialize the input file for hashes;
  input-file fingerprints are exposed separately at `ida://idb/fingerprint`.
- `resources/read` removes the central namespace before forwarding the standard
  `uri` parameter to the selected IDA instance.
- Resource listings are discovered per registered instance; tool visibility is
  governed separately by the static tool schema federation.

## Traceability
- Tool cache/federation: `src/ida_multi_mcp/server.py`
- Cache model: `src/ida_multi_mcp/cache.py`
- IDA resource providers: `src/ida_multi_mcp/ida_mcp/api_resources.py`
- Resource routing: `src/ida_multi_mcp/server.py`, `src/ida_multi_mcp/router.py`
