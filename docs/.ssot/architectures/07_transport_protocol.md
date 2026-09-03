# 07. Transport and Protocol Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Transport Layers
- Client <-> Aggregator: MCP stdio
- Aggregator <-> IDA instance: HTTP JSON-RPC (`POST /mcp`)

## Protocol Calls
Central-server-side core methods:
- `tools/list`: returns the local tool cache
- `tools/call`: invokes a local management tool or a remote IDA tool
- `resources/list`: returns namespaced resources from registered IDA instances
- `resources/templates/list`: returns namespaced resource templates from registered IDA instances
- `resources/read`: routes `ida://instance/<instance_id>/...` to the selected IDA instance

Provided by the IDA side (zeromcp):
- `initialize`, `ping`, `tools/*`, `resources/*`, `prompts/*`, `notifications/cancelled`

## Routing Contract
- Immediate error if `instance_id` is missing
- Strip `arguments.instance_id` before forwarding
- Resource reads carry the routed `instance_id` internally and forward only the
  standard `uri` parameter to the IDA instance.
- Respect the IDA response envelope as-is; apply structured normalization only when necessary
