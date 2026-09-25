# 10. Reliability and Failure Handling

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Primary Failure Scenarios
- Tool call while no IDA is connected
- Use of a missing/expired `instance_id`
- Stale registry after IDA process exit
- HTTP connection failure/timeout

## Response Strategies
- Provide proactive error messages and recovery hints
- Guide users to current state via `list_instances`
- Clean up dead processes at startup
- Auto-recover via rediscovery and re-registration

## Degraded Behavior
- Binary verification runs inside IDA's execution of each request; a plugin that predates the `_meta` expected-binary field skips it (fail-open) (`src/ida_multi_mcp/ida_mcp/sync.py`, 2026-09-25)
- On tool-discovery failure, serve only the static schema

## Operational Notes
- Error responses are designed to include human-readable hints

