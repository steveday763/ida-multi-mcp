# Tool Reference

[← back to README](../README.md)

## Management Tools

The server provides built-in management tools:

### list_instances()
Lists all registered instances with metadata (binary name, path, architecture, port, **type**: `gui` or `idalib`).

### refresh_tools()
Re-discovers tools from IDA instances. Use this if you update the IDA plugin.

### get_cached_output(cache_id, offset, size)
Retrieve cached output from a previous tool call that was truncated.

### decompile_to_file(...)
Decompile functions and save results directly to files on disk. Requires `instance_id`.

### idalib_open(input_path, timeout, unsafe) *(IDA Pro only)*
Open a binary in a new headless idalib session. Spawns a subprocess, waits for auto-analysis, registers in the shared registry.

### idalib_close(instance_id) *(IDA Pro only)*
Terminate a headless idalib session and remove it from the registry.

### idalib_list() *(IDA Pro only)*
List all managed headless idalib sessions.

### idalib_status(instance_id) *(IDA Pro only)*
Health/readiness check for a specific idalib session.

## Pattern Search

### find(type, targets, limit=1000, offset=0, encoding="utf-8")
Searches raw bytes across the loaded binary. For `type="string"`, `encoding`
selects how each target is encoded before searching; supported values are
`"utf-8"`, `"utf-16le"`, and `"utf-16be"`. The default is `"utf-8"`, so
existing calls are unchanged. `encoding` is rejected for `immediate`,
`data_ref`, and `code_ref` searches unless it is left at the default.

For example, to find the UTF-16LE string `test`:

```json
{"type": "string", "targets": "test", "encoding": "utf-16le"}
```

The search is a byte scan, so it does not add or remove a BOM or require a
NUL terminator. Unsupported encodings return an error listing the accepted
values.

### Function Similarity (BCSD)
Local, cross-instance binary code similarity — no cloud, no external service. Signals are name-independent (survive stripping): instruction-shingle MinHash, IDF-weighted imported-API / string / constant anchors, and CFG structure/shape, plus symbol-gated pseudocode tokens. An optional `[neural]` extra adds on-demand jTrans embeddings for anchor-less cross-compiler matches.

- **`index_functions(instance_id, rebuild=False)`** — build/refresh the searchable index for a binary (content-hash keyed, persisted under `~/.ida-mcp/index/`, incremental, backgroundable).
- **`index_status(instance_id)`** — index readiness, function count, staleness, and background progress.
- **`similar_functions(instance_id, func, top_k=20, scope="binary"|"instances"|"all")`** — rank the most similar functions within the binary or across instances; returns a per-signal breakdown and confidence label.
- **`compare_functions(a, b)`** — direct pairwise similarity between two functions (optionally across instances).
