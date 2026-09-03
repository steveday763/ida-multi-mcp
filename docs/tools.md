# Tool Reference

[← back to README](../README.md)

## Input and output conventions

所有批量参数统一使用数组，即使只有一项也写成 `[item]`。地址、名称和
搜索目标使用字符串；`find` 的数值目标也写成十进制或 `0x` 前缀字符串。
旧版单对象/逗号分隔字符串仍会在 IDA 侧归一化，供旧客户端过渡，但不会
出现在新的工具 schema 中。

`get_bytes` 返回不带 `0x` 前缀的空格分隔小写十六进制，例如 `00 01 ff`；
地址字段仍使用 `0x` 前缀。

## Resources

只读 IDB 状态通过 namespaced resources 暴露：

- `ida://instance/<instance_id>/idb/metadata`：轻量路径、模块、基址和镜像大小
- `ida://instance/<instance_id>/idb/fingerprint`：输入文件 md5、sha256 和文件大小
- `ida://instance/<instance_id>/idb/segments`：段布局和权限
- `ida://instance/<instance_id>/idb/entrypoints`：入口点

需要结构、导入、导出或 xrefs 时，使用 `resources/templates/list` 返回的参数化
resource templates，再通过 `resources/read` 读取。

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
{"type": "string", "targets": ["test"], "encoding": "utf-16le"}
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
