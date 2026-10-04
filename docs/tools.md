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

### get_cached_output(cache_id, offset, size)
Retrieve cached output from a previous tool call that was truncated.

### decompile_to_file(...)
Decompile functions and save results directly to files on disk. Requires `instance_id`.

### idalib_open(input_path, output_path, timeout, save_on_close) *(IDA Pro only)*
Open a binary in a new headless idalib session. Spawns a subprocess, waits for auto-analysis, registers in the shared registry.

### idalib_close(instance_id) *(IDA Pro only)*
Terminate a headless idalib session and remove it from the registry.

### idalib_list() *(IDA Pro only)*
List all managed headless idalib sessions.

### idalib_status(instance_id) *(IDA Pro only)*
Health/readiness check for a specific idalib session.

## Pattern Search

### find(type, targets, limit=1000, offset=0, encoding="auto")
Searches raw bytes across the loaded binary. For `type="string"`, `encoding`
selects how each target is encoded before searching; supported values are
`"auto"`, `"utf-8"`, `"utf-16le"`, and `"utf-16be"`. The default, `"auto"`,
searches the UTF-8 and UTF-16LE forms and reports which one each match came
from — wide strings are common (about a fifth of a UE4 dump's string table) and
an ASCII-only search misses them silently. `encoding` is rejected for
`immediate`, `data_ref`, and `code_ref` searches unless it is left at the
default.

Each match is `{"ea": "0x...", "encoding": "utf-8"|"utf-16le"}`:

```json
{"type": "string", "targets": ["test"], "limit": 100}
```

To search one form only, pass it explicitly:

```json
{"type": "string", "targets": ["test"], "encoding": "utf-16le"}
```

The search is a byte scan, so it does not add or remove a BOM or require a
NUL terminator. Unsupported encodings return an error listing the accepted
values.

### find_regex(pattern, limit=30, offset=0)
Case-insensitive regex over **IDA's string list**, not raw bytes — so it is
bounded by the list's own filters (`min_length`, `only_7bit`, read from the
IDB's Strings-window options and echoed back in `string_list`). A target
shorter than `min_length` returns nothing at all, which is why the bounds come
back with every result. Each match reports whether it is stored as UTF-8 or
UTF-16. For short or non-ASCII targets, use `find(type="string")` instead: it
scans raw bytes and has no such bound.
