# ida-multi-mcp

通过一个 MCP server 让 AI agent 同时使用多个本地 IDA Pro 实例。适合同时分析 dropper、payload、C2、driver 等多份二进制。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.3%2B-orange.svg)
![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)

[English](README.md) | 简体中文

## 安装

让 AI agent 安装。安装文档是给 agent 读的，里面包含 Python、IDA、MCP client 配置细节。

**Claude Code / AmpCode:**
> Install and configure ida-multi-mcp by following the instructions here: https://raw.githubusercontent.com/steveday763/ida-multi-mcp/main/docs/installation.md

**Cursor:**
> @Web fetch https://raw.githubusercontent.com/steveday763/ida-multi-mcp/main/docs/installation.md and follow the installation steps.

手动安装见 [`docs/installation.md`](docs/installation.md)。

## 使用

1. 用 IDA Pro 打开一个或多个 binary。
2. 让 AI agent 使用 ida-multi-mcp。

例子：

```text
Decompile `main` in malware.exe and compare it with the entry point in dropper.dll.
```

如果要用 IDA Pro headless 分析：

```text
Use idalib_open to analyze /path/to/malware.exe headlessly.
```

## 它做什么

- 让一个 MCP client 同时操作多个 IDA GUI 实例。
- 有 IDA Pro 时支持 headless `idalib` 会话。
- 把 AI 的每次 tool call 路由到正确的 IDA 实例。
- 让长分析结果仍然适合交给 agent 使用。

MCP tools 是给 AI agent 用的。普通用户通常不需要知道内部 MCP 细节。

## 要求

- IDA Pro 8.3 或更新版本。
- Python 3.11 或更新版本。
- Headless 模式需要 IDA Pro；IDA Home/Free 不包含 `idalib`。

## 文档

| 文档 | 读者 |
|---|---|
| [`docs/installation.md`](docs/installation.md) | AI agent 和手动安装者 |
| [`docs/README.md`](docs/README.md) | 维护者 |

## 排错

先看安装文档，并让 AI agent 检查本机环境。

最常见原因：

- IDA Pro 没有运行，或没有加载 binary。
- IDA 使用的 Python 版本和安装包的 Python 版本不一致。
- MCP client 还在使用旧 command 或 stale config。

## 支持

- 先看 [`docs/installation.md`](docs/installation.md)。
- 提 issue: [steveday763/ida-multi-mcp](https://github.com/steveday763/ida-multi-mcp/issues)。

## License

MIT

## 致谢

本仓库已独立维护，基于原上游项目 [MeroZemory/ida-multi-mcp](https://github.com/MeroZemory/ida-multi-mcp)，原作者为 [Jio Kim (MeroZemory)](https://github.com/MeroZemory)。

本项目借鉴并延续了 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [Duncan Ogilvie (mrexodia)](https://github.com/mrexodia) 的 IDA MCP tool 工作；agent-friendly 安装流程受 [oh-my-opencode](https://github.com/code-yeongyu/oh-my-opencode) by [Yeongyu Yun (code-yeongyu)](https://github.com/code-yeongyu) 影响。
