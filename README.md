# ida-multi-mcp

Use multiple local IDA Pro instances from one MCP server. Built for AI agents that need to analyze more than one binary at a time.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.3%2B-orange.svg)
![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)

English | [简体中文](README.zh-CN.md)

## Install

Ask your AI agent to install it. The guide is written for agents and includes the Python/IDA/MCP client details they need.

**Claude Code / AmpCode:**
> Install and configure ida-multi-mcp by following the instructions here: https://raw.githubusercontent.com/steveday763/ida-multi-mcp/main/docs/installation.md

**Cursor:**
> @Web fetch https://raw.githubusercontent.com/steveday763/ida-multi-mcp/main/docs/installation.md and follow the installation steps.

Manual path: [`docs/installation.md`](docs/installation.md).

## Use

1. Open one or more binaries in IDA Pro.
2. Ask your AI agent to use ida-multi-mcp.

Example:

```text
Decompile `main` in malware.exe and compare it with the entry point in dropper.dll.
```

For headless analysis with IDA Pro:

```text
Use idalib_open to analyze /path/to/malware.exe headlessly.
```

## What It Does

- Lets one MCP client work with multiple IDA GUI instances.
- Supports headless `idalib` sessions when IDA Pro is available.
- Routes each AI tool call to the right IDA instance.
- Keeps long analysis results usable for the agent.

The AI agent sees the MCP tools. Users normally do not need the internal MCP details.

## Requirements

- IDA Pro 8.3 or later.
- Python 3.11 or later.
- Headless mode requires IDA Pro; IDA Home/Free do not include `idalib`.

## Docs

| Document | Audience |
|---|---|
| [`docs/installation.md`](docs/installation.md) | AI agents and manual installers |
| [`docs/README.md`](docs/README.md) | Maintainers |

## Troubleshooting

Start with the installation guide and let your AI agent inspect the local setup.

The common causes are:

- IDA Pro is not running with a binary loaded.
- IDA's Python version does not match the Python used for installation.
- The MCP client is still using an old command or stale config.

## Support

- Check [`docs/installation.md`](docs/installation.md) first.
- Open an issue at [steveday763/ida-multi-mcp](https://github.com/steveday763/ida-multi-mcp/issues).

## License

MIT

## Acknowledgments

This repository is maintained independently and is based on the original upstream project [MeroZemory/ida-multi-mcp](https://github.com/MeroZemory/ida-multi-mcp) by [Jio Kim (MeroZemory)](https://github.com/MeroZemory).

This project builds on ideas and tool work from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [Duncan Ogilvie (mrexodia)](https://github.com/mrexodia), and its agent-friendly installation flow was influenced by [oh-my-opencode](https://github.com/code-yeongyu/oh-my-opencode) by [Yeongyu Yun (code-yeongyu)](https://github.com/code-yeongyu).
