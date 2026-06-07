"""Management tools package for ida-multi-mcp.

These tools are implemented directly by the MCP server and handle:
- Instance listing and discovery
- Cross-instance management operations
"""

from .management import (
    list_instances,
    set_registry,
)

__all__ = [
    "list_instances",
    "set_registry",
]
