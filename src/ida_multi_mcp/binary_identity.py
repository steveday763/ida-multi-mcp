"""Binary identity check shared by the router and the IDA-side executor.

The router forwards the binary name it registered for an instance; the IDA side
compares it with the loaded database on the main thread, inside the same
execution as the tool, and answers a mismatch with BINARY_MISMATCH_CODE.
"""

import os

EXPECTED_BINARY_META_KEY = "ida-multi-mcp/expected_binary"
BINARY_MISMATCH_CODE = -32010


def normalize_binary_name(name: str | None) -> str | None:
    """Basename of either path style, case-folded; None when empty."""
    if not name:
        return None
    normalized = os.path.basename(name.replace("\\", "/")).strip()
    return normalized.casefold() if normalized else None
