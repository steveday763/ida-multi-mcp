"""A client that disconnects before its response is written must not kill the host.

The IDA GUI embeds Python without ignoring SIGPIPE (unlike the python
executable), so the server runs in a child process that restores SIG_DFL to
reproduce that host. A large response forces several socket writes, so the
peer's RST lands between them and the next write raises EPIPE.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

_SERVER = textwrap.dedent(
    """
    import signal, sys, time, types
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    # Load only the zeromcp copy; the ida_mcp package __init__ needs IDA.
    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [sys.argv[1]]
    sys.modules["ida_multi_mcp.ida_mcp"] = pkg
    from ida_multi_mcp.ida_mcp.zeromcp.mcp import McpServer

    srv = McpServer("sigpipe-test")

    @srv.tool
    def big() -> str:
        time.sleep(0.5)
        return "x" * 2_000_000

    srv.serve("127.0.0.1", 0, background=True)
    print(srv._http_server.server_address[1], flush=True)
    sys.stdin.read()
    """
)


def _send_and_disconnect(port: int) -> None:
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "big", "arguments": {}},
    }).encode()
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall(
            b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body) + body
        )


@pytest.mark.skipif(not hasattr(signal, "SIGPIPE"), reason="POSIX only")
def test_disconnected_client_does_not_kill_host():
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(SRC), os.environ.get("PYTHONPATH", "")]))
    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER, str(SRC / "ida_multi_mcp" / "ida_mcp")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
    )
    try:
        # serve() prints its banner first; the port is the first bare number.
        line = b""
        while not line.strip().isdigit():
            line = proc.stdout.readline()
            assert line, "server exited before reporting its port"
        port = int(line)
        for _ in range(3):
            _send_and_disconnect(port)
        time.sleep(2.0)
        assert proc.poll() is None, f"server exited with {proc.returncode}"
    finally:
        proc.kill()
        proc.wait()
