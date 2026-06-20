"""idalib subprocess lifecycle manager.

Spawns, monitors, and terminates headless idalib worker processes.
Each worker opens one binary and listens on a unique localhost port.
Does NOT depend on ``idapro`` — purely manages subprocesses.
"""

from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import tempfile
import time
from typing import TYPE_CHECKING

from .health import is_process_alive, ping_instance, query_binary_metadata

if TYPE_CHECKING:
    from .registry import InstanceRegistry

# Default timeout (seconds) waiting for worker to become ready.
_READY_TIMEOUT = 120
# Poll interval while waiting for worker readiness.
_READY_POLL_INTERVAL = 0.5
_WORKER_LOG_TAIL_BYTES = 4096
_PREFLIGHT_TIMEOUT = 20

# idalib library file name per platform.
_IDALIB_NAMES = {
    "win32": "idalib.dll",
    "darwin": "libidalib.dylib",
    "linux": "libidalib.so",
}


def is_idalib_available() -> bool:
    """Check whether the detected IDA installation includes idalib (Pro only).

    Returns True if idalib.dll / libidalib.* exists in the IDA directory
    resolved from IDADIR or ida-config.json.
    """
    ida_dir = _resolve_ida_dir()
    if not ida_dir:
        return False
    lib_name = _IDALIB_NAMES.get(sys.platform, "libidalib.so")
    return os.path.isfile(os.path.join(ida_dir, lib_name))


def _current_package_root() -> str:
    """Return the import root containing the active ida_multi_mcp package."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _resolve_ida_dir() -> str | None:
    """Resolve IDA dir from IDADIR env or ida-config.json (no filesystem scan)."""
    env_dir = os.environ.get("IDADIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        return env_dir
    # ida-config.json
    if sys.platform == "win32":
        cfg_path = os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "ida-config.json")
    else:
        cfg_path = os.path.join(os.path.expanduser("~"), ".idapro", "ida-config.json")
    try:
        import json
        with open(cfg_path, "r") as f:
            cfg = json.load(f)
        d = cfg.get("Paths", {}).get("ida-install-dir", "").strip()
        if d and os.path.isdir(d):
            return d
    except Exception:
        pass
    return None


def _find_free_port(host: str = "127.0.0.1") -> int:
    """Bind an ephemeral port, release it, return the number.

    There is a small TOCTOU race, but acceptable for localhost-only use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _open_worker_log():
    log_dir = os.path.join(tempfile.gettempdir(), "ida-multi-mcp-idalib")
    os.makedirs(log_dir, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="worker-", suffix=".log", dir=log_dir)
    return os.fdopen(fd, "ab", buffering=0), path


def _read_file_tail(path: str, max_bytes: int = _WORKER_LOG_TAIL_BYTES) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes), os.SEEK_SET)
            return f.read().decode(errors="replace")
    except OSError:
        return ""


def _prepend_env_paths(env: dict[str, str], key: str, paths: list[str]) -> None:
    existing = [p for p in env.get(key, "").split(os.pathsep) if p]
    ordered: list[str] = []
    seen: set[str] = set()
    for path in paths + existing:
        norm = os.path.normcase(os.path.abspath(path))
        if norm in seen:
            continue
        seen.add(norm)
        ordered.append(path)
    env[key] = os.pathsep.join(ordered)


def _build_worker_env(ida_dir: str) -> dict[str, str]:
    """Build the child process environment for an idalib worker."""
    env = os.environ.copy()
    env["IDADIR"] = ida_dir

    import_paths = [_current_package_root()]
    idapro_path = os.path.join(ida_dir, "idalib", "python")
    if os.path.isdir(idapro_path):
        import_paths.append(idapro_path)
    _prepend_env_paths(env, "PYTHONPATH", import_paths)
    return env


def _preflight_worker_python(python_executable: str, env: dict[str, str]) -> str | None:
    """Return None when the worker Python can import required runtime modules."""
    code = (
        "import importlib\n"
        "importlib.import_module('ida_multi_mcp.idalib_worker')\n"
        "importlib.import_module('idapro')\n"
        "importlib.import_module('ida_auto')\n"
    )
    try:
        result = subprocess.run(
            [python_executable, "-c", code],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=_PREFLIGHT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return f"Python executable not found: {python_executable}"
    except subprocess.TimeoutExpired:
        return f"Worker Python preflight timed out after {_PREFLIGHT_TIMEOUT}s: {python_executable}"
    except Exception as exc:
        return f"Worker Python preflight failed: {exc}"

    if result.returncode == 0:
        return None
    output = (result.stdout or "").strip()
    if len(output) > 500:
        output = output[-500:]
    return (
        f"Worker Python preflight failed for {python_executable} "
        f"(exit {result.returncode}). {output}"
    )


class IdalibManager:
    """Manages headless idalib worker subprocesses.

    Each call to :meth:`spawn_session` starts a new Python subprocess
    that opens one binary via ``idapro``, starts an HTTP MCP server on
    a unique port, and registers itself in the shared
    :class:`InstanceRegistry` so the router can forward tool calls.
    """

    def __init__(
        self,
        registry: InstanceRegistry,
        python_executable: str | None = None,
    ):
        self.registry = registry
        self.python_executable = python_executable or sys.executable
        # instance_id -> subprocess.Popen
        self._processes: dict[str, subprocess.Popen] = {}
        # Register cleanup on interpreter shutdown
        atexit.register(self.close_all_sessions)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def spawn_session(
        self,
        input_path: str,
        *,
        host: str = "127.0.0.1",
        timeout: int = _READY_TIMEOUT,
        save_on_close: bool = False,
    ) -> dict:
        """Spawn a headless idalib worker for *input_path*.

        Returns a dict with ``instance_id``, ``host``, ``port``, ``pid``,
        ``binary`` on success, or ``error`` on failure.
        """
        if not is_idalib_available():
            return {
                "error": (
                    "idalib is not available. Headless mode requires IDA Pro "
                    "(IDA Home/Free do not include idalib). "
                    "Ensure IDADIR points to an IDA Pro installation."
                )
            }
        ida_dir = _resolve_ida_dir()
        if not ida_dir:
            return {"error": "Unable to resolve IDA Pro installation directory"}

        resolved_path = os.path.realpath(input_path)
        if not os.path.isfile(resolved_path):
            return {"error": f"File not found: {input_path}"}

        worker_env = _build_worker_env(ida_dir)
        preflight_error = _preflight_worker_python(self.python_executable, worker_env)
        if preflight_error is not None:
            return {
                "error": (
                    f"{preflight_error}. Ensure IDADIR points to an IDA Pro "
                    "installation with idalib/python, or set --idalib-python "
                    "to a compatible Python interpreter."
                )
            }

        port = _find_free_port(host)

        cmd = [
            self.python_executable,
            "-m", "ida_multi_mcp.idalib_worker",
            "--host", host,
            "--port", str(port),
        ]
        if save_on_close:
            cmd.append("--save-on-close")
        cmd.append(resolved_path)

        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        log_file = None
        log_path = ""
        try:
            log_file, log_path = _open_worker_log()
            proc = subprocess.Popen(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=worker_env,
                creationflags=creation_flags,
            )
        except FileNotFoundError:
            return {
                "error": (
                    f"Python executable not found: {self.python_executable}. "
                    "Set --idalib-python to the correct Python with idapro installed."
                )
            }
        except Exception as exc:
            return {"error": f"Failed to spawn idalib worker: {exc}"}
        finally:
            if log_file is not None:
                log_file.close()

        # Wait for the worker to become ready.
        if not self._wait_for_ready(host, port, proc, timeout):
            # Worker didn't come up — collect the worker log tail for diagnostics.
            log_tail = _read_file_tail(log_path)
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            return {
                "error": (
                    f"idalib worker did not become ready within {timeout}s. "
                    f"Log: {log_tail[-500:]}"
                )
            }

        # Ask the worker for its canonical module name so the registry matches
        # what the metadata resource reports. Falls back to basename when the
        # input was an IDB (e.g. foo.exe.i64 → module is "foo.exe") or query fails.
        metadata = query_binary_metadata(host, port, timeout=5.0)
        module_name = (metadata or {}).get("module") if metadata else None
        binary_name = module_name or os.path.basename(resolved_path)
        instance_id = self.registry.register(
            pid=proc.pid,
            port=port,
            idb_path=resolved_path,
            host=host,
            binary_name=binary_name,
            binary_path=resolved_path,
            log_path=log_path,
            type="idalib",
        )

        self._processes[instance_id] = proc
        return {
            "instance_id": instance_id,
            "host": host,
            "port": port,
            "pid": proc.pid,
            "binary": binary_name,
            "log_path": log_path,
        }

    def close_session(self, instance_id: str) -> dict:
        """Terminate the worker for *instance_id* and unregister it.

        Returns ``{"ok": True}`` on success or ``{"error": ...}`` on failure.
        """
        proc = self._processes.get(instance_id)
        if proc is None:
            # Not managed by us (might be GUI or already closed).
            info = self.registry.get_instance(instance_id)
            if info is not None and info.get("type") == "idalib":
                # Orphaned idalib entry — clean it up from registry.
                self.registry.unregister(instance_id)
                return {"ok": True, "note": "orphaned entry removed"}
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        # Terminate the subprocess.
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        del self._processes[instance_id]
        self.registry.unregister(instance_id)
        return {"ok": True}

    def close_all_sessions(self) -> int:
        """Terminate all managed idalib workers. Returns count closed."""
        ids = list(self._processes.keys())
        for iid in ids:
            self.close_session(iid)
        return len(ids)

    def _session_info(self, instance_id: str, info: dict | None, *, managed: bool) -> dict:
        pid = int(info.get("pid", 0)) if info else 0
        host = info.get("host", "127.0.0.1") if info else "127.0.0.1"
        port = info.get("port", 0) if info else 0
        alive = is_process_alive(pid) if pid > 0 else False
        reachable = ping_instance(host, port, timeout=1.0) if alive and port else False
        return {
            "instance_id": instance_id,
            "pid": pid,
            "host": host,
            "port": port,
            "binary_name": info.get("binary_name", "unknown") if info else "unknown",
            "binary_path": info.get("binary_path", "") if info else "",
            "type": "idalib",
            "managed": managed,
            "orphaned": not managed,
            "alive": alive,
            "reachable": reachable,
        }

    def list_sessions(self) -> list[dict]:
        """Return registered idalib sessions and current-server ownership state."""
        result = []
        seen = set()
        for iid, proc in list(self._processes.items()):
            info = self.registry.get_instance(iid)
            alive = is_process_alive(proc.pid)
            if not alive:
                # Clean up dead workers.
                del self._processes[iid]
                self.registry.unregister(iid)
                continue
            seen.add(iid)
            result.append(self._session_info(iid, info, managed=True))

        for iid, info in self.registry.list_instances().items():
            if iid in seen or info.get("type") != "idalib":
                continue
            result.append(self._session_info(iid, info, managed=False))
        return result

    def get_status(self, instance_id: str) -> dict:
        """Health / readiness check for a specific idalib session."""
        proc = self._processes.get(instance_id)
        if proc is None:
            info = self.registry.get_instance(instance_id)
            if info is not None and info.get("type") == "idalib":
                return {
                    "instance_id": instance_id,
                    **self._session_info(instance_id, info, managed=False),
                }
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        info = self.registry.get_instance(instance_id)
        alive = is_process_alive(proc.pid)
        if not alive:
            del self._processes[instance_id]
            self.registry.unregister(instance_id)
            return {
                "instance_id": instance_id,
                "alive": False,
                "reachable": False,
                "error": "Worker process is dead",
            }

        host = info.get("host", "127.0.0.1") if info else "127.0.0.1"
        port = info.get("port", 0) if info else 0
        reachable = ping_instance(host, port, timeout=5.0)

        return {
            "instance_id": instance_id,
            "pid": proc.pid,
            "alive": True,
            "reachable": reachable,
            "binary_name": info.get("binary_name", "unknown") if info else "unknown",
            "managed": True,
            "orphaned": False,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _wait_for_ready(
        self,
        host: str,
        port: int,
        proc: subprocess.Popen,
        timeout: int,
    ) -> bool:
        """Poll until the worker responds to ping or until timeout/death."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Check if process died.
            if proc.poll() is not None:
                return False
            if ping_instance(host, port, timeout=2.0):
                return True
            time.sleep(_READY_POLL_INTERVAL)
        return False
