#!/usr/bin/env python3
"""Build standalone sc5 (CLI) and squidc5 (server) binaries with PyInstaller."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
WEB = ROOT / "web"
DIST = ROOT / "dist" / "binaries"
BUILD = ROOT / "build" / "pyinstaller"


def _sep() -> str:
    return ";" if os.name == "nt" else ":"


def _run(args: list[str]) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.check_call(args, cwd=str(ROOT))


def _common_flags(name: str) -> list[str]:
    return [
        "--noconfirm",
        "--clean",
        "--onefile",
        f"--name={name}",
        f"--distpath={DIST}",
        f"--workpath={BUILD / name}",
        f"--specpath={BUILD / 'specs'}",
        f"--paths={SRC}",
        "--noupx",
    ]


def build_cli() -> Path:
    name = "sc5"
    _run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            *_common_flags(name),
            "--console",
            "--hidden-import=httpx",
            "--hidden-import=httpx._transports.default",
            "--hidden-import=anyio",
            "--hidden-import=anyio._backends._asyncio",
            "--collect-submodules=httpx",
            str(SRC / "squidc5" / "cli.py"),
        ]
    )
    return DIST / (f"{name}.exe" if os.name == "nt" else name)


def build_server() -> Path:
    name = "squidc5"
    data = f"{WEB}{_sep()}web"
    _run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            *_common_flags(name),
            "--console",
            f"--add-data={data}",
            "--hidden-import=uvicorn",
            "--hidden-import=uvicorn.logging",
            "--hidden-import=uvicorn.loops",
            "--hidden-import=uvicorn.loops.auto",
            "--hidden-import=uvicorn.protocols",
            "--hidden-import=uvicorn.protocols.http",
            "--hidden-import=uvicorn.protocols.http.auto",
            "--hidden-import=uvicorn.protocols.websockets",
            "--hidden-import=uvicorn.protocols.websockets.auto",
            "--hidden-import=uvicorn.lifespan",
            "--hidden-import=uvicorn.lifespan.on",
            "--hidden-import=fastapi",
            "--hidden-import=starlette",
            "--hidden-import=pydantic",
            "--hidden-import=pydantic_settings",
            "--hidden-import=aiosqlite",
            "--hidden-import=multipart",
            "--hidden-import=orjson",
            "--hidden-import=sse_starlette",
            "--hidden-import=mcp",
            "--hidden-import=squidc5",
            "--hidden-import=squidc5.main",
            "--hidden-import=squidc5.cli",
            "--collect-all=uvicorn",
            "--collect-all=fastapi",
            "--collect-all=starlette",
            "--collect-all=pydantic",
            "--collect-all=sse_starlette",
            "--collect-submodules=squidc5",
            str(SRC / "squidc5" / "__main__.py"),
        ]
    )
    return DIST / (f"{name}.exe" if os.name == "nt" else name)


def write_readme(cli_path: Path, server_path: Path) -> None:
    system = platform.system().lower()
    arch = platform.machine().lower()
    text = f"""# SquidC5 standalone binaries ({system}-{arch})

No Python / venv required.

## Operator CLI

```
./{cli_path.name} login --url http://HOST:8443 --token sc5_...
./{cli_path.name} health
./{cli_path.name} sessions list
```

Windows: `sc5.exe ...`

## Server

```
./{server_path.name}
```

Listens on `0.0.0.0:8443` by default (override with `SQUIDC5_HOST` / `SQUIDC5_PORT`).
Admin token is written once to `./data/admin_token.txt` (or `$SQUIDC5_DATA_DIR`).

Ops console: `http://HOST:8443/ops`

Authorized use only.
"""
    (DIST / "README.txt").write_text(text, encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="Build SquidC5 standalone binaries")
    p.add_argument("--cli-only", action="store_true")
    p.add_argument("--server-only", action="store_true")
    args = p.parse_args()

    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)

    cli_path = server_path = None
    if not args.server_only:
        cli_path = build_cli()
        print("CLI:", cli_path, "size=", cli_path.stat().st_size if cli_path.exists() else 0)
    if not args.cli_only:
        server_path = build_server()
        print(
            "SERVER:",
            server_path,
            "size=",
            server_path.stat().st_size if server_path and server_path.exists() else 0,
        )

    # normalize names for artifact consumers
    if cli_path and cli_path.exists() and os.name != "nt":
        cli_path.chmod(cli_path.stat().st_mode | 0o111)
    if server_path and server_path.exists() and os.name != "nt":
        server_path.chmod(server_path.stat().st_mode | 0o111)

    write_readme(
        cli_path or Path("sc5.exe" if os.name == "nt" else "sc5"),
        server_path or Path("squidc5.exe" if os.name == "nt" else "squidc5"),
    )

    # platform-tagged copies for multi-OS artifact merge
    tag = f"{platform.system().lower()}-{platform.machine().lower()}"
    out = DIST / tag
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for src in DIST.iterdir():
        if src.is_file() and src.name != "README.txt":
            dest = out / src.name
            shutil.copy2(src, dest)
            if os.name != "nt" and dest.suffix != ".txt":
                dest.chmod(dest.stat().st_mode | 0o111)
    shutil.copy2(DIST / "README.txt", out / "README.txt")
    print("Tagged output:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
