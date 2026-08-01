"""Official post-ex / BOF / inject module catalog (authorized lab only)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Techniques are named for operator planning; agent enforces SC5_ALLOW_INJECT=1
INJECT_TECHNIQUES = [
    {
        "id": "create_remote_thread",
        "platforms": ["windows"],
        "risk": "high",
        "description": "Classic CreateRemoteThread injection (lab only)",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "apc_queue",
        "platforms": ["windows"],
        "risk": "high",
        "description": "QueueUserAPC-style injection (lab only)",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "process_vm_write",
        "platforms": ["linux"],
        "risk": "high",
        "description": "process_vm_writev self/remote write lab stub",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
]

SLEEP_MASK_MODES = [
    {
        "id": "jitter_only",
        "description": "Sleep with jitter; wipe sensitive buffers before sleep",
    },
    {
        "id": "timer_wait",
        "description": "Wait via timer channel instead of plain Sleep (cross-platform)",
    },
    {
        "id": "ekko_style",
        "platforms": ["windows"],
        "description": "Windows timer-stack encrypt sleep pattern (lab research mode)",
        "requires_env": "SC5_SLEEP_MASK=ekko",
    },
]


def bof_modules_dir() -> Path:
    # repo root / modules / bof
    return Path(__file__).resolve().parents[3] / "modules" / "bof"


def list_bof_modules() -> list[dict[str, Any]]:
    root = bof_modules_dir()
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for p in sorted(root.glob("*.c")):
        out.append(
            {
                "id": p.stem,
                "name": p.stem,
                "path": str(p.relative_to(root.parent.parent)) if root.parent.parent.exists() else p.name,
                "source": p.name,
                "entry": "go",
                "platforms": ["windows"],
                "description": f"BOF-style source {p.name} (compile with mingw; load via bof:run)",
            }
        )
    return out


def list_inject_techniques(platform: str | None = None) -> list[dict[str, Any]]:
    if not platform:
        return list(INJECT_TECHNIQUES)
    pl = platform.lower()
    return [t for t in INJECT_TECHNIQUES if pl in t.get("platforms", []) or not t.get("platforms")]


def sleep_mask_catalog() -> list[dict[str, Any]]:
    return list(SLEEP_MASK_MODES)
