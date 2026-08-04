"""Official post-ex / BOF / inject / SA module catalog (authorized lab only)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Techniques are named for operator planning; agent enforces SC5_ALLOW_* gates
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
        "id": "early_bird",
        "platforms": ["windows"],
        "risk": "high",
        "description": "Early-bird APC into suspended process (lab stub)",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "nt_queue_apc",
        "platforms": ["windows"],
        "risk": "high",
        "description": "NtQueueApcThread-style path (lab stub)",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "process_hollowing",
        "platforms": ["windows"],
        "risk": "critical",
        "description": "Process hollowing research path (lab stub)",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "process_vm_write",
        "platforms": ["linux"],
        "risk": "high",
        "description": "process_vm_writev self/remote write lab stub",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "memfd_exec",
        "platforms": ["linux"],
        "risk": "high",
        "description": "memfd_create + exec lab stub",
        "requires_env": "SC5_ALLOW_INJECT=1",
    },
    {
        "id": "self_inject",
        "platforms": ["windows", "linux"],
        "risk": "high",
        "description": "Self-process inject lab stub",
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

SA_MODULES = [
    {"id": "sa:whoami", "command": "sa:whoami", "risk": "low", "gate": None, "description": "Identity JSON"},
    {"id": "sa:sysinfo", "command": "sa:sysinfo", "risk": "low", "gate": None, "description": "Host sysinfo JSON"},
    {"id": "sa:env", "command": "sa:env", "risk": "low", "gate": None, "description": "Selected environment vars"},
    {"id": "sa:net", "command": "sa:net", "risk": "low", "gate": None, "description": "Network interfaces"},
    {"id": "sa:users", "command": "sa:users", "risk": "low", "gate": None, "description": "Home directory enumeration"},
    {"id": "sa:procs", "command": "sa:procs", "risk": "low", "gate": None, "description": "Process list"},
]

CRED_MODULES = [
    {
        "id": "cred:list",
        "command": "cred:list",
        "risk": "low",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "List available credential helpers",
    },
    {
        "id": "cred:env_secrets",
        "command": "cred:env_secrets",
        "risk": "medium",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "Scan env for secret-like names (redacted values)",
    },
    {
        "id": "cred:browser_paths",
        "command": "cred:browser_paths",
        "risk": "low",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "Locate browser profile directories (no dump)",
    },
]

LATERAL_MODULES = [
    {
        "id": "lat:tcp_probe",
        "command": "lat:tcp_probe",
        "risk": "low",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "TCP connect probe host:port",
        "args": ["host", "port"],
    },
    {
        "id": "lat:ssh_probe",
        "command": "lat:ssh_probe",
        "risk": "medium",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "SSH banner grab (no auth)",
        "args": ["host", "port"],
    },
    {
        "id": "lat:smb_probe",
        "command": "lat:smb_probe",
        "risk": "medium",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "TCP/445 reachability",
        "args": ["host"],
    },
]

PERSIST_MODULES = [
    {
        "id": "persist:plan",
        "command": "persist:plan",
        "risk": "high",
        "gate": "SC5_ALLOW_POSTEX=1",
        "description": "Emit persistence plan only (no install in default build)",
        "args": ["method"],
    },
]


def bof_modules_dir() -> Path:
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
                "risk": "high",
                "gate": "SC5_ALLOW_BOF=1",
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


def list_sa_modules() -> list[dict[str, Any]]:
    return list(SA_MODULES)


def list_cred_modules() -> list[dict[str, Any]]:
    return list(CRED_MODULES)


def list_lateral_modules() -> list[dict[str, Any]]:
    return list(LATERAL_MODULES)


def list_persist_modules() -> list[dict[str, Any]]:
    return list(PERSIST_MODULES)


def full_catalog() -> dict[str, Any]:
    return {
        "inject": list_inject_techniques(),
        "bof": list_bof_modules(),
        "sleep_mask": sleep_mask_catalog(),
        "sa": list_sa_modules(),
        "cred": list_cred_modules(),
        "lateral": list_lateral_modules(),
        "persist": list_persist_modules(),
        "gates": {
            "inject": "SC5_ALLOW_INJECT=1 on implant",
            "bof": "SC5_ALLOW_BOF=1 on implant (+ SC5_BOF_EXECUTE=1 for research map)",
            "postex": "SC5_ALLOW_POSTEX=1 on implant (cred/lateral/persist)",
        },
        "note": "Authorized red team / lab only. Default builds refuse sensitive ops without gates.",
    }
