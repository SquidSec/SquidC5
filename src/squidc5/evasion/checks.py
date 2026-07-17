"""Evasion / anti-analysis helpers (deterministic suggestions + implant snippets)."""

from __future__ import annotations

from typing import Any


def anti_analysis_checklist(platform: str = "linux") -> list[dict[str, str]]:
    """Operator checklist — not automatic offensive action."""
    common = [
        {"id": "sleep_jitter", "title": "Sleep with jitter", "detail": "Use profile jitter_pct; avoid fixed intervals"},
        {"id": "decoy", "title": "Decoy HTTP paths", "detail": "Enable profile decoy_paths to blend with site noise"},
        {"id": "ua_blend", "title": "User-Agent blend", "detail": "Match environment-common UA strings in profile"},
    ]
    if platform.startswith("win"):
        common.extend(
            [
                {"id": "vm_check", "title": "VM artifact awareness", "detail": "Review known hypervisor MAC/OEM strings before long-haul implants"},
                {"id": "dbg_check", "title": "Debugger resistance", "detail": "Prefer memory-only stages; avoid obvious debug APIs in payloads"},
            ]
        )
    else:
        common.extend(
            [
                {"id": "container", "title": "Container/sandbox signals", "detail": "cgroup / .dockerenv presence may indicate lab sandboxes"},
                {"id": "ptrace", "title": "Tracer awareness", "detail": "Unexpected TracerPid may indicate analysis"},
            ]
        )
    return common


def sleep_obfuscation_plan(base_sec: float, jitter_pct: float = 25.0) -> dict[str, Any]:
    return {
        "mode": "jittered_sleep",
        "base_sec": base_sec,
        "jitter_pct": jitter_pct,
        "impl_hint": "sleep(base ± base*jitter_pct/100); avoid busy-spin",
        "encrypt_sleep": False,  # placeholder for future Ekko/Zilean-style techniques
    }


def sandbox_probe_snippet(platform: str = "linux") -> str:
    """Read-only probe snippet for authorized lab implants (string template only)."""
    if platform.startswith("win"):
        return (
            "# sandbox probe (authorized lab only)\n"
            "try:\n"
            "    import os\n"
            "    _ = os.environ.get('USERNAME','')\n"
            "except Exception:\n"
            "    pass\n"
        )
    return (
        "# sandbox probe (authorized lab only)\n"
        "import os\n"
        "signals = []\n"
        "if os.path.exists('/.dockerenv'): signals.append('docker')\n"
        "if os.path.exists('/proc/1/cgroup'):\n"
        "    try:\n"
        "        c = open('/proc/1/cgroup').read()\n"
        "        if 'docker' in c or 'kubepods' in c: signals.append('cgroup')\n"
        "    except Exception:\n"
        "        pass\n"
    )
