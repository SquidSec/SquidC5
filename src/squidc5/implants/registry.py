"""Advanced implant / beacon template registry (deterministic, arch-aware)."""

from __future__ import annotations

from typing import Any


class ImplantRegistry:
    """Catalog of implant families beyond basic reverse shells."""

    FAMILIES = {
        "native_sc5beacon": {
            "platforms": ["linux", "windows", "darwin", "macos"],
            "arches": ["amd64", "arm64", "386", "x64", "x86"],
            "stages": ["stage0_stager", "stage1_native"],
            "memory_only": False,
            "description": "Go native sc5beacon v3 (AEAD, jobs, WS/HTTP, BOF host, config blob)",
            "factory": True,
        },
        "windows_stager": {
            "platforms": ["windows"],
            "arches": ["x64", "x86", "amd64"],
            "stages": ["stage0_ps1", "stage1_native"],
            "memory_only": False,
            "description": "PowerShell stage0 launching native sc5beacon",
        },
        "http_beacon": {
            "platforms": ["linux", "windows", "macos"],
            "arches": ["x64", "x86", "arm64"],
            "stages": ["stage0_stager", "stage1_beacon"],
            "memory_only": False,
            "description": "HTTP beacon with profile-aware callbacks",
        },
        "reverse_shell_stable": {
            "platforms": ["linux", "windows"],
            "arches": ["x64", "x86"],
            "stages": ["stage0_shell", "stage2_reconnect"],
            "memory_only": False,
            "description": "Reverse shell with stage-2 reconnect agent",
        },
        "memory_beacon_python": {
            "platforms": ["linux", "macos", "windows"],
            "arches": ["x64", "x86", "arm64"],
            "stages": ["stage0_loader", "stage1_inmem"],
            "memory_only": True,
            "description": "Python/PowerShell memory-style beacon",
        },
        "dns_beacon": {
            "platforms": ["linux", "macos", "windows"],
            "arches": ["x64", "arm64"],
            "stages": ["stage1_dns"],
            "memory_only": True,
            "description": "DNS TXT C2 beacon (lab UDP DNS listener)",
        },
        "ws_beacon": {
            "platforms": ["linux", "macos", "windows"],
            "arches": ["x64", "arm64"],
            "stages": ["stage1_ws"],
            "memory_only": True,
            "description": "WebSocket C2 beacon",
        },
        "linux_stager": {
            "platforms": ["linux"],
            "arches": ["x64", "arm64"],
            "stages": ["stage0_stager", "stage1_beacon"],
            "memory_only": False,
            "description": "Linux stage0 stager into stage1 beacon",
        },
        "linux_memfd": {
            "platforms": ["linux"],
            "arches": ["x64"],
            "stages": ["stage0_memfd", "stage1_beacon"],
            "memory_only": True,
            "description": "Linux memfd_create loader + embedded stage1",
        },
        "bof_stub": {
            "platforms": ["windows"],
            "arches": ["x64", "x86"],
            "stages": ["object_module"],
            "memory_only": True,
            "description": "BOF-style C module (compile with mingw)",
        },
        "bof": {
            "platforms": ["windows"],
            "arches": ["x64", "x86"],
            "stages": ["object_module"],
            "memory_only": True,
            "description": "Alias for bof_stub",
        },
    }

    def list_families(self) -> list[dict[str, Any]]:
        out = []
        for name, meta in self.FAMILIES.items():
            out.append({"name": name, **meta})
        return out

    def resolve(
        self,
        family: str,
        platform: str,
        arch: str = "x64",
    ) -> dict[str, Any]:
        meta = self.FAMILIES.get(family)
        if not meta:
            raise ValueError(f"Unknown implant family: {family}")
        if platform not in meta["platforms"]:
            raise ValueError(f"Family {family} does not support platform {platform}")
        if arch not in meta["arches"]:
            raise ValueError(f"Family {family} does not support arch {arch}")
        return {
            "family": family,
            "platform": platform,
            "arch": arch,
            "stages": list(meta["stages"]),
            "memory_only": meta["memory_only"],
            "description": meta["description"],
        }

    def stager_plan(
        self,
        family: str,
        platform: str,
        arch: str,
        host: str,
        port: int,
        profile_plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resolved = self.resolve(family, platform, arch)
        return {
            **resolved,
            "callback_host": host,
            "callback_port": port,
            "profile": profile_plan or {},
            "injection": {
                "techniques": ["self_inject"] if resolved["memory_only"] else ["disk_drop", "self_inject"],
                "note": "Technique selection is operator-driven; no automatic injection against unauthorized hosts",
            },
        }
