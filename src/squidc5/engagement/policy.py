"""Engagement scope / ROE server-side policy object."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EngagementPolicy:
    name: str = "default"
    cidrs: list[str] = field(default_factory=list)  # allowed target nets (informational + checks)
    banned_commands: list[str] = field(default_factory=lambda: ["rm -rf /", "format c:"])
    end_ts: float | None = None  # unix; deny tasking after
    require_hitl_file_write: bool = True
    max_sessions: int = 500
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementPolicy:
        return cls(
            name=str(data.get("name") or "default"),
            cidrs=list(data.get("cidrs") or []),
            banned_commands=list(data.get("banned_commands") or []),
            end_ts=data.get("end_ts"),
            require_hitl_file_write=bool(data.get("require_hitl_file_write", True)),
            max_sessions=int(data.get("max_sessions") or 500),
            notes=str(data.get("notes") or ""),
        )

    def expired(self) -> bool:
        return self.end_ts is not None and time.time() > float(self.end_ts)

    def command_banned(self, command: str) -> bool:
        c = (command or "").lower()
        return any(b.lower() in c for b in self.banned_commands if b)

    def addr_in_scope(self, addr: str | None) -> bool:
        if not self.cidrs or not addr:
            return True
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return True
        for c in self.cidrs:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False
