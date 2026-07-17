"""Signed / allow-listed plugin registry (deny by default)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


class PluginRegistry:
    """In-process allow-list. Plugins must be registered with a signature check."""

    def __init__(self, signing_secret: bytes | None = None) -> None:
        self._plugins: dict[str, dict[str, Any]] = {}
        self._signing_secret = signing_secret or b"sc5-dev-plugin-secret-change-me"
        self._enabled: set[str] = set()

    def sign_manifest(self, manifest: dict[str, Any]) -> str:
        body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._signing_secret, body, hashlib.sha256).hexdigest()

    def verify(self, manifest: dict[str, Any], signature: str) -> bool:
        expected = self.sign_manifest(manifest)
        return hmac.compare_digest(expected, signature or "")

    def register(self, manifest: dict[str, Any], signature: str, *, enable: bool = False) -> dict[str, Any]:
        name = manifest.get("name")
        if not name or not isinstance(name, str):
            raise ValueError("manifest.name required")
        if not self.verify(manifest, signature):
            raise ValueError("invalid plugin signature")
        entry = {
            "name": name,
            "version": manifest.get("version") or "0.0.0",
            "capabilities": list(manifest.get("capabilities") or []),
            "description": manifest.get("description") or "",
            "signature_ok": True,
            "enabled": False,
        }
        self._plugins[name] = entry
        if enable:
            self.enable(name)
        return entry

    def enable(self, name: str) -> None:
        if name not in self._plugins:
            raise KeyError(name)
        self._enabled.add(name)
        self._plugins[name]["enabled"] = True

    def disable(self, name: str) -> None:
        self._enabled.discard(name)
        if name in self._plugins:
            self._plugins[name]["enabled"] = False

    def list_plugins(self) -> list[dict[str, Any]]:
        return list(self._plugins.values())

    def is_allowed(self, name: str, capability: str) -> bool:
        if name not in self._enabled:
            return False
        caps = self._plugins.get(name, {}).get("capabilities") or []
        return capability in caps
