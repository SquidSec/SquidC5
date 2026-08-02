"""Signed / allow-listed plugin registry (deny by default)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from pathlib import Path
from typing import Any

# db is optional Database-like

log = logging.getLogger("squidc5.plugins")

# Legacy default - refused outside debug (see resolve_plugin_signing_secret).
LEGACY_DEV_PLUGIN_SECRET = b"sc5-dev-plugin-secret-change-me"
PLUGIN_SECRET_FILENAME = "plugin_signing.secret"

# Built-in deterministic plugin handlers (allow-listed capabilities only)
_BUILTIN_HANDLERS: dict[str, Any] = {}


def resolve_plugin_signing_secret(
    *,
    explicit: str | None,
    data_dir: Path,
    debug: bool = False,
) -> bytes:
    """Resolve HMAC secret from env/settings, data_dir file, or generate once.

    Refuses the legacy hardcoded default when debug is False.
    """
    secret: bytes | None = None
    if explicit is not None and str(explicit).strip():
        secret = str(explicit).strip().encode("utf-8")
    else:
        path = Path(data_dir) / PLUGIN_SECRET_FILENAME
        if path.is_file():
            secret = path.read_bytes().strip()
        if not secret:
            Path(data_dir).mkdir(parents=True, exist_ok=True)
            secret = secrets.token_hex(32).encode("utf-8")
            path.write_bytes(secret + b"\n")
            try:
                path.chmod(0o600)
            except OSError:
                log.warning("Could not chmod 0600 on %s", path)
            log.info("Generated plugin signing secret at %s", path)

    if secret == LEGACY_DEV_PLUGIN_SECRET and not debug:
        raise RuntimeError(
            "Refusing legacy default plugin signing secret outside debug mode. "
            "Set SQUIDC5_PLUGIN_SIGNING_SECRET or remove a stale "
            f"{PLUGIN_SECRET_FILENAME} containing the default."
        )
    if not secret:
        raise RuntimeError("Plugin signing secret is empty")
    return secret


def _handle_recon_summary(args: dict[str, Any]) -> dict[str, Any]:
    host = str(args.get("hostname") or "unknown")
    return {
        "hostname": host,
        "summary": f"Lab recon stub for {host}",
        "checks": ["hostname", "os", "users", "listeners"],
    }


def _handle_session_triage(args: dict[str, Any]) -> dict[str, Any]:
    kind = str(args.get("kind") or "unknown")
    verified = bool(args.get("verified"))
    return {
        "kind": kind,
        "verified": verified,
        "priority": "high" if kind in ("reverse_shell", "tcp") and not verified else "normal",
        "actions": ["reap" if not verified else "interact", "document owner"],
    }


def _handle_opsec_checklist(args: dict[str, Any]) -> dict[str, Any]:
    channel = str(args.get("channel") or "http")
    return {
        "channel": channel,
        "checklist": [
            "Confirm authorization and scope",
            f"Match implant channel to profile ({channel})",
            "Enable jitter and decoys where supported",
            "Use redirector for TLS termination",
            "Rotate domains/certs on schedule",
            "Reap unverified shells",
        ],
    }


def _handle_listener_suggest(args: dict[str, Any]) -> dict[str, Any]:
    purpose = str(args.get("purpose") or "beacon")
    if purpose == "dns":
        return {"kind": "dns", "port": 53, "config": {"zone": "c2.lab.invalid"}}
    if purpose == "shell":
        return {"kind": "reverse_shell", "port": 4444, "config": {}}
    return {"kind": "http", "port": 8080, "config": {}}


_BUILTIN_HANDLERS["recon.summary"] = _handle_recon_summary
_BUILTIN_HANDLERS["session.triage"] = _handle_session_triage
_BUILTIN_HANDLERS["opsec.checklist"] = _handle_opsec_checklist
_BUILTIN_HANDLERS["listener.suggest"] = _handle_listener_suggest

# Catalog for marketplace-style discovery (still deny-by-default until registered+enabled)
BUILTIN_PLUGIN_CATALOG: list[dict[str, Any]] = [
    {
        "name": "lab_recon",
        "version": "1.0.0",
        "capabilities": ["recon.summary"],
        "description": "Lab recon summary helper",
    },
    {
        "name": "session_triage",
        "version": "1.0.0",
        "capabilities": ["session.triage"],
        "description": "Prioritize sessions for operators",
    },
    {
        "name": "opsec_helper",
        "version": "1.0.0",
        "capabilities": ["opsec.checklist"],
        "description": "Channel OPSEC checklist",
    },
    {
        "name": "listener_helper",
        "version": "1.0.0",
        "capabilities": ["listener.suggest"],
        "description": "Suggest listener kind/port for lab",
    },
]


class PluginRegistry:
    """In-process allow-list. Plugins must be registered with a signature check."""

    def __init__(self, signing_secret: bytes | None = None, db: Any = None) -> None:
        self._plugins: dict[str, dict[str, Any]] = {}
        # Callers in production must pass resolve_plugin_signing_secret(...).
        # Unit tests may pass an explicit secret; bare None uses legacy only for isolated unit tests.
        self._signing_secret = signing_secret if signing_secret is not None else LEGACY_DEV_PLUGIN_SECRET
        self._enabled: set[str] = set()
        self.db = db

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

    async def persist(self, manifest: dict[str, Any], signature: str, *, enable: bool = False) -> dict[str, Any]:
        entry = self.register(manifest, signature, enable=enable)
        if self.db is not None:
            await self.db.upsert_plugin(
                entry["name"],
                entry["version"],
                manifest,
                signature,
                enabled=entry["enabled"],
            )
        return entry

    async def load_from_db(self) -> int:
        if self.db is None:
            return 0
        rows = await self.db.list_plugins_db()
        n = 0
        for row in rows:
            manifest = row.get("manifest") or {}
            if isinstance(manifest, str):
                import json

                manifest = json.loads(manifest)
            name = row["name"]
            entry = {
                "name": name,
                "version": row.get("version") or "0.0.0",
                "capabilities": list(manifest.get("capabilities") or []),
                "description": manifest.get("description") or "",
                "signature_ok": True,
                "enabled": bool(row.get("enabled")),
            }
            self._plugins[name] = entry
            if entry["enabled"]:
                self._enabled.add(name)
            n += 1
        return n

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

    def execute(self, name: str, capability: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.is_allowed(name, capability):
            raise PermissionError(f"plugin capability not allowed: {name}/{capability}")
        handler = _BUILTIN_HANDLERS.get(capability)
        if handler is None:
            raise ValueError(f"no built-in handler for capability: {capability}")
        return {"ok": True, "plugin": name, "capability": capability, "result": handler(args or {})}

    def catalog(self) -> list[dict[str, Any]]:
        """Marketplace-style discovery list (not enabled until registered)."""
        enabled = {p["name"]: p for p in self.list_plugins()}
        out = []
        for item in BUILTIN_PLUGIN_CATALOG:
            e = enabled.get(item["name"])
            out.append(
                {
                    **item,
                    "installed": e is not None,
                    "enabled": bool(e and e.get("enabled")),
                }
            )
        return out

    def install_catalog_item(self, name: str, *, enable: bool = True) -> dict[str, Any]:
        item = next((x for x in BUILTIN_PLUGIN_CATALOG if x["name"] == name), None)
        if not item:
            raise KeyError(name)
        man = {
            "name": item["name"],
            "version": item["version"],
            "capabilities": list(item["capabilities"]),
            "description": item.get("description") or "",
        }
        sig = self.sign_manifest(man)
        return self.register(man, sig, enable=enable)
