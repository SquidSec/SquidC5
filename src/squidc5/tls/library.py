"""TLS certificate library under data_dir/tls/library/ + active selection."""

from __future__ import annotations

import json
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

from squidc5.tls.certs import CERT_DIRNAME, tls_material_paths

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _lib_root(data_dir: Path) -> Path:
    p = Path(data_dir) / CERT_DIRNAME / "library"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _active_path(data_dir: Path) -> Path:
    return Path(data_dir) / CERT_DIRNAME / "active.json"


def list_certs(data_dir: Path) -> list[dict[str, Any]]:
    root = _lib_root(data_dir)
    active = get_active_id(data_dir)
    out: list[dict[str, Any]] = []
    for d in sorted(root.iterdir() if root.is_dir() else [], key=lambda x: x.name):
        if not d.is_dir():
            continue
        cert = d / "fullchain.pem"
        key = d / "privkey.pem"
        meta_p = d / "meta.json"
        meta: dict[str, Any] = {}
        if meta_p.is_file():
            try:
                meta = json.loads(meta_p.read_text(encoding="utf-8"))
            except Exception:
                meta = {}
        out.append(
            {
                "id": d.name,
                "label": meta.get("label") or d.name,
                "note": meta.get("note") or "",
                "created_at": meta.get("created_at"),
                "has_cert": cert.is_file() and cert.stat().st_size > 0,
                "has_key": key.is_file() and key.stat().st_size > 0,
                "active": d.name == active,
            }
        )
    return out


def get_active_id(data_dir: Path) -> str | None:
    p = _active_path(data_dir)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return str(data.get("id") or "") or None
    except Exception:
        return None


def upload_cert(
    data_dir: Path,
    *,
    label: str,
    cert_pem: str,
    key_pem: str,
    note: str = "",
) -> dict[str, Any]:
    cert_pem = (cert_pem or "").strip()
    key_pem = (key_pem or "").strip()
    if "BEGIN CERTIFICATE" not in cert_pem:
        raise ValueError("cert_pem must be PEM (BEGIN CERTIFICATE)")
    if "BEGIN" not in key_pem or "PRIVATE KEY" not in key_pem:
        raise ValueError("key_pem must be PEM private key")
    if len(cert_pem) > 512_000 or len(key_pem) > 512_000:
        raise ValueError("cert/key too large")
    cid = "tls_" + secrets.token_hex(6)
    dest = _lib_root(data_dir) / cid
    dest.mkdir(parents=True, exist_ok=False)
    (dest / "fullchain.pem").write_text(cert_pem + ("\n" if not cert_pem.endswith("\n") else ""), encoding="utf-8")
    (dest / "privkey.pem").write_text(key_pem + ("\n" if not key_pem.endswith("\n") else ""), encoding="utf-8")
    try:
        (dest / "privkey.pem").chmod(0o600)
    except OSError:
        pass
    clean_label = (label or cid).strip()[:80] or cid
    meta = {
        "label": clean_label,
        "note": (note or "").strip()[:200],
        "created_at": time.time(),
    }
    (dest / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return {"id": cid, **meta, "active": False}


def activate_cert(data_dir: Path, cert_id: str) -> dict[str, Any]:
    cid = (cert_id or "").strip()
    if not _SAFE.match(cid) and not cid.startswith("tls_"):
        # allow tls_ hex ids
        if not re.match(r"^tls_[a-f0-9]+$", cid):
            raise ValueError("invalid cert id")
    src = _lib_root(data_dir) / cid
    cert_src = src / "fullchain.pem"
    key_src = src / "privkey.pem"
    if not cert_src.is_file() or not key_src.is_file():
        raise FileNotFoundError("certificate not found in library")
    cert_dst, key_dst = tls_material_paths(data_dir)
    cert_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(cert_src, cert_dst)
    shutil.copy2(key_src, key_dst)
    try:
        key_dst.chmod(0o600)
    except OSError:
        pass
    _active_path(data_dir).write_text(
        json.dumps({"id": cid, "activated_at": time.time()}),
        encoding="utf-8",
    )
    return {
        "id": cid,
        "active": True,
        "cert_path": str(cert_dst),
        "key_path": str(key_dst),
        "restart_required": True,
        "note": "TLS material updated on disk. Restart squidc5 to serve the new certificate.",
    }


def delete_cert(data_dir: Path, cert_id: str) -> bool:
    cid = (cert_id or "").strip()
    if get_active_id(data_dir) == cid:
        raise ValueError("cannot delete the active certificate; activate another first")
    src = _lib_root(data_dir) / cid
    if not src.is_dir():
        return False
    shutil.rmtree(src)
    return True


def resolve_listener_ssl_paths(data_dir: Path) -> tuple[Path, Path] | None:
    """Paths for HTTPS listeners - prefer active library cert, else instance TLS."""
    active = get_active_id(data_dir)
    if active:
        d = _lib_root(data_dir) / active
        c, k = d / "fullchain.pem", d / "privkey.pem"
        if c.is_file() and k.is_file():
            return c, k
    c, k = tls_material_paths(data_dir)
    if c.is_file() and k.is_file():
        return c, k
    return None
