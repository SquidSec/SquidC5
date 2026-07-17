"""Resource path resolution for source, Docker, and frozen (PyInstaller) installs."""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"))


def bundle_root() -> Path:
    """Root of packaged assets (PyInstaller _MEIPASS) or project root."""
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    # src/squidc5/paths.py -> repo root
    return Path(__file__).resolve().parent.parent.parent


def web_dir() -> Path:
    """Directory containing phone-dashboard.html / ops-admin.js / assets."""
    candidates = [
        bundle_root() / "web",
        Path("/app/web"),
        Path(__file__).resolve().parent.parent.parent / "web",
    ]
    for p in candidates:
        if p.is_dir():
            return p
    return candidates[0]


def web_file(*parts: str) -> Path:
    return web_dir().joinpath(*parts)
