"""TLS helpers for SquidC5 listeners (ops UI, API, MCP)."""

from __future__ import annotations

from squidc5.tls.certs import ensure_instance_tls, tls_material_paths

__all__ = ["ensure_instance_tls", "tls_material_paths"]
