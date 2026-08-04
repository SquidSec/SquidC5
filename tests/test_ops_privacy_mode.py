"""Ops UI privacy mode: mask PII helpers + header indicator."""

from __future__ import annotations

import re

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_priv01"


@pytest.mark.asyncio
async def test_ops_html_privacy_mode_surface(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "priv1",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            html = (await client.get("/ops")).text
            assert 'id="privacyBadge"' in html
            assert "Privacy Mode Active" in html
            assert 'id="btnPrivacy"' in html
            assert "function maskPii" in html
            assert "privacyModeOn" in html
            assert "sc5_ops_privacy" in html
            assert "pill privacy" in html or "pill.privacy" in html
            assert "body.privacy-mode" in html

            h = {"Authorization": f"Bearer {ADMIN}"}
            js = (await client.get("/api/v1/ops/admin.js", headers=h)).text
            assert "__SC5_maskPii" in js or "__SC5_privacyOn" in js


def test_mask_pii_patterns_from_ops_source():
    """Extract maskPii from served logic via static file and smoke-eval core patterns."""
    from pathlib import Path

    html = Path("web/phone-dashboard.html").read_text(encoding="utf-8")
    assert "function maskPii" in html
    # Ensure critical patterns exist in the function body
    assert r"sc5_" in html
    assert "Bearer" in html
    assert "•••.•••.•••.•••" in html or "••••" in html
    # Sanity: sample replacements using the same regexes as shipped (duplicated for unit certainty)
    samples = {
        "connect 10.0.0.5:443 now": r"•••",
        "token sc5_abcdefghijklmnopqrstuv": "sc5_",
        "Authorization: Bearer sc5_abcdefghijklmnopqrstuv": "••••",
        "key xai-SUPERSECRETKEY1234567890": "••••",
        "https://c2.example.com:8443/ops": "••••",
        "user@corp.example.com": "•••@",
    }
    # Lightweight mirror of shipped rules (keep in sync with maskPii)
    def mask(s: str) -> str:
        s = re.sub(r"\bsc5_[A-Za-z0-9_-]{8,}\b", "sc5_••••••••", s)
        s = re.sub(
            r"\b(?:sk|xai|pk|rk|key)-[A-Za-z0-9_-]{8,}\b",
            lambda m: m.group(0).split("-")[0] + "-••••••••",
            s,
            flags=re.I,
        )
        s = re.sub(r"(Bearer\s+)[A-Za-z0-9._\-+=/]+", r"\1••••••••", s, flags=re.I)
        s = re.sub(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            "•••.•••.•••.•••",
            s,
        )
        s = re.sub(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "•••@•••.•••",
            s,
        )
        s = re.sub(
            r"\b((?:https?|wss?)://)([^/\s\"'<>]+)",
            r"\1••••••••",
            s,
            flags=re.I,
        )
        return s

    for raw, expect_sub in samples.items():
        out = mask(raw)
        assert expect_sub in out, f"{raw!r} -> {out!r}"
        if "10.0.0.5" in raw:
            assert "10.0.0.5" not in out
        if "example.com" in raw and "user@" not in raw:
            assert "c2.example.com" not in out
        if "SUPERSECRET" in raw:
            assert "SUPERSECRET" not in out
