"""Five-star Pack A: factory, engagement, AI caps offline."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.ai.admin_ai import ALLOWED_CAPABILITIES, AdminAI
from squidc5.config import Settings
from squidc5.engagement.policy import EngagementPolicy
from squidc5.implants.factory import SUPPORTED, build_plan
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_5star01"


def test_build_plan_linux_amd64():
    p = build_plan(os_name="linux", arch="amd64", host="c2.lab", port=8443, sleep=7, jitter=30)
    assert p["os"] == "linux"
    assert "go build" in p["build_script"]
    assert "https://c2.lab:8443" in p["url"]
    assert ("linux", "amd64") in SUPPORTED


def test_build_plan_rejects_bad_arch():
    with pytest.raises(ValueError):
        build_plan(os_name="linux", arch="mips", host="h", port=1)


def test_engagement_bans_and_expiry():
    eng = EngagementPolicy(banned_commands=["shutdown"], end_ts=1.0)
    assert eng.expired()
    assert eng.command_banned("sudo shutdown -h now")
    assert eng.addr_in_scope("10.0.0.5")  # no cidrs = open


def test_ai_new_capabilities_offline():
    # minimal mock - only offline path
    class _P:
        async def get_rules(self):
            return {"admin_ai": {"sandbox": True, "allowed_capabilities": list(ALLOWED_CAPABILITIES)}}

    ai = AdminAI(db=None, metrics=None, policy=_P())  # type: ignore[arg-type]
    for cap in (
        "opsec_review",
        "profile_mutate",
        "implant_build_plan",
        "session_triage",
        "task_suggest",
        "report_draft",
        "hitl_brief",
        "anomaly_explain",
    ):
        assert cap in ALLOWED_CAPABILITIES
        out = ai._offline_fallback(cap, "windows arm host")
        assert "error" not in out or out.get("error") != "unknown capability"


@pytest.mark.asyncio
async def test_api_implant_build_and_engagement(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/implants/build",
                headers=h,
                json={"os": "linux", "arch": "amd64", "host": "c2.example", "port": 8443},
            )
            assert r.status_code == 200, r.text
            assert r.json()["output"].startswith("sc5beacon-linux")
            e = await client.get("/api/v1/engagement", headers=h)
            assert e.status_code == 200
            u = await client.put(
                "/api/v1/engagement",
                headers=h,
                json={"banned_commands": ["format"], "notes": "lab"},
            )
            assert u.status_code == 200
            assert "format" in u.json()["banned_commands"]
            # banned task
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "t"})
            sid = b.json()["session_id"]
            bad = await client.post(
                "/api/v1/tasks",
                headers=h,
                json={"session_id": sid, "command": "format c:"},
            )
            assert bad.status_code == 400
