"""Malleable C2 profile engine unit + API tests."""

from __future__ import annotations

import random

import pytest

from squidc5.profiles.engine import ProfileEngine
from squidc5.profiles.models import DEFAULT_PROFILES, C2Profile, HttpProfile


def test_default_profiles_include_active_http():
    assert any(p.active and p.channel == "http" for p in DEFAULT_PROFILES)
    assert any(p.channel == "dns" for p in DEFAULT_PROFILES)
    assert any(p.channel == "ws" for p in DEFAULT_PROFILES)


def test_jitter_bounds():
    rng = random.Random(0)
    for _ in range(50):
        s = ProfileEngine.compute_sleep(10.0, 20.0, rng)
        assert 8.0 <= s <= 12.0


def test_shape_http_includes_uri_and_decoy():
    eng = ProfileEngine.__new__(ProfileEngine)
    eng._cache = {}
    eng._active_id = None
    prof = C2Profile(
        id="t1",
        name="test",
        channel="http",
        http=HttpProfile(
            uris=["/a", "/b"],
            decoy_enabled=True,
            decoy_paths=["/x", "/y", "/z"],
            jitter_pct=0,
            sleep_sec=5,
            request_body_template='{"q":{beacon}}',
        ),
    )
    shaped = eng.shape_http_request(prof, {"session_id": "ses_1"}, rng=random.Random(1))
    assert shaped["uri"] in ("/a", "/b")
    assert shaped["method"] == "POST"
    assert "ses_1" in shaped["body"]
    assert shaped["sleep_sec"] == 5.0
    assert len(shaped["decoy_uris"]) == 2


@pytest.mark.asyncio
async def test_profiles_api_list_and_activate(client, admin_headers):
    r = await client.get("/api/v1/profiles", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["active_id"]
    assert len(data["profiles"]) >= 3

    # activate amazon blend
    target = next(p for p in data["profiles"] if p["id"] == "prof_amazon_cdn")
    act = await client.post(
        f"/api/v1/profiles/{target['id']}/activate", headers=admin_headers
    )
    assert act.status_code == 200
    assert act.json()["active"] is True

    active = await client.get("/api/v1/profiles/active", headers=admin_headers)
    assert active.status_code == 200
    assert active.json()["id"] == "prof_amazon_cdn"

    shape = await client.post(
        "/api/v1/profiles/shape",
        headers=admin_headers,
        json={"beacon": {"hostname": "lab-host"}},
    )
    assert shape.status_code == 200
    body = shape.json()
    assert body["uri"] in target["http"]["uris"]
    assert body["profile_id"] == "prof_amazon_cdn"


@pytest.mark.asyncio
async def test_profiles_require_auth(client):
    assert (await client.get("/api/v1/profiles")).status_code == 401
