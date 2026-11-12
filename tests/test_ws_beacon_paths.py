"""WebSocket beacon channel: path allow-list, AEAD envelopes, message routing."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from squidc5.implants.crypto import seal


def _ws_client(app) -> TestClient:
    return TestClient(app)


def test_ws_plain_beacon_creates_session(app):
    with _ws_client(app) as tc:
        with tc.websocket_connect("/ws/v1/beacon") as ws:
            ws.send_json({"type": "beacon", "hostname": "ws-plain"})
            data = ws.receive_json()
            assert data["session_id"].startswith("ses_")
            assert "task" in data


def test_ws_result_message_completes_task(app):
    with _ws_client(app) as tc:
        with tc.websocket_connect("/ws/v1/beacon") as ws:
            ws.send_json({"type": "beacon", "hostname": "ws-result"})
            sid = ws.receive_json()["session_id"]

            task = app.state.app_state.tasks
            created = None

            async def _make() -> None:
                nonlocal created
                created = await task.create(session_id=sid, command="id", created_by="tester")

            # TestClient runs the app in its own loop; use the portal.
            tc.portal.call(_make)
            assert created is not None

            ws.send_json({"type": "result", "task_id": created["id"], "result": "uid=0"})
            out = ws.receive_json()
            assert out["status"] == "ok"


def test_ws_unknown_path_is_closed(app):
    with _ws_client(app) as tc:
        with pytest.raises(WebSocketDisconnect) as exc:
            with tc.websocket_connect("/ws/not/a/beacon") as ws:
                ws.receive_json()
        assert exc.value.code == 1008


def test_ws_closed_when_implant_beacon_disabled(app):
    async def _disable() -> None:
        await app.state.app_state.features.set_many({"implant_beacon": False}, actor="test")

    with _ws_client(app) as tc:
        tc.portal.call(_disable)
        with pytest.raises(WebSocketDisconnect) as exc:
            with tc.websocket_connect("/ws/v1/beacon") as ws:
                ws.receive_json()
        assert exc.value.code == 1008


def test_ws_sealed_envelope_with_correct_psk(app):
    psk = app.state.app_state.implant_psk
    assert psk
    envelope = seal(psk, {"type": "beacon", "hostname": "ws-sealed"})
    with _ws_client(app) as tc:
        with tc.websocket_connect("/ws/v1/beacon") as ws:
            ws.send_json(envelope)
            data = ws.receive_json()
            assert data["session_id"].startswith("ses_")


def test_ws_sealed_envelope_with_wrong_psk_is_closed(app):
    envelope = seal("not-the-server-psk", {"type": "beacon", "hostname": "ws-bad"})
    with _ws_client(app) as tc:
        with pytest.raises(WebSocketDisconnect) as exc:
            with tc.websocket_connect("/ws/v1/beacon") as ws:
                ws.send_json(envelope)
                ws.receive_json()
        assert exc.value.code == 1008


def test_ws_profile_path_is_accepted(app):
    async def _activate() -> None:
        await app.state.app_state.profiles.set_active("prof_default_ws")

    with _ws_client(app) as tc:
        tc.portal.call(_activate)
        profile = app.state.app_state.profiles.active()
        assert profile is not None
        path = profile.ws.path
        with tc.websocket_connect(path) as ws:
            ws.send_json({"type": "beacon", "hostname": "ws-profile"})
            data = ws.receive_json()
            assert data["session_id"].startswith("ses_")


def test_ws_malformed_json_closes_socket(app):
    with _ws_client(app) as tc:
        with pytest.raises(WebSocketDisconnect):
            with tc.websocket_connect("/ws/v1/beacon") as ws:
                ws.send_text("this is not json")
                ws.receive_json()


def test_ws_client_disconnect_is_clean(app):
    with _ws_client(app) as tc:
        with tc.websocket_connect("/ws/v1/beacon") as ws:
            ws.send_json({"type": "beacon", "hostname": "ws-bye"})
            assert ws.receive_json()["session_id"].startswith("ses_")
        # Exiting the context closes the socket; the server must not raise.
    assert True
