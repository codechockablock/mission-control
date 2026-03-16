"""Tests for WebSocket event streaming."""

import json
import pytest
from fastapi.testclient import TestClient

from mission_control import MissionControl
from mission_control.server.app import create_app


@pytest.fixture
def app():
    mc = MissionControl()
    mc.start_session(session_id="ws_test")
    return create_app(mc=mc)


class TestWebSocket:
    def test_connect_disconnect(self, app):
        client = TestClient(app)
        with client.websocket_connect("/v1/ws") as ws:
            # Connection established
            pass
        # Disconnect happened cleanly

    def test_receive_step_event(self, app):
        client = TestClient(app)
        with client.websocket_connect("/v1/ws") as ws:
            # Evaluate an action — should produce a step event
            resp = client.post("/v1/evaluate", json={
                "tool_type": "shell_exec",
                "content": "echo hello",
            })
            assert resp.status_code == 200

            data = ws.receive_json()
            assert data["type"] == "step"
            assert "verdict" in data
            assert "alert_level" in data

    def test_receive_block_event(self, app):
        client = TestClient(app)
        with client.websocket_connect("/v1/ws") as ws:
            resp = client.post("/v1/evaluate", json={
                "tool_type": "shell_exec",
                "content": "rm -rf /",
            })
            assert resp.status_code == 200

            data = ws.receive_json()
            assert data["type"] == "block"
            assert "rule" in data

    def test_receive_session_start_event(self, app):
        client = TestClient(app)
        with client.websocket_connect("/v1/ws") as ws:
            resp = client.post("/v1/session/start", json={})
            assert resp.status_code == 200

            data = ws.receive_json()
            assert data["type"] == "session_start"
            assert "session_id" in data
