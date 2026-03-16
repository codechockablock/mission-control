"""Tests for session lifecycle endpoints."""

import pytest
from fastapi.testclient import TestClient

from mission_control import MissionControl
from mission_control.server.app import create_app
from mission_control.recorder.storage import FileStorage

import tempfile
import os


@pytest.fixture
def client_with_storage(tmp_dir):
    storage = FileStorage(base_dir=os.path.join(tmp_dir, "sessions"))
    mc = MissionControl(storage=storage)
    app = create_app(mc=mc)
    with TestClient(app) as c:
        yield c, mc


@pytest.fixture
def client():
    mc = MissionControl()
    app = create_app(mc=mc)
    with TestClient(app) as c:
        yield c


class TestStartSession:
    def test_start_session(self, client):
        resp = client.post("/v1/session/start", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert data["status"] == "active"
        assert data["session_id"].startswith("sess_")

    def test_start_session_custom_id(self, client):
        resp = client.post("/v1/session/start", json={
            "session_id": "my_session_42"
        })
        assert resp.status_code == 200
        assert resp.json()["session_id"] == "my_session_42"

    def test_start_session_with_metadata(self, client):
        resp = client.post("/v1/session/start", json={
            "metadata": {"agent": "test", "task": "review"}
        })
        assert resp.status_code == 200


class TestEndSession:
    def test_end_session(self, client):
        # Start first
        client.post("/v1/session/start", json={})
        # Evaluate something to create steps
        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "ls"
        })
        resp = client.post("/v1/session/end")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_steps"] >= 1
        assert "verdict_distribution" in data
        assert "chain_hash" in data

    def test_end_without_start(self, client):
        resp = client.post("/v1/session/end")
        # Might succeed with auto-started session or fail — either way should not crash
        assert resp.status_code in (200, 400)


class TestSessionStatus:
    def test_active_session_status(self, client):
        start_resp = client.post("/v1/session/start", json={})
        session_id = start_resp.json()["session_id"]

        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "echo hello"
        })

        resp = client.get(f"/v1/session/{session_id}/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == session_id
        assert data["is_active"] is True
        assert data["step_count"] >= 1

    def test_not_found(self, client):
        resp = client.get("/v1/session/nonexistent/status")
        assert resp.status_code == 404


class TestSessionHistory:
    def test_history(self, client_with_storage):
        client, mc = client_with_storage
        start_resp = client.post("/v1/session/start", json={})
        session_id = start_resp.json()["session_id"]

        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "ls -la"
        })
        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "pwd"
        })

        resp = client.get(f"/v1/session/{session_id}/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == session_id
        assert len(data["entries"]) >= 2

    def test_history_not_found(self, client):
        resp = client.get("/v1/session/nonexistent/history")
        assert resp.status_code == 404
