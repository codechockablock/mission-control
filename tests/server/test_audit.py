"""Tests for audit verification endpoints."""

import pytest
from fastapi.testclient import TestClient

from mission_control import MissionControl
from mission_control.server.app import create_app


@pytest.fixture
def client():
    mc = MissionControl()
    mc.start_session(session_id="audit_test")
    app = create_app(mc=mc)
    with TestClient(app) as c:
        yield c


class TestAuditVerify:
    def test_verify_empty_chain(self, client):
        resp = client.post("/v1/audit/verify", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True

    def test_verify_after_steps(self, client):
        # Generate some steps
        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "ls"
        })
        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "pwd"
        })

        resp = client.post("/v1/audit/verify", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["chain_length"] > 0
        assert len(data["head_hash"]) > 0
        assert "verified" in data["message"].lower()

    def test_verify_after_blocked(self, client):
        # Generate a blocked action
        client.post("/v1/evaluate", json={
            "tool_type": "shell_exec",
            "content": "rm -rf /"
        })

        resp = client.post("/v1/audit/verify", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True

    def test_verify_response_fields(self, client):
        resp = client.post("/v1/audit/verify", json={})
        data = resp.json()
        assert "valid" in data
        assert "chain_length" in data
        assert "head_hash" in data
        assert "message" in data
