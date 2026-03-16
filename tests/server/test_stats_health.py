"""Tests for stats and health endpoints."""

import pytest
from fastapi.testclient import TestClient

from mission_control import MissionControl
from mission_control.server.app import create_app


@pytest.fixture
def client():
    mc = MissionControl()
    app = create_app(mc=mc)
    with TestClient(app) as c:
        yield c


class TestHealth:
    def test_health(self, client):
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "uptime_seconds" in data
        assert "active_connections" in data


class TestStats:
    def test_stats(self, client):
        resp = client.get("/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_sessions" in data
        assert "total_steps" in data
        assert "blocked_count" in data
