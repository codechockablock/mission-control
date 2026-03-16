"""Tests for constitution CRUD endpoints."""

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


class TestConstitutionCRUD:
    def test_create_constitution(self, client):
        resp = client.post("/v1/constitution", json={
            "name": "test_constitution",
            "description": "A test constitution",
            "principles": ["be safe", "be helpful"],
            "boundaries": {"max_risk": 0.5},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "test_constitution"
        assert data["description"] == "A test constitution"
        assert len(data["principles"]) == 2
        assert data["boundaries"]["max_risk"] == 0.5

    def test_get_constitution(self, client):
        # Create first
        client.post("/v1/constitution", json={
            "name": "my_const",
            "description": "test",
            "principles": ["principle1"],
        })
        # Then get
        resp = client.get("/v1/constitution/my_const")
        assert resp.status_code == 200
        assert resp.json()["name"] == "my_const"

    def test_get_not_found(self, client):
        resp = client.get("/v1/constitution/nonexistent")
        assert resp.status_code == 404

    def test_update_constitution(self, client):
        client.post("/v1/constitution", json={
            "name": "updatable",
            "description": "v1",
        })
        client.post("/v1/constitution", json={
            "name": "updatable",
            "description": "v2",
        })
        resp = client.get("/v1/constitution/updatable")
        assert resp.json()["description"] == "v2"

    def test_get_builtin_constitution(self, client):
        resp = client.get("/v1/constitution/agent_safety_default")
        # Should succeed if frontier-ops is installed
        assert resp.status_code in (200, 404)

    def test_create_minimal(self, client):
        resp = client.post("/v1/constitution", json={
            "name": "minimal",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["principles"] == []
        assert data["boundaries"] == {}
