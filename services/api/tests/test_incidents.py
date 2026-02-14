"""
Phase A.1: Incidents API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run (incidents tables exist).
Run: pytest services/api/tests/test_incidents.py -v
"""
import os
import sys
from pathlib import Path

# Ensure project root is on path (e.g. in Docker: /app when tests live in /app/tests)
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import pytest
from fastapi.testclient import TestClient

from app.main import app

# Skip entire module if no DB (e.g. CI without Postgres)
pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; incidents tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers(client):
    """Login and return headers with Bearer token."""
    r = client.post(
        "/auth/login",
        data={"username": os.getenv("ADMIN_USERNAME", "admin"), "password": os.getenv("ADMIN_PASSWORD", "admin")},
    )
    if r.status_code != 200:
        pytest.skip(f"Login failed: {r.status_code} {r.text}")
    token = r.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


def test_incidents_list(client, auth_headers):
    r = client.get("/incidents", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_incidents_list_with_filters(client, auth_headers):
    r = client.get("/incidents?status=new&severity=medium&limit=5", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data


def test_incidents_create_and_get(client, auth_headers):
    # Create
    r = client.post(
        "/incidents",
        json={"title": "Test incident from pytest", "severity": "medium"},
        headers=auth_headers,
    )
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["title"] == "Test incident from pytest"
    assert created["severity"] == "medium"
    assert created["status"] == "new"
    incident_id = created["id"]
    assert isinstance(incident_id, int)

    # Get one
    r2 = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert r2.status_code == 200
    one = r2.json()
    assert one["id"] == incident_id
    assert one["title"] == "Test incident from pytest"
    assert "alerts" in one
    assert "timeline" in one
    assert isinstance(one["alerts"], list)
    assert isinstance(one["timeline"], list)


def test_incidents_update_status(client, auth_headers):
    r = client.post(
        "/incidents",
        json={"title": "Status test incident", "severity": "low"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    incident_id = r.json()["id"]

    r2 = client.patch(f"/incidents/{incident_id}/status", json={"status": "triaged"}, headers=auth_headers)
    assert r2.status_code == 200
    assert r2.json()["status"] == "triaged"

    r3 = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert r3.status_code == 200
    assert r3.json()["status"] == "triaged"
    assert len(r3.json()["timeline"]) >= 1  # state_change entry


def test_incidents_add_note(client, auth_headers):
    r = client.post(
        "/incidents",
        json={"title": "Note test incident", "severity": "info"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    incident_id = r.json()["id"]

    r2 = client.post(
        f"/incidents/{incident_id}/notes",
        json={"body": "This is a test note from pytest."},
        headers=auth_headers,
    )
    assert r2.status_code == 201
    note = r2.json()
    assert note["event_type"] == "note"
    assert "This is a test note" in (note.get("body") or "")

    r3 = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert r3.status_code == 200
    timeline = r3.json()["timeline"]
    assert any(t.get("event_type") == "note" and "test note" in (t.get("body") or "") for t in timeline)


def test_incidents_link_and_unlink_alert(client, auth_headers):
    r = client.post(
        "/incidents",
        json={"title": "Link alert test", "severity": "high"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    incident_id = r.json()["id"]

    r2 = client.post(
        f"/incidents/{incident_id}/alerts",
        json={"asset_key": "test-asset-pytest"},
        headers=auth_headers,
    )
    assert r2.status_code == 201

    r3 = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert r3.status_code == 200
    alerts = r3.json()["alerts"]
    assert any(a["asset_key"] == "test-asset-pytest" for a in alerts)

    r4 = client.delete(f"/incidents/{incident_id}/alerts?asset_key=test-asset-pytest", headers=auth_headers)
    assert r4.status_code == 200
    assert r4.json().get("ok") is True

    r5 = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert r5.status_code == 200
    assert not any(a["asset_key"] == "test-asset-pytest" for a in r5.json()["alerts"])


def test_incidents_get_404(client, auth_headers):
    r = client.get("/incidents/999999", headers=auth_headers)
    assert r.status_code == 404


def test_incidents_unauthorized(client):
    r = client.get("/incidents")
    assert r.status_code == 401  # No auth header
