"""
Phase A.1: Incidents API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run (incidents tables exist).
Run: pytest services/api/tests/test_incidents.py -v
"""

import os
import sys
import uuid
from pathlib import Path

# Ensure project root is on path (e.g. in Docker: /app when tests live in /app/tests)
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import pytest
from fastapi.testclient import TestClient

from app.db_migrate import run_startup_migrations
from app.main import app

# Skip entire module if no DB (e.g. CI without Postgres)
pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; incidents tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    run_startup_migrations()


@pytest.fixture(scope="module")
def auth_headers(client):
    """Login and return headers with Bearer token."""
    r = client.post(
        "/auth/login",
        data={
            "username": os.getenv("ADMIN_USERNAME", "admin"),
            "password": os.getenv("ADMIN_PASSWORD", "admin"),
        },
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


def test_incidents_idempotency_key_dedupes(client, auth_headers):
    incident_key = f"pytest-idem-{uuid.uuid4().hex[:12]}"
    payload = {
        "incident_key": incident_key,
        "title": "Idempotent incident",
        "severity": "medium",
        "asset_keys": ["idempotency-asset-1"],
    }
    r1 = client.post("/incidents", json=payload, headers=auth_headers)
    assert r1.status_code == 201, r1.text
    first = r1.json()
    assert first["deduped"] is False

    r2 = client.post("/incidents", json=payload, headers=auth_headers)
    assert r2.status_code == 200, r2.text
    second = r2.json()
    assert second["deduped"] is True
    assert second["id"] == first["id"]
    assert second["incident_key"] == incident_key

    r3 = client.get(f"/incidents/{first['id']}", headers=auth_headers)
    assert r3.status_code == 200
    one = r3.json()
    linked = [a["asset_key"] for a in one["alerts"] if a.get("asset_key") == "idempotency-asset-1"]
    assert len(linked) == 1


def test_incidents_update_status(client, auth_headers):
    r = client.post(
        "/incidents",
        json={"title": "Status test incident", "severity": "low"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    incident_id = r.json()["id"]

    r2 = client.patch(
        f"/incidents/{incident_id}/status", json={"status": "triaged"}, headers=auth_headers
    )
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
    assert any(
        t.get("event_type") == "note" and "test note" in (t.get("body") or "") for t in timeline
    )


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

    r4 = client.delete(
        f"/incidents/{incident_id}/alerts?asset_key=test-asset-pytest", headers=auth_headers
    )
    assert r4.status_code == 200
    assert r4.json().get("ok") is True

    r5 = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert r5.status_code == 200
    assert not any(a["asset_key"] == "test-asset-pytest" for a in r5.json()["alerts"])


def test_incident_get_includes_linked_risk(client, auth_headers):
    asset_key = f"incident-risk-{uuid.uuid4().hex[:10]}"

    asset = client.post(
        "/assets/",
        headers=auth_headers,
        json={
            "asset_key": asset_key,
            "type": "external_web",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "tags": ["public"],
        },
    )
    assert asset.status_code == 200, asset.text

    finding_payloads = [
        {
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding-high",
            "title": "High risk incident-linked finding",
            "severity": "high",
            "confidence": "high",
            "source": "smoke_test",
            "category": "web_security",
        },
        {
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding-medium",
            "title": "Medium risk incident-linked finding",
            "severity": "medium",
            "confidence": "medium",
            "source": "pytest",
            "category": "web_security",
        },
    ]
    for payload in finding_payloads:
        created = client.post("/findings/", headers=auth_headers, json=payload)
        assert created.status_code == 200, created.text

    incident = client.post(
        "/incidents",
        json={
            "title": "Incident with linked risk context",
            "severity": "high",
            "asset_keys": [asset_key],
        },
        headers=auth_headers,
    )
    assert incident.status_code == 201, incident.text
    incident_id = incident.json()["id"]

    loaded = client.get(f"/incidents/{incident_id}", headers=auth_headers)
    assert loaded.status_code == 200, loaded.text
    one = loaded.json()
    linked_risk = one.get("linked_risk")
    assert linked_risk is not None
    assert linked_risk["asset_count"] == 1
    assert linked_risk["finding_count"] >= 2
    assert linked_risk["active_finding_count"] >= 2
    assert len(linked_risk["items"]) >= 2
    assert linked_risk["items"][0]["risk_score"] >= linked_risk["items"][1]["risk_score"]
    assert linked_risk["top_risk_score"] == linked_risk["items"][0]["risk_score"]
    assert linked_risk["top_risk_level"] == linked_risk["items"][0]["risk_level"]


def test_incidents_get_404(client, auth_headers):
    r = client.get("/incidents/999999", headers=auth_headers)
    assert r.status_code == 404


def test_incidents_unauthorized(client):
    r = client.get("/incidents")
    assert r.status_code == 401  # No auth header
