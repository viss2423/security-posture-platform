"""
Unified incident timeline aggregation tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_incident_timeline_unified.py -q
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.db_migrate import run_startup_migrations
from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; timeline aggregation tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    run_startup_migrations()


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post("/auth/login", data={"username": username, "password": password})
    if response.status_code != 200:
        pytest.skip(f"Login failed for {username}: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def admin_headers(client):
    return _login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )


def test_incident_timeline_includes_unified_sources(client: TestClient, admin_headers: dict):
    asset_key = f"timeline-asset-{uuid.uuid4().hex[:8]}"
    created_asset = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "owner": "soc",
            "address": "http://172.20.0.210",
            "port": 443,
            "tags": ["pytest", "timeline"],
        },
    )
    assert created_asset.status_code == 200, created_asset.text

    created_finding = client.post(
        "/findings/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding",
            "title": "Timeline finding signal",
            "severity": "high",
            "confidence": "high",
            "source": "pytest",
            "category": "web_security",
        },
    )
    assert created_finding.status_code == 200, created_finding.text

    now = datetime.now(UTC)
    event_time = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    ingested = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "suricata",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": event_time,
                    "event_type": "alert",
                    "src_ip": "203.0.113.121",
                    "src_port": 47111,
                    "dest_ip": "172.20.0.210",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2090001,
                        "signature": "ET TEST Timeline signal",
                        "severity": 1,
                    },
                    "domain": "timeline-c2.example.test",
                    "process": "nginx",
                }
            ],
            "create_alerts": True,
        },
    )
    assert ingested.status_code == 200, ingested.text

    created_incident = client.post(
        "/incidents",
        headers=admin_headers,
        json={
            "title": f"Unified timeline incident {asset_key}",
            "severity": "high",
            "asset_keys": [asset_key],
        },
    )
    assert created_incident.status_code == 201, created_incident.text
    incident_id = int(created_incident.json()["id"])

    created_note = client.post(
        f"/incidents/{incident_id}/notes",
        headers=admin_headers,
        json={"body": "Analyst triage note for unified timeline test."},
    )
    assert created_note.status_code == 201, created_note.text

    timeline_response = client.get(f"/incidents/{incident_id}/timeline", headers=admin_headers)
    assert timeline_response.status_code == 200, timeline_response.text
    timeline = timeline_response.json().get("items") or []
    assert len(timeline) >= 4

    source_types = {str(item.get("source_type") or "") for item in timeline}
    assert "note" in source_types
    assert "alert" in source_types
    assert "finding" in source_types
    assert "log" in source_types

    sort_keys = [
        (
            str(item.get("created_at") or ""),
            str(item.get("source_type") or ""),
            str(item.get("id") or ""),
        )
        for item in timeline
    ]
    assert sort_keys == sorted(sort_keys)

    incident_response = client.get(f"/incidents/{incident_id}", headers=admin_headers)
    assert incident_response.status_code == 200, incident_response.text
    incident_timeline = incident_response.json().get("timeline") or []
    assert len(incident_timeline) >= len(timeline)
    incident_source_types = {str(item.get("source_type") or "") for item in incident_timeline}
    assert {"note", "alert", "finding", "log"}.issubset(incident_source_types)

    log_only = client.get(
        f"/incidents/{incident_id}/timeline?source_type=log&limit=50",
        headers=admin_headers,
    )
    assert log_only.status_code == 200, log_only.text
    log_items = log_only.json().get("items") or []
    assert len(log_items) >= 1
    assert all(str(item.get("source_type") or "") == "log" for item in log_items)

    alert_only = client.get(
        f"/incidents/{incident_id}/timeline?event_type=alert_activity&limit=50",
        headers=admin_headers,
    )
    assert alert_only.status_code == 200, alert_only.text
    alert_items = alert_only.json().get("items") or []
    assert len(alert_items) >= 1
    assert all(str(item.get("event_type") or "") == "alert_activity" for item in alert_items)
