"""
Attack-graph API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_attack_graph_routes.py -q
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
    reason="POSTGRES_DSN not set; attack-graph tests require Postgres",
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


def test_attack_graph_incident_and_query(client: TestClient, admin_headers: dict):
    asset_key = f"graph-asset-{uuid.uuid4().hex[:8]}"
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
            "address": "http://172.20.0.188",
            "port": 443,
            "tags": ["pytest", "attack-graph"],
        },
    )
    assert created_asset.status_code == 200, created_asset.text

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
                    "src_ip": "203.0.113.210",
                    "src_port": 41321,
                    "dest_ip": "172.20.0.188",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2088001,
                        "signature": "ET TEST Attack graph signal",
                        "severity": 1,
                    },
                    "domain": "c2.example.test",
                    "user": "svc-nginx",
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
            "title": f"Attack graph incident {asset_key}",
            "severity": "high",
            "asset_keys": [asset_key],
        },
    )
    assert created_incident.status_code == 201, created_incident.text
    incident_id = int(created_incident.json()["id"])

    incident_graph = client.get(
        f"/attack-graph/incidents/{incident_id}?lookback_hours=48",
        headers=admin_headers,
    )
    assert incident_graph.status_code == 200, incident_graph.text
    incident_body = incident_graph.json()
    node_ids = {str(item.get("id") or "") for item in incident_body.get("nodes") or []}
    assert f"incident:{incident_id}" in node_ids
    assert f"asset:{asset_key}" in node_ids
    assert int(incident_body.get("summary", {}).get("node_count") or 0) >= 2
    assert int(incident_body.get("summary", {}).get("edge_count") or 0) >= 1

    query_graph = client.post(
        "/attack-graph/query",
        headers=admin_headers,
        json={"asset_key": asset_key, "lookback_hours": 48},
    )
    assert query_graph.status_code == 200, query_graph.text
    query_body = query_graph.json()
    query_node_ids = {str(item.get("id") or "") for item in query_body.get("nodes") or []}
    assert f"asset:{asset_key}" in query_node_ids
    assert int(query_body.get("summary", {}).get("node_count") or 0) >= 1

