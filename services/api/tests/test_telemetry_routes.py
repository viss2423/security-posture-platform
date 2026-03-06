"""
Telemetry and new roadmap route tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_telemetry_routes.py -q
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.db import engine
from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import jobs as jobs_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; telemetry route tests require Postgres",
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


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer")


def _create_asset(client: TestClient, headers: dict, asset_key: str, address: str) -> dict:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key}.example.test",
            "environment": "dev",
            "criticality": "high",
            "owner": "platform-security",
            "address": address,
            "tags": ["pytest", "telemetry"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_telemetry_ingest_summary_and_rule_test(client, admin_headers):
    asset_key = f"telemetry-asset-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "http://172.20.0.15")

    ingest_response = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "suricata",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": "2026-03-05T09:00:01.120000Z",
                    "event_type": "alert",
                    "src_ip": "203.0.113.10",
                    "src_port": 51515,
                    "dest_ip": "172.20.0.15",
                    "dest_port": 80,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2024210,
                        "signature": "ET WEB_SERVER Possible SQL Injection Attempt",
                        "severity": 2,
                    },
                }
            ],
            "create_alerts": True,
        },
    )
    assert ingest_response.status_code == 200, ingest_response.text
    ingest_body = ingest_response.json()
    assert ingest_body["ok"] is True
    assert ingest_body["processed_events"] >= 1

    summary_response = client.get("/telemetry/summary", headers=admin_headers)
    assert summary_response.status_code == 200, summary_response.text
    summary_body = summary_response.json()
    assert summary_body["totals"]["events"] >= 1
    assert any(item["source"] == "suricata" for item in summary_body["sources"])

    alerts_response = client.get("/alerts", headers=admin_headers)
    assert alerts_response.status_code == 200, alerts_response.text
    alerts_body = alerts_response.json()
    assert any(
        (item.get("source") == "suricata") and (item.get("alert_id") is not None)
        for item in alerts_body["firing"]
    )

    create_rule = client.post(
        "/detections/rules",
        headers=admin_headers,
        json={
            "name": f"pytest-suricata-rule-{uuid.uuid4().hex[:8]}",
            "description": "Rule used by telemetry route test",
            "source": "suricata",
            "severity": "high",
            "enabled": True,
            "definition_json": {
                "condition_mode": "all",
                "conditions": [
                    {"field": "event_type", "op": "eq", "value": "alert"},
                    {"field": "source", "op": "eq", "value": "suricata"},
                ],
            },
        },
    )
    assert create_rule.status_code == 200, create_rule.text
    rule_id = int(create_rule.json()["rule_id"])

    test_rule = client.post(
        f"/detections/rules/{rule_id}/test",
        headers=admin_headers,
        json={"lookback_hours": 48, "create_alerts": True},
    )
    assert test_rule.status_code == 200, test_rule.text
    rule_test_body = test_rule.json()
    assert rule_test_body["rule_id"] == rule_id
    assert rule_test_body["matches"] >= 1


def test_new_job_types_launchers(client, admin_headers, monkeypatch):
    launched: list[tuple[str, int]] = []

    monkeypatch.setattr(
        jobs_router,
        "launch_telemetry_import_job",
        lambda job_id: launched.append(("telemetry_import", int(job_id))),
    )
    monkeypatch.setattr(
        jobs_router,
        "launch_network_anomaly_job",
        lambda job_id: launched.append(("network_anomaly_score", int(job_id))),
    )
    monkeypatch.setattr(
        jobs_router,
        "launch_attack_lab_job",
        lambda job_id: launched.append(("attack_lab_run", int(job_id))),
    )
    monkeypatch.setattr(
        jobs_router,
        "launch_detection_rule_job",
        lambda job_id: launched.append(("detection_rule_test", int(job_id))),
    )

    rule_name = f"pytest-job-rule-{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        rule_id = (
            conn.execute(
                text(
                    """
                    INSERT INTO detection_rules(
                      name, description, source, severity, enabled, definition_json, created_by
                    )
                    VALUES (
                      :name, 'pytest detection rule', 'suricata', 'high', TRUE,
                      CAST(:definition_json AS jsonb), 'pytest'
                    )
                    RETURNING rule_id
                    """
                ),
                {
                    "name": rule_name,
                    "definition_json": json.dumps(
                        {
                            "condition_mode": "all",
                            "conditions": [
                                {"field": "source", "op": "eq", "value": "suricata"},
                            ],
                        }
                    ),
                },
            )
            .mappings()
            .first()
        )
        assert rule_id is not None
        rule_id = int(rule_id["rule_id"])

    payloads = [
        {
            "job_type": "telemetry_import",
            "job_params_json": {
                "source": "suricata",
                "file_path": "/workspace/lab-data/suricata/eve.json",
            },
        },
        {
            "job_type": "network_anomaly_score",
            "job_params_json": {"lookback_hours": 24, "threshold": 2.5},
        },
        {
            "job_type": "attack_lab_run",
            "job_params_json": {
                "task_type": "port_scan",
                "target": "verify-web",
                "asset_key": "verify-web",
            },
        },
        {
            "job_type": "detection_rule_test",
            "job_params_json": {"rule_id": rule_id, "lookback_hours": 24},
        },
    ]
    for payload in payloads:
        response = client.post("/jobs", headers=admin_headers, json=payload)
        assert response.status_code == 200, response.text

    launched_types = [item[0] for item in launched]
    assert "telemetry_import" in launched_types
    assert "network_anomaly_score" in launched_types
    assert "attack_lab_run" in launched_types
    assert "detection_rule_test" in launched_types


def test_cowrie_events_restricted_to_admin(client, admin_headers, viewer_headers):
    asset_key = f"cowrie-asset-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "ssh://172.20.0.41:2222")

    ingest_response = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "cowrie",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": "2026-03-05T12:30:21.000000Z",
                    "eventid": "cowrie.login.failed",
                    "src_ip": "198.51.100.44",
                    "username": "root",
                    "password": "admin",
                    "message": "failed login",
                    "session": "pytest-cowrie-session",
                }
            ],
            "create_alerts": True,
        },
    )
    assert ingest_response.status_code == 200, ingest_response.text
    ingest_body = ingest_response.json()
    assert ingest_body.get("processed_events", 0) >= 1

    admin_cowrie = client.get("/telemetry/events?source=cowrie&limit=25", headers=admin_headers)
    assert admin_cowrie.status_code == 200, admin_cowrie.text
    admin_items = admin_cowrie.json().get("items") or []
    assert any(str(item.get("asset_key") or "") == asset_key for item in admin_items)

    viewer_forbidden = client.get(
        "/telemetry/events?source=cowrie&limit=25", headers=viewer_headers
    )
    assert viewer_forbidden.status_code == 403, viewer_forbidden.text

    viewer_events = client.get("/telemetry/events?limit=300", headers=viewer_headers)
    assert viewer_events.status_code == 200, viewer_events.text
    viewer_items = viewer_events.json().get("items") or []
    assert all(str(item.get("source") or "") != "cowrie" for item in viewer_items)
