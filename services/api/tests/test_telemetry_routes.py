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
from datetime import UTC, datetime, timedelta
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


def test_alert_enrichment_related_events_and_clusters(client, admin_headers):
    asset_key = f"alert-m3-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "http://172.20.0.66")
    now = datetime.now(UTC)
    event_one_ts = (now - timedelta(minutes=3)).isoformat().replace("+00:00", "Z")
    event_two_ts = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")

    ingest_response = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "suricata",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": event_one_ts,
                    "event_type": "alert",
                    "src_ip": "203.0.113.77",
                    "src_port": 44321,
                    "dest_ip": "172.20.0.66",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2040001,
                        "signature": "ET TEST M3 suspicious connection",
                        "severity": 2,
                    },
                },
                {
                    "timestamp": event_two_ts,
                    "event_type": "alert",
                    "src_ip": "203.0.113.77",
                    "src_port": 44322,
                    "dest_ip": "172.20.0.66",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2040001,
                        "signature": "ET TEST M3 suspicious connection",
                        "severity": 2,
                    },
                },
            ],
            "create_alerts": True,
        },
    )
    assert ingest_response.status_code == 200, ingest_response.text
    assert ingest_response.json()["processed_events"] >= 2

    alerts_response = client.get("/alerts", headers=admin_headers)
    assert alerts_response.status_code == 200, alerts_response.text
    firing = alerts_response.json().get("firing") or []
    candidate = next(
        (
            item
            for item in firing
            if str(item.get("asset_key") or "") == asset_key and int(item.get("alert_id") or 0) > 0
        ),
        None,
    )
    assert candidate is not None
    alert_id = int(candidate["alert_id"])
    assert candidate.get("effective_severity")

    enrichment_response = client.get(
        f"/alerts/{alert_id}/enrichment?lookback_hours=24&related_limit=25",
        headers=admin_headers,
    )
    assert enrichment_response.status_code == 200, enrichment_response.text
    enrichment = enrichment_response.json()
    assert enrichment["alert_id"] == alert_id
    assert enrichment.get("asset_context", {}).get("asset_name")
    assert enrichment.get("severity_analysis", {}).get("effective_severity")
    assert isinstance(enrichment.get("recommended_next_steps"), list)
    assert isinstance(enrichment.get("dedupe_group"), list)
    assert enrichment.get("effective_severity")

    related_events_response = client.get(
        f"/alerts/{alert_id}/related-events?lookback_hours=24&limit=20",
        headers=admin_headers,
    )
    assert related_events_response.status_code == 200, related_events_response.text
    related = related_events_response.json()
    assert related["alert_id"] == alert_id
    assert len(related.get("items") or []) >= 1

    asset_cluster_response = client.get(
        "/alerts/clusters?by=asset&status=firing&limit=50",
        headers=admin_headers,
    )
    assert asset_cluster_response.status_code == 200, asset_cluster_response.text
    asset_clusters = asset_cluster_response.json().get("items") or []
    assert any(asset_key in (item.get("asset_keys") or []) for item in asset_clusters)

    source_cluster_response = client.get(
        "/alerts/clusters?by=source_ip&status=firing&limit=50",
        headers=admin_headers,
    )
    assert source_cluster_response.status_code == 200, source_cluster_response.text
    source_clusters = source_cluster_response.json().get("items") or []
    assert any(
        item.get("cluster_key") == "203.0.113.77"
        or "203.0.113.77" in (item.get("source_ips") or [])
        for item in source_clusters
    )


def test_telemetry_lineage_filters_and_summary_metrics(client, admin_headers):
    asset_key = f"telemetry-lineage-{uuid.uuid4().hex[:8]}"
    collector = f"pytest.collector.{uuid.uuid4().hex[:6]}"
    raw_path = f"/tmp/{collector}.jsonl"
    _create_asset(client, admin_headers, asset_key, "http://172.20.0.55")

    ingest_response = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "zeek",
            "asset_key": asset_key,
            "collector": collector,
            "raw_path": raw_path,
            "events": [
                {
                    "ts": "2026-03-05T09:10:12Z",
                    "event_type": "dns",
                    "uid": f"pytest-lineage-{uuid.uuid4().hex[:10]}",
                    "id.orig_h": "172.20.0.55",
                    "id.resp_h": "8.8.4.4",
                    "id.orig_p": 51001,
                    "id.resp_p": 53,
                    "query": "lineage.example.test",
                    "proto": "udp",
                }
            ],
            "create_alerts": False,
        },
    )
    assert ingest_response.status_code == 200, ingest_response.text
    ingest_body = ingest_response.json()
    assert ingest_body["collector"] == collector
    assert ingest_body["raw_path"] == raw_path
    assert ingest_body["processed_events"] >= 1
    assert ingest_body["traceable_events"] >= 1
    assert ingest_body["traceability_coverage_pct"] > 0
    assert ingest_body["ingest_lag_seconds_avg"] is not None
    assert ingest_body["ingest_lag_seconds_p95"] is not None
    assert ingest_body["ingest_lag_seconds_max"] is not None

    events_response = client.get(
        f"/telemetry/events?collector={collector}&raw_path={raw_path}&limit=25",
        headers=admin_headers,
    )
    assert events_response.status_code == 200, events_response.text
    events = events_response.json().get("items") or []
    assert any(str(item.get("asset_key") or "") == asset_key for item in events)
    matched = next(
        item
        for item in events
        if str(item.get("asset_key") or "") == asset_key and str(item.get("collector") or "") == collector
    )
    assert matched.get("raw_path") == raw_path
    assert int(matched.get("raw_offset") or 0) >= 1
    assert matched.get("ingest_lag_seconds") is not None

    summary_response = client.get("/telemetry/summary", headers=admin_headers)
    assert summary_response.status_code == 200, summary_response.text
    summary = summary_response.json()
    assert summary["totals"]["traceable_events"] >= 1
    assert summary["totals"]["traceability_coverage_pct"] > 0
    assert summary["totals"]["ingest_lag_seconds_avg"] is not None
    assert summary["totals"]["ingest_lag_seconds_p95"] is not None
    assert summary["totals"]["ingest_lag_seconds_max"] is not None
    assert any(
        item.get("source") == "zeek"
        and int(item.get("traceable_events") or 0) >= 1
        and item.get("ingest_lag_seconds_avg") is not None
        for item in summary.get("sources") or []
    )


def test_detection_rule_v2_yaml_and_version_fields(client, admin_headers):
    asset_key = f"det-v2-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "http://172.20.0.91")
    ingest_response = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "zeek",
            "asset_key": asset_key,
            "events": [
                {
                    "ts": "2026-03-05T11:10:12Z",
                    "event_type": "dns",
                    "uid": f"pytest-detv2-{uuid.uuid4().hex[:10]}",
                    "id.orig_h": "172.20.0.91",
                    "id.resp_h": "8.8.8.8",
                    "query": "detv2.example.test",
                    "proto": "udp",
                }
            ],
            "create_alerts": False,
        },
    )
    assert ingest_response.status_code == 200, ingest_response.text

    create_rule = client.post(
        "/detections/rules",
        headers=admin_headers,
        json={
            "name": f"pytest-yaml-rule-{uuid.uuid4().hex[:8]}",
            "description": "YAML detection rule creation",
            "source": "zeek",
            "rule_key": f"pytest.yaml.{uuid.uuid4().hex[:6]}",
            "version": 2,
            "stage": "canary",
            "rule_format": "yaml",
            "mitre_tactic": "TA0011",
            "mitre_technique": "T1071.004",
            "severity": "high",
            "enabled": True,
            "definition_yaml": (
                "condition_mode: all\n"
                "conditions:\n"
                "  - field: event_type\n"
                "    op: eq\n"
                "    value: dns\n"
                "  - field: source\n"
                "    op: eq\n"
                "    value: zeek\n"
            ),
        },
    )
    assert create_rule.status_code == 200, create_rule.text
    rule = create_rule.json()
    assert rule["rule_format"] == "yaml"
    assert rule["version"] == 2
    assert rule["stage"] == "canary"
    assert rule["mitre_tactic"] == "TA0011"
    assert rule["mitre_technique"] == "T1071.004"
    assert rule["definition_json"]["condition_mode"] == "all"
    assert len(rule["definition_json"]["conditions"]) == 2

    rule_id = int(rule["rule_id"])
    update_rule = client.patch(
        f"/detections/rules/{rule_id}",
        headers=admin_headers,
        json={"version": 3, "stage": "active"},
    )
    assert update_rule.status_code == 200, update_rule.text
    updated = update_rule.json()
    assert updated["version"] == 3
    assert updated["stage"] == "active"
    assert updated["rule_format"] == "yaml"

    test_rule = client.post(
        f"/detections/rules/{rule_id}/test",
        headers=admin_headers,
        json={"lookback_hours": 48, "create_alerts": False},
    )
    assert test_rule.status_code == 200, test_rule.text
    rule_test_body = test_rule.json()
    assert rule_test_body["rule_id"] == rule_id
    assert rule_test_body["matches"] >= 1


def test_detection_rule_simulate_and_scheduled_execution(client, admin_headers):
    asset_key = f"det-sim-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "http://172.20.0.92")
    ingest_response = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "suricata",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": "2026-03-05T13:20:12.120000Z",
                    "event_type": "alert",
                    "src_ip": "203.0.113.88",
                    "src_port": 51515,
                    "dest_ip": "172.20.0.92",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2024999,
                        "signature": "ET TEST Suspicious outbound connection",
                        "severity": 2,
                    },
                }
            ],
            "create_alerts": False,
        },
    )
    assert ingest_response.status_code == 200, ingest_response.text

    create_rule = client.post(
        "/detections/rules",
        headers=admin_headers,
        json={
            "name": f"pytest-sim-rule-{uuid.uuid4().hex[:8]}",
            "description": "Rule used for simulator and scheduled runs",
            "source": "suricata",
            "rule_key": f"pytest.sim.{uuid.uuid4().hex[:6]}",
            "version": 1,
            "stage": "active",
            "rule_format": "json",
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

    simulate_response = client.post(
        f"/detections/rules/{rule_id}/simulate",
        headers=admin_headers,
        json={"lookback_hours": 72},
    )
    assert simulate_response.status_code == 200, simulate_response.text
    simulated = simulate_response.json()
    assert simulated["rule_id"] == rule_id
    assert simulated["run_mode"] == "simulate"
    assert simulated["create_alerts"] is False
    assert simulated["matches"] >= 1
    assert simulated["generated_alert"] is None
    assert simulated.get("snapshot_hash")

    runs_response = client.get(f"/detections/runs?rule_id={rule_id}&limit=5", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    runs = runs_response.json().get("items") or []
    assert any(
        int(item.get("rule_id") or 0) == rule_id
        and str(item.get("run_mode") or "") == "simulate"
        and str(item.get("trigger_source") or "") == "manual"
        and str(item.get("snapshot_hash") or "")
        and isinstance(item.get("snapshot_json"), dict)
        for item in runs
    )

    schedule_job = client.post(
        "/jobs",
        headers=admin_headers,
        json={
            "job_type": "detection_rule_schedule",
            "job_params_json": {
                "rule_id": rule_id,
                "lookback_hours": 72,
                "schedule_ref": "pytest-hourly",
            },
        },
    )
    assert schedule_job.status_code == 200, schedule_job.text
    job_id = int(schedule_job.json()["job_id"])

    execute_job = client.post(f"/jobs/{job_id}/execute", headers=admin_headers)
    assert execute_job.status_code == 200, execute_job.text
    execute_body = execute_job.json()
    assert execute_body["job_type"] == "detection_rule_schedule"
    assert execute_body["status"] == "done"

    runs_response = client.get(f"/detections/runs?rule_id={rule_id}&limit=10", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    runs = runs_response.json().get("items") or []
    assert any(
        int(item.get("rule_id") or 0) == rule_id
        and str(item.get("run_mode") or "") == "scheduled"
        and str(item.get("trigger_source") or "") == "scheduler"
        and str(item.get("schedule_ref") or "") == "pytest-hourly"
        and str(item.get("snapshot_hash") or "")
        for item in runs
    )


def test_correlation_rule_run_and_mitre_coverage(client, admin_headers):
    asset_key = f"corr-asset-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "http://172.20.0.93")
    now = datetime.now(UTC)
    suricata_ts = (now - timedelta(seconds=45)).isoformat().replace("+00:00", "Z")
    authlog_ts = (now - timedelta(seconds=15)).isoformat().replace("+00:00", "Z")

    suricata_ingest = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "suricata",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": suricata_ts,
                    "event_type": "alert",
                    "src_ip": "203.0.113.90",
                    "src_port": 41111,
                    "dest_ip": "172.20.0.93",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 210001,
                        "signature": "ET TEST Correlation precursor network alert",
                        "severity": 2,
                    },
                }
            ],
            "create_alerts": True,
        },
    )
    assert suricata_ingest.status_code == 200, suricata_ingest.text

    authlog_ingest = client.post(
        "/telemetry/ingest",
        headers=admin_headers,
        json={
            "source": "authlog",
            "asset_key": asset_key,
            "events": [
                {
                    "timestamp": authlog_ts,
                    "event_type": "ssh_auth_failed",
                    "title": "SSH authentication failed",
                    "description": "Failed password for root",
                    "severity": "high",
                    "protocol": "ssh",
                    "src_ip": "203.0.113.90",
                    "host": "secplat-lab",
                    "process": "sshd",
                }
            ],
            "create_alerts": True,
        },
    )
    assert authlog_ingest.status_code == 200, authlog_ingest.text

    create_corr_rule = client.post(
        "/detections/correlations/rules",
        headers=admin_headers,
        json={
            "name": f"pytest-correlation-{uuid.uuid4().hex[:8]}",
            "description": "Correlate suricata + authlog alerts on same asset",
            "severity": "high",
            "enabled": True,
            "group_by": "asset_key",
            "window_minutes": 180,
            "min_distinct_sources": 2,
            "mitre_tactic": "TA0008",
            "mitre_technique": "T1021",
            "definition_json": {
                "steps": [
                    {"source": "suricata", "min_count": 1},
                    {"source": "authlog", "min_count": 1},
                ]
            },
        },
    )
    assert create_corr_rule.status_code == 200, create_corr_rule.text
    corr_rule = create_corr_rule.json()
    corr_rule_id = int(corr_rule["correlation_rule_id"])

    run_corr = client.post(
        f"/detections/correlations/rules/{corr_rule_id}/run",
        headers=admin_headers,
        json={"lookback_minutes": 240, "create_alerts": True},
    )
    assert run_corr.status_code == 200, run_corr.text
    run_body = run_corr.json()
    assert run_body["correlation_rule_id"] == corr_rule_id
    assert run_body["matched_chains"] >= 1
    assert run_body["alerts_created"] >= 1
    assert run_body.get("snapshot_hash")

    list_corr_runs = client.get(
        f"/detections/correlations/runs?correlation_rule_id={corr_rule_id}&limit=20",
        headers=admin_headers,
    )
    assert list_corr_runs.status_code == 200, list_corr_runs.text
    runs = list_corr_runs.json().get("items") or []
    assert any(
        int(item.get("correlation_rule_id") or 0) == corr_rule_id
        and int(item.get("matched_chains") or 0) >= 1
        and int(item.get("alerts_created") or 0) >= 1
        and str(item.get("snapshot_hash") or "")
        for item in runs
    )

    coverage = client.get("/detections/coverage/mitre?lookback_days=180", headers=admin_headers)
    assert coverage.status_code == 200, coverage.text
    coverage_body = coverage.json()
    assert coverage_body["totals"]["enabled_rules"] >= 1
    assert coverage_body["totals"]["covered_tactics"] >= 1
    assert any(item.get("mitre_tactic") == "TA0008" for item in coverage_body.get("tactics") or [])

    create_corr_job = client.post(
        "/jobs",
        headers=admin_headers,
        json={
            "job_type": "correlation_pass",
            "job_params_json": {
                "lookback_minutes": 240,
                "correlation_rule_id": corr_rule_id,
            },
        },
    )
    assert create_corr_job.status_code == 200, create_corr_job.text
    corr_job_id = int(create_corr_job.json()["job_id"])

    execute_corr_job = client.post(f"/jobs/{corr_job_id}/execute", headers=admin_headers)
    assert execute_corr_job.status_code == 200, execute_corr_job.text
    execute_body = execute_corr_job.json()
    assert execute_body["job_type"] == "correlation_pass"
    assert execute_body["status"] in {"done", "failed"}


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
    monkeypatch.setattr(
        jobs_router,
        "launch_detection_rule_scheduled_job",
        lambda job_id: launched.append(("detection_rule_schedule", int(job_id))),
    )
    monkeypatch.setattr(
        jobs_router,
        "launch_correlation_pass_job",
        lambda job_id: launched.append(("correlation_pass", int(job_id))),
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
        {
            "job_type": "detection_rule_schedule",
            "job_params_json": {
                "rule_id": rule_id,
                "lookback_hours": 24,
                "schedule_ref": "pytest-hourly",
            },
        },
        {
            "job_type": "correlation_pass",
            "job_params_json": {"lookback_minutes": 120},
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
    assert "detection_rule_schedule" in launched_types
    assert "correlation_pass" in launched_types


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

    admin_cowrie = client.get(
        f"/telemetry/events?source=cowrie&asset_key={asset_key}&limit=25",
        headers=admin_headers,
    )
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
