from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.main import app
from app.stability import evaluate_release_gate


def test_stability_contract_endpoint_exposes_release_policy():
    c = TestClient(app)
    r = c.get("/platform/stability-contract")
    assert r.status_code == 200
    body = r.json()
    assert body["contract_version"]
    assert body["window_days"] == 28
    assert body["release_policy"]["freeze_threshold"] == 1.0
    assert len(body["service_objectives"]) == 5


def test_release_gate_passes_with_healthy_measurements():
    result = evaluate_release_gate(
        {
            "api_availability": 0.997,
            "api_p95_latency_ms": 420,
            "ingestion_visibility_seconds": 90,
            "alert_creation_seconds": 120,
            "background_job_freshness_minutes": 20,
        }
    )
    assert result["gate_passed"] is True
    assert result["action"] == "ship_allowed"
    assert result["error_budget_exhausted"] is False


def test_release_gate_fails_when_availability_error_budget_exhausted():
    result = evaluate_release_gate(
        {
            "api_availability": 0.992,
            "api_p95_latency_ms": 420,
            "ingestion_visibility_seconds": 90,
            "alert_creation_seconds": 120,
            "background_job_freshness_minutes": 20,
        }
    )
    assert result["gate_passed"] is False
    assert result["error_budget_exhausted"] is True
    assert result["action"] == "reliability_fixes_only"


def test_release_gate_endpoint_accepts_measurements():
    c = TestClient(app)
    r = c.post(
        "/platform/release-gate/evaluate",
        json={
            "measurements": {
                "api_availability": 0.997,
                "api_p95_latency_ms": 450,
                "ingestion_visibility_seconds": 110,
                "alert_creation_seconds": 150,
                "background_job_freshness_minutes": 10,
            }
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["gate_passed"] is True
    assert isinstance(body["results"], list)
    assert json.dumps(body)  # ensure payload is JSON-serializable
