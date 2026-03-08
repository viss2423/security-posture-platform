"""
Alert AI guidance guardrail tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_alert_guidance_guardrails.py -q
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import ai as ai_router
from app.routers import alerts as alerts_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; alert guidance guardrail tests require Postgres",
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


def _create_asset(client: TestClient, headers: dict, asset_key: str) -> None:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "external_web",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "owner": "soc-team",
            "tags": ["pytest", "guardrail"],
        },
    )
    assert response.status_code == 200, response.text


def _create_finding(client: TestClient, headers: dict, asset_key: str) -> None:
    response = client.post(
        "/findings/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding-1",
            "title": "Guardrail alert finding",
            "severity": "critical",
            "confidence": "high",
            "source": "pytest",
            "category": "web_security",
            "evidence": "Critical finding evidence for alert guardrail testing.",
        },
    )
    assert response.status_code == 200, response.text


def _patch_red_posture(monkeypatch: pytest.MonkeyPatch, asset_key: str) -> None:
    monkeypatch.setattr(
        alerts_router,
        "_fetch_posture_list_raw",
        lambda: (
            1,
            [
                {
                    "asset_key": asset_key,
                    "status": "timeout",
                    "posture_state": "red",
                    "posture_score": 18,
                    "last_seen": "2026-03-03T10:00:00Z",
                    "staleness_seconds": 420,
                }
            ],
        ),
    )


def _patch_alert_events(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ai_router,
        "_events_for_asset",
        lambda *_args, **_kwargs: [
            {
                "@timestamp": "2026-03-03T10:00:00Z",
                "status": "timeout",
                "code": 504,
                "latency_ms": 1200,
            },
            {
                "@timestamp": "2026-03-03T09:58:00Z",
                "status": "down",
                "code": 503,
                "latency_ms": 890,
            },
        ],
    )


def test_alert_guidance_guardrails_drop_unknown_evidence(
    client: TestClient,
    admin_headers: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    asset_key = f"alert-guardrail-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key)
    _create_finding(client, admin_headers, asset_key)
    _patch_red_posture(monkeypatch, asset_key)
    _patch_alert_events(monkeypatch)

    monkeypatch.setattr(
        ai_router,
        "generate_text",
        lambda **_kwargs: json.dumps(
            {
                "recommended_action": "assign",
                "urgency": "high",
                "facts": [{"statement": "Alert is active and posture is red.", "evidence": ["E1"]}],
                "inference": [
                    {"statement": "Unsupported claim should be removed.", "evidence": ["E999"]}
                ],
                "recommendations": [
                    {"statement": "Assign the responder and track timeline events.", "evidence": ["E2"]}
                ],
            }
        ),
    )

    generated = client.post(
        f"/ai/alerts/{asset_key}/guidance/generate",
        headers=admin_headers,
        json={"force": True},
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["recommended_action"] == "assign"
    assert body["urgency"] == "high"

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "alert_grounded_v1"
    sections = guardrails.get("sections") or {}
    inference_items = sections.get("inference") or []
    assert all(
        "E999" not in [str(e).strip().upper() for e in (item.get("evidence") or [])]
        for item in inference_items
    )


def test_alert_guidance_guardrails_fallback_on_invalid_output(
    client: TestClient,
    admin_headers: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    asset_key = f"alert-guardrail-fallback-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key)
    _create_finding(client, admin_headers, asset_key)
    _patch_red_posture(monkeypatch, asset_key)
    _patch_alert_events(monkeypatch)

    monkeypatch.setattr(ai_router, "generate_text", lambda **_kwargs: "not-json-response")

    generated = client.post(
        f"/ai/alerts/{asset_key}/guidance/generate",
        headers=admin_headers,
        json={"force": True},
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body.get("provider", "").endswith("-guarded")
    assert body.get("recommended_action") in {"ack", "suppress", "assign", "escalate", "resolve", "monitor"}
    assert body.get("urgency") in {"critical", "high", "medium", "low"}

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "alert_grounded_v1"
    assert guardrails.get("parse_mode") == "fallback"
    assert guardrails.get("used_fallback_sections") is True

