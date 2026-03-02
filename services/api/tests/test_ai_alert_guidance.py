"""
AI alert response guidance tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_alert_guidance.py -q
"""

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

from app.ai_client import AIClientError
from app.db import engine
from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import ai as ai_router
from app.routers import alerts as alerts_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; AI alert guidance tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    run_startup_migrations()


@pytest.fixture(scope="module")
def auth_headers(client):
    response = client.post(
        "/auth/login",
        data={
            "username": os.getenv("ADMIN_USERNAME", "admin"),
            "password": os.getenv("ADMIN_PASSWORD", "admin"),
        },
    )
    if response.status_code != 200:
        pytest.skip(f"Login failed: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


def _create_asset(client: TestClient, headers: dict, asset_key: str) -> dict:
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
            "tags": ["pytest", "public"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_finding(
    client: TestClient, headers: dict, asset_key: str, suffix: str, severity: str
) -> None:
    response = client.post(
        "/findings/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding-{suffix}",
            "title": f"Finding {suffix}",
            "severity": severity,
            "confidence": "high",
            "source": "pytest",
            "category": "web_security",
            "evidence": f"evidence for {suffix}",
        },
    )
    assert response.status_code == 200, response.text


def _insert_maintenance_window(asset_key: str) -> None:
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO maintenance_windows (asset_key, start_at, end_at, reason, created_by)
                VALUES (:asset_key, :start_at, :end_at, :reason, :created_by)
                """
            ),
            {
                "asset_key": asset_key,
                "start_at": now - timedelta(minutes=15),
                "end_at": now + timedelta(minutes=45),
                "reason": "pytest maintenance",
                "created_by": "pytest",
            },
        )


def _insert_open_incident(asset_key: str, *, severity: str = "high") -> int:
    with engine.begin() as conn:
        incident_row = (
            conn.execute(
                text(
                    """
                    INSERT INTO incidents (title, severity, status, assigned_to, metadata)
                    VALUES (:title, :severity, 'new', 'pytest-analyst', '{}'::jsonb)
                    RETURNING id
                    """
                ),
                {"title": f"Alert incident for {asset_key}", "severity": severity},
            )
            .mappings()
            .first()
        )
        assert incident_row is not None
        incident_id = int(incident_row["id"])
        conn.execute(
            text(
                """
                INSERT INTO incident_alerts (incident_id, asset_key, added_by)
                VALUES (:incident_id, :asset_key, 'pytest')
                """
            ),
            {"incident_id": incident_id, "asset_key": asset_key},
        )
    return incident_id


def _insert_asset_suppression_rule(asset_key: str) -> None:
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO suppression_rules (scope, scope_value, starts_at, ends_at, reason, created_by)
                VALUES ('asset', :asset_key, :starts_at, :ends_at, :reason, 'pytest')
                """
            ),
            {
                "asset_key": asset_key,
                "starts_at": now - timedelta(minutes=5),
                "ends_at": now + timedelta(hours=2),
                "reason": "pytest suppression",
            },
        )


def _patch_red_posture(monkeypatch: pytest.MonkeyPatch, asset_key: str, *, score: int = 28) -> None:
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
                    "posture_score": score,
                    "last_seen": "2026-03-02T20:00:00Z",
                    "staleness_seconds": 360,
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
                "@timestamp": "2026-03-02T20:00:00Z",
                "status": "timeout",
                "code": 504,
                "latency_ms": 1200,
            },
            {
                "@timestamp": "2026-03-02T19:58:00Z",
                "status": "down",
                "code": 503,
                "latency_ms": 760,
            },
            {
                "@timestamp": "2026-03-02T19:56:00Z",
                "status": "up",
                "code": 200,
                "latency_ms": 140,
            },
        ],
    )


def test_alerts_list_includes_enrichment_and_suppression_context(client, auth_headers, monkeypatch):
    asset_key = f"alert-enrich-{uuid.uuid4().hex[:8]}"
    _create_asset(client, auth_headers, asset_key)
    _create_finding(client, auth_headers, asset_key, "1", "critical")
    _insert_maintenance_window(asset_key)
    _patch_red_posture(monkeypatch, asset_key, score=19)

    response = client.get("/alerts", headers=auth_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    suppressed_item = next(
        (item for item in body["suppressed"] if item["asset_key"] == asset_key),
        None,
    )
    assert suppressed_item is not None
    assert suppressed_item["asset_name"] == f"{asset_key}.example.test"
    assert suppressed_item["criticality"] == "high"
    assert suppressed_item["posture_status"] == "red"
    assert suppressed_item["maintenance_active"] is True
    assert suppressed_item["maintenance_reason"] == "pytest maintenance"
    assert suppressed_item["active_finding_count"] >= 1
    assert suppressed_item["top_risk_score"] is not None


def test_alert_ai_guidance_generate_get_cache_and_parse_labels(client, auth_headers, monkeypatch):
    asset_key = f"alert-ai-{uuid.uuid4().hex[:8]}"
    _create_asset(client, auth_headers, asset_key)
    _create_finding(client, auth_headers, asset_key, "1", "critical")
    _patch_red_posture(monkeypatch, asset_key, score=24)
    _patch_alert_events(monkeypatch)

    monkeypatch.setattr(
        ai_router,
        "generate_text",
        lambda **_kwargs: (
            "Recommended action: escalate\n"
            "Urgency: high\n"
            "Why:\n"
            "- The asset is currently down in production.\n"
            "- A critical finding is still active on the asset.\n"
            "Next steps:\n"
            "- Create or update an incident owner.\n"
            "- Review the latest failed health checks.\n"
            "Escalate if:\n"
            "- Additional production assets show the same failure pattern.\n"
            "- Customer traffic is impacted.\n"
        ),
    )

    generated = client.post(
        f"/ai/alerts/{asset_key}/guidance/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["asset_key"] == asset_key
    assert body["cached"] is False
    assert body["recommended_action"] == "escalate"
    assert body["urgency"] == "high"
    assert body["context_json"]["generated_from"]["asset"]["posture_status"] == "red"
    assert body["context_json"]["generated_from"]["finding_summary"]["active_finding_count"] >= 1

    loaded = client.get(f"/ai/alerts/{asset_key}/guidance", headers=auth_headers)
    assert loaded.status_code == 200, loaded.text
    loaded_body = loaded.json()
    assert loaded_body["guidance_text"] == body["guidance_text"]
    assert loaded_body["stale"] is False

    second = client.post(
        f"/ai/alerts/{asset_key}/guidance/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["cached"] is True
    assert second_body["recommended_action"] == "escalate"


def test_alert_ai_guidance_retries_and_regenerates_when_context_changes(
    client, auth_headers, monkeypatch
):
    asset_key = f"alert-ai-retry-{uuid.uuid4().hex[:8]}"
    _create_asset(client, auth_headers, asset_key)
    _create_finding(client, auth_headers, asset_key, "1", "high")
    _patch_red_posture(monkeypatch, asset_key, score=31)
    _patch_alert_events(monkeypatch)
    _insert_open_incident(asset_key)

    calls = {"count": 0}

    def fake_generate_text(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise AIClientError("request timed out")
        if calls["count"] == 2:
            return (
                "Recommended action: assign\n"
                "Urgency: high\n"
                "Why:\n"
                "- There is already an open incident linked to this asset.\n"
                "- The alert should be owned and worked through that incident.\n"
                "Next steps:\n"
                "- Assign the alert to the active responder.\n"
                "- Track current outage evidence in the incident timeline.\n"
                "Escalate if:\n"
                "- The linked incident scope expands.\n"
                "- Containment is not progressing.\n"
            )
        return (
            "Recommended action: suppress\n"
            "Urgency: medium\n"
            "Why:\n"
            "- The asset is under an active planned suppression rule.\n"
            "- The alert should stay visible but not page responders repeatedly.\n"
            "Next steps:\n"
            "- Keep the suppression window bounded.\n"
            "- Recheck posture when the window ends.\n"
            "Escalate if:\n"
            "- The issue persists after suppression expires.\n"
            "- Additional unsuppressed assets fail.\n"
        )

    monkeypatch.setattr(ai_router, "generate_text", fake_generate_text)

    first = client.post(
        f"/ai/alerts/{asset_key}/guidance/generate",
        json={"force": True},
        headers=auth_headers,
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert calls["count"] == 2
    assert first_body["recommended_action"] == "assign"
    assert first_body["urgency"] == "high"
    assert first_body["provider"] == "ollama"
    assert first_body["model"] != "template-v1"

    _insert_asset_suppression_rule(asset_key)

    stale = client.get(f"/ai/alerts/{asset_key}/guidance", headers=auth_headers)
    assert stale.status_code == 200, stale.text
    assert stale.json()["stale"] is True

    refreshed = client.post(
        f"/ai/alerts/{asset_key}/guidance/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert refreshed.status_code == 200, refreshed.text
    refreshed_body = refreshed.json()
    assert refreshed_body["cached"] is False
    assert refreshed_body["recommended_action"] == "suppress"
    assert refreshed_body["urgency"] == "medium"
    assert calls["count"] == 3
