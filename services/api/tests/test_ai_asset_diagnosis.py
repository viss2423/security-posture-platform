"""
AI asset diagnosis tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_asset_diagnosis.py -q
"""

import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.ai_client import AIClientError
from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import ai as ai_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; AI asset diagnosis tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    run_startup_migrations()


@pytest.fixture(scope="module")
def auth_headers(client):
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


def _create_asset(client: TestClient, headers: dict, asset_key: str) -> None:
    r = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "external_web",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "owner": "platform-security",
            "tags": ["public"],
        },
    )
    assert r.status_code == 200, r.text


def test_asset_ai_diagnosis_generate_get_and_cache(client, auth_headers, monkeypatch):
    asset_key = f"asset-ai-{uuid.uuid4().hex[:10]}"
    _create_asset(client, auth_headers, asset_key)

    finding = client.post(
        "/findings/",
        headers=auth_headers,
        json={
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding-1",
            "title": "Missing HSTS",
            "severity": "high",
            "confidence": "high",
            "source": "pytest",
            "category": "security_headers",
            "evidence": "Header Strict-Transport-Security not present",
        },
    )
    assert finding.status_code == 200, finding.text

    monkeypatch.setattr(
        ai_router,
        "_opensearch_get",
        lambda path: {
            "found": True,
            "_source": {
                "asset_key": asset_key,
                "status": "timeout",
                "posture_state": "red",
                "posture_score": 22,
                "last_seen": "2026-03-02T18:00:00Z",
                "staleness_seconds": 720,
            },
        },
    )
    monkeypatch.setattr(
        ai_router,
        "_events_for_asset",
        lambda *_args, **_kwargs: [
            {
                "@timestamp": "2026-03-02T18:00:00Z",
                "status": "timeout",
                "code": 504,
                "latency_ms": 1400,
            },
            {
                "@timestamp": "2026-03-02T17:58:00Z",
                "status": "down",
                "code": 503,
                "latency_ms": 900,
            },
            {
                "@timestamp": "2026-03-02T17:56:00Z",
                "status": "up",
                "code": 200,
                "latency_ms": 120,
            },
        ],
    )
    monkeypatch.setattr(
        ai_router,
        "generate_text",
        lambda **_kwargs: (
            "1) Current state\n"
            "Asset is degraded and missing key transport protections.\n\n"
            "2) Most likely causes\n"
            "- repeated timeout responses\n"
            "- weak header posture\n\n"
            "3) Evidence signals\n"
            "- 504 and 503 responses\n"
            "- latency above SLO\n\n"
            "4) Next actions\n"
            "- restore availability\n"
            "- add HSTS\n"
        ),
    )

    generated = client.post(
        f"/ai/assets/{asset_key}/diagnose",
        json={"force": False},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["asset_key"] == asset_key
    assert body["cached"] is False
    assert "Current state" in body["diagnosis_text"]
    assert body["context_json"]["generated_from"]["signals"]["unhealthy_events"] >= 2
    assert len(body["context_json"]["generated_from"]["findings"]) >= 1

    loaded = client.get(f"/ai/assets/{asset_key}/diagnosis", headers=auth_headers)
    assert loaded.status_code == 200, loaded.text
    cached = loaded.json()
    assert cached["asset_key"] == asset_key
    assert cached["diagnosis_text"] == body["diagnosis_text"]

    second = client.post(
        f"/ai/assets/{asset_key}/diagnose",
        json={"force": False},
        headers=auth_headers,
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["cached"] is True
    assert second_body["diagnosis_text"] == body["diagnosis_text"]


def test_asset_ai_diagnosis_retries_real_model_when_first_attempt_times_out(
    client, auth_headers, monkeypatch
):
    asset_key = f"asset-ai-retry-{uuid.uuid4().hex[:8]}"
    _create_asset(client, auth_headers, asset_key)

    monkeypatch.setattr(
        ai_router,
        "_opensearch_get",
        lambda path: {
            "found": True,
            "_source": {
                "asset_key": asset_key,
                "status": "ssl error",
                "posture_state": "red",
                "posture_score": 10,
                "last_seen": "2026-03-02T19:00:00Z",
                "staleness_seconds": 60,
            },
        },
    )
    monkeypatch.setattr(
        ai_router,
        "_events_for_asset",
        lambda *_args, **_kwargs: [
            {
                "@timestamp": "2026-03-02T19:00:00Z",
                "status": "ssl error",
                "code": 525,
                "latency_ms": 350,
            }
        ],
    )
    calls = {"count": 0}

    def fake_generate_text(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise AIClientError("request timed out")
        return (
            "1) Current state\n"
            "The asset is seeing SSL-related failures on recent checks.\n\n"
            "2) Most likely causes\n"
            "- certificate validation error\n"
            "- upstream TLS misconfiguration\n\n"
            "3) Evidence signals\n"
            "- latest event is ssl error with 525\n"
            "- posture score is low\n\n"
            "4) Next actions\n"
            "- inspect certificate chain\n"
            "- confirm TLS settings on the endpoint\n"
        )

    monkeypatch.setattr(ai_router, "generate_text", fake_generate_text)

    generated = client.post(
        f"/ai/assets/{asset_key}/diagnose",
        json={"force": True},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["asset_key"] == asset_key
    assert calls["count"] == 2
    assert not body["provider"].endswith("-fallback")
    assert body["model"] != "template-v1"
    assert "Most likely causes" in body["diagnosis_text"]
    assert "Next actions" in body["diagnosis_text"]
    assert len(body["context_json"]["generated_from"]["findings"]) <= 3
    assert len(body["context_json"]["generated_from"]["recommendations"]) <= 3
