"""
AI job triage tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_job_triage.py -q
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

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; AI job triage tests require Postgres",
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


def _create_asset(
    client: TestClient,
    headers: dict,
    *,
    asset_key: str,
    asset_type: str = "external_web",
    environment: str = "prod",
) -> dict:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": asset_type,
            "name": f"{asset_key}.example.test",
            "environment": environment,
            "criticality": "high",
            "owner": "platform-security",
            "tags": ["pytest"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _insert_failed_job(
    *,
    asset_id: int,
    job_type: str,
    requested_by: str,
    error: str,
    log_output: str,
    retry_count: int = 0,
) -> int:
    started_at = datetime.now(UTC) - timedelta(minutes=3)
    finished_at = started_at + timedelta(seconds=47)
    with engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    """
                    INSERT INTO scan_jobs (
                      job_type,
                      target_asset_id,
                      requested_by,
                      status,
                      created_at,
                      started_at,
                      finished_at,
                      error,
                      log_output,
                      retry_count
                    )
                    VALUES (
                      :job_type,
                      :target_asset_id,
                      :requested_by,
                      'failed',
                      :created_at,
                      :started_at,
                      :finished_at,
                      :error,
                      :log_output,
                      :retry_count
                    )
                    RETURNING job_id
                    """
                ),
                {
                    "job_type": job_type,
                    "target_asset_id": asset_id,
                    "requested_by": requested_by,
                    "created_at": started_at - timedelta(seconds=8),
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "error": error,
                    "log_output": log_output,
                    "retry_count": retry_count,
                },
            )
            .mappings()
            .first()
        )
    assert row is not None
    return int(row["job_id"])


def test_job_ai_triage_generate_get_cache_and_list_context(client, auth_headers, monkeypatch):
    asset_key = f"job-triage-{uuid.uuid4().hex[:10]}"
    asset = _create_asset(client, auth_headers, asset_key=asset_key)
    asset_id = int(asset["asset_id"])

    previous_job_id = _insert_failed_job(
        asset_id=asset_id,
        job_type="web_exposure",
        requested_by="pytest",
        error="connection timed out during scan",
        log_output="dial tcp 10.0.0.1:443: i/o timeout\nretrying probe",
        retry_count=1,
    )
    job_id = _insert_failed_job(
        asset_id=asset_id,
        job_type="web_exposure",
        requested_by="pytest",
        error="Domain not verified",
        log_output=(
            "starting web exposure scan\n"
            "verification check failed\n"
            "Domain not verified for requested asset\n"
        ),
    )

    monkeypatch.setattr(
        ai_router,
        "generate_text",
        lambda **_kwargs: (
            "1) Likely cause\n"
            "The web exposure job failed because the target domain has not been verified.\n\n"
            "2) Retry guidance\n"
            "Do not retry until verification is complete.\n\n"
            "3) Next steps\n"
            "- Verify the asset ownership record.\n"
            "- Retry after verification succeeds.\n\n"
            "4) Evidence used\n"
            "- job error says Domain not verified\n"
            "- prior related failure exists\n"
        ),
    )

    generated = client.post(
        f"/ai/jobs/{job_id}/triage/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["job_id"] == job_id
    assert body["cached"] is False
    assert "Likely cause" in body["triage_text"]
    assert (
        body["context_json"]["generated_from"]["failure_signals"]["cause_category"]
        == "verification"
    )
    assert body["context_json"]["generated_from"]["failure_signals"]["recent_related_failures"] >= 1
    assert any(
        item["job_id"] == previous_job_id
        for item in body["context_json"]["generated_from"]["recent_related_jobs"]
    )

    loaded = client.get(f"/ai/jobs/{job_id}/triage", headers=auth_headers)
    assert loaded.status_code == 200, loaded.text
    loaded_body = loaded.json()
    assert loaded_body["job_id"] == job_id
    assert loaded_body["triage_text"] == body["triage_text"]

    listed = client.get("/jobs?status=failed&limit=20", headers=auth_headers)
    assert listed.status_code == 200, listed.text
    listed_job = next(
        (item for item in listed.json()["items"] if int(item["job_id"]) == job_id),
        None,
    )
    assert listed_job is not None
    assert listed_job["asset_key"] == asset_key
    assert listed_job["asset_name"] == f"{asset_key}.example.test"

    detail = client.get(f"/jobs/{job_id}", headers=auth_headers)
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["asset_key"] == asset_key
    assert detail_body["asset_type"] == "external_web"
    assert detail_body["asset_environment"] == "prod"
    assert detail_body["asset_verified"] is False

    second = client.post(
        f"/ai/jobs/{job_id}/triage/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["cached"] is True
    assert second_body["triage_text"] == body["triage_text"]


def test_job_ai_triage_retries_real_model_when_first_attempt_times_out(
    client, auth_headers, monkeypatch
):
    asset_key = f"job-triage-retry-{uuid.uuid4().hex[:8]}"
    asset = _create_asset(
        client, auth_headers, asset_key=asset_key, asset_type="app", environment="staging"
    )
    asset_id = int(asset["asset_id"])
    job_id = _insert_failed_job(
        asset_id=asset_id,
        job_type="web_exposure",
        requested_by="pytest",
        error="Target is not external_web",
        log_output="worker rejected job because target is not external_web",
    )

    calls = {"count": 0}

    def fake_generate_text(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise AIClientError("request timed out")
        return (
            "1) Likely cause\n"
            "The job targeted an asset that is not external_web.\n\n"
            "2) Retry guidance\n"
            "Do not retry until the target asset type is corrected.\n\n"
            "3) Next steps\n"
            "- use a web_exposure job only for external_web assets\n"
            "- enqueue the correct job type for this asset\n\n"
            "4) Evidence used\n"
            "- worker error says target is not external_web\n"
        )

    monkeypatch.setattr(ai_router, "generate_text", fake_generate_text)

    generated = client.post(
        f"/ai/jobs/{job_id}/triage/generate",
        json={"force": True},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["job_id"] == job_id
    assert calls["count"] == 2
    assert not body["provider"].endswith("-fallback")
    assert body["model"] != "template-v1"
    assert "Likely cause" in body["triage_text"]
    assert "Retry guidance" in body["triage_text"]
    assert (
        body["context_json"]["generated_from"]["failure_signals"]["cause_category"]
        == "asset_type_mismatch"
    )
    assert len(body["context_json"]["generated_from"]["recent_related_jobs"]) <= 2
