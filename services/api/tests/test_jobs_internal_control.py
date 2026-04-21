"""
Internal worker job-control endpoint tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_jobs_internal_control.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if POSTGRES_DSN:
    from app.db import SessionLocal
    from app.db_migrate import run_startup_migrations
    from app.main import app
else:
    app = None
    SessionLocal = None

    def run_startup_migrations():
        return None


pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; internal job-control tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    try:
        run_startup_migrations()
    except Exception as exc:
        pytest.skip(f"Postgres not reachable for internal job-control tests: {exc}")


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
def service_headers(client):
    return _login(
        client,
        os.getenv("SCANNER_SERVICE_USERNAME", "scanner-service"),
        os.getenv("SCANNER_SERVICE_PASSWORD", "scanner-local-strong"),
    )


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer")


def _create_job(client: TestClient, admin_headers: dict) -> int:
    created = client.post(
        "/jobs",
        headers=admin_headers,
        json={"job_type": "score_recompute"},
    )
    assert created.status_code == 200, created.text
    return int(created.json()["job_id"])


def test_internal_job_control_claim_heartbeat_complete(client, admin_headers, service_headers):
    job_id = _create_job(client, admin_headers)

    claimed = client.post(
        f"/internal/jobs/{job_id}/claim",
        headers=service_headers,
        json={"worker_id": "pytest-worker"},
    )
    assert claimed.status_code == 200, claimed.text
    claimed_body = claimed.json()
    assert claimed_body["claimed"] is True
    claim_token = claimed_body["claim_token"]

    heartbeat = client.post(
        f"/internal/jobs/{job_id}/heartbeat",
        headers=service_headers,
        json={"worker_id": "pytest-worker", "claim_token": claim_token},
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["status"] == "running"

    completed = client.post(
        f"/internal/jobs/{job_id}/complete",
        headers=service_headers,
        json={
            "worker_id": "pytest-worker",
            "claim_token": claim_token,
            "log_line": "Done",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "done"

    detail = client.get(f"/jobs/{job_id}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "done"


def test_internal_job_control_fail_requeues_retryable(client, admin_headers, service_headers):
    job_id = _create_job(client, admin_headers)

    claimed = client.post(
        f"/internal/jobs/{job_id}/claim",
        headers=service_headers,
        json={"worker_id": "pytest-worker"},
    )
    assert claimed.status_code == 200, claimed.text
    claim_token = claimed.json()["claim_token"]

    failed = client.post(
        f"/internal/jobs/{job_id}/fail",
        headers=service_headers,
        json={
            "worker_id": "pytest-worker",
            "claim_token": claim_token,
            "error": "retryable=true error=upstream timeout",
            "retryable": True,
            "log_line": "Retrying from stream after error",
        },
    )
    assert failed.status_code == 200, failed.text
    failed_body = failed.json()
    assert failed_body["status"] == "queued"
    assert failed_body["requeued"] is True

    detail = client.get(f"/jobs/{job_id}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "queued"


def test_internal_job_control_fail_marks_terminal_when_not_retryable(
    client, admin_headers, service_headers
):
    job_id = _create_job(client, admin_headers)

    claimed = client.post(
        f"/internal/jobs/{job_id}/claim",
        headers=service_headers,
        json={"worker_id": "pytest-worker"},
    )
    assert claimed.status_code == 200, claimed.text
    claim_token = claimed.json()["claim_token"]

    failed = client.post(
        f"/internal/jobs/{job_id}/fail",
        headers=service_headers,
        json={
            "worker_id": "pytest-worker",
            "claim_token": claim_token,
            "error": "terminal failure",
            "retryable": False,
            "log_line": "Permanent failure reached",
        },
    )
    assert failed.status_code == 200, failed.text
    failed_body = failed.json()
    assert failed_body["status"] == "failed"
    assert failed_body["requeued"] is False
    assert failed_body["acknowledge"] is True

    detail = client.get(f"/jobs/{job_id}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "failed"


def test_recover_stale_jobs_requeues_expired_running_job(client, admin_headers, service_headers):
    job_id = _create_job(client, admin_headers)

    claimed = client.post(
        f"/internal/jobs/{job_id}/claim",
        headers=service_headers,
        json={"worker_id": "pytest-worker"},
    )
    assert claimed.status_code == 200, claimed.text

    db = SessionLocal()
    try:
        db.execute(
            __import__("sqlalchemy").text(
                """
                UPDATE scan_jobs
                SET last_heartbeat_at = NOW() - INTERVAL '90 minutes'
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id},
        )
        db.commit()
    finally:
        db.close()

    preview = client.post(
        "/jobs/maintenance/recover-stale",
        headers=admin_headers,
        json={"running_stale_minutes": 30, "limit": 10, "dry_run": True},
    )
    assert preview.status_code == 200, preview.text
    preview_body = preview.json()
    assert any(int(item["job_id"]) == job_id for item in preview_body["jobs"])

    recovered = client.post(
        "/jobs/maintenance/recover-stale",
        headers=admin_headers,
        json={"running_stale_minutes": 30, "limit": 10},
    )
    assert recovered.status_code == 200, recovered.text
    recovered_body = recovered.json()
    assert recovered_body["recovered_count"] >= 1
    recovered_job = next(item for item in recovered_body["jobs"] if int(item["job_id"]) == job_id)
    assert recovered_job["status"] == "queued"

    detail = client.get(f"/jobs/{job_id}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["status"] == "queued"
    assert int(detail_body["retry_count"]) >= 1


def test_internal_job_control_requires_worker_executor(client, admin_headers, viewer_headers):
    job_id = _create_job(client, admin_headers)
    forbidden = client.post(
        f"/internal/jobs/{job_id}/claim",
        headers=viewer_headers,
        json={"worker_id": "pytest-viewer"},
    )
    assert forbidden.status_code == 403, forbidden.text
