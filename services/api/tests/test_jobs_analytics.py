"""
Job analytics route tests.
"""

from __future__ import annotations

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

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; jobs analytics tests require Postgres",
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


def test_jobs_analytics_returns_reliability_metrics(client: TestClient, admin_headers: dict):
    job_type = f"pytest-analytics-{uuid.uuid4().hex[:10]}"
    now = datetime.now(UTC)
    queued_created = now - timedelta(minutes=5)
    running_created = now - timedelta(minutes=55)
    running_started = now - timedelta(minutes=45)
    done_created = now - timedelta(minutes=30)
    done_started = now - timedelta(minutes=25)
    done_finished = now - timedelta(minutes=20)
    failed_created = now - timedelta(minutes=20)
    failed_started = now - timedelta(minutes=15)
    failed_finished = now - timedelta(minutes=10)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO scan_jobs(
                  job_type, requested_by, status, retry_count, created_at, job_params_json
                )
                VALUES
                  (:job_type, 'pytest', 'queued', 0, :queued_created, '{}'::jsonb),
                  (:job_type, 'pytest', 'running', 0, :running_created, '{}'::jsonb),
                  (:job_type, 'pytest', 'done', 0, :done_created, '{}'::jsonb),
                  (:job_type, 'pytest', 'failed', 2, :failed_created, '{}'::jsonb)
                """
            ),
            {
                "job_type": job_type,
                "queued_created": queued_created,
                "running_created": running_created,
                "done_created": done_created,
                "failed_created": failed_created,
            },
        )
        conn.execute(
            text(
                """
                UPDATE scan_jobs
                SET started_at = :running_started
                WHERE job_type = :job_type
                  AND status = 'running'
                  AND requested_by = 'pytest'
                  AND created_at = :running_created
                """
            ),
            {
                "job_type": job_type,
                "running_started": running_started,
                "running_created": running_created,
            },
        )
        conn.execute(
            text(
                """
                UPDATE scan_jobs
                SET started_at = :done_started, finished_at = :done_finished
                WHERE job_type = :job_type
                  AND status = 'done'
                  AND requested_by = 'pytest'
                  AND created_at = :done_created
                """
            ),
            {
                "job_type": job_type,
                "done_started": done_started,
                "done_finished": done_finished,
                "done_created": done_created,
            },
        )
        conn.execute(
            text(
                """
                UPDATE scan_jobs
                SET started_at = :failed_started, finished_at = :failed_finished
                WHERE job_type = :job_type
                  AND status = 'failed'
                  AND requested_by = 'pytest'
                  AND created_at = :failed_created
                """
            ),
            {
                "job_type": job_type,
                "failed_started": failed_started,
                "failed_finished": failed_finished,
                "failed_created": failed_created,
            },
        )

    response = client.get(
        f"/jobs/analytics?lookback_hours=2&running_stale_minutes=30&job_type={job_type}",
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    totals = body.get("totals") or {}

    assert int(totals.get("total_jobs") or 0) == 4
    assert int(totals.get("queued_jobs") or 0) == 1
    assert int(totals.get("running_jobs") or 0) == 1
    assert int(totals.get("stale_running_jobs") or 0) == 1
    assert int(totals.get("done_jobs") or 0) == 1
    assert int(totals.get("failed_jobs") or 0) == 1
    assert int(totals.get("completed_jobs") or 0) == 2
    assert int(totals.get("retried_jobs") or 0) == 1
    assert float(totals.get("success_rate_pct") or 0.0) == pytest.approx(50.0, abs=0.01)
    assert float(totals.get("failure_rate_pct") or 0.0) == pytest.approx(50.0, abs=0.01)
    assert float(totals.get("oldest_queued_minutes") or 0.0) >= 4.0
    assert float(totals.get("avg_duration_seconds") or 0.0) == pytest.approx(300.0, abs=0.1)
    assert float(totals.get("p95_duration_seconds") or 0.0) == pytest.approx(300.0, abs=0.1)
    assert float(totals.get("max_duration_seconds") or 0.0) == pytest.approx(300.0, abs=0.1)

    by_job_type = body.get("by_job_type") or []
    assert len(by_job_type) == 1
    row = by_job_type[0]
    assert row.get("job_type") == job_type
    assert int(row.get("total_jobs") or 0) == 4
    assert int(row.get("queued_jobs") or 0) == 1
    assert int(row.get("running_jobs") or 0) == 1
    assert int(row.get("done_jobs") or 0) == 1
    assert int(row.get("failed_jobs") or 0) == 1
    assert int(row.get("retried_jobs") or 0) == 1
    assert float(row.get("success_rate_pct") or 0.0) == pytest.approx(50.0, abs=0.01)
    assert float(row.get("failure_rate_pct") or 0.0) == pytest.approx(50.0, abs=0.01)
    assert float(row.get("avg_duration_seconds") or 0.0) == pytest.approx(300.0, abs=0.1)
    assert float(row.get("p95_duration_seconds") or 0.0) == pytest.approx(300.0, abs=0.1)
    assert float(row.get("max_duration_seconds") or 0.0) == pytest.approx(300.0, abs=0.1)
