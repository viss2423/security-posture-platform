"""
Worker-execution endpoint tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_jobs_execute_endpoint.py -q
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
    from app.db_migrate import run_startup_migrations
    from app.main import app
else:
    app = None

    def run_startup_migrations():
        return None

pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; jobs execute endpoint tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    try:
        run_startup_migrations()
    except Exception as exc:
        pytest.skip(f"Postgres not reachable for jobs execute endpoint tests: {exc}")


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


def test_execute_endpoint_runs_score_recompute_job(client, admin_headers):
    created = client.post(
        "/jobs",
        headers=admin_headers,
        json={"job_type": "score_recompute"},
    )
    assert created.status_code == 200, created.text
    job_id = int(created.json()["job_id"])

    executed = client.post(f"/jobs/{job_id}/execute", headers=admin_headers)
    assert executed.status_code == 200, executed.text
    body = executed.json()
    assert body["job_id"] == job_id
    assert body["job_type"] == "score_recompute"
    assert body["status"] in {"done", "failed"}

    detail = client.get(f"/jobs/{job_id}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["status"] in {"done", "failed"}


def test_execute_endpoint_requires_worker_executor(client, admin_headers, viewer_headers):
    created = client.post(
        "/jobs",
        headers=admin_headers,
        json={"job_type": "score_recompute"},
    )
    assert created.status_code == 200, created.text
    job_id = int(created.json()["job_id"])

    forbidden = client.post(f"/jobs/{job_id}/execute", headers=viewer_headers)
    assert forbidden.status_code == 403, forbidden.text
