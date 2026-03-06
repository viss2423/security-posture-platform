"""
Threat-intel route tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_threat_intel_routes.py -q
"""

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

from app import threat_intel
from app.db import engine
from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import jobs as jobs_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; threat-intel route tests require Postgres",
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
            "tags": ["pytest"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_threat_intel_job_creation_launches_runner(client, admin_headers, monkeypatch):
    launched: list[int] = []
    monkeypatch.setattr(
        jobs_router,
        "launch_threat_intel_refresh_job",
        lambda job_id: launched.append(job_id),
    )

    response = client.post(
        "/jobs",
        headers=admin_headers,
        json={"job_type": "threat_intel_refresh"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job_type"] == "threat_intel_refresh"
    assert launched == [int(body["job_id"])]


def test_threat_intel_summary_and_asset_route(client, admin_headers):
    asset_key = f"threat-asset-{uuid.uuid4().hex[:10]}"
    feed_source = f"pytest-feed-{uuid.uuid4().hex[:8]}"
    asset = _create_asset(client, admin_headers, asset_key, "https://bad.example/login")

    with engine.begin() as conn:
        ioc_row = (
            conn.execute(
                text(
                    """
                    INSERT INTO threat_iocs(
                      source, indicator, indicator_type, feed_url,
                      is_active, metadata
                    )
                    VALUES (
                      :source,
                      'bad.example',
                      'domain',
                      'https://feed.example/iocs.txt',
                      TRUE,
                      CAST(:metadata AS jsonb)
                    )
                    RETURNING id
                    """
                ),
                {"source": feed_source, "metadata": json.dumps({"note": "pytest"})},
            )
            .mappings()
            .first()
        )
        assert ioc_row is not None
        conn.execute(
            text(
                """
                INSERT INTO threat_ioc_asset_matches(
                  threat_ioc_id, asset_id, asset_key, match_field, matched_value, metadata
                )
                VALUES (
                  :threat_ioc_id, :asset_id, :asset_key, 'address', 'bad.example',
                    CAST(:metadata AS jsonb)
                )
                """
            ),
            {
                "threat_ioc_id": int(ioc_row["id"]),
                "asset_id": int(asset["asset_id"]),
                "asset_key": asset_key,
                "metadata": json.dumps({"source": feed_source}),
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO scan_jobs(job_type, requested_by, status, job_params_json)
                VALUES (
                  'threat_intel_refresh',
                  'pytest',
                  'done',
                  CAST(:job_params_json AS jsonb)
                )
                """
            ),
            {"job_params_json": json.dumps({"mode": "default"})},
        )

    summary = client.get("/threat-intel/summary", headers=admin_headers)
    assert summary.status_code == 200, summary.text
    body = summary.json()
    assert body["total_indicators"] >= 1
    assert body["matched_asset_count"] >= 1
    assert any(item["source"] == feed_source for item in body["sources"])
    assert any(job["job_type"] == "threat_intel_refresh" for job in body["latest_jobs"])

    asset_matches = client.get(f"/threat-intel/assets/{asset_key}", headers=admin_headers)
    assert asset_matches.status_code == 200, asset_matches.text
    asset_body = asset_matches.json()
    assert asset_body["asset_key"] == asset_key
    assert asset_body["total"] >= 1
    assert asset_body["items"][0]["indicator"] == "bad.example"


def test_threat_intel_refresh_keeps_ip_and_domain_for_same_source():
    source = f"pytest-mixed-{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    """
                    INSERT INTO scan_jobs(job_type, requested_by, status, job_params_json)
                    VALUES (
                      'threat_intel_refresh',
                      'pytest',
                      'queued',
                      CAST(:job_params_json AS jsonb)
                    )
                    RETURNING job_id
                    """
                ),
                {
                    "job_params_json": json.dumps(
                        {
                            "feeds": [],
                            "manual_iocs": [
                                {
                                    "source": source,
                                    "indicator_type": "ip",
                                    "indicator": "198.51.100.77",
                                },
                                {
                                    "source": source,
                                    "indicator_type": "domain",
                                    "indicator": "evil-test.example",
                                },
                            ],
                        }
                    )
                },
            )
            .mappings()
            .first()
        )
        assert row is not None
        job_id = int(row["job_id"])

    threat_intel.run_threat_intel_refresh_job(job_id)

    with engine.begin() as conn:
        job = (
            conn.execute(
                text("SELECT status, error FROM scan_jobs WHERE job_id = :job_id"),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        assert job is not None
        assert job["status"] == "done"
        assert not job["error"]

        rows = (
            conn.execute(
                text(
                    """
                    SELECT
                      indicator_type,
                      COUNT(*) FILTER (WHERE is_active = TRUE) AS active_count,
                      COUNT(*) AS total_count
                    FROM threat_iocs
                    WHERE source = :source
                    GROUP BY indicator_type
                    ORDER BY indicator_type
                    """
                ),
                {"source": source},
            )
            .mappings()
            .all()
        )
        counts = {str(row["indicator_type"]): int(row["active_count"] or 0) for row in rows}
        assert counts.get("ip", 0) >= 1
        assert counts.get("domain", 0) >= 1
