"""
Repository scan route tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_repository_scan_routes.py -q
"""

import json
import os
import sys
import uuid
from pathlib import Path

import httpx
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
from app.routers import posture as posture_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; repository scan route tests require Postgres",
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


def _create_repository_asset(client: TestClient, headers: dict, asset_key: str) -> dict:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key} repository",
            "environment": "dev",
            "criticality": "medium",
            "owner": "platform-security",
            "tags": ["pytest", "repository"],
        },
    )
    assert response.status_code == 200, response.text
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE assets SET asset_type = 'repository' WHERE asset_key = :asset_key"),
            {"asset_key": asset_key},
        )
    return response.json()


def _create_finding(
    client: TestClient,
    headers: dict,
    *,
    asset_key: str,
    finding_key: str,
    title: str,
    severity: str,
    source: str,
    category: str,
    package_name: str | None = None,
    package_version: str | None = None,
    vulnerability_id: str | None = None,
    fixed_version: str | None = None,
) -> int:
    created = client.post(
        "/findings/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "finding_key": finding_key,
            "title": title,
            "severity": severity,
            "confidence": "high",
            "source": source,
            "category": category,
            "package_name": package_name,
            "package_version": package_version,
            "vulnerability_id": vulnerability_id,
            "fixed_version": fixed_version,
        },
    )
    assert created.status_code == 200, created.text
    with engine.begin() as conn:
        row = (
            conn.execute(
                text("SELECT finding_id FROM findings WHERE finding_key = :finding_key"),
                {"finding_key": finding_key},
            )
            .mappings()
            .first()
        )
    assert row is not None
    return int(row["finding_id"])


def _set_finding_status(finding_id: int, status: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE findings SET status = :status WHERE finding_id = :finding_id"),
            {"status": status, "finding_id": finding_id},
        )


def test_repository_scan_job_creation_uses_job_params_and_launches(
    client, admin_headers, monkeypatch
):
    launched: list[int] = []
    monkeypatch.setattr(
        jobs_router, "launch_repository_scan_job", lambda job_id: launched.append(job_id)
    )

    asset_key = f"repo-job-{uuid.uuid4().hex[:10]}"
    response = client.post(
        "/jobs",
        headers=admin_headers,
        json={
            "job_type": "repository_scan",
            "job_params_json": {
                "path": "/workspace/services",
                "asset_key": asset_key,
                "asset_name": "Repository under test",
                "environment": "dev",
                "criticality": "high",
                "trivy_scanners": "vuln,misconfig",
                "enable_osv": True,
                "enable_trivy": False,
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job_type"] == "repository_scan"
    assert body["job_params_json"]["asset_key"] == asset_key
    assert body["job_params_json"]["path"] == "/workspace/services"
    assert body["job_params_json"]["enable_osv"] is True
    assert body["job_params_json"]["enable_trivy"] is False
    assert launched == [int(body["job_id"])]

    detail = client.get(f"/jobs/{body['job_id']}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["asset_key"] == asset_key
    assert detail_body["asset_name"] == "Repository under test"
    assert detail_body["asset_environment"] == "dev"
    assert detail_body["asset_criticality"] == "high"


def test_repository_summary_aggregates_findings_and_jobs(client, admin_headers):
    asset_key = f"repo-summary-{uuid.uuid4().hex[:10]}"
    asset = _create_repository_asset(client, admin_headers, asset_key)

    open_id = _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-osv-open",
        title="Known vulnerable dependency",
        severity="high",
        source="osv_scanner",
        category="dependency_vulnerability",
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="GHSA-1234-5678-9012",
        fixed_version="2.31.0",
    )
    in_progress_id = _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-trivy-progress",
        title="Container runs as root",
        severity="medium",
        source="trivy_fs",
        category="misconfiguration",
    )
    remediated_id = _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-trivy-remediated",
        title="Leaked test secret",
        severity="low",
        source="trivy_fs",
        category="secret",
    )
    _set_finding_status(open_id, "open")
    _set_finding_status(in_progress_id, "in_progress")
    _set_finding_status(remediated_id, "remediated")

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO scan_jobs (
                  job_type,
                  requested_by,
                  status,
                  job_params_json
                )
                VALUES (
                  'repository_scan',
                  'pytest',
                  'done',
                  CAST(:job_params_json AS jsonb)
                )
                """
            ),
            {
                "job_params_json": json.dumps(
                    {
                        "asset_key": asset_key,
                        "asset_name": asset["name"],
                        "path": "/workspace",
                    }
                )
            },
        )

    response = client.get(
        f"/findings/repository-summary?asset_key={asset_key}",
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["asset_key"] == asset_key
    assert body["asset_type"] == "repository"
    assert body["total_findings"] >= 3
    assert body["open_findings"] >= 1
    assert body["in_progress_findings"] >= 1
    assert body["remediated_findings"] >= 1
    assert any(item["source"] == "osv_scanner" and item["open"] >= 1 for item in body["sources"])
    assert any(item["source"] == "trivy_fs" and item["remediated"] >= 1 for item in body["sources"])
    assert any(item["package_name"] == "requests" for item in body["top_packages"])
    assert any(job["job_type"] == "repository_scan" for job in body["latest_jobs"])


def test_dependency_risk_summary_returns_package_distribution_and_queue(client, admin_headers):
    asset_key = f"repo-dependency-{uuid.uuid4().hex[:10]}"
    _create_repository_asset(client, admin_headers, asset_key)

    open_id = _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-osv-open",
        title="OpenSSL vulnerable release",
        severity="critical",
        source="osv_scanner",
        category="dependency_vulnerability",
        package_name="openssl",
        package_version="1.1.1k",
        vulnerability_id="CVE-2025-12345",
        fixed_version="1.1.1z",
    )
    accepted_id = _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-trivy-accepted",
        title="Lodash vulnerable release",
        severity="high",
        source="trivy_fs",
        category="dependency_vulnerability",
        package_name="lodash",
        package_version="4.17.20",
        vulnerability_id="CVE-2024-99999",
        fixed_version="4.17.21",
    )
    remediated_id = _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-trivy-remediated",
        title="Requests vulnerable release",
        severity="medium",
        source="trivy_fs",
        category="dependency_vulnerability",
        package_name="requests",
        package_version="2.25.0",
        vulnerability_id="CVE-2023-12345",
        fixed_version="2.31.0",
    )

    _set_finding_status(open_id, "open")
    _set_finding_status(accepted_id, "accepted_risk")
    _set_finding_status(remediated_id, "remediated")

    response = client.get(
        f"/findings/dependency-risk?asset_key={asset_key}&remediation_limit=10",
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["asset_key"] == asset_key
    assert body["total_findings"] >= 3
    assert body["active_findings"] >= 2
    assert body["remediated_findings"] >= 1
    assert body["accepted_risk_findings"] >= 1
    assert body["active_dependency_count"] >= 1
    assert any(item["source"] == "osv_scanner" for item in body["source_distribution"])
    assert any(item["source"] == "trivy_fs" for item in body["source_distribution"])
    assert any(pkg["package_name"] == "openssl" for pkg in body["dependency_distribution"])
    assert any(item["status"] != "remediated" for item in body["remediation_queue"])


def test_repository_assets_fallback_when_missing_from_posture_index(
    client, admin_headers, monkeypatch
):
    asset_key = f"repo-posture-{uuid.uuid4().hex[:10]}"
    _create_repository_asset(client, admin_headers, asset_key)
    _create_finding(
        client,
        admin_headers,
        asset_key=asset_key,
        finding_key=f"{asset_key}-osv-open",
        title="Repository vulnerability",
        severity="critical",
        source="osv_scanner",
        category="dependency_vulnerability",
        package_name="jinja2",
        package_version="3.0.0",
        vulnerability_id="GHSA-abcd-efgh-ijkl",
        fixed_version="3.1.6",
    )

    def _raise_not_found(_path: str, _index: str = posture_router.STATUS_INDEX):
        request = httpx.Request("GET", f"http://pytest.local{_path}")
        response = httpx.Response(404, request=request, text='{"found": false}')
        raise httpx.HTTPStatusError("not found", request=request, response=response)

    monkeypatch.setattr(posture_router, "_opensearch_get", _raise_not_found)

    state = client.get(f"/posture/{asset_key}", headers=admin_headers)
    assert state.status_code == 200, state.text
    state_body = state.json()
    assert state_body["status"] == "red"
    assert state_body["reason"] == "repository_findings"

    detail = client.get(f"/posture/{asset_key}/detail", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["reason_display"] == "repository_scan"
    assert detail_body["timeline"] == []
    assert detail_body["evidence"]["summary"].startswith("Repository asset detail")
    assert detail_body["recommendations"]
