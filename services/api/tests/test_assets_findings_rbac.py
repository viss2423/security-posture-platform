"""
RBAC tests for assets/findings:
- auth required for reads
- viewer redaction on sensitive fields
- viewer cannot write findings
"""

import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.db_migrate import run_startup_migrations
from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; RBAC tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> dict:
    r = client.post(
        "/auth/login",
        data={"username": username, "password": password},
    )
    if r.status_code != 200:
        pytest.skip(f"Login failed for {username}: {r.status_code} {r.text}")
    token = r.json().get("access_token")
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


def test_assets_requires_auth(client):
    r = client.get("/assets/")
    assert r.status_code == 401


def test_assets_viewer_redaction(client, admin_headers, viewer_headers):
    asset_key = f"rbac-asset-{int(time.time())}"
    create = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": asset_key,
            "owner_email": "owner@example.com",
            "address": "https://example.com",
            "port": 443,
            "metadata": {"sensitive": True},
            "tags": ["internal"],
        },
    )
    assert create.status_code == 200, create.text

    viewer_list = client.get("/assets/", headers=viewer_headers)
    assert viewer_list.status_code == 200, viewer_list.text
    rows = viewer_list.json()
    row = next((x for x in rows if x.get("asset_key") == asset_key), None)
    assert row is not None
    assert row.get("owner_email") is None
    assert row.get("address") is None
    assert row.get("port") is None
    assert row.get("verification_token") is None
    assert row.get("metadata") == {}


def test_findings_viewer_cannot_write_and_sees_redacted_evidence(
    client, admin_headers, viewer_headers
):
    finding_key = f"rbac-finding-{int(time.time())}"

    # Viewer cannot write finding.
    denied = client.post(
        "/findings/",
        headers=viewer_headers,
        json={
            "asset_key": "secplat-api",
            "finding_key": finding_key + "-denied",
            "title": "viewer write denied",
            "severity": "low",
            "evidence": "should not be accepted",
        },
    )
    assert denied.status_code == 403

    # Admin can write finding with evidence.
    created = client.post(
        "/findings/",
        headers=admin_headers,
        json={
            "asset_key": "secplat-api",
            "finding_key": finding_key,
            "title": "rbac finding",
            "severity": "medium",
            "evidence": '{"secret":"value"}',
            "source": "pytest",
        },
    )
    assert created.status_code == 200, created.text

    viewer_rows = client.get("/findings/?limit=200", headers=viewer_headers)
    assert viewer_rows.status_code == 200, viewer_rows.text
    rows = viewer_rows.json()
    row = next((x for x in rows if x.get("finding_key") == finding_key), None)
    assert row is not None
    assert row.get("evidence") is None
    assert row.get("accepted_risk_reason") is None


def test_service_identities_seeded(client, admin_headers):
    run_startup_migrations()
    expected = {
        os.getenv("SCANNER_SERVICE_USERNAME", "scanner-service"),
        os.getenv("INGESTION_SERVICE_USERNAME", "ingestion-service"),
        os.getenv("CORRELATOR_SERVICE_USERNAME", "correlator-service"),
    }
    r = client.get("/auth/users", headers=admin_headers)
    assert r.status_code == 200, r.text
    items = r.json().get("items", [])
    usernames = {x.get("username") for x in items}
    assert expected.issubset(usernames)
