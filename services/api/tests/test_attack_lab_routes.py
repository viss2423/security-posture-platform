"""
Attack-lab route tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_attack_lab_routes.py -q
"""

from __future__ import annotations

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
from app.routers import attack_lab as attack_lab_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; attack-lab route tests require Postgres",
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


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer")


def _create_asset(client: TestClient, headers: dict, asset_key: str, address: str) -> None:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key}.example.test",
            "environment": "dev",
            "criticality": "medium",
            "owner": "platform-security",
            "address": address,
            "tags": ["pytest", "attack-lab"],
        },
    )
    assert response.status_code == 200, response.text


def test_scan_asset_route_enqueues_attack_lab_job(client, admin_headers, monkeypatch):
    launched: list[int] = []
    monkeypatch.setattr(
        attack_lab_router,
        "launch_attack_lab_job",
        lambda job_id: launched.append(int(job_id)),
    )

    asset_key = f"attack-lab-asset-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key, "http://verify-web")

    response = client.post(
        "/attack-lab/scan-asset",
        headers=admin_headers,
        json={"asset_key": asset_key},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job_type"] == "attack_lab_run"
    assert body["job_params_json"]["asset_key"] == asset_key
    assert body["job_params_json"]["task_type"] == "web_scan"
    assert str(body["job_params_json"]["target"]).startswith("http://")
    assert launched == [int(body["job_id"])]

    explicit = client.post(
        "/attack-lab/scan-asset",
        headers=admin_headers,
        json={"asset_key": asset_key, "task_type": "port_scan"},
    )
    assert explicit.status_code == 200, explicit.text
    explicit_body = explicit.json()
    assert explicit_body["job_params_json"]["task_type"] == "port_scan"


def test_scan_asset_route_requires_admin(client, viewer_headers):
    response = client.post(
        "/attack-lab/scan-asset",
        headers=viewer_headers,
        json={"asset_key": "verify-web"},
    )
    assert response.status_code == 403, response.text
