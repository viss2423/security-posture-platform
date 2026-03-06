"""
Cyber-range route tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_cyber_range_routes.py -q
"""

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.main import app
from app.routers import cyber_range as cyber_range_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; cyber-range route tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


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


def test_list_cyber_range_missions(client, admin_headers):
    response = client.get("/cyber-range/missions", headers=admin_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    items = body.get("items") or []
    assert len(items) >= 3
    mission_ids = {item.get("mission_id") for item in items}
    assert "verify-web-baseline-scan" in mission_ids
    assert "juice-shop-web-hardening" in mission_ids
    assert "cowrie-bruteforce-drill" in mission_ids


def test_launch_cyber_range_mission_requires_admin(
    client, admin_headers, viewer_headers, monkeypatch
):
    launched: list[int] = []
    monkeypatch.setattr(
        cyber_range_router, "launch_attack_lab_job", lambda job_id: launched.append(job_id)
    )

    forbidden = client.post(
        "/cyber-range/missions/verify-web-baseline-scan/launch", headers=viewer_headers
    )
    assert forbidden.status_code == 403

    response = client.post(
        "/cyber-range/missions/verify-web-baseline-scan/launch", headers=admin_headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mission_id"] == "verify-web-baseline-scan"
    assert body["job"]["job_type"] == "attack_lab_run"
    assert body["job"]["job_params_json"]["mission_id"] == "verify-web-baseline-scan"
    assert launched == [int(body["job"]["job_id"])]
