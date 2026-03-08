"""
Admin user lifecycle tests for /auth/users.
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

from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; auth user lifecycle tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> tuple[int, dict]:
    response = client.post("/auth/login", data={"username": username, "password": password})
    payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    return response.status_code, payload


def _refresh(client: TestClient, refresh_token: str) -> tuple[int, dict]:
    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    return response.status_code, payload


@pytest.fixture(scope="module")
def admin_headers(client):
    status, payload = _login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )
    if status != 200:
        pytest.skip(f"admin login failed: {status} {payload}")
    token = payload.get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_create_update_disable_enable_and_reset_user(client, admin_headers):
    suffix = str(int(time.time()))
    username = f"roadmap-user-{suffix}"
    first_password = f"Start-{suffix}-pwd"
    second_password = f"Reset-{suffix}-pwd"

    created = client.post(
        "/auth/users",
        headers=admin_headers,
        json={"username": username, "role": "viewer", "password": first_password},
    )
    assert created.status_code == 200, created.text
    created_body = created.json()
    assert created_body["username"] == username
    assert created_body["role"] == "viewer"
    assert created_body["disabled"] is False
    assert created_body["password_configured"] is True

    status, payload = _login(client, username, first_password)
    assert status == 200, payload
    assert payload.get("access_token")
    assert payload.get("refresh_token")

    updated = client.patch(
        f"/auth/users/{username}",
        headers=admin_headers,
        json={"role": "analyst"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["role"] == "analyst"

    disabled = client.post(f"/auth/users/{username}/disable", headers=admin_headers)
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["disabled"] is True

    status, _ = _login(client, username, first_password)
    assert status == 401

    enabled = client.post(f"/auth/users/{username}/enable", headers=admin_headers)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["disabled"] is False

    reset = client.post(
        f"/auth/users/{username}/reset-password",
        headers=admin_headers,
        json={"password": second_password},
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["password_configured"] is True

    status_old, _ = _login(client, username, first_password)
    assert status_old == 401
    status_new, payload_new = _login(client, username, second_password)
    assert status_new == 200, payload_new
    assert payload_new.get("refresh_token")

    for action in (
        "user.create",
        "user.update",
        "user.disable",
        "user.enable",
        "user.reset_password",
    ):
        audit = client.get(f"/audit?action={action}&limit=50", headers=admin_headers)
        assert audit.status_code == 200, audit.text
        items = audit.json().get("items", [])
        assert any((item.get("details") or {}).get("username") == username for item in items)


def test_user_admin_routes_require_admin(client, admin_headers):
    suffix = str(int(time.time()))
    username = f"roadmap-viewer-{suffix}"
    password = f"Start-{suffix}-pwd"
    create = client.post(
        "/auth/users",
        headers=admin_headers,
        json={"username": username, "role": "viewer", "password": password},
    )
    assert create.status_code == 200, create.text

    status, payload = _login(client, username, password)
    assert status == 200, payload
    viewer_headers = {"Authorization": f"Bearer {payload['access_token']}"}

    denied_create = client.post(
        "/auth/users",
        headers=viewer_headers,
        json={"username": f"{username}-x", "role": "viewer", "password": password},
    )
    assert denied_create.status_code == 403

    denied_patch = client.patch(
        f"/auth/users/{username}",
        headers=viewer_headers,
        json={"role": "admin"},
    )
    assert denied_patch.status_code == 403


def test_refresh_token_rotation(client, admin_headers):
    suffix = str(int(time.time()))
    username = f"roadmap-refresh-{suffix}"
    password = f"Rotate-{suffix}-pwd"
    created = client.post(
        "/auth/users",
        headers=admin_headers,
        json={"username": username, "role": "analyst", "password": password},
    )
    assert created.status_code == 200, created.text

    status, payload = _login(client, username, password)
    assert status == 200, payload
    first_access = payload.get("access_token")
    first_refresh = payload.get("refresh_token")
    assert first_access
    assert first_refresh

    me_first = client.get("/auth/me", headers={"Authorization": f"Bearer {first_access}"})
    assert me_first.status_code == 200, me_first.text
    assert me_first.json().get("username") == username

    refresh_status, refresh_payload = _refresh(client, first_refresh)
    assert refresh_status == 200, refresh_payload
    second_access = refresh_payload.get("access_token")
    second_refresh = refresh_payload.get("refresh_token")
    assert second_access
    assert second_refresh
    assert second_refresh != first_refresh

    reuse_status, _ = _refresh(client, first_refresh)
    assert reuse_status == 401

    me_second = client.get("/auth/me", headers={"Authorization": f"Bearer {second_access}"})
    assert me_second.status_code == 200, me_second.text
    assert me_second.json().get("username") == username
