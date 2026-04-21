from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.main import app


def _postgres_available() -> bool:
    dsn = str(os.getenv("POSTGRES_DSN", "") or "").strip()
    if not dsn:
        return False
    try:
        engine = create_engine(dsn, pool_pre_ping=True, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_available(),
    reason="POSTGRES_DSN unavailable; privacy DSAR tests require reachable Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> tuple[int, dict]:
    response = client.post("/auth/login", data={"username": username, "password": password})
    payload = (
        response.json()
        if response.headers.get("content-type", "").startswith("application/json")
        else {}
    )
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


def test_privacy_dsar_export_and_delete_flow(client, admin_headers):
    suffix = str(int(time.time()))
    username = f"dsar-user-{suffix}"
    password = f"Dsar-{suffix}-pwd"

    created = client.post(
        "/auth/users",
        headers=admin_headers,
        json={"username": username, "role": "viewer", "password": password},
    )
    assert created.status_code == 200, created.text

    status, payload = _login(client, username, password)
    assert status == 200, payload
    assert payload.get("refresh_token")

    exported = client.post(
        "/privacy/dsar/export",
        headers=admin_headers,
        json={"username": username, "include_samples": True, "sample_limit": 10},
    )
    assert exported.status_code == 200, exported.text
    body = exported.json()
    by_source = {entry["source"]: entry for entry in body["sources"]}
    assert by_source["users"]["count"] == 1
    assert by_source["auth_refresh_tokens"]["count"] >= 1
    assert by_source["audit_events"]["count"] >= 1

    dry_run = client.post(
        "/privacy/dsar/delete",
        headers=admin_headers,
        json={"username": username, "execute": False},
    )
    assert dry_run.status_code == 200, dry_run.text
    assert dry_run.json()["execute"] is False

    executed = client.post(
        "/privacy/dsar/delete",
        headers=admin_headers,
        json={"username": username, "execute": True},
    )
    assert executed.status_code == 200, executed.text
    executed_body = executed.json()
    assert executed_body["execute"] is True
    assert executed_body["replacement_username"].startswith("deleted-user-")

    exported_after = client.post(
        "/privacy/dsar/export",
        headers=admin_headers,
        json={"username": username, "include_samples": False},
    )
    assert exported_after.status_code == 200, exported_after.text
    body_after = exported_after.json()
    by_source_after = {entry["source"]: entry for entry in body_after["sources"]}
    assert by_source_after["users"]["count"] == 0
    assert by_source_after["auth_refresh_tokens"]["count"] == 0
    assert by_source_after["audit_events"]["count"] == 0

    status_old, _ = _login(client, username, password)
    assert status_old == 401

    audit = client.get("/audit?action=privacy.dsar_delete&limit=100", headers=admin_headers)
    assert audit.status_code == 200, audit.text
    items = audit.json().get("items", [])
    assert any(
        (item.get("details") or {}).get("subject_username") == username
        and (item.get("details") or {}).get("execute") is True
        for item in items
    )


def test_privacy_dsar_requires_admin(client, admin_headers):
    suffix = str(int(time.time()))
    username = f"dsar-viewer-{suffix}"
    password = f"DsarViewer-{suffix}-pwd"
    created = client.post(
        "/auth/users",
        headers=admin_headers,
        json={"username": username, "role": "viewer", "password": password},
    )
    assert created.status_code == 200, created.text

    status, payload = _login(client, username, password)
    assert status == 200, payload
    viewer_headers = {"Authorization": f"Bearer {payload['access_token']}"}

    denied = client.post(
        "/privacy/dsar/export",
        headers=viewer_headers,
        json={"username": username},
    )
    assert denied.status_code == 403
