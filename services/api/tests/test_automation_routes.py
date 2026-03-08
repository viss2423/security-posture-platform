"""
Automation playbook API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_automation_routes.py -q
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

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; automation route tests require Postgres",
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


def _create_asset(client: TestClient, headers: dict, asset_key: str) -> None:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "owner": "soc",
            "address": "http://172.20.0.200",
            "tags": ["pytest", "automation"],
        },
    )
    assert response.status_code == 200, response.text


def test_automation_playbook_run_approval_and_rollback(client, admin_headers):
    asset_key = f"auto-plbk-{uuid.uuid4().hex[:8]}"
    _create_asset(client, admin_headers, asset_key)

    low_playbook = client.post(
        "/automation/playbooks",
        headers=admin_headers,
        json={
            "title": f"pytest-auto-low-{uuid.uuid4().hex[:8]}",
            "description": "Tag impacted asset from alert trigger",
            "trigger": "manual",
            "conditions": [{"field": "asset_key", "op": "exists"}],
            "actions": [
                {
                    "type": "tag_asset",
                    "params": {"asset_key": "{{asset_key}}", "tag": "under_investigation"},
                }
            ],
            "enabled": True,
        },
    )
    assert low_playbook.status_code == 201, low_playbook.text
    low_playbook_id = int(low_playbook.json()["playbook_id"])

    medium_playbook = client.post(
        "/automation/playbooks",
        headers=admin_headers,
        json={
            "title": f"pytest-auto-medium-{uuid.uuid4().hex[:8]}",
            "description": "Create incident from manual trigger",
            "trigger": "manual",
            "conditions": [{"field": "severity", "op": "gte", "value": "high"}],
            "actions": [
                {
                    "type": "create_incident",
                    "params": {
                        "title": "Automation incident for {{asset_key}}",
                        "severity": "high",
                        "asset_key": "{{asset_key}}",
                    },
                    "risk_tier": "medium",
                }
            ],
            "enabled": True,
        },
    )
    assert medium_playbook.status_code == 201, medium_playbook.text
    medium_playbook_id = int(medium_playbook.json()["playbook_id"])

    trigger = client.post(
        "/automation/runs/trigger",
        headers=admin_headers,
        json={
            "trigger": "manual",
            "payload": {"asset_key": asset_key, "severity": "high"},
            "playbook_ids": [low_playbook_id, medium_playbook_id],
        },
    )
    assert trigger.status_code == 200, trigger.text
    trigger_body = trigger.json()
    assert trigger_body["runs_created"] == 2

    low_run = next(
        (
            item
            for item in trigger_body["items"]
            if int(item.get("playbook_id") or 0) == low_playbook_id
        ),
        None,
    )
    medium_run = next(
        (
            item
            for item in trigger_body["items"]
            if int(item.get("playbook_id") or 0) == medium_playbook_id
        ),
        None,
    )
    assert low_run is not None
    assert medium_run is not None
    assert any(action.get("status") == "done" for action in low_run.get("actions") or [])
    assert any(
        action.get("status") == "pending_approval" for action in medium_run.get("actions") or []
    )

    approvals = client.get("/automation/approvals", headers=admin_headers)
    assert approvals.status_code == 200, approvals.text
    approval_item = next(
        (
            item
            for item in approvals.json().get("items") or []
            if int(item.get("run_id") or 0) == int(medium_run["run_id"])
        ),
        None,
    )
    assert approval_item is not None
    approval_id = int(approval_item["approval_id"])

    approved = client.post(
        f"/automation/approvals/{approval_id}/approve",
        headers=admin_headers,
        json={"note": "pytest approval"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["approval"]["status"] == "approved"
    assert approved.json()["run_status"] == "done"

    incident_list = client.get("/incidents?status=new&limit=50", headers=admin_headers)
    assert incident_list.status_code == 200, incident_list.text
    assert any(
        asset_key in str(item.get("title") or "")
        for item in incident_list.json().get("items") or []
    )

    rollback_items = client.get("/automation/rollbacks?status=pending", headers=admin_headers)
    assert rollback_items.status_code == 200, rollback_items.text
    rollback = next(
        (
            item
            for item in rollback_items.json().get("items") or []
            if int(item.get("run_id") or 0) == int(low_run["run_id"])
        ),
        None,
    )
    assert rollback is not None
    rollback_id = int(rollback["rollback_id"])

    execute_rollback = client.post(
        f"/automation/rollbacks/{rollback_id}/execute",
        headers=admin_headers,
    )
    assert execute_rollback.status_code == 200, execute_rollback.text
    assert execute_rollback.json()["rollback"]["status"] == "executed"

    asset = client.get(f"/assets/by-key/{asset_key}", headers=admin_headers)
    assert asset.status_code == 200, asset.text
    tags = asset.json().get("tags") or []
    assert "under_investigation" not in tags
