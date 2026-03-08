"""
Audit coverage checks for mutating endpoints added in roadmap hardening.
"""

import os
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; audit route tests require Postgres",
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


def _assert_audit_contains(client: TestClient, headers: dict, action: str, matcher):
    audit = client.get(f"/audit?action={action}&limit=200", headers=headers)
    assert audit.status_code == 200, audit.text
    items = audit.json().get("items", [])
    assert any(matcher(item) for item in items), f"missing audit action {action}"


def test_assets_and_findings_emit_audit_events(client, admin_headers):
    suffix = uuid.uuid4().hex[:10]
    asset_key = f"audit-asset-{suffix}"
    finding_key = f"audit-finding-{suffix}"

    created = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "type": "host",
            "name": f"Audit asset {suffix}",
            "owner": "soc",
            "environment": "dev",
            "criticality": "medium",
        },
    )
    assert created.status_code == 200, created.text

    patched = client.patch(
        f"/assets/by-key/{asset_key}",
        headers=admin_headers,
        json={"owner": "soc-ops"},
    )
    assert patched.status_code == 200, patched.text

    finding = client.post(
        "/findings/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "finding_key": finding_key,
            "title": "Audit finding",
            "severity": "high",
            "confidence": "high",
            "source": "pytest",
            "category": "auth",
        },
    )
    assert finding.status_code == 200, finding.text

    deleted = client.delete(f"/assets/by-key/{asset_key}", headers=admin_headers)
    assert deleted.status_code in (200, 409), deleted.text

    _assert_audit_contains(
        client,
        admin_headers,
        "asset.create",
        lambda item: (item.get("details") or {}).get("asset_key") == asset_key,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "asset.update",
        lambda item: item.get("asset_key") == asset_key and "owner" in (item.get("details") or {}),
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "finding.upsert",
        lambda item: (item.get("details") or {}).get("finding_key") == finding_key,
    )


def test_alert_policy_and_suppression_emit_audit_events(client, admin_headers):
    suffix = uuid.uuid4().hex[:10]
    asset_key = f"audit-alert-{suffix}"
    now = datetime.now(UTC)
    until = (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
    window_start = (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    window_end = (now + timedelta(minutes=21)).isoformat().replace("+00:00", "Z")

    ack = client.post("/alerts/ack", headers=admin_headers, json={"asset_key": asset_key})
    assert ack.status_code == 200, ack.text
    suppress = client.post(
        "/alerts/suppress",
        headers=admin_headers,
        json={"asset_key": asset_key, "until_iso": until},
    )
    assert suppress.status_code == 200, suppress.text
    resolve = client.post("/alerts/resolve", headers=admin_headers, json={"asset_key": asset_key})
    assert resolve.status_code == 200, resolve.text
    assign = client.post(
        "/alerts/assign",
        headers=admin_headers,
        json={"asset_key": asset_key, "assigned_to": "analyst-a"},
    )
    assert assign.status_code == 200, assign.text

    mw = client.post(
        "/suppression/maintenance-windows",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "start_at": window_start,
            "end_at": window_end,
            "reason": "maintenance",
        },
    )
    assert mw.status_code == 201, mw.text
    mw_id = mw.json()["id"]
    mw_delete = client.delete(f"/suppression/maintenance-windows/{mw_id}", headers=admin_headers)
    assert mw_delete.status_code == 200, mw_delete.text

    rule = client.post(
        "/suppression/rules",
        headers=admin_headers,
        json={
            "scope": "asset",
            "scope_value": asset_key,
            "starts_at": window_start,
            "ends_at": window_end,
            "reason": "noise reduction",
        },
    )
    assert rule.status_code == 201, rule.text
    rule_id = rule.json()["id"]
    rule_delete = client.delete(f"/suppression/rules/{rule_id}", headers=admin_headers)
    assert rule_delete.status_code == 200, rule_delete.text

    bundle_name = f"audit-policy-{suffix}-{int(time.time())}"
    bundle = client.post(
        "/policy/bundles",
        headers=admin_headers,
        json={
            "name": bundle_name,
            "description": "audit test bundle",
            "definition": "rules:\n  - id: no-critical\n    type: no_critical_findings\n",
        },
    )
    assert bundle.status_code == 200, bundle.text
    bundle_id = bundle.json()["id"]
    policy_delete = client.delete(f"/policy/bundles/{bundle_id}", headers=admin_headers)
    assert policy_delete.status_code == 200, policy_delete.text

    _assert_audit_contains(
        client, admin_headers, "alert.ack", lambda item: item.get("asset_key") == asset_key
    )
    _assert_audit_contains(
        client, admin_headers, "alert.suppress", lambda item: item.get("asset_key") == asset_key
    )
    _assert_audit_contains(
        client, admin_headers, "alert.resolve", lambda item: item.get("asset_key") == asset_key
    )
    _assert_audit_contains(
        client, admin_headers, "alert.assign", lambda item: item.get("asset_key") == asset_key
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "maintenance_window.create",
        lambda item: (item.get("details") or {}).get("asset_key") == asset_key,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "maintenance_window.delete",
        lambda item: (item.get("details") or {}).get("asset_key") == asset_key,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "suppression_rule.create",
        lambda item: (item.get("details") or {}).get("scope_value") == asset_key,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "suppression_rule.delete",
        lambda item: (item.get("details") or {}).get("scope_value") == asset_key,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "policy_bundle.create",
        lambda item: (item.get("details") or {}).get("name") == bundle_name,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "policy_bundle.delete",
        lambda item: (item.get("details") or {}).get("bundle_id") == bundle_id,
    )


def test_incident_mutations_emit_audit_events(client, admin_headers):
    suffix = uuid.uuid4().hex[:8]
    incident = client.post(
        "/incidents",
        headers=admin_headers,
        json={"title": f"Audit incident {suffix}", "severity": "medium"},
    )
    assert incident.status_code == 201, incident.text
    incident_id = incident.json()["id"]

    note = client.post(
        f"/incidents/{incident_id}/notes",
        headers=admin_headers,
        json={"body": "Audit note"},
    )
    assert note.status_code == 201, note.text

    linked_asset = f"audit-incident-asset-{suffix}"
    link = client.post(
        f"/incidents/{incident_id}/alerts",
        headers=admin_headers,
        json={"asset_key": linked_asset},
    )
    assert link.status_code == 201, link.text

    unlink = client.delete(
        f"/incidents/{incident_id}/alerts?asset_key={linked_asset}",
        headers=admin_headers,
    )
    assert unlink.status_code == 200, unlink.text

    _assert_audit_contains(
        client,
        admin_headers,
        "incident.note.create",
        lambda item: (item.get("details") or {}).get("incident_id") == incident_id,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "incident.alert.link",
        lambda item: (item.get("details") or {}).get("incident_id") == incident_id
        and (item.get("details") or {}).get("asset_key") == linked_asset,
    )
    _assert_audit_contains(
        client,
        admin_headers,
        "incident.alert.unlink",
        lambda item: (item.get("details") or {}).get("incident_id") == incident_id
        and (item.get("details") or {}).get("asset_key") == linked_asset,
    )
