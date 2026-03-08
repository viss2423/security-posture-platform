"""
Entity-level risk API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_risk_routes.py -q
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
    reason="POSTGRES_DSN not set; risk route tests require Postgres",
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


def _seed_risk_fixture(client: TestClient, headers: dict) -> tuple[str, str]:
    asset_key = f"risk-asset-{uuid.uuid4().hex[:8]}"
    created_asset = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "external_web",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "owner": "soc",
            "address": f"https://{asset_key}.edge.example.test",
            "port": 443,
            "tags": ["public", "pytest-risk"],
        },
    )
    assert created_asset.status_code == 200, created_asset.text

    created_finding = client.post(
        "/findings/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding",
            "title": "Critical vuln for risk routing test",
            "severity": "critical",
            "confidence": "high",
            "source": "pytest",
            "category": "web_security",
        },
    )
    assert created_finding.status_code == 200, created_finding.text
    finding_key = str(created_finding.json().get("finding_key") or f"{asset_key}-finding")

    run_surface = client.post(
        "/attack-surface/discovery/run",
        headers=headers,
        json={"domains": [f"{asset_key}.edge.example.test"], "cert_salt": "risk-seed"},
    )
    assert run_surface.status_code == 200, run_surface.text

    created_incident = client.post(
        "/incidents",
        headers=headers,
        json={
            "title": f"Risk incident {asset_key}",
            "severity": "high",
            "asset_keys": [asset_key],
        },
    )
    assert created_incident.status_code == 201, created_incident.text
    return asset_key, finding_key


def test_risk_entity_endpoints(client: TestClient, admin_headers: dict):
    asset_key, finding_key = _seed_risk_fixture(client, admin_headers)

    refreshed = client.post("/risk/snapshots/refresh", headers=admin_headers)
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json().get("ok") is True

    assets = client.get("/risk/assets?limit=1000&include_trend_days=30", headers=admin_headers)
    assert assets.status_code == 200, assets.text
    asset_item = next(
        (
            item
            for item in assets.json().get("items") or []
            if str(item.get("entity_key") or "") == asset_key
        ),
        None,
    )
    assert asset_item is not None
    assert int(asset_item.get("score") or 0) >= 1
    assert isinstance(asset_item.get("top_drivers"), list)

    incidents = client.get("/risk/incidents?limit=50", headers=admin_headers)
    assert incidents.status_code == 200, incidents.text
    assert len(incidents.json().get("items") or []) >= 1

    environments = client.get("/risk/environments", headers=admin_headers)
    assert environments.status_code == 200, environments.text
    assert any(
        str(item.get("entity_key") or "") == "prod"
        for item in environments.json().get("items") or []
    )

    trends = client.get(
        f"/risk/trends?entity_type=asset&entity_key={asset_key}&days=30&limit=30",
        headers=admin_headers,
    )
    assert trends.status_code == 200, trends.text
    assert len(trends.json().get("items") or []) >= 1

    priorities = client.get("/risk/priorities?limit=50", headers=admin_headers)
    assert priorities.status_code == 200, priorities.text
    assert any(
        str(item.get("finding_key") or "") == finding_key
        for item in priorities.json().get("items") or []
    )
