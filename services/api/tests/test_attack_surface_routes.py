"""
Attack-surface API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_attack_surface_routes.py -q
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
    reason="POSTGRES_DSN not set; attack-surface tests require Postgres",
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


def _create_asset(
    client: TestClient,
    headers: dict,
    *,
    asset_key: str,
    address: str,
    port: int,
) -> None:
    response = client.post(
        "/assets/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "type": "external_web",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
            "owner": "soc",
            "address": address,
            "port": port,
            "tags": ["pytest", "attack-surface"],
        },
    )
    assert response.status_code == 200, response.text


def test_attack_surface_discovery_and_drift(client: TestClient, admin_headers: dict):
    source_asset = f"as-src-{uuid.uuid4().hex[:8]}"
    target_asset = f"as-dst-{uuid.uuid4().hex[:8]}"
    _create_asset(
        client,
        admin_headers,
        asset_key=source_asset,
        address=f"http://{source_asset}.edge.example.test",
        port=80,
    )
    _create_asset(
        client,
        admin_headers,
        asset_key=target_asset,
        address=f"http://{target_asset}.edge.example.test",
        port=443,
    )

    run_one = client.post(
        "/attack-surface/discovery/run",
        headers=admin_headers,
        json={"domains": ["alpha.example.test"], "cert_salt": "seed-a"},
    )
    assert run_one.status_code == 200, run_one.text
    first_body = run_one.json()
    run_one_id = int(first_body["run_id"])
    assert first_body["status"] == "done"
    assert int(first_body["summary"]["hosts_discovered"]) >= 2
    assert int(first_body["summary"]["services_discovered"]) >= 2

    hosts = client.get(
        f"/attack-surface/discovery/hosts?run_id={run_one_id}", headers=admin_headers
    )
    assert hosts.status_code == 200, hosts.text
    assert any(
        str(item.get("asset_key")) == source_asset for item in hosts.json().get("items") or []
    )

    services = client.get(
        f"/attack-surface/discovery/services?run_id={run_one_id}",
        headers=admin_headers,
    )
    assert services.status_code == 200, services.text
    assert any(int(item.get("port") or 0) == 443 for item in services.json().get("items") or [])

    certs = client.get(
        f"/attack-surface/discovery/certs?run_id={run_one_id}",
        headers=admin_headers,
    )
    assert certs.status_code == 200, certs.text
    assert len(certs.json().get("items") or []) >= 1

    exposures = client.get("/attack-surface/exposures", headers=admin_headers)
    assert exposures.status_code == 200, exposures.text
    source_exposure = next(
        (
            item
            for item in exposures.json().get("items") or []
            if str(item.get("asset_key") or "") == source_asset
        ),
        None,
    )
    assert source_exposure is not None
    assert bool(source_exposure.get("internet_exposed")) is True
    assert int(source_exposure.get("open_port_count") or 0) >= 1

    first_drift = client.get(
        f"/attack-surface/drift?run_id={run_one_id}",
        headers=admin_headers,
    )
    assert first_drift.status_code == 200, first_drift.text
    first_drift_types = {
        str(item.get("event_type") or "") for item in first_drift.json().get("items") or []
    }
    assert "new_host" in first_drift_types

    updated_asset = client.patch(
        f"/assets/by-key/{source_asset}",
        headers=admin_headers,
        json={"port": 443},
    )
    assert updated_asset.status_code == 200, updated_asset.text

    run_two = client.post(
        "/attack-surface/discovery/run",
        headers=admin_headers,
        json={"domains": ["alpha.example.test", "beta.example.test"], "cert_salt": "seed-b"},
    )
    assert run_two.status_code == 200, run_two.text
    second_body = run_two.json()
    run_two_id = int(second_body["run_id"])

    second_drift = client.get(
        f"/attack-surface/drift?run_id={run_two_id}",
        headers=admin_headers,
    )
    assert second_drift.status_code == 200, second_drift.text
    second_drift_types = {
        str(item.get("event_type") or "") for item in second_drift.json().get("items") or []
    }
    assert "new_port" in second_drift_types
    assert "new_subdomain" in second_drift_types
    assert "unexpected_cert_change" in second_drift_types

    relationship = client.post(
        "/attack-surface/relationships",
        headers=admin_headers,
        json={
            "source_asset_key": source_asset,
            "target_asset_key": target_asset,
            "relation_type": "talks_to",
            "confidence": 0.91,
            "details": {"channel": "https"},
        },
    )
    assert relationship.status_code == 201, relationship.text
    assert relationship.json()["relation_type"] == "talks_to"

    relationship_list = client.get(
        f"/attack-surface/relationships?asset_key={source_asset}",
        headers=admin_headers,
    )
    assert relationship_list.status_code == 200, relationship_list.text
    assert any(
        str(item.get("source_asset_key") or "") == source_asset
        and str(item.get("target_asset_key") or "") == target_asset
        for item in relationship_list.json().get("items") or []
    )
