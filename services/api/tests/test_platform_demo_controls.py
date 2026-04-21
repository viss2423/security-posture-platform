from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if POSTGRES_DSN:
    from app.alerts_v2 import upsert_security_alert
    from app.db import SessionLocal
    from app.db_migrate import run_startup_migrations
    from app.main import app
else:
    app = None
    SessionLocal = None
    upsert_security_alert = None

    def run_startup_migrations():
        return None


pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; demo control tests require Postgres",
)


@pytest.fixture()
def client():
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        test_client.close()


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    try:
        run_startup_migrations()
    except Exception as exc:
        pytest.skip(f"Postgres not reachable for demo control tests: {exc}")


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post("/auth/login", data={"username": username, "password": password})
    if response.status_code != 200:
        pytest.skip(f"Login failed for {username}: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_headers(client):
    return _login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )


@pytest.fixture()
def viewer_headers(client):
    return _login(client, "viewer", "viewer")


def test_demo_status_requires_auth(client):
    response = client.get("/platform/demo/status")
    assert response.status_code == 401


def test_demo_seed_and_status_expose_baseline(client, admin_headers):
    seed = client.post("/platform/demo/seed", headers=admin_headers, json={"force": True})
    assert seed.status_code == 200, seed.text
    payload = seed.json()["result"]
    assert payload["seeded"] is True
    assert payload["asset_key"]
    assert payload["repo_asset_key"]
    assert int(payload["attack_lab_run_id"]) > 0

    status = client.get("/platform/demo/status", headers=admin_headers)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["seeded"] is True
    assert body["assets_present"] >= 2
    assert body["telemetry_events"] >= 1
    assert body["attack_lab_runs"] >= 1
    assert body["detection_rule"] is not None
    assert body["latest_seed_at"] is not None


def test_demo_reset_reseeds_without_admin_forbidden(client, viewer_headers, admin_headers):
    forbidden = client.post("/platform/demo/reset", headers=viewer_headers)
    assert forbidden.status_code == 403

    reset = client.post("/platform/demo/reset", headers=admin_headers)
    assert reset.status_code == 200, reset.text
    body = reset.json()
    assert body["reset"] is True
    assert body["requested_by"] == os.getenv("ADMIN_USERNAME", "admin")
    assert body["seed"]["seeded"] is True
    cleanup = body["cleanup"]
    assert "assets" in cleanup
    assert "security_events" in cleanup

    status = client.get("/platform/demo/status", headers=admin_headers)
    assert status.status_code == 200, status.text
    status_body = status.json()
    assert status_body["seeded"] is True
    assert status_body["assets_present"] >= 2
    assert status_body["attack_lab_runs"] >= 1


def test_demo_reset_cleans_curated_site_noise(client, admin_headers):
    probe_asset_key = "ai-feedback-cleanup-probe"
    attack_lab_asset_key = "attack-lab-asset-cleanup-probe"
    create_asset = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": probe_asset_key,
            "type": "external_web",
            "name": "cleanup-probe.example.test",
            "owner": "pytest",
            "environment": "dev",
            "criticality": "low",
            "address": "cleanup-probe.example.test",
        },
    )
    assert create_asset.status_code == 200, create_asset.text

    create_attack_lab_asset = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": attack_lab_asset_key,
            "type": "app",
            "name": "attack-lab-cleanup.example.test",
            "owner": "pytest",
            "environment": "dev",
            "criticality": "low",
            "address": "http://verify-web",
        },
    )
    assert create_attack_lab_asset.status_code == 200, create_attack_lab_asset.text

    db = SessionLocal()
    try:
        db.execute(text("SELECT set_config('secplat.tenant_id', 'default', false)"))
        alert = upsert_security_alert(
            db,
            source="pytest-cleanup",
            title="Cleanup probe alert",
            description="Synthetic alert that should not survive demo reset.",
            dedupe_key=f"cleanup:{probe_asset_key}",
            severity="medium",
            asset_key=probe_asset_key,
            context_json={"probe": True},
        )
        incident_id = int(
            db.execute(
                text(
                    """
                    INSERT INTO incidents(title, severity, status, metadata)
                    VALUES (:title, 'medium', 'new', '{}'::jsonb)
                    RETURNING id
                    """
                ),
                {"title": f"AI feedback incident {probe_asset_key}"},
            ).scalar_one()
        )
        db.execute(
            text(
                """
                INSERT INTO incident_alerts(incident_id, asset_key, added_by, alert_id, org_id)
                VALUES (:incident_id, :asset_key, 'pytest', :alert_id, 'default')
                """
            ),
            {
                "incident_id": incident_id,
                "asset_key": probe_asset_key,
                "alert_id": int(alert["alert_id"]),
            },
        )
        db.execute(
            text(
                """
                INSERT INTO threat_iocs(
                  source, indicator, indicator_type, feed_url, is_active, metadata
                )
                VALUES (:source, 'bad.example', 'domain', NULL, TRUE, '{}'::jsonb)
                ON CONFLICT (source, indicator_type, indicator) DO NOTHING
                """
            ),
            {"source": "pytest-feed-cleanup-probe"},
        )
        db.execute(
            text(
                """
                INSERT INTO threat_ioc_campaigns(campaign_tag, title, description, created_by)
                VALUES (
                  'pytest-campaign-cleanup-probe',
                  'Pytest cleanup campaign',
                  'Synthetic threat-intel campaign that should be removed.',
                  'pytest'
                )
                ON CONFLICT (campaign_tag) DO NOTHING
                """
            )
        )
        db.execute(
            text(
                """
                INSERT INTO incidents(title, severity, status, metadata)
                VALUES ('Collaboration endpoint test', 'medium', 'new', '{}'::jsonb)
                """
            )
        )
        db.execute(
            text(
                """
                INSERT INTO threat_iocs(
                  source, indicator, indicator_type, feed_url, is_active, metadata
                )
                VALUES (:source, 'cleanup.openphish.test', 'domain', NULL, TRUE, '{}'::jsonb)
                ON CONFLICT (source, indicator_type, indicator) DO NOTHING
                """
            ),
            {"source": "openphish-urls-cleanup-probe"},
        )
        db.commit()
    finally:
        db.close()

    reset = client.post("/platform/demo/reset", headers=admin_headers)
    assert reset.status_code == 200, reset.text
    payload = reset.json()
    assert payload["seed"]["seeded"] is True
    assert payload["cleanup"]["assets"] >= 1
    assert payload["cleanup"]["security_alerts"] >= 1
    assert payload["cleanup"]["incidents"] >= 1
    assert payload["cleanup"]["threat_iocs"] >= 1
    assert payload["cleanup"]["threat_ioc_campaigns"] >= 1

    db = SessionLocal()
    try:
        db.execute(text("SELECT set_config('secplat.tenant_id', 'default', false)"))
        remaining_asset = db.execute(
            text("SELECT 1 FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": probe_asset_key},
        ).first()
        remaining_attack_lab_asset = db.execute(
            text("SELECT 1 FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": attack_lab_asset_key},
        ).first()
        remaining_incident = db.execute(
            text("SELECT 1 FROM incidents WHERE title = :title"),
            {"title": f"AI feedback incident {probe_asset_key}"},
        ).first()
        remaining_collaboration_incident = db.execute(
            text("SELECT 1 FROM incidents WHERE title = 'Collaboration endpoint test'"),
        ).first()
        remaining_ioc = db.execute(
            text("SELECT 1 FROM threat_iocs WHERE source = :source"),
            {"source": "pytest-feed-cleanup-probe"},
        ).first()
        remaining_openphish_ioc = db.execute(
            text("SELECT 1 FROM threat_iocs WHERE source = :source"),
            {"source": "openphish-urls-cleanup-probe"},
        ).first()
        remaining_campaign = db.execute(
            text("SELECT 1 FROM threat_ioc_campaigns WHERE campaign_tag = :campaign_tag"),
            {"campaign_tag": "pytest-campaign-cleanup-probe"},
        ).first()
    finally:
        db.close()

    assert remaining_asset is None
    assert remaining_attack_lab_asset is None
    assert remaining_incident is None
    assert remaining_collaboration_incident is None
    assert remaining_ioc is None
    assert remaining_openphish_ioc is None
    assert remaining_campaign is None
