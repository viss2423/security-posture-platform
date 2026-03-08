"""
AI feedback and summary versioning API tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_feedback_routes.py -q
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
    reason="POSTGRES_DSN not set; AI feedback tests require Postgres",
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
    return _login(
        client,
        os.getenv("VIEWER_USERNAME", "viewer"),
        os.getenv("VIEWER_PASSWORD", "viewer"),
    )


def test_ai_summary_versions_and_feedback(client: TestClient, admin_headers: dict):
    asset_key = f"ai-feedback-{uuid.uuid4().hex[:8]}"
    created_asset = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "high",
        },
    )
    assert created_asset.status_code == 200, created_asset.text

    created_incident = client.post(
        "/incidents",
        headers=admin_headers,
        json={
            "title": f"AI feedback incident {asset_key}",
            "severity": "high",
            "asset_keys": [asset_key],
        },
    )
    assert created_incident.status_code == 201, created_incident.text
    incident_id = int(created_incident.json()["id"])

    first_created_version = client.post(
        f"/ai/summaries/incident/{incident_id}/versions",
        headers=admin_headers,
        json={
            "content_text": f"Initial summary for incident {incident_id}",
            "source_type": "seeded",
            "evidence_json": {"source": "pytest-initial"},
        },
    )
    assert first_created_version.status_code == 201, first_created_version.text
    version_id = int(first_created_version.json()["version_id"])
    version_no = int(first_created_version.json()["version_no"])

    created_version = client.post(
        f"/ai/summaries/incident/{incident_id}/versions",
        headers=admin_headers,
        json={
            "content_text": f"Analyst-edited summary for incident {incident_id}",
            "source_type": "regenerate",
            "evidence_json": {"source": "pytest"},
        },
    )
    assert created_version.status_code == 201, created_version.text
    created_version_body = created_version.json()
    assert int(created_version_body["version_no"]) == version_no + 1

    versions = client.get(
        f"/ai/summaries/incident/{incident_id}/versions",
        headers=admin_headers,
    )
    assert versions.status_code == 200, versions.text
    assert len(versions.json().get("items") or []) >= 2

    compared = client.get(
        f"/ai/summaries/incident/{incident_id}/versions/compare?from_version={version_no}&to_version={version_no + 1}",
        headers=admin_headers,
    )
    assert compared.status_code == 200, compared.text
    assert "word_delta" in compared.json()

    feedback = client.post(
        "/ai/feedback",
        headers=admin_headers,
        json={
            "entity_type": "incident",
            "entity_id": str(incident_id),
            "version_id": version_id,
            "feedback": "up",
            "comment": "Summary was useful for triage",
            "context_json": {"channel": "pytest"},
        },
    )
    assert feedback.status_code == 201, feedback.text
    feedback_id = int(feedback.json()["feedback_id"])

    listed_feedback = client.get(
        f"/ai/feedback?entity_type=incident&entity_id={incident_id}",
        headers=admin_headers,
    )
    assert listed_feedback.status_code == 200, listed_feedback.text
    assert any(
        int(item.get("feedback_id") or 0) == feedback_id
        for item in listed_feedback.json().get("items") or []
    )

    one_feedback = client.get(f"/ai/feedback/{feedback_id}", headers=admin_headers)
    assert one_feedback.status_code == 200, one_feedback.text
    assert one_feedback.json()["feedback"] == "up"


def test_ai_feedback_mutations_require_analyst_or_admin(
    client: TestClient,
    admin_headers: dict,
    viewer_headers: dict,
):
    asset_key = f"ai-feedback-rbac-{uuid.uuid4().hex[:8]}"
    created_asset = client.post(
        "/assets/",
        headers=admin_headers,
        json={
            "asset_key": asset_key,
            "type": "app",
            "name": f"{asset_key}.example.test",
            "environment": "prod",
            "criticality": "medium",
        },
    )
    assert created_asset.status_code == 200, created_asset.text

    created_incident = client.post(
        "/incidents",
        headers=admin_headers,
        json={
            "title": f"AI feedback RBAC incident {asset_key}",
            "severity": "medium",
            "asset_keys": [asset_key],
        },
    )
    assert created_incident.status_code == 201, created_incident.text
    incident_id = int(created_incident.json()["id"])

    denied_version = client.post(
        f"/ai/summaries/incident/{incident_id}/versions",
        headers=viewer_headers,
        json={
            "content_text": "viewer attempt",
            "source_type": "manual",
        },
    )
    assert denied_version.status_code == 403, denied_version.text

    denied_feedback = client.post(
        "/ai/feedback",
        headers=viewer_headers,
        json={
            "entity_type": "incident",
            "entity_id": str(incident_id),
            "feedback": "up",
            "comment": "viewer should be read-only",
        },
    )
    assert denied_feedback.status_code == 403, denied_feedback.text
