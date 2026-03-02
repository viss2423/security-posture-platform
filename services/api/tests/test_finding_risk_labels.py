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
    reason="POSTGRES_DSN not set; finding risk label tests require Postgres",
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


def _create_finding(client: TestClient, admin_headers: dict) -> int:
    finding_key = f"risk-label-{int(time.time())}"
    created = client.post(
        "/findings/",
        headers=admin_headers,
        json={
            "asset_key": "secplat-api",
            "finding_key": finding_key,
            "title": "finding to label",
            "severity": "medium",
            "confidence": "high",
            "source": "pytest",
        },
    )
    assert created.status_code == 200, created.text

    rows = client.get("/findings/?limit=200", headers=admin_headers)
    assert rows.status_code == 200, rows.text
    finding = next((item for item in rows.json() if item.get("finding_key") == finding_key), None)
    assert finding is not None
    return int(finding["finding_id"])


def test_finding_risk_labels_can_be_created_and_listed(client, admin_headers, viewer_headers):
    finding_id = _create_finding(client, admin_headers)

    denied = client.post(
        f"/findings/{finding_id}/risk-labels",
        headers=viewer_headers,
        json={"label": "incident_worthy"},
    )
    assert denied.status_code == 403

    created = client.post(
        f"/findings/{finding_id}/risk-labels",
        headers=admin_headers,
        json={
            "label": "incident_worthy",
            "source": "analyst",
            "note": "Escalated during investigation",
        },
    )
    assert created.status_code == 200, created.text
    payload = created.json()
    assert payload["finding_id"] == finding_id
    assert payload["label"] == "incident_worthy"
    assert payload["source"] == "analyst"

    listed = client.get(f"/findings/{finding_id}/risk-labels", headers=viewer_headers)
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    assert len(items) >= 1
    assert items[0]["label"] == "incident_worthy"
    assert items[0]["created_by"] == os.getenv("ADMIN_USERNAME", "admin")
