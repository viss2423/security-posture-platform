"""
Incident AI summary guardrail tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_incident_summary_guardrails.py -q
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import app.routers.ai as ai_router_module
from app.db_migrate import run_startup_migrations
from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; incident summary guardrail tests require Postgres",
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


def _seed_incident(client: TestClient, headers: dict, prefix: str) -> int:
    asset_key = f"{prefix}-{uuid.uuid4().hex[:8]}"
    created_asset = client.post(
        "/assets/",
        headers=headers,
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
        headers=headers,
        json={
            "title": f"Guardrail test {asset_key}",
            "severity": "high",
            "asset_keys": [asset_key],
        },
    )
    assert created_incident.status_code == 201, created_incident.text
    return int(created_incident.json()["id"])


def test_incident_summary_guardrails_drop_unknown_evidence(
    client: TestClient,
    admin_headers: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    incident_id = _seed_incident(client, admin_headers, "ai-guardrail")

    def _fake_generate_text(*_args, **_kwargs) -> str:
        return json.dumps(
            {
                "facts": [{"statement": "Incident is high severity.", "evidence": ["E1"]}],
                "inference": [
                    {"statement": "Unsupported claim should be removed.", "evidence": ["E999"]}
                ],
                "recommendations": [
                    {"statement": "Confirm scope and ownership.", "evidence": ["E2"]}
                ],
            }
        )

    monkeypatch.setattr(ai_router_module, "generate_text", _fake_generate_text)

    generated = client.post(
        f"/ai/incidents/{incident_id}/summary/generate",
        headers=admin_headers,
        json={"force": True},
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert "Facts" in (body.get("summary_text") or "")

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    sections = guardrails.get("sections") or {}
    inference_items = sections.get("inference") or []
    assert all(
        "E999" not in [str(e).strip().upper() for e in (item.get("evidence") or [])]
        for item in inference_items
    )


def test_incident_summary_guardrails_fallback_on_invalid_ai_output(
    client: TestClient,
    admin_headers: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    incident_id = _seed_incident(client, admin_headers, "ai-guardrail-fallback")

    def _fake_generate_text(*_args, **_kwargs) -> str:
        return "not-json-response"

    monkeypatch.setattr(ai_router_module, "generate_text", _fake_generate_text)

    generated = client.post(
        f"/ai/incidents/{incident_id}/summary/generate",
        headers=admin_headers,
        json={"force": True},
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body.get("provider", "").endswith("-guarded")

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "incident_grounded_v1"
    assert guardrails.get("used_fallback_sections") is True
    assert isinstance(guardrails.get("evidence_catalog"), list)
