"""
Finding AI explanation guardrail tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_finding_explanation_guardrails.py -q
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
    reason="POSTGRES_DSN not set; finding explanation guardrail tests require Postgres",
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


def _seed_finding(client: TestClient, headers: dict, prefix: str) -> int:
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
            "owner": "soc",
        },
    )
    assert created_asset.status_code == 200, created_asset.text

    created_finding = client.post(
        "/findings/",
        headers=headers,
        json={
            "asset_key": asset_key,
            "finding_key": f"{asset_key}-finding",
            "title": "Guardrail finding example",
            "severity": "high",
            "confidence": "high",
            "source": "pytest",
            "category": "web_security",
            "evidence": "TLS cert validation missing for external call path.",
            "remediation": "Enable strict certificate validation and deploy pinned trust config.",
        },
    )
    assert created_finding.status_code == 200, created_finding.text
    finding_key = str(created_finding.json().get("finding_key") or f"{asset_key}-finding")

    listed = client.get(f"/findings/?asset_key={asset_key}&limit=50", headers=headers)
    assert listed.status_code == 200, listed.text
    listed_payload = listed.json()
    if isinstance(listed_payload, list):
        items = listed_payload
    elif isinstance(listed_payload, dict):
        items = listed_payload.get("items") or []
    else:
        items = []
    match = next((item for item in items if str(item.get("finding_key") or "") == finding_key), None)
    assert match is not None, f"finding_key {finding_key} not found in listing"
    return int(match["finding_id"])


def test_finding_explanation_guardrails_drop_unknown_evidence(
    client: TestClient,
    admin_headers: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    finding_id = _seed_finding(client, admin_headers, "ai-finding-guardrail")

    def _fake_generate_text(*_args, **_kwargs) -> str:
        return json.dumps(
            {
                "facts": [{"statement": "Finding is high severity.", "evidence": ["E1"]}],
                "inference": [
                    {"statement": "Unsupported claim should be removed.", "evidence": ["E999"]}
                ],
                "recommendations": [
                    {"statement": "Apply remediation and verify.", "evidence": ["E2"]}
                ],
            }
        )

    monkeypatch.setattr(ai_router_module, "generate_text", _fake_generate_text)

    generated = client.post(
        f"/ai/findings/{finding_id}/explain",
        headers=admin_headers,
        json={"force": True},
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert "Facts" in (body.get("explanation_text") or "")

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "finding_grounded_v1"
    sections = guardrails.get("sections") or {}
    inference_items = sections.get("inference") or []
    assert all(
        "E999" not in [str(e).strip().upper() for e in (item.get("evidence") or [])]
        for item in inference_items
    )


def test_finding_explanation_guardrails_fallback_on_invalid_ai_output(
    client: TestClient,
    admin_headers: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    finding_id = _seed_finding(client, admin_headers, "ai-finding-guardrail-fallback")

    def _fake_generate_text(*_args, **_kwargs) -> str:
        return "not-json-response"

    monkeypatch.setattr(ai_router_module, "generate_text", _fake_generate_text)

    generated = client.post(
        f"/ai/findings/{finding_id}/explain",
        headers=admin_headers,
        json={"force": True},
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body.get("provider", "").endswith("-guarded")

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "finding_grounded_v1"
    assert guardrails.get("used_fallback_sections") is True
    assert isinstance(guardrails.get("evidence_catalog"), list)
