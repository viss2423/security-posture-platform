"""
AI policy evaluation summary guardrail tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_policy_summary_guardrails.py -q
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.db import engine
from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import ai as ai_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; AI policy summary guardrail tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    run_startup_migrations()


@pytest.fixture(scope="module")
def auth_headers(client):
    response = client.post(
        "/auth/login",
        data={
            "username": os.getenv("ADMIN_USERNAME", "admin"),
            "password": os.getenv("ADMIN_PASSWORD", "admin"),
        },
    )
    if response.status_code != 200:
        pytest.skip(f"Login failed: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


def _insert_policy_evaluation() -> int:
    bundle_name = f"policy-guardrail-{uuid.uuid4().hex[:8]}"
    result_payload = {
        "bundle_id": None,
        "bundle_name": bundle_name,
        "score": 39.5,
        "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "bundle_approved_by": "admin",
        "rules": [
            {
                "id": "csp-required",
                "name": "CSP header required",
                "type": "require_header",
                "passed": 1,
                "failed": 2,
                "total": 3,
                "pass_pct": 33.3,
            },
            {
                "id": "min-score",
                "name": "Minimum posture score 80",
                "type": "posture_score_min",
                "passed": 1,
                "failed": 2,
                "total": 3,
                "pass_pct": 33.3,
            },
        ],
        "violations": [
            {
                "rule_id": "csp-required",
                "rule_name": "CSP header required",
                "rule_type": "require_header",
                "asset_key": "juice-shop",
                "timestamp": "2026-03-02T20:00:00Z",
                "bundle_approved_by": "admin",
                "evidence": {
                    "required_header": "content-security-policy",
                },
            },
            {
                "rule_id": "min-score",
                "rule_name": "Minimum posture score 80",
                "rule_type": "posture_score_min",
                "asset_key": "edge-api",
                "timestamp": "2026-03-02T20:00:00Z",
                "bundle_approved_by": "admin",
                "evidence": {
                    "required_min_score": 80,
                    "actual_posture_score": 42,
                },
            },
        ],
    }

    with engine.begin() as conn:
        bundle_row = (
            conn.execute(
                text(
                    """
                    INSERT INTO policy_bundles (name, description, definition, status, approved_at, approved_by)
                    VALUES (:name, :description, :definition, 'approved', NOW(), 'admin')
                    RETURNING id
                    """
                ),
                {
                    "name": bundle_name,
                    "description": "pytest policy guardrail bundle",
                    "definition": "rules: []",
                },
            )
            .mappings()
            .first()
        )
        assert bundle_row is not None
        bundle_id = int(bundle_row["id"])
        result_payload["bundle_id"] = bundle_id
        evaluation_row = (
            conn.execute(
                text(
                    """
                    INSERT INTO policy_evaluation_runs (
                      bundle_id,
                      evaluated_by,
                      bundle_approved_by,
                      score,
                      violations_count,
                      result_json
                    )
                    VALUES (
                      :bundle_id,
                      'admin',
                      'admin',
                      :score,
                      :violations_count,
                      CAST(:result_json AS jsonb)
                    )
                    RETURNING id
                    """
                ),
                {
                    "bundle_id": bundle_id,
                    "score": result_payload["score"],
                    "violations_count": len(result_payload["violations"]),
                    "result_json": json.dumps(result_payload),
                },
            )
            .mappings()
            .first()
        )
        assert evaluation_row is not None
        return int(evaluation_row["id"])


def test_policy_summary_guardrails_drop_unknown_evidence(
    client: TestClient, auth_headers: dict, monkeypatch: pytest.MonkeyPatch
):
    evaluation_id = _insert_policy_evaluation()
    monkeypatch.setattr(
        ai_router,
        "generate_text",
        lambda **_kwargs: json.dumps(
            {
                "facts": [
                    {
                        "statement": "Evaluation score is below target with multiple violations.",
                        "evidence": ["E1"],
                    }
                ],
                "inference": [
                    {
                        "statement": "Unsupported claim should be dropped.",
                        "evidence": ["E999"],
                    }
                ],
                "recommendations": [
                    {
                        "statement": "Prioritize remediation on top failing controls.",
                        "evidence": ["E2"],
                    }
                ],
            }
        ),
    )

    generated = client.post(
        f"/ai/policy/evaluations/{evaluation_id}/summary/generate",
        json={"force": True},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "policy_evaluation_grounded_v1"
    sections = guardrails.get("sections") or {}
    inference_items = sections.get("inference") or []
    assert all(
        "E999" not in [str(e).strip().upper() for e in (item.get("evidence") or [])]
        for item in inference_items
    )


def test_policy_summary_guardrails_fallback_on_invalid_output(
    client: TestClient, auth_headers: dict, monkeypatch: pytest.MonkeyPatch
):
    evaluation_id = _insert_policy_evaluation()
    monkeypatch.setattr(ai_router, "generate_text", lambda **_kwargs: "not-json-response")

    generated = client.post(
        f"/ai/policy/evaluations/{evaluation_id}/summary/generate",
        json={"force": True},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body.get("provider", "").endswith("-guarded")
    assert "Facts" in body.get("summary_text", "")

    guardrails = (body.get("context_json") or {}).get("guardrails") or {}
    assert guardrails.get("mode") == "policy_evaluation_grounded_v1"
    assert guardrails.get("parse_mode") == "fallback"
    assert guardrails.get("used_fallback_sections") is True
