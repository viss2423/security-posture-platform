"""
AI policy evaluation summary tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run: pytest services/api/tests/test_ai_policy_summary.py -q
"""

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

from app.ai_client import AIClientError
from app.db import engine
from app.db_migrate import run_startup_migrations
from app.main import app
from app.routers import ai as ai_router

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; AI policy summary tests require Postgres",
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


def _insert_policy_evaluation() -> tuple[int, int]:
    bundle_name = f"policy-ai-{uuid.uuid4().hex[:8]}"
    result_payload = {
        "bundle_id": None,
        "bundle_name": bundle_name,
        "score": 41.7,
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
                "id": "no-critical",
                "name": "No open critical findings",
                "type": "no_critical_findings",
                "passed": 2,
                "failed": 1,
                "total": 3,
                "pass_pct": 66.7,
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
                    "open_findings": [
                        {"finding_id": 1, "title": "Missing CSP", "severity": "high"}
                    ],
                },
            },
            {
                "rule_id": "min-score",
                "rule_name": "Minimum posture score 80",
                "rule_type": "posture_score_min",
                "asset_key": "juice-shop",
                "timestamp": "2026-03-02T20:00:00Z",
                "bundle_approved_by": "admin",
                "evidence": {
                    "required_min_score": 80,
                    "actual_posture_score": 42,
                    "status": "red",
                },
            },
            {
                "rule_id": "no-critical",
                "rule_name": "No open critical findings",
                "rule_type": "no_critical_findings",
                "asset_key": "edge-api",
                "timestamp": "2026-03-02T20:00:00Z",
                "bundle_approved_by": "admin",
                "evidence": {
                    "severity": "critical",
                    "open_findings": [
                        {"finding_id": 2, "title": "Outdated TLS", "severity": "critical"}
                    ],
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
                    "description": "pytest policy bundle",
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
        return bundle_id, int(evaluation_row["id"])


def test_policy_ai_summary_generate_get_and_cache(client, auth_headers, monkeypatch):
    _bundle_id, evaluation_id = _insert_policy_evaluation()

    monkeypatch.setattr(
        ai_router,
        "generate_text",
        lambda **_kwargs: (
            "1) Overall posture\n"
            "The bundle is failing materially, with repeated header and posture control gaps.\n\n"
            "2) Main failure themes\n"
            "- missing CSP controls\n"
            "- low posture scores\n\n"
            "3) Highest-impact assets\n"
            "- juice-shop\n"
            "- edge-api\n\n"
            "4) Remediation priorities\n"
            "- fix CSP headers\n"
            "- restore assets below minimum posture threshold\n"
        ),
    )

    generated = client.post(
        f"/ai/policy/evaluations/{evaluation_id}/summary/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["evaluation_id"] == evaluation_id
    assert body["cached"] is False
    assert "Overall posture" in body["summary_text"]
    generated_from = body["context_json"]["generated_from"]
    assert generated_from["evaluation"]["score"] == 41.7
    assert len(generated_from["violation_themes"]) >= 2
    assert generated_from["top_assets"][0]["asset_key"] == "juice-shop"

    loaded = client.get(
        f"/ai/policy/evaluations/{evaluation_id}/summary",
        headers=auth_headers,
    )
    assert loaded.status_code == 200, loaded.text
    loaded_body = loaded.json()
    assert loaded_body["summary_text"] == body["summary_text"]

    second = client.post(
        f"/ai/policy/evaluations/{evaluation_id}/summary/generate",
        json={"force": False},
        headers=auth_headers,
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["cached"] is True
    assert second_body["summary_text"] == body["summary_text"]


def test_policy_ai_summary_retries_real_model_when_first_attempt_times_out(
    client, auth_headers, monkeypatch
):
    _bundle_id, evaluation_id = _insert_policy_evaluation()
    calls = {"count": 0}

    def fake_generate_text(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise AIClientError("request timed out")
        return (
            "1) Overall posture\n"
            "The evaluation is below target because multiple controls fail across a small set of assets.\n\n"
            "2) Main failure themes\n"
            "- missing CSP\n"
            "- low posture score\n\n"
            "3) Highest-impact assets\n"
            "- juice-shop\n\n"
            "4) Remediation priorities\n"
            "- fix CSP on juice-shop first\n"
        )

    monkeypatch.setattr(ai_router, "generate_text", fake_generate_text)

    generated = client.post(
        f"/ai/policy/evaluations/{evaluation_id}/summary/generate",
        json={"force": True},
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["evaluation_id"] == evaluation_id
    assert calls["count"] == 2
    assert not body["provider"].endswith("-fallback")
    assert body["model"] != "template-v1"
    assert "Main failure themes" in body["summary_text"]
    generated_from = body["context_json"]["generated_from"]
    assert len(generated_from["failed_rules"]) <= 3
    assert len(generated_from["top_assets"]) <= 3
    assert len(generated_from["sample_violations"]) <= 3
