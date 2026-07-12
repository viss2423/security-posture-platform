"""AWS workspace-scan isolation tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run in the Docker api container (Python 3.11):
  docker compose exec api pytest tests/test_aws_workspace_scan.py -q

Coverage:
  (a) /workspace/connect with provider="aws" rejects malformed AWS creds (non-JSON,
      missing access_key_id/secret_access_key) with 400 and persists nothing
  (b) /workspace/scans with provider="aws" returns 404 when credential_id belongs to
      a different workspace's tenant (RLS isolation) or to a github credential
  (c) A successful AWS scan enqueues an aws_iam_posture job whose job_params_json has
      credential_id + validated region, org_id = caller's workspace
  (d) run_aws_iam_posture_job with a credential_id calls _iam_client with the decrypted
      per-workspace credential (mock boto3, assert the injected keys match what was
      stored, and assert server-side AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are NOT used)
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if POSTGRES_DSN:
    from app.db import SessionLocal, engine
    from app.db_migrate import run_startup_migrations
    from app.main import app
    from app.request_context import tenant_id_ctx
    from app.settings import settings
else:
    SessionLocal = None
    engine = None
    app = None
    tenant_id_ctx = None
    settings = None

    def run_startup_migrations():
        return None


pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; AWS workspace-scan tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    try:
        run_startup_migrations()
    except Exception as exc:
        pytest.skip(f"Postgres not reachable for AWS workspace-scan tests: {exc}")


async def _allow_all_rate_limits(*_args, **_kwargs):
    return True


@pytest.fixture(autouse=True)
def _disable_rate_limits(monkeypatch):
    """Disable rate limiting during tests — multiple user registrations in quick
    succession would otherwise hit the 429 threshold."""
    monkeypatch.setattr("app.routers.workspace.check_rate_limit", _allow_all_rate_limits)
    monkeypatch.setattr("app.routers.auth.check_rate_limit", _allow_all_rate_limits)


# ---------------------------------------------------------------------------
# Auth helpers (same pattern as test_repository_scan_routes.py)
# ---------------------------------------------------------------------------
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


def _register_and_login(client: TestClient, username: str, password: str) -> dict:
    """Register a new self-serve user and return auth headers (viewer token, no ws claim)."""
    reg = client.post("/auth/register", json={"username": username, "password": password})
    if reg.status_code == 403:
        pytest.skip("Self-registration is disabled (ALLOW_SELF_REGISTRATION)")
    assert reg.status_code == 200, f"Register failed: {reg.status_code} {reg.text}"
    return _login(client, username, password)


# ---------------------------------------------------------------------------
# AWS credential payloads (valid, session-token variant, and malformed)
# ---------------------------------------------------------------------------
_VALID_AWS_CREDENTIAL = json.dumps(
    {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)

_VALID_AWS_CREDENTIAL_WITH_SESSION = json.dumps(
    {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "session_token": "FQoGZXIvYXdzE...",
    }
)


def _credential_count() -> int:
    """Count user_credentials rows visible on the current tenant (RLS-scoped)."""
    with engine.begin() as conn:
        row = conn.execute(text("SELECT count(*) AS n FROM user_credentials")).mappings().first()
    return int(row["n"]) if row else 0


# ===========================================================================
# (a) /workspace/connect — malformed AWS credentials rejected with 400
# ===========================================================================
def test_connect_aws_rejects_non_json_input(client, admin_headers):
    """Non-JSON token body → 400; nothing persisted."""
    before = _credential_count()
    resp = client.post(
        "/workspace/connect",
        headers=admin_headers,
        json={"provider": "aws", "token": "not-json-at-all"},
    )
    assert resp.status_code == 400, resp.text
    err_detail = resp.json()["error"]["detail"].lower()
    assert "aws credentials must be a json object" in err_detail
    assert _credential_count() == before


def test_connect_aws_rejects_json_without_access_key_id(client, admin_headers):
    """JSON body missing access_key_id → 400."""
    before = _credential_count()
    resp = client.post(
        "/workspace/connect",
        headers=admin_headers,
        json={
            "provider": "aws",
            "token": json.dumps({"secret_access_key": "somekey"}),
        },
    )
    assert resp.status_code == 400, resp.text
    assert "access_key_id" in resp.json()["error"]["detail"].lower()
    assert _credential_count() == before


def test_connect_aws_rejects_json_without_secret_access_key(client, admin_headers):
    """JSON body missing secret_access_key → 400."""
    before = _credential_count()
    resp = client.post(
        "/workspace/connect",
        headers=admin_headers,
        json={
            "provider": "aws",
            "token": json.dumps({"access_key_id": "AKIAIOSFODNN7EXAMPLE"}),
        },
    )
    assert resp.status_code == 400, resp.text
    assert "secret_access_key" in resp.json()["error"]["detail"].lower()
    assert _credential_count() == before


def test_connect_aws_rejects_empty_required_fields(client, admin_headers):
    """JSON body with empty access_key_id or secret_access_key → 400."""
    before = _credential_count()
    resp = client.post(
        "/workspace/connect",
        headers=admin_headers,
        json={
            "provider": "aws",
            "token": json.dumps({"access_key_id": "", "secret_access_key": "x"}),
        },
    )
    assert resp.status_code == 400, resp.text

    resp2 = client.post(
        "/workspace/connect",
        headers=admin_headers,
        json={
            "provider": "aws",
            "token": json.dumps({"access_key_id": "x", "secret_access_key": ""}),
        },
    )
    assert resp2.status_code == 400, resp2.text

    # Also verify an empty object is rejected
    resp3 = client.post(
        "/workspace/connect",
        headers=admin_headers,
        json={
            "provider": "aws",
            "token": json.dumps({}),
        },
    )
    assert resp3.status_code == 400, resp3.text

    assert _credential_count() == before


# ===========================================================================
# (b) /workspace/scans — RLS isolation (wrong workspace / wrong provider)
# ===========================================================================
def test_scans_aws_404_when_credential_belongs_to_other_workspace(client, monkeypatch):
    """Workspace-B cannot scan workspace-A's AWS credential (RLS isolation)."""
    monkeypatch.setattr("app.routers.workspace.launch_aws_iam_posture_job", lambda job_id: None)

    # Workspace A: register, connect AWS, get ws-pinned analyst token
    user_a = f"aws-iso-a-{uuid.uuid4().hex[:10]}"
    headers_a = _register_and_login(client, user_a, "testpass-a-123!X")

    connect_a = client.post(
        "/workspace/connect",
        headers=headers_a,
        json={"provider": "aws", "token": _VALID_AWS_CREDENTIAL, "label": "ws-a"},
    )
    assert connect_a.status_code == 200, connect_a.text
    ws_a_token = {"Authorization": f"Bearer {connect_a.json()['access_token']}"}
    cred_id_a = int(connect_a.json()["credential_id"])

    # Workspace B: register, connect AWS (separate workspace)
    user_b = f"aws-iso-b-{uuid.uuid4().hex[:10]}"
    headers_b = _register_and_login(client, user_b, "testpass-b-456!Y")

    connect_b = client.post(
        "/workspace/connect",
        headers=headers_b,
        json={"provider": "aws", "token": _VALID_AWS_CREDENTIAL, "label": "ws-b"},
    )
    assert connect_b.status_code == 200, connect_b.text
    ws_b_token = {"Authorization": f"Bearer {connect_b.json()['access_token']}"}

    # Workspace B tries to scan Workspace A's credential → 404 (RLS isolation)
    cross = client.post(
        "/workspace/scans",
        headers=ws_b_token,
        json={"provider": "aws", "credential_id": cred_id_a},
    )
    assert cross.status_code == 404, cross.text
    assert "credential not found" in cross.json()["error"]["detail"].lower()

    # Workspace A can still scan its own credential (sanity check — RLS is not
    # blocking legitimate access)
    own = client.post(
        "/workspace/scans",
        headers=ws_a_token,
        json={"provider": "aws", "credential_id": cred_id_a},
    )
    assert own.status_code == 200, own.text
    assert own.json()["provider"] == "aws"


def test_scans_aws_404_when_credential_is_github(client, monkeypatch):
    """provider='aws' with a github credential_id → 404 (wrong provider)."""
    monkeypatch.setattr("app.routers.workspace.launch_github_posture_job", lambda job_id: None)
    monkeypatch.setattr("app.routers.workspace.launch_aws_iam_posture_job", lambda job_id: None)

    user = f"aws-gh-mix-{uuid.uuid4().hex[:10]}"
    headers = _register_and_login(client, user, "testpass-ghmix-789!Z")

    # Connect a GitHub credential first
    connect_gh = client.post(
        "/workspace/connect",
        headers=headers,
        json={
            "provider": "github",
            "token": "ghp_fakePAT1234567890abcdefghijklmnop",
            "label": "gh-cred",
        },
    )
    assert connect_gh.status_code == 200, connect_gh.text
    ws_token = {"Authorization": f"Bearer {connect_gh.json()['access_token']}"}
    gh_cred_id = int(connect_gh.json()["credential_id"])

    # Also connect an AWS credential for the same workspace so the tenant and user
    # are fully set up for scanning
    connect_aws = client.post(
        "/workspace/connect",
        headers=ws_token,
        json={"provider": "aws", "token": _VALID_AWS_CREDENTIAL, "label": "aws-cred"},
    )
    assert connect_aws.status_code == 200, connect_aws.text
    ws_token = {"Authorization": f"Bearer {connect_aws.json()['access_token']}"}

    # Try scanning with provider="aws" but passing the github credential_id → 404
    resp = client.post(
        "/workspace/scans",
        headers=ws_token,
        json={"provider": "aws", "credential_id": gh_cred_id},
    )
    assert resp.status_code == 404, resp.text
    assert "credential not found" in resp.json()["error"]["detail"].lower()

    # Sanity: scanning with provider="github" and the github credential_id works
    github_scan = client.post(
        "/workspace/scans",
        headers=ws_token,
        json={
            "provider": "github",
            "credential_id": gh_cred_id,
            "scope_type": "user",
        },
    )
    assert github_scan.status_code == 200, github_scan.text
    assert github_scan.json()["provider"] == "github"


# ===========================================================================
# (c) Successful AWS scan enqueues correct job params
# ===========================================================================
def test_successful_aws_scan_enqueues_correct_job_params(client, monkeypatch):
    """job_params_json has credential_id + region; org_id = caller's workspace."""
    launched: list[int] = []
    monkeypatch.setattr(
        "app.routers.workspace.launch_aws_iam_posture_job",
        lambda job_id: launched.append(job_id),
    )

    user = f"aws-scan-{uuid.uuid4().hex[:10]}"
    headers = _register_and_login(client, user, "testpass-scan-000!W")

    connect = client.post(
        "/workspace/connect",
        headers=headers,
        json={
            "provider": "aws",
            "token": _VALID_AWS_CREDENTIAL,
            "label": "scan-test",
        },
    )
    assert connect.status_code == 200, connect.text
    body = connect.json()
    ws_token = {"Authorization": f"Bearer {body['access_token']}"}
    cred_id = int(body["credential_id"])
    workspace_id = body["workspace_id"]
    assert workspace_id.startswith("ws_"), f"unexpected workspace_id: {workspace_id}"

    # Run a scan with an explicit region via `scope`
    resp = client.post(
        "/workspace/scans",
        headers=ws_token,
        json={
            "provider": "aws",
            "credential_id": cred_id,
            "scope": "eu-west-1",
        },
    )
    assert resp.status_code == 200, resp.text
    scan_body = resp.json()
    job_id = int(scan_body["job_id"])
    assert scan_body["status"] == "queued"
    assert scan_body["provider"] == "aws"
    assert launched == [job_id]

    # Verify the persisted job row directly. The job was written under the
    # workspace tenant, so bind the same tenant before reading back.
    ctx_token = tenant_id_ctx.set(workspace_id)
    try:
        with engine.begin() as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT job_type, job_params_json, org_id FROM scan_jobs WHERE job_id = :jid"
                    ),
                    {"jid": job_id},
                )
                .mappings()
                .first()
            )
        assert row is not None, "job row not found in scan_jobs — RLS may have filtered it"
        assert row["job_type"] == "aws_iam_posture"
        params = row["job_params_json"]
        if isinstance(params, str):
            params = json.loads(params)
        assert (
            int(params["credential_id"]) == cred_id
        ), f"credential_id mismatch: {params.get('credential_id')} != {cred_id}"
        assert params["region"] == "eu-west-1", f"region mismatch: {params.get('region')}"
        # org_id must be the caller's workspace, not the shared default tenant
        assert row["org_id"] == workspace_id, f"org_id mismatch: {row['org_id']} != {workspace_id}"
    finally:
        tenant_id_ctx.reset(ctx_token)

    # Region validation: an invalid region is rejected before any job is created
    bad = client.post(
        "/workspace/scans",
        headers=ws_token,
        json={
            "provider": "aws",
            "credential_id": cred_id,
            "scope": "invalid region!!!",
        },
    )
    assert bad.status_code == 400, bad.text
    assert "region" in bad.json()["error"]["detail"].lower()


def test_successful_aws_scan_defaults_region_when_scope_omitted(client, monkeypatch):
    """When scope is omitted, region falls back to AWS_REGION (us-east-1) default."""
    launched: list[int] = []
    monkeypatch.setattr(
        "app.routers.workspace.launch_aws_iam_posture_job",
        lambda job_id: launched.append(job_id),
    )

    user = f"aws-defreg-{uuid.uuid4().hex[:10]}"
    headers = _register_and_login(client, user, "testpass-defreg-111!V")

    connect = client.post(
        "/workspace/connect",
        headers=headers,
        json={"provider": "aws", "token": _VALID_AWS_CREDENTIAL},
    )
    assert connect.status_code == 200, connect.text
    ws_token = {"Authorization": f"Bearer {connect.json()['access_token']}"}
    cred_id = int(connect.json()["credential_id"])
    workspace_id = connect.json()["workspace_id"]

    # Omit scope entirely
    resp = client.post(
        "/workspace/scans",
        headers=ws_token,
        json={"provider": "aws", "credential_id": cred_id},
    )
    assert resp.status_code == 200, resp.text
    job_id = int(resp.json()["job_id"])

    ctx_token = tenant_id_ctx.set(workspace_id)
    try:
        with engine.begin() as conn:
            row = (
                conn.execute(
                    text("SELECT job_params_json FROM scan_jobs WHERE job_id = :jid"),
                    {"jid": job_id},
                )
                .mappings()
                .first()
            )
    finally:
        tenant_id_ctx.reset(ctx_token)
    params = row["job_params_json"]
    if isinstance(params, str):
        params = json.loads(params)
    # Should default to us-east-1 (matching the docker-compose env default)
    assert params["region"] == "us-east-1"


# ===========================================================================
# (d) run_aws_iam_posture_job uses decrypted per-workspace credentials
# ===========================================================================
def test_run_aws_iam_posture_job_uses_decrypted_credential_not_server_keys(client, monkeypatch):
    """Mock boto3, assert decrypted workspace keys are injected into boto3.client.

    Server-side AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY settings must NOT be
    used for a workspace scan — only the per-workspace decrypted credential.
    """
    # --- Setup: register workspace user, connect AWS credential, create scan job ---
    monkeypatch.setattr("app.routers.workspace.launch_aws_iam_posture_job", lambda job_id: None)

    user = f"aws-run-{uuid.uuid4().hex[:10]}"
    headers = _register_and_login(client, user, "testpass-run-222!U")

    connect = client.post(
        "/workspace/connect",
        headers=headers,
        json={
            "provider": "aws",
            "token": _VALID_AWS_CREDENTIAL_WITH_SESSION,
            "label": "run-test",
        },
    )
    assert connect.status_code == 200, connect.text
    body = connect.json()
    ws_token = {"Authorization": f"Bearer {body['access_token']}"}
    cred_id = int(body["credential_id"])
    workspace_id = body["workspace_id"]

    scan = client.post(
        "/workspace/scans",
        headers=ws_token,
        json={
            "provider": "aws",
            "credential_id": cred_id,
            "scope": "us-east-2",
        },
    )
    assert scan.status_code == 200, scan.text
    job_id = int(scan.json()["job_id"])

    # --- Mock boto3.client to capture the injected credentials ---
    boto3_client_calls: list[tuple] = []

    def _fake_boto3_client(service, **kwargs):
        boto3_client_calls.append((service, kwargs))
        mock_client = MagicMock()
        # get_account_summary: MFA enabled → no finding triggered
        mock_client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        # get_account_password_policy: strong policy → no finding triggered
        mock_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "AllowUsersToChangePassword": True,
                "MaxPasswordAge": 90,
            }
        }
        # list_users paginator: empty → no per-user checks
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": []}]
        mock_client.get_paginator.return_value = paginator
        return mock_client

    import boto3 as _boto3

    monkeypatch.setattr(_boto3, "client", _fake_boto3_client)

    # --- Run the job ---
    from app.aws_iam_connector import run_aws_iam_posture_job

    run_aws_iam_posture_job(job_id)

    # --- Assertions ---
    assert (
        len(boto3_client_calls) >= 1
    ), "boto3.client was never called — _iam_client path not exercised"
    service, kw = boto3_client_calls[0]
    assert service == "iam"

    # The injected keys must match the decrypted workspace credential
    assert (
        kw.get("aws_access_key_id") == "AKIAIOSFODNN7EXAMPLE"
    ), f"access key mismatch: {kw.get('aws_access_key_id')}"
    assert (
        kw.get("aws_secret_access_key") == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ), f"secret key mismatch: {kw.get('aws_secret_access_key')}"
    assert (
        kw.get("aws_session_token") == "FQoGZXIvYXdzE..."
    ), f"session token mismatch: {kw.get('aws_session_token')}"
    assert kw.get("region_name") == "us-east-2"

    # Server-side keys must NOT be present (security: a workspace scan must never
    # silently fall back to the operator's AWS account)
    server_access_key = str(getattr(settings, "AWS_ACCESS_KEY_ID", "") or "").strip()
    server_secret_key = str(getattr(settings, "AWS_SECRET_ACCESS_KEY", "") or "").strip()

    if server_access_key:
        assert kw.get("aws_access_key_id") != server_access_key, (
            "boto3.client received the server-side AWS_ACCESS_KEY_ID — "
            "workspace scan leaked into the operator's AWS account"
        )
    if server_secret_key:
        assert kw.get("aws_secret_access_key") != server_secret_key, (
            "boto3.client received the server-side AWS_SECRET_ACCESS_KEY — "
            "workspace scan leaked into the operator's AWS account"
        )

    # Verify the job finished successfully (status = 'done'). The job was written
    # under the workspace tenant, so bind that tenant before reading back.
    ctx_token = tenant_id_ctx.set(workspace_id)
    try:
        with engine.begin() as conn:
            row = (
                conn.execute(
                    text("SELECT status, error FROM scan_jobs WHERE job_id = :jid"),
                    {"jid": job_id},
                )
                .mappings()
                .first()
            )
        assert row is not None, "job row missing after run_aws_iam_posture_job"
        assert row["status"] == "done", f"Job failed — status={row['status']}, error={row['error']}"
    finally:
        tenant_id_ctx.reset(ctx_token)
