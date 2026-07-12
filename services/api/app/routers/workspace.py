"""Self-serve workspace: connect real read-only credentials and get an isolated tenant.

A self-serve user signs up as a viewer on the shared ``default`` tenant (demo sandbox).
The first time they connect a credential here we lazily provision their own workspace
(``ws_<uuid>``), promote them to ``analyst``, store the secret encrypted under their
workspace tenant (RLS-isolated in ``user_credentials``), and re-issue a token carrying the
signed ``ws`` claim so every later request is pinned to their workspace and can never read
another tenant's rows.

Scan execution (POST /workspace/scans) is a separate follow-up; this module covers the
credential-at-rest + workspace-activation half.
"""

from __future__ import annotations

import json
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.aws_credentials import AwsCredentialError, canonicalize_aws_credential
from app.aws_iam_connector import launch_aws_iam_posture_job
from app.credential_crypto import CredentialEncryptionUnavailableError, encrypt_secret
from app.db import get_db
from app.github_connector import launch_github_posture_job
from app.rate_limit import check_rate_limit
from app.request_context import current_tenant_id, request_id_ctx, tenant_id_ctx
from app.routers.auth import _client_id, _issue_token_pair, require_auth
from app.settings import settings

router = APIRouter(prefix="/workspace", tags=["workspace"])

_SUPPORTED_PROVIDERS = {"github", "aws"}


class ConnectBody(BaseModel):
    provider: str
    token: str
    scope_type: str | None = None
    scope: str | None = None
    label: str | None = None


class ScanBody(BaseModel):
    provider: str
    credential_id: int
    scope_type: str | None = None
    scope: str | None = None
    max_repos: int | None = None


def _default_tenant() -> str:
    return str(getattr(settings, "DEFAULT_TENANT_ID", "default") or "default").strip() or "default"


@router.post("/connect")
async def connect_workspace(
    body: ConnectBody,
    request: Request,
    user: str = Depends(require_auth),
    db: Session = Depends(get_db),
) -> dict:
    provider = (body.provider or "").strip().lower()
    if provider not in _SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="provider must be 'github' or 'aws'")
    secret = (body.token or "").strip()
    if not secret:
        raise HTTPException(status_code=400, detail="token required")

    # AWS credentials are a multi-field JSON blob ({access_key_id, secret_access_key,
    # session_token?}); canonicalize + validate before we ever encrypt/persist so a
    # malformed or partial key can't be stored. GitHub stays a single raw PAT.
    if provider == "aws":
        try:
            secret = canonicalize_aws_credential(secret)
        except AwsCredentialError as exc:
            raise HTTPException(status_code=400, detail=f"invalid aws credentials: {exc}")

    key = f"workspace-connect:{_client_id(request)}"
    if not await check_rate_limit(key, settings.RATE_LIMIT_LOGIN_PER_MINUTE, 60.0):
        raise HTTPException(status_code=429, detail="Too many connect attempts. Try again later.")

    # Workspace is derived from the authenticated user's row, never from client input,
    # so a caller can only ever act on their own workspace.
    row = (
        db.execute(
            text("SELECT workspace_id FROM users WHERE username = :u AND disabled = FALSE"),
            {"u": user},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    workspace_id = str(row.get("workspace_id") or "").strip()
    activated = False
    if not workspace_id:
        workspace_id = f"ws_{uuid.uuid4().hex}"
        # Guard on workspace_id IS NULL so concurrent connects can't clobber an existing
        # workspace; if another request won the race, re-read the committed value.
        db.execute(
            text(
                "UPDATE users SET workspace_id = :ws, role = 'analyst' "
                "WHERE username = :u AND workspace_id IS NULL"
            ),
            {"ws": workspace_id, "u": user},
        )
        confirmed = (
            db.execute(
                text("SELECT workspace_id FROM users WHERE username = :u"),
                {"u": user},
            )
            .mappings()
            .first()
        )
        workspace_id = str((confirmed or {}).get("workspace_id") or workspace_id).strip()
        activated = True

    # Encrypt before any DB write; fail closed (503) rather than persist a secret in clear.
    try:
        ciphertext, key_version = encrypt_secret(secret)
    except CredentialEncryptionUnavailableError:
        raise HTTPException(status_code=503, detail="credential encryption is not configured")

    # Stamp the credential under the user's workspace tenant so RLS isolates it from every
    # other tenant. org_id defaults from the secplat.tenant_id GUC, driven by this contextvar.
    ctx_token = tenant_id_ctx.set(workspace_id)
    try:
        cred = (
            db.execute(
                text(
                    """
                    INSERT INTO user_credentials
                      (owner_username, provider, label, ciphertext, key_version, scope_type, scope)
                    VALUES
                      (:owner, :provider, :label, :ciphertext, :kv, :scope_type, :scope)
                    RETURNING credential_id
                    """
                ),
                {
                    "owner": user,
                    "provider": provider,
                    "label": (body.label or "").strip() or None,
                    "ciphertext": ciphertext,
                    "kv": key_version,
                    "scope_type": (body.scope_type or "").strip() or None,
                    "scope": (body.scope or "").strip() or None,
                },
            )
            .mappings()
            .first()
        )
        db.commit()
    finally:
        tenant_id_ctx.reset(ctx_token)

    log_audit(
        db,
        "workspace.connect",
        user_name=user,
        details={"provider": provider, "activated": activated, "workspace_id": workspace_id},
        request_id=request_id_ctx.get(None),
    )
    # Re-issue the token pinned to the workspace, now as analyst.
    token_pair = _issue_token_pair(
        db, username=user, role="analyst", request=request, ws=workspace_id
    )
    db.commit()

    return {
        "workspace_id": workspace_id,
        "credential_id": int(cred["credential_id"]),
        "provider": provider,
        "activated": activated,
        "access_token": token_pair.access_token,
        "refresh_token": token_pair.refresh_token,
    }


@router.post("/scans")
async def start_workspace_scan(
    body: ScanBody,
    request: Request,
    user: str = Depends(require_auth),
    db: Session = Depends(get_db),
) -> dict:
    provider = (body.provider or "").strip().lower()
    if provider not in _SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="provider must be 'github' or 'aws'")

    # The caller's tenant comes from their signed `ws` claim. A user who has not connected
    # a workspace is still on the shared default tenant and must connect first.
    tenant = current_tenant_id()
    if tenant == _default_tenant():
        raise HTTPException(status_code=403, detail="connect a workspace before running scans")

    key = f"workspace-scan:{user}"
    if not await check_rate_limit(key, settings.RATE_LIMIT_LOGIN_PER_MINUTE, 60.0):
        raise HTTPException(status_code=429, detail="Too many scans. Try again later.")

    # RLS scopes this read to the caller's workspace, so a workspace can only ever scan with
    # its own credential — referencing another workspace's credential_id (or one belonging to
    # a different provider) returns 404. The credential is only ever loaded/decrypted later,
    # in the tenant-bound worker; here we just confirm ownership and enqueue.
    cred = (
        db.execute(
            text(
                "SELECT credential_id FROM user_credentials "
                "WHERE credential_id = :cid AND provider = :provider"
            ),
            {"cid": int(body.credential_id), "provider": provider},
        )
        .mappings()
        .first()
    )
    if not cred:
        raise HTTPException(
            status_code=404, detail=f"{provider} credential not found in this workspace"
        )

    if provider == "github":
        scope_type = (body.scope_type or "user").strip().lower()
        if scope_type not in {"user", "org"}:
            raise HTTPException(status_code=400, detail="scope_type must be 'user' or 'org'")
        scope = (body.scope or "").strip()
        if scope_type == "org" and not scope:
            raise HTTPException(
                status_code=400, detail="scope (org name) is required for org scans"
            )
        max_repos = max(1, min(int(body.max_repos or settings.GITHUB_MAX_REPOS), 500))
        job_type = "github_posture"
        job_params = {
            "credential_id": int(body.credential_id),
            "scope_type": scope_type,
            "scope": scope,
            "max_repos": max_repos,
        }
    else:  # aws
        # AWS IAM is global, but boto3 needs a region for endpoint resolution. The region
        # travels in `scope`; validate its shape so it can't smuggle anything into the SDK.
        region = (body.scope or "").strip().lower() or str(
            getattr(settings, "AWS_REGION", None) or "us-east-1"
        ).strip().lower()
        if not re.fullmatch(r"[a-z0-9-]{1,32}", region):
            raise HTTPException(status_code=400, detail="invalid aws region")
        job_type = "aws_iam_posture"
        job_params = {
            "credential_id": int(body.credential_id),
            "region": region,
        }

    # org_id defaults from the tenant GUC (the caller's workspace); the job — and every
    # finding it later writes — is therefore RLS-scoped to this workspace.
    row = (
        db.execute(
            text(
                """
                INSERT INTO scan_jobs (org_id, job_type, requested_by, status, job_params_json)
                VALUES (:org_id, :job_type, :rb, 'queued', CAST(:params AS jsonb))
                RETURNING job_id
                """
            ),
            {
                "org_id": tenant,
                "job_type": job_type,
                "rb": user,
                "params": json.dumps(job_params),
            },
        )
        .mappings()
        .first()
    )
    job_id = int(row["job_id"])
    db.commit()

    log_audit(
        db,
        "workspace.scan",
        user_name=user,
        details={"job_id": job_id, "provider": provider, "credential_id": int(body.credential_id)},
        request_id=request_id_ctx.get(None),
    )
    db.commit()

    # Enqueue for the worker. This runs while tenant_id_ctx is still the caller's workspace,
    # so launch's own DB reads see the job; the runner later re-discovers the tenant via
    # secplat_job_org_id when the worker executes it on the default tenant.
    if provider == "github":
        launch_github_posture_job(job_id)
    else:
        launch_aws_iam_posture_job(job_id)

    return {"job_id": job_id, "status": "queued", "provider": provider}
