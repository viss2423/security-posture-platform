"""AWS IAM posture connector.

Read-only checks against AWS IAM that map to common SOC 2 / security-baseline
controls. Credentials are loaded only from server-side settings/env:
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from sqlalchemy import text

from .db import SessionLocal
from .queue import publish_scan_job
from .risk_scoring import recompute_finding_risk
from .routers.findings import FindingUpsertBody, upsert_finding_record
from .settings import settings

logger = logging.getLogger("secplat.aws_iam_connector")

SOURCE = "aws_iam_posture"
_STALE_DAYS = 90
_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


# --------------------------------------------------------------------------- #
# Job lifecycle helpers (same conventions as repository_scan.py)
# --------------------------------------------------------------------------- #
def _job_log_line(message: str) -> str:
    return f"[{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}] {message}"


def _append_job_log(db, job_id: int, message: str) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET log_output = COALESCE(log_output, '') || :line || E'\n'
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "line": _job_log_line(message)},
    )
    db.commit()


def _set_job_running(db, job_id: int) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET status = 'running', started_at = NOW(), finished_at = NULL, error = NULL
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id},
    )
    db.commit()


def _finish_job(
    db, job_id: int, *, ok: bool, error: str | None = None, message: str | None = None
) -> None:
    if message:
        _append_job_log(db, job_id, message)
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET status = :status, finished_at = NOW(), error = :error
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "status": "done" if ok else "failed", "error": error},
    )
    db.commit()


def _ensure_aws_asset(db, *, asset_key: str, asset_name: str, region: str) -> None:
    existing = (
        db.execute(
            text("SELECT asset_id FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if existing:
        return
    db.execute(
        text(
            """
            INSERT INTO assets(
              asset_key, type, name, asset_type, environment, criticality, tags, metadata
            )
            VALUES (
              :asset_key, 'cloud', :name, 'aws_iam_account', 'prod', 'high',
              CAST(:tags AS text[]), CAST(:metadata AS jsonb)
            )
            """
        ),
        {
            "asset_key": asset_key,
            "name": asset_name,
            "tags": ["aws", "iam", "posture", f"aws-region-{region}"],
            "metadata": json.dumps({"aws_iam_posture": True, "region": region}),
        },
    )
    db.commit()


def _reconcile_findings_for_source(
    db, *, asset_key: str, source: str, current_keys: set[str]
) -> int:
    rows = (
        db.execute(
            text(
                """
                SELECT f.finding_id, f.finding_key, COALESCE(f.status, 'open') AS status
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key AND f.source = :source
                """
            ),
            {"asset_key": asset_key, "source": source},
        )
        .mappings()
        .all()
    )
    resolved = 0
    for row in rows:
        finding_key = str(row.get("finding_key") or "").strip()
        if not finding_key or finding_key in current_keys:
            continue
        if str(row.get("status") or "open").strip().lower() == "remediated":
            continue
        finding_id = int(row["finding_id"])
        db.execute(
            text("UPDATE findings SET status = 'remediated' WHERE finding_id = :finding_id"),
            {"finding_id": finding_id},
        )
        recompute_finding_risk(db, finding_id)
        resolved += 1
    db.commit()
    return resolved


def _finding_key(*parts: str) -> str:
    raw = ":".join(p.strip() for p in parts if p and p.strip())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# --------------------------------------------------------------------------- #
# AWS IAM client and read-only checks
# --------------------------------------------------------------------------- #
def _iam_client(region: str):
    import boto3

    access_key = str(getattr(settings, "AWS_ACCESS_KEY_ID", None) or "").strip()
    secret_key = str(getattr(settings, "AWS_SECRET_ACCESS_KEY", None) or "").strip()
    if not access_key or not secret_key:
        raise ValueError("aws_credentials_missing")
    return boto3.client(
        "iam",
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )


def _client_error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error = response.get("Error") or {}
    if not isinstance(error, dict):
        return None
    code = error.get("Code")
    return str(code) if code else None


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _paginate(client, operation: str, **kwargs) -> list[dict[str, Any]]:
    paginator = client.get_paginator(operation)
    items: list[dict[str, Any]] = []
    result_key = {
        "list_users": "Users",
        "list_access_keys": "AccessKeyMetadata",
        "list_attached_user_policies": "AttachedPolicies",
        "list_user_policies": "PolicyNames",
    }[operation]
    for page in paginator.paginate(**kwargs):
        values = page.get(result_key) or []
        if isinstance(values, list):
            items.extend(values)
    return items


def _policy_document_allows_admin(document: dict[str, Any]) -> bool:
    statements = document.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect") or "").lower() != "allow":
            continue
        actions = stmt.get("Action") or []
        resources = stmt.get("Resource") or []
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        action_set = {str(a).strip().lower() for a in actions}
        resource_set = {str(r).strip() for r in resources}
        if ("*" in action_set or "*:*" in action_set) and ("*" in resource_set or not resource_set):
            return True
    return False


def _decode_policy_document(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        return json.loads(unquote(document))
    return {}


def _scan_aws_iam(client, *, region: str) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    logs: list[str] = []
    now = datetime.now(UTC)
    stale_before = now - timedelta(days=_STALE_DAYS)
    account_scope = "account"

    summary = client.get_account_summary().get("SummaryMap") or {}
    if int(summary.get("AccountMFAEnabled") or 0) != 1:
        findings.append(
            {
                "finding_key": _finding_key("aws", account_scope, "root_mfa"),
                "title": "AWS root account MFA is not enabled",
                "severity": "critical",
                "evidence": "iam:GetAccountSummary returned AccountMFAEnabled=0.",
                "remediation": "Enable MFA on the AWS root account and avoid using root for daily operations.",
                "scanner_metadata_json": {"region": region, "check": "aws_root_mfa"},
            }
        )

    try:
        policy = client.get_account_password_policy().get("PasswordPolicy") or {}
        weak_reasons: list[str] = []
        if int(policy.get("MinimumPasswordLength") or 0) < 14:
            weak_reasons.append("minimum length is below 14")
        for key, label in [
            ("RequireUppercaseCharacters", "uppercase"),
            ("RequireLowercaseCharacters", "lowercase"),
            ("RequireNumbers", "numbers"),
            ("RequireSymbols", "symbols"),
        ]:
            if not bool(policy.get(key)):
                weak_reasons.append(f"{label} is not required")
        if not bool(policy.get("AllowUsersToChangePassword")):
            weak_reasons.append("users cannot change their own passwords")
        max_age = policy.get("MaxPasswordAge")
        if max_age is None or int(max_age) > 90:
            weak_reasons.append("password max age is missing or above 90 days")
        if weak_reasons:
            findings.append(
                {
                    "finding_key": _finding_key("aws", account_scope, "password_policy"),
                    "title": "AWS IAM password policy is missing or weak",
                    "severity": "high",
                    "evidence": "Password policy weaknesses: " + "; ".join(weak_reasons) + ".",
                    "remediation": "Set a strong IAM account password policy with length, complexity, change, and rotation controls.",
                    "scanner_metadata_json": {
                        "region": region,
                        "check": "aws_password_policy",
                        "weak_reasons": weak_reasons,
                    },
                }
            )
    except Exception as exc:
        code = _client_error_code(exc)
        if code == "NoSuchEntity":
            findings.append(
                {
                    "finding_key": _finding_key("aws", account_scope, "password_policy"),
                    "title": "AWS IAM password policy is not configured",
                    "severity": "high",
                    "evidence": "iam:GetAccountPasswordPolicy returned NoSuchEntity.",
                    "remediation": "Create an IAM account password policy with strong length, complexity, and rotation controls.",
                    "scanner_metadata_json": {"region": region, "check": "aws_password_policy"},
                }
            )
        else:
            raise

    users = _paginate(client, "list_users")
    logs.append(f"Scanning {len(users)} IAM users")
    for user in users:
        user_name = str(user.get("UserName") or "")
        if not user_name:
            continue

        password_last_used = _aware(user.get("PasswordLastUsed"))
        user_detail = client.get_user(UserName=user_name).get("User") or {}
        password_last_used = _aware(user_detail.get("PasswordLastUsed")) or password_last_used
        access_keys = _paginate(client, "list_access_keys", UserName=user_name)

        latest_activity = password_last_used
        for key_meta in access_keys:
            key_id = str(key_meta.get("AccessKeyId") or "")
            created_at = _aware(key_meta.get("CreateDate"))
            if key_id and created_at and created_at < stale_before:
                age_days = (now - created_at).days
                findings.append(
                    {
                        "finding_key": _finding_key("aws", user_name, "stale_access_key", key_id),
                        "title": f"IAM access key for user '{user_name}' is older than 90 days",
                        "severity": "medium",
                        "evidence": f"Access key was created {age_days} days ago.",
                        "remediation": "Rotate the access key, then remove the old key after dependent workloads are updated.",
                        "scanner_metadata_json": {
                            "region": region,
                            "check": "aws_stale_access_keys",
                            "user": user_name,
                            "access_key_id_hash": _finding_key("aws_access_key", key_id),
                            "age_days": age_days,
                        },
                    }
                )
            if key_id:
                key_last_used = _aware(
                    (
                        client.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed")
                        or {}
                    ).get("LastUsedDate")
                )
                if key_last_used and (latest_activity is None or key_last_used > latest_activity):
                    latest_activity = key_last_used

        if latest_activity is None or latest_activity < stale_before:
            inactive_days = None if latest_activity is None else (now - latest_activity).days
            findings.append(
                {
                    "finding_key": _finding_key("aws", user_name, "unused_user"),
                    "title": f"IAM user '{user_name}' has no activity in 90+ days",
                    "severity": "medium",
                    "evidence": (
                        "No console or access key last-used timestamp was found."
                        if inactive_days is None
                        else f"Most recent IAM activity was {inactive_days} days ago."
                    ),
                    "remediation": "Disable or remove unused IAM users after confirming ownership and business need.",
                    "scanner_metadata_json": {
                        "region": region,
                        "check": "aws_unused_user",
                        "user": user_name,
                        "inactive_days": inactive_days,
                    },
                }
            )

        admin_evidence: list[str] = []
        for attached in _paginate(client, "list_attached_user_policies", UserName=user_name):
            policy_arn = str(attached.get("PolicyArn") or "")
            policy_name = str(attached.get("PolicyName") or policy_arn)
            if policy_arn == _ADMIN_POLICY_ARN:
                admin_evidence.append(f"managed policy {policy_name} is directly attached")
                continue
            policy_meta = client.get_policy(PolicyArn=policy_arn).get("Policy") or {}
            version_id = str(policy_meta.get("DefaultVersionId") or "")
            if not version_id:
                continue
            version = (
                client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get(
                    "PolicyVersion"
                )
                or {}
            )
            if _policy_document_allows_admin(_decode_policy_document(version.get("Document"))):
                admin_evidence.append(f"managed policy {policy_name} allows wildcard admin access")

        for policy_name in _paginate(client, "list_user_policies", UserName=user_name):
            inline = client.get_user_policy(UserName=user_name, PolicyName=str(policy_name))
            if _policy_document_allows_admin(_decode_policy_document(inline.get("PolicyDocument"))):
                admin_evidence.append(f"inline policy {policy_name} allows wildcard admin access")

        if admin_evidence:
            findings.append(
                {
                    "finding_key": _finding_key("aws", user_name, "admin_policy"),
                    "title": f"IAM user '{user_name}' has directly-attached administrator access",
                    "severity": "critical",
                    "evidence": "; ".join(admin_evidence) + ".",
                    "remediation": "Remove direct administrator policies from IAM users; use least-privilege roles and groups.",
                    "scanner_metadata_json": {
                        "region": region,
                        "check": "aws_admin_policy",
                        "user": user_name,
                    },
                }
            )

    return findings, logs


# --------------------------------------------------------------------------- #
# Job entrypoints (match repository_scan.py signatures)
# --------------------------------------------------------------------------- #
def run_aws_iam_posture_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text(
                    """
                    SELECT job_id, requested_by, COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
                    FROM scan_jobs WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            return
        params = row.get("job_params_json") or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}

        _set_job_running(db, job_id)

        region = str(params.get("region") or getattr(settings, "AWS_REGION", None) or "").strip()
        if not region:
            raise ValueError("aws_region_missing")
        asset_key = str(params.get("asset_key") or f"aws:iam:{region}").strip()

        _append_job_log(db, job_id, f"AWS IAM posture scan started (region={region})")
        _ensure_aws_asset(
            db,
            asset_key=asset_key,
            asset_name=f"AWS IAM: {region}",
            region=region,
        )

        findings, logs = _scan_aws_iam(_iam_client(region), region=region)
        for line in logs:
            _append_job_log(db, job_id, line)

        current_keys: set[str] = set()
        for finding in findings:
            upsert_finding_record(
                db,
                FindingUpsertBody(
                    finding_key=finding["finding_key"],
                    asset_key=asset_key,
                    category="configuration",
                    title=finding["title"],
                    severity=finding.get("severity", "medium"),
                    confidence="high",
                    evidence=finding.get("evidence"),
                    remediation=finding.get("remediation"),
                    source=SOURCE,
                    scanner_metadata_json=finding.get("scanner_metadata_json"),
                ),
            )
            current_keys.add(str(finding["finding_key"]))

        resolved = _reconcile_findings_for_source(
            db, asset_key=asset_key, source=SOURCE, current_keys=current_keys
        )
        _finish_job(
            db,
            job_id,
            ok=True,
            message=f"AWS IAM posture scan completed. Detected {len(findings)} issue(s), resolved {resolved}.",
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("aws_iam_posture_failed job_id=%s", job_id)
        _finish_job(
            db, job_id, ok=False, error=str(exc), message=f"AWS IAM posture scan failed: {exc}"
        )
    finally:
        db.close()


def launch_aws_iam_posture_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text("SELECT target_asset_id, requested_by FROM scan_jobs WHERE job_id = :job_id"),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            logger.warning("aws_iam_posture_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    if not publish_scan_job(
        int(job_id),
        "aws_iam_posture",
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    ):
        logger.warning("aws_iam_posture_enqueue_failed job_id=%s", job_id)
