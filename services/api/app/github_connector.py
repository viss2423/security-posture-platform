"""GitHub posture connector.

Read-only checks against a GitHub org or user account that map to common
SOC 2 / security-baseline controls (2FA enforcement, branch protection,
Dependabot alerts, secret scanning, repo visibility). Findings are written
through the same lifecycle path as the repository scanner so they show up in
the existing findings/posture views.

Auth: a fine-grained or classic Personal Access Token with *read-only* scope.
Provided via the GITHUB_TOKEN setting or per-job `token` param.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy import text

from .db import SessionLocal
from .queue import publish_scan_job
from .risk_scoring import recompute_finding_risk
from .routers.findings import FindingUpsertBody, upsert_finding_record
from .settings import settings

logger = logging.getLogger("secplat.github_connector")

SOURCE = "github_posture"
_DEFAULT_API_URL = "https://api.github.com"
_API_VERSION = "2022-11-28"


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


def _ensure_github_asset(
    db, *, asset_key: str, asset_name: str, scope_type: str, scope: str
) -> None:
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
              :asset_key, 'app', :name, 'github_account', 'prod', 'medium',
              CAST(:tags AS text[]), CAST(:metadata AS jsonb)
            )
            """
        ),
        {
            "asset_key": asset_key,
            "name": asset_name,
            "tags": ["github", "posture", f"github-{scope_type}"],
            "metadata": json.dumps(
                {"github_posture": True, "scope_type": scope_type, "scope": scope}
            ),
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
# GitHub API client (read-only)
# --------------------------------------------------------------------------- #
def _gh_client(token: str, *, timeout: float) -> httpx.Client:
    base_url = str(getattr(settings, "GITHUB_API_URL", _DEFAULT_API_URL) or _DEFAULT_API_URL)
    return httpx.Client(
        base_url=base_url.rstrip("/"),
        timeout=timeout,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": "secplat-github-connector",
        },
    )


def _list_repos(client: httpx.Client, *, scope_type: str, scope: str, max_repos: int) -> list[dict]:
    if scope_type == "org":
        path = f"/orgs/{scope}/repos"
    elif scope and scope_type == "user":
        path = f"/users/{scope}/repos"
    else:
        path = "/user/repos"  # repos accessible to the token owner (incl. private)
    repos: list[dict] = []
    page = 1
    while len(repos) < max_repos and page <= 10:
        resp = client.get(path, params={"per_page": 100, "page": page, "type": "all"})
        if resp.status_code != 200:
            raise RuntimeError(f"github_list_repos_failed status={resp.status_code} path={path}")
        batch = resp.json()
        if not isinstance(batch, list) or not batch:
            break
        repos.extend(batch)
        page += 1
    return repos[:max_repos]


def _scan_github(
    token: str, *, scope_type: str, scope: str, max_repos: int, timeout: float
) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    logs: list[str] = []
    key_scope = scope or "self"

    with _gh_client(token, timeout=timeout) as client:
        # Org-level: 2FA enforcement
        if scope_type == "org" and scope:
            resp = client.get(f"/orgs/{scope}")
            if resp.status_code == 200:
                enforced = resp.json().get("two_factor_requirement_enabled")
                if enforced is False:
                    findings.append(
                        {
                            "finding_key": _finding_key("github", key_scope, "org_2fa"),
                            "title": f"Organization '{scope}' does not enforce two-factor authentication",
                            "severity": "high",
                            "evidence": "GET /orgs/{org} returned two_factor_requirement_enabled=false",
                            "remediation": "Enable 'Require two-factor authentication' in the org security settings (SOC 2 CC6.1).",
                            "scanner_metadata_json": {"scope": scope, "check": "org_2fa"},
                        }
                    )
                elif enforced is None:
                    logs.append(
                        "2FA enforcement not visible to this token (need org owner) - skipped"
                    )
            else:
                logs.append(f"Org lookup returned {resp.status_code} - 2FA check skipped")

        repos = _list_repos(client, scope_type=scope_type, scope=scope, max_repos=max_repos)
        logs.append(f"Scanning {len(repos)} repositories")

        for repo in repos:
            full_name = str(repo.get("full_name") or "")
            owner = str((repo.get("owner") or {}).get("login") or "")
            name = str(repo.get("name") or "")
            default_branch = str(repo.get("default_branch") or "main")
            if not owner or not name:
                continue

            # Public visibility (informational/low)
            if repo.get("private") is False:
                findings.append(
                    {
                        "finding_key": _finding_key("github", key_scope, "public_repo", full_name),
                        "title": f"Public repository: {full_name}",
                        "severity": "low",
                        "evidence": "Repository visibility is public.",
                        "remediation": "Confirm public exposure is intentional; otherwise set the repository to private.",
                        "scanner_metadata_json": {"repo": full_name, "check": "public_repo"},
                    }
                )

            # Default branch protection
            pr = client.get(f"/repos/{owner}/{name}/branches/{default_branch}/protection")
            if pr.status_code == 404:
                findings.append(
                    {
                        "finding_key": _finding_key(
                            "github", key_scope, "branch_protection", full_name
                        ),
                        "title": f"Default branch '{default_branch}' is not protected on {full_name}",
                        "severity": "medium",
                        "evidence": f"GET branch protection for {default_branch} returned 404 (no protection rule).",
                        "remediation": "Add a branch protection rule requiring pull-request review before merge (SOC 2 CC8.1 change management).",
                        "scanner_metadata_json": {"repo": full_name, "check": "branch_protection"},
                    }
                )
            elif pr.status_code == 403:
                logs.append(
                    f"Branch protection for {full_name} not readable by token (need admin) - skipped"
                )

            # Dependabot vulnerability alerts (204 enabled, 404 disabled)
            va = client.get(f"/repos/{owner}/{name}/vulnerability-alerts")
            if va.status_code == 404:
                findings.append(
                    {
                        "finding_key": _finding_key(
                            "github", key_scope, "dependabot_alerts", full_name
                        ),
                        "title": f"Dependabot vulnerability alerts disabled on {full_name}",
                        "severity": "medium",
                        "evidence": "GET vulnerability-alerts returned 404 (alerts disabled).",
                        "remediation": "Enable Dependabot alerts in the repository security settings (SOC 2 CC7.1).",
                        "scanner_metadata_json": {"repo": full_name, "check": "dependabot_alerts"},
                    }
                )

            # Secret scanning (only present with GHAS/org-enabled repos)
            saa = repo.get("security_and_analysis") or {}
            secret_scanning = (saa.get("secret_scanning") or {}).get("status")
            if secret_scanning == "disabled":
                findings.append(
                    {
                        "finding_key": _finding_key(
                            "github", key_scope, "secret_scanning", full_name
                        ),
                        "title": f"Secret scanning disabled on {full_name}",
                        "severity": "medium",
                        "evidence": "security_and_analysis.secret_scanning.status = disabled.",
                        "remediation": "Enable secret scanning to detect committed credentials (SOC 2 CC6.1).",
                        "scanner_metadata_json": {"repo": full_name, "check": "secret_scanning"},
                    }
                )

    return findings, logs


# --------------------------------------------------------------------------- #
# Job entrypoints (match repository_scan.py signatures)
# --------------------------------------------------------------------------- #
def run_github_posture_job(job_id: int) -> None:
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

        token = str(params.get("token") or getattr(settings, "GITHUB_TOKEN", None) or "").strip()
        scope_type = str(params.get("scope_type") or "user").strip().lower()
        scope = str(params.get("scope") or "").strip()
        max_repos = int(params.get("max_repos") or getattr(settings, "GITHUB_MAX_REPOS", 100))
        timeout = float(getattr(settings, "GITHUB_HTTP_TIMEOUT_SECONDS", 30))
        asset_key = str(params.get("asset_key") or f"github:{scope or 'self'}").strip()

        if not token:
            raise ValueError("github_token_missing")
        if scope_type not in {"user", "org"}:
            raise ValueError("github_scope_type_invalid")

        _append_job_log(
            db,
            job_id,
            f"GitHub posture scan started (scope_type={scope_type}, scope={scope or 'self'})",
        )
        _ensure_github_asset(
            db,
            asset_key=asset_key,
            asset_name=f"GitHub: {scope or 'account'}",
            scope_type=scope_type,
            scope=scope,
        )

        findings, logs = _scan_github(
            token, scope_type=scope_type, scope=scope, max_repos=max_repos, timeout=timeout
        )
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
            message=f"GitHub posture scan completed. Detected {len(findings)} issue(s), resolved {resolved}.",
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("github_posture_failed job_id=%s", job_id)
        _finish_job(
            db, job_id, ok=False, error=str(exc), message=f"GitHub posture scan failed: {exc}"
        )
    finally:
        db.close()


def launch_github_posture_job(job_id: int) -> None:
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
            logger.warning("github_posture_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    if not publish_scan_job(
        int(job_id),
        "github_posture",
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    ):
        logger.warning("github_posture_enqueue_failed job_id=%s", job_id)
