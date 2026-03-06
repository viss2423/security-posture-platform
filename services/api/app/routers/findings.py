import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import log_audit
from ..db import get_db
from ..queue import publish_correlation_event
from ..request_context import request_id_ctx
from ..risk_labels import VALID_RISK_LABEL_SOURCES, VALID_RISK_LABELS
from ..risk_scoring import recompute_finding_risk
from ..suppression import is_asset_suppressed
from .auth import get_current_role, require_auth, require_role

router = APIRouter()

VALID_STATUS = ("open", "in_progress", "remediated", "accepted_risk")
VALID_RISK_LEVELS = ("critical", "high", "medium", "low", "unscored")
SENSITIVE_FINDING_FIELDS_FOR_VIEWER = {"evidence", "accepted_risk_reason"}
REPOSITORY_SCAN_SOURCES = ("osv_scanner", "trivy_fs")
SOURCE_LABELS = {
    "osv_scanner": "OSV Scanner",
    "trivy_fs": "Trivy FS",
}


def _redact_finding(row: dict, role: str) -> dict:
    out = dict(row)
    if role == "viewer":
        for key in SENSITIVE_FINDING_FIELDS_FOR_VIEWER:
            out[key] = None
    return out


def _as_jsonb_or_none(value: dict[str, Any] | None) -> str | None:
    if value is None:
        return None
    return json.dumps(value)


def _serialize_datetime_value(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


@router.get("/")
def list_findings(
    db: Session = Depends(get_db),
    status: str | None = Query(None, description="Filter by status (open, ignored, remediated)"),
    source: str | None = Query(None, description="Filter by source (e.g. tls_scan, header_scan)"),
    risk_level: str | None = Query(
        None, description="Filter by risk level (critical, high, medium, low, unscored)"
    ),
    asset_key: str | None = Query(None, description="Filter by asset_key"),
    limit: int = Query(200, ge=1, le=500),
    _user: str = Depends(require_auth),
    role: str = Depends(get_current_role),
):
    """List findings with optional filters. Returns finding_key, first_seen, last_seen, status, source, asset_key."""
    conditions = ["1=1"]
    params: dict = {"limit": limit}
    if status:
        conditions.append("COALESCE(f.status, 'open') = :status")
        params["status"] = status
    if source:
        conditions.append("f.source = :source")
        params["source"] = source
    if risk_level:
        normalized_risk_level = risk_level.strip().lower()
        if normalized_risk_level not in VALID_RISK_LEVELS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk_level. Use one of: {VALID_RISK_LEVELS}",
            )
        if normalized_risk_level == "unscored":
            conditions.append("f.risk_score IS NULL")
        else:
            conditions.append("COALESCE(f.risk_level, '') = :risk_level")
            params["risk_level"] = normalized_risk_level
    if asset_key:
        conditions.append("a.asset_key = :asset_key")
        params["asset_key"] = asset_key
    where = " AND ".join(conditions)
    q = text(f"""
      SELECT
        f.finding_id, f.finding_key, f.asset_id,
        COALESCE(f.first_seen, f.time) AS first_seen,
        COALESCE(f.last_seen, f.time) AS last_seen,
        COALESCE(f.status, 'open') AS status,
        f.source,
        f.time,
        a.asset_key,
        a.name AS asset_name,
        f.category, f.title, f.severity, f.confidence, f.evidence, f.remediation,
        f.vulnerability_id, f.package_ecosystem, f.package_name, f.package_version,
        f.fixed_version, f.scanner_metadata_json,
        f.risk_score, f.risk_level, f.risk_factors_json,
        rl.label AS risk_label,
        rl.source AS risk_label_source,
        rl.created_at AS risk_label_created_at,
        rl.created_by AS risk_label_created_by,
        f.accepted_risk_at, f.accepted_risk_expires_at, f.accepted_risk_reason, f.accepted_risk_by
      FROM findings f
      LEFT JOIN assets a ON a.asset_id = f.asset_id
      LEFT JOIN LATERAL (
        SELECT label, source, created_at, created_by
        FROM finding_risk_labels frl
        WHERE frl.finding_id = f.finding_id
        ORDER BY
          CASE
            WHEN frl.source = 'analyst' THEN 0
            WHEN frl.source = 'incident_linked' THEN 1
            ELSE 2
          END,
          frl.created_at DESC,
          frl.id DESC
        LIMIT 1
      ) rl ON TRUE
      WHERE {where}
      ORDER BY COALESCE(f.risk_score, 0) DESC, COALESCE(f.last_seen, f.time) DESC
      LIMIT :limit
    """)
    rows = db.execute(q, params).mappings().all()

    def _serialize(r):
        out = dict(r)
        for k in (
            "first_seen",
            "last_seen",
            "risk_label_created_at",
            "accepted_risk_at",
            "accepted_risk_expires_at",
        ):
            v = out.get(k)
            if hasattr(v, "isoformat"):
                out[k] = v.isoformat()
            elif v is not None and k in out:
                out[k] = str(v)
        if isinstance(out.get("risk_factors_json"), str):
            try:
                out["risk_factors_json"] = json.loads(out["risk_factors_json"])
            except json.JSONDecodeError:
                out["risk_factors_json"] = {}
        if isinstance(out.get("scanner_metadata_json"), str):
            try:
                out["scanner_metadata_json"] = json.loads(out["scanner_metadata_json"])
            except json.JSONDecodeError:
                out["scanner_metadata_json"] = {}
        return out

    return [_redact_finding(_serialize(r), role=role) for r in rows]


@router.get("/repository-summary")
def get_repository_summary(
    asset_key: str = Query("secplat-repo", description="Repository asset key"),
    recent_limit: int = Query(8, ge=1, le=20),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    asset = (
        db.execute(
            text(
                """
                SELECT asset_id, asset_key, name, asset_type, environment, criticality
                FROM assets
                WHERE asset_key = :asset_key
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    params = {"asset_key": asset_key}
    counts = (
        db.execute(
            text(
                """
                SELECT
                  f.source,
                  COALESCE(f.status, 'open') AS status,
                  COALESCE(f.severity, 'medium') AS severity,
                  COALESCE(f.category, 'uncategorized') AS category,
                  COUNT(*) AS finding_count
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key
                  AND COALESCE(f.source, '') IN ('osv_scanner', 'trivy_fs')
                GROUP BY f.source, COALESCE(f.status, 'open'), COALESCE(f.severity, 'medium'), COALESCE(f.category, 'uncategorized')
                """
            ),
            params,
        )
        .mappings()
        .all()
    )

    sources: dict[str, dict[str, Any]] = {
        source: {
            "source": source,
            "label": SOURCE_LABELS.get(source, source),
            "total": 0,
            "open": 0,
            "in_progress": 0,
            "accepted_risk": 0,
            "remediated": 0,
            "by_severity": {},
            "by_category": {},
        }
        for source in REPOSITORY_SCAN_SOURCES
    }
    totals = {
        "total_findings": 0,
        "open_findings": 0,
        "in_progress_findings": 0,
        "accepted_risk_findings": 0,
        "remediated_findings": 0,
    }
    for row in counts:
        source = str(row.get("source") or "").strip()
        if source not in sources:
            continue
        status = str(row.get("status") or "open").strip().lower()
        severity = str(row.get("severity") or "medium").strip().lower()
        category = str(row.get("category") or "uncategorized").strip() or "uncategorized"
        count = int(row.get("finding_count") or 0)
        bucket = sources[source]
        bucket["total"] += count
        bucket[status] = int(bucket.get(status) or 0) + count
        bucket["by_severity"][severity] = int(bucket["by_severity"].get(severity) or 0) + count
        bucket["by_category"][category] = int(bucket["by_category"].get(category) or 0) + count
        totals["total_findings"] += count
        totals_key = f"{status}_findings"
        if totals_key in totals:
            totals[totals_key] += count

    recent_rows = (
        db.execute(
            text(
                """
                SELECT
                  f.finding_id,
                  f.finding_key,
                  f.source,
                  f.category,
                  f.title,
                  f.severity,
                  COALESCE(f.status, 'open') AS status,
                  f.package_name,
                  f.package_version,
                  f.fixed_version,
                  f.vulnerability_id,
                  f.risk_score,
                  f.risk_level,
                  COALESCE(f.last_seen, f.time) AS last_seen
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key
                  AND COALESCE(f.source, '') IN ('osv_scanner', 'trivy_fs')
                ORDER BY COALESCE(f.last_seen, f.time) DESC, f.finding_id DESC
                LIMIT :recent_limit
                """
            ),
            {"asset_key": asset_key, "recent_limit": recent_limit},
        )
        .mappings()
        .all()
    )
    recent_findings = []
    for row in recent_rows:
        item = dict(row)
        item["last_seen"] = _serialize_datetime_value(item.get("last_seen"))
        recent_findings.append(item)

    package_rows = (
        db.execute(
            text(
                """
                SELECT
                  f.package_name,
                  COUNT(*) AS total_count,
                  SUM(CASE WHEN COALESCE(f.status, 'open') <> 'remediated' THEN 1 ELSE 0 END) AS active_count,
                  MAX(
                    CASE COALESCE(f.severity, 'medium')
                      WHEN 'critical' THEN 4
                      WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2
                      WHEN 'low' THEN 1
                      ELSE 0
                    END
                  ) AS severity_rank
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key
                  AND COALESCE(f.source, '') IN ('osv_scanner', 'trivy_fs')
                  AND f.package_name IS NOT NULL
                GROUP BY f.package_name
                ORDER BY active_count DESC, total_count DESC, package_name ASC
                LIMIT 8
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    severity_by_rank = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    top_packages = [
        {
            "package_name": row.get("package_name"),
            "active_count": int(row.get("active_count") or 0),
            "total_count": int(row.get("total_count") or 0),
            "max_severity": severity_by_rank.get(int(row.get("severity_rank") or 0), "info"),
        }
        for row in package_rows
    ]

    job_rows = (
        db.execute(
            text(
                """
                SELECT
                  job_id,
                  job_type,
                  target_asset_id,
                  status,
                  created_at,
                  started_at,
                  finished_at,
                  error,
                  requested_by,
                  job_params_json,
                  job_params_json ->> 'asset_key' AS asset_key,
                  job_params_json ->> 'asset_name' AS asset_name
                FROM scan_jobs
                WHERE job_type = 'repository_scan'
                  AND COALESCE(job_params_json ->> 'asset_key', :asset_key) = :asset_key
                ORDER BY created_at DESC
                LIMIT 5
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    latest_jobs = []
    for row in job_rows:
        item = dict(row)
        for key in ("created_at", "started_at", "finished_at"):
            item[key] = _serialize_datetime_value(item.get(key))
        if isinstance(item.get("job_params_json"), str):
            try:
                item["job_params_json"] = json.loads(item["job_params_json"])
            except json.JSONDecodeError:
                item["job_params_json"] = {}
        latest_jobs.append(item)

    return {
        "asset_key": asset.get("asset_key"),
        "asset_name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "environment": asset.get("environment"),
        "criticality": asset.get("criticality"),
        **totals,
        "sources": list(sources.values()),
        "top_packages": top_packages,
        "recent_findings": recent_findings,
        "latest_jobs": latest_jobs,
    }


@router.get("/dependency-risk")
def get_dependency_risk(
    asset_key: str = Query("secplat-repo", description="Repository asset key"),
    remediation_limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    asset = (
        db.execute(
            text(
                """
                SELECT asset_id, asset_key, name, asset_type, environment, criticality
                FROM assets
                WHERE asset_key = :asset_key
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    counts = (
        db.execute(
            text(
                """
                SELECT
                  COALESCE(f.source, 'unknown') AS source,
                  COALESCE(f.status, 'open') AS status,
                  COALESCE(f.severity, 'medium') AS severity,
                  COALESCE(f.package_ecosystem, 'unknown') AS package_ecosystem,
                  COUNT(*) AS finding_count
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key
                  AND COALESCE(f.source, '') IN ('osv_scanner', 'trivy_fs')
                GROUP BY
                  COALESCE(f.source, 'unknown'),
                  COALESCE(f.status, 'open'),
                  COALESCE(f.severity, 'medium'),
                  COALESCE(f.package_ecosystem, 'unknown')
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .all()
    )

    totals = {
        "total_findings": 0,
        "active_findings": 0,
        "remediated_findings": 0,
        "accepted_risk_findings": 0,
    }
    by_source: dict[str, dict[str, Any]] = {}
    severity_distribution_active: dict[str, int] = {}
    ecosystem_distribution_active: dict[str, int] = {}
    for row in counts:
        source = str(row.get("source") or "unknown")
        status = str(row.get("status") or "open").strip().lower()
        severity = str(row.get("severity") or "medium").strip().lower()
        ecosystem = str(row.get("package_ecosystem") or "unknown").strip().lower() or "unknown"
        count = int(row.get("finding_count") or 0)

        totals["total_findings"] += count
        if status == "remediated":
            totals["remediated_findings"] += count
        else:
            totals["active_findings"] += count
            severity_distribution_active[severity] = (
                int(severity_distribution_active.get(severity) or 0) + count
            )
            ecosystem_distribution_active[ecosystem] = (
                int(ecosystem_distribution_active.get(ecosystem) or 0) + count
            )
            if status == "accepted_risk":
                totals["accepted_risk_findings"] += count

        bucket = by_source.setdefault(
            source,
            {
                "source": source,
                "total": 0,
                "active": 0,
                "remediated": 0,
                "accepted_risk": 0,
                "by_severity": {},
            },
        )
        bucket["total"] += count
        if status == "remediated":
            bucket["remediated"] += count
        else:
            bucket["active"] += count
            bucket["by_severity"][severity] = int(bucket["by_severity"].get(severity) or 0) + count
            if status == "accepted_risk":
                bucket["accepted_risk"] += count

    dependency_rows = (
        db.execute(
            text(
                """
                SELECT
                  f.package_name,
                  COALESCE(f.package_ecosystem, 'unknown') AS package_ecosystem,
                  COUNT(*) AS total_count,
                  SUM(CASE WHEN COALESCE(f.status, 'open') <> 'remediated' THEN 1 ELSE 0 END) AS active_count,
                  MAX(COALESCE(f.risk_score, 0)) AS max_risk_score,
                  MAX(
                    CASE COALESCE(f.severity, 'medium')
                      WHEN 'critical' THEN 4
                      WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2
                      WHEN 'low' THEN 1
                      ELSE 0
                    END
                  ) AS severity_rank,
                  MAX(COALESCE(f.last_seen, f.time)) AS last_seen
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key
                  AND COALESCE(f.source, '') IN ('osv_scanner', 'trivy_fs')
                  AND f.package_name IS NOT NULL
                GROUP BY f.package_name, COALESCE(f.package_ecosystem, 'unknown')
                ORDER BY
                  SUM(CASE WHEN COALESCE(f.status, 'open') <> 'remediated' THEN 1 ELSE 0 END) DESC,
                  MAX(COALESCE(f.risk_score, 0)) DESC,
                  COUNT(*) DESC
                LIMIT 25
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .all()
    )
    severity_by_rank = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    dependency_distribution = []
    active_dependency_count = 0
    for row in dependency_rows:
        active_count = int(row.get("active_count") or 0)
        if active_count > 0:
            active_dependency_count += 1
        dependency_distribution.append(
            {
                "package_name": row.get("package_name"),
                "package_ecosystem": row.get("package_ecosystem"),
                "active_count": active_count,
                "total_count": int(row.get("total_count") or 0),
                "max_risk_score": int(round(float(row.get("max_risk_score") or 0))),
                "max_severity": severity_by_rank.get(int(row.get("severity_rank") or 0), "info"),
                "last_seen": _serialize_datetime_value(row.get("last_seen")),
            }
        )

    remediation_rows = (
        db.execute(
            text(
                """
                SELECT
                  f.finding_id,
                  f.finding_key,
                  f.title,
                  f.source,
                  COALESCE(f.status, 'open') AS status,
                  COALESCE(f.severity, 'medium') AS severity,
                  f.vulnerability_id,
                  f.package_ecosystem,
                  f.package_name,
                  f.package_version,
                  f.fixed_version,
                  f.risk_score,
                  f.risk_level,
                  COALESCE(f.last_seen, f.time) AS last_seen
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key
                  AND COALESCE(f.source, '') IN ('osv_scanner', 'trivy_fs')
                  AND f.package_name IS NOT NULL
                  AND COALESCE(f.status, 'open') <> 'remediated'
                ORDER BY
                  COALESCE(f.risk_score, 0) DESC,
                  CASE COALESCE(f.severity, 'medium')
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                  END DESC,
                  COALESCE(f.last_seen, f.time) DESC,
                  f.finding_id DESC
                LIMIT :remediation_limit
                """
            ),
            {"asset_key": asset_key, "remediation_limit": remediation_limit},
        )
        .mappings()
        .all()
    )
    remediation_queue = []
    for row in remediation_rows:
        item = dict(row)
        item["last_seen"] = _serialize_datetime_value(item.get("last_seen"))
        remediation_queue.append(item)

    return {
        "asset_key": asset.get("asset_key"),
        "asset_name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "environment": asset.get("environment"),
        "criticality": asset.get("criticality"),
        **totals,
        "active_dependency_count": active_dependency_count,
        "source_distribution": list(by_source.values()),
        "severity_distribution_active": severity_distribution_active,
        "ecosystem_distribution_active": ecosystem_distribution_active,
        "dependency_distribution": dependency_distribution,
        "remediation_queue": remediation_queue,
    }


class FindingUpsertBody(BaseModel):
    finding_key: str
    asset_key: str | None = None
    asset_id: int | None = None
    category: str | None = None
    title: str
    severity: str = "medium"
    confidence: str = "high"
    evidence: str | None = None
    remediation: str | None = None
    source: str | None = None  # e.g. tls_scan, header_scan
    vulnerability_id: str | None = None
    package_ecosystem: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    scanner_metadata_json: dict[str, Any] | None = None


def upsert_finding_record(db: Session, body: FindingUpsertBody) -> dict[str, Any]:
    """Internal helper so scanner-style imports and HTTP route share one finding lifecycle path."""
    asset_id = body.asset_id
    if asset_id is None and body.asset_key:
        row = (
            db.execute(
                text("SELECT asset_id FROM assets WHERE asset_key = :k"),
                {"k": body.asset_key},
            )
            .mappings()
            .first()
        )
        if not row:
            raise HTTPException(status_code=400, detail=f"Asset not found: {body.asset_key}")
        asset_id = row["asset_id"]
    if asset_id is None:
        raise HTTPException(status_code=400, detail="Provide asset_id or asset_key")

    existing = (
        db.execute(
            text("SELECT finding_id, last_seen FROM findings WHERE finding_key = :k"),
            {"k": body.finding_key},
        )
        .mappings()
        .first()
    )

    if existing:
        finding_id = int(existing["finding_id"])
        db.execute(
            text("""
              UPDATE findings SET last_seen = NOW(), evidence = COALESCE(:evidence, evidence),
                category = COALESCE(:category, category),
                remediation = COALESCE(:remediation, remediation),
                title = COALESCE(NULLIF(:title, ''), title),
                severity = COALESCE(NULLIF(:severity, ''), severity),
                confidence = COALESCE(NULLIF(:confidence, ''), confidence),
                source = COALESCE(NULLIF(:source, ''), source),
                vulnerability_id = COALESCE(NULLIF(:vulnerability_id, ''), vulnerability_id),
                package_ecosystem = COALESCE(NULLIF(:package_ecosystem, ''), package_ecosystem),
                package_name = COALESCE(NULLIF(:package_name, ''), package_name),
                package_version = COALESCE(NULLIF(:package_version, ''), package_version),
                fixed_version = COALESCE(NULLIF(:fixed_version, ''), fixed_version),
                scanner_metadata_json = COALESCE(CAST(:scanner_metadata_json AS jsonb), scanner_metadata_json),
                status = CASE
                  WHEN COALESCE(status, 'open') = 'remediated' THEN 'open'
                  ELSE COALESCE(status, 'open')
                END,
                asset_id = COALESCE(:asset_id, asset_id)
              WHERE finding_key = :k
            """),
            {
                "k": body.finding_key,
                "evidence": body.evidence,
                "category": body.category,
                "remediation": body.remediation,
                "title": body.title,
                "severity": body.severity,
                "confidence": body.confidence,
                "source": body.source,
                "vulnerability_id": body.vulnerability_id,
                "package_ecosystem": body.package_ecosystem,
                "package_name": body.package_name,
                "package_version": body.package_version,
                "fixed_version": body.fixed_version,
                "scanner_metadata_json": _as_jsonb_or_none(body.scanner_metadata_json),
                "asset_id": asset_id,
            },
        )
        recompute_finding_risk(db, finding_id)
        db.commit()
        return {"ok": True, "finding_key": body.finding_key, "updated": True}
    else:
        row = (
            db.execute(
                text("""
              INSERT INTO findings (
                finding_key, asset_id, first_seen, last_seen, time, status, source, category,
                title, severity, confidence, evidence, remediation, vulnerability_id,
                package_ecosystem, package_name, package_version, fixed_version, scanner_metadata_json
              )
              VALUES (
                :finding_key, :asset_id, NOW(), NOW(), NOW(), 'open', :source, :category,
                :title, :severity, :confidence, :evidence, :remediation, :vulnerability_id,
                :package_ecosystem, :package_name, :package_version, :fixed_version,
                CAST(:scanner_metadata_json AS jsonb)
              )
              RETURNING finding_id
            """),
                {
                    "finding_key": body.finding_key,
                    "asset_id": asset_id,
                    "source": body.source or "",
                    "category": body.category or "",
                    "title": body.title,
                    "severity": body.severity,
                    "confidence": body.confidence,
                    "evidence": body.evidence or "",
                    "remediation": body.remediation or "",
                    "vulnerability_id": body.vulnerability_id,
                    "package_ecosystem": body.package_ecosystem,
                    "package_name": body.package_name,
                    "package_version": body.package_version,
                    "fixed_version": body.fixed_version,
                    "scanner_metadata_json": _as_jsonb_or_none(body.scanner_metadata_json) or "{}",
                },
            )
            .mappings()
            .first()
        )
        if not row:
            raise HTTPException(status_code=500, detail="Failed to create finding")
        recompute_finding_risk(db, int(row["finding_id"]))
        db.commit()
        ak = body.asset_key
        if not ak:
            row = (
                db.execute(
                    text("SELECT asset_key FROM assets WHERE asset_id = :id"), {"id": asset_id}
                )
                .mappings()
                .first()
            )
            ak = (row["asset_key"] or "") if row else ""
        if ak and not is_asset_suppressed(db, ak):
            publish_correlation_event(
                "finding.created",
                asset_key=ak,
                finding_key=body.finding_key,
                severity=body.severity,
                incident_key=f"finding:{ak}:{body.finding_key}",
            )
        return {"ok": True, "finding_key": body.finding_key, "updated": False}


@router.post("/")
def upsert_finding(
    body: FindingUpsertBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """
    Upsert by finding_key. If exists: update last_seen (and optionally evidence).
    If new: insert with first_seen=last_seen=now. Requires asset_id or asset_key to resolve.
    """
    return upsert_finding_record(db, body)


class UpdateStatusBody(BaseModel):
    status: str


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    body: UpdateStatusBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Update finding status: open | in_progress | remediated | accepted_risk."""
    if body.status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail=f"Invalid status. Use one of: {VALID_STATUS}")
    row = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.execute(
        text("UPDATE findings SET status = :status WHERE finding_id = :id"),
        {"status": body.status, "id": finding_id},
    )
    recompute_finding_risk(db, finding_id)
    log_audit(
        db,
        "finding_status",
        user_name=_user,
        asset_key=None,
        details={"finding_id": finding_id, "status": body.status},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True, "finding_id": finding_id, "status": body.status}


class AcceptRiskBody(BaseModel):
    reason: str
    expires_at: str  # ISO datetime


@router.post("/{finding_id}/accept-risk")
def accept_finding_risk(
    finding_id: int,
    body: AcceptRiskBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    """Set finding to accepted_risk with reason and expiry. Must be reviewed when expires_at passes."""
    try:
        expires_at = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="expires_at must be ISO 8601 datetime")
    row = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    now = datetime.now(UTC)
    db.execute(
        text("""
          UPDATE findings SET
            status = 'accepted_risk',
            accepted_risk_at = :now,
            accepted_risk_expires_at = :expires_at,
            accepted_risk_reason = :reason,
            accepted_risk_by = :user
          WHERE finding_id = :id
        """),
        {
            "id": finding_id,
            "now": now,
            "expires_at": expires_at,
            "reason": body.reason or "",
            "user": user,
        },
    )
    recompute_finding_risk(db, finding_id)
    log_audit(
        db,
        "accept_risk",
        user_name=user,
        asset_key=None,
        details={
            "finding_id": finding_id,
            "reason": body.reason[:100] if body.reason else "",
            "expires_at": body.expires_at,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"ok": True, "finding_id": finding_id, "status": "accepted_risk"}


class CreateRiskLabelBody(BaseModel):
    label: str
    source: str = "analyst"
    note: str | None = None


@router.get("/{finding_id}/risk-labels")
def list_finding_risk_labels(
    finding_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    finding = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    rows = (
        db.execute(
            text(
                """
                SELECT id, finding_id, label, source, note, created_by, created_at
                FROM finding_risk_labels
                WHERE finding_id = :finding_id
                ORDER BY created_at DESC, id DESC
                """
            ),
            {"finding_id": finding_id},
        )
        .mappings()
        .all()
    )
    items = []
    for row in rows:
        item = dict(row)
        created_at = item.get("created_at")
        if hasattr(created_at, "isoformat"):
            item["created_at"] = created_at.isoformat()
        items.append(item)
    return {"items": items}


@router.post("/{finding_id}/risk-labels")
def create_finding_risk_label(
    finding_id: int,
    body: CreateRiskLabelBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    finding = (
        db.execute(
            text("SELECT finding_id FROM findings WHERE finding_id = :id"),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    label = body.label.strip().lower()
    source = body.source.strip().lower()
    if label not in VALID_RISK_LABELS:
        raise HTTPException(
            status_code=400, detail=f"Invalid label. Use one of: {VALID_RISK_LABELS}"
        )
    if source not in VALID_RISK_LABEL_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source. Use one of: {VALID_RISK_LABEL_SOURCES}",
        )

    row = (
        db.execute(
            text(
                """
                INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
                VALUES (:finding_id, :label, :source, :note, :created_by)
                RETURNING id, finding_id, label, source, note, created_by, created_at
                """
            ),
            {
                "finding_id": finding_id,
                "label": label,
                "source": source,
                "note": (body.note or "").strip() or None,
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "finding_risk_label",
        user_name=user,
        asset_key=None,
        details={"finding_id": finding_id, "label": label, "source": source},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    item = dict(row or {})
    created_at = item.get("created_at")
    if hasattr(created_at, "isoformat"):
        item["created_at"] = created_at.isoformat()
    return item
