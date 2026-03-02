"""AI enrichment endpoints: incident summaries, finding explanations, anomaly detection."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai_anomaly import SeriesPoint, detect_latest_anomaly
from app.ai_client import AIClientError, compact_json, generate_text, model_name, provider_name
from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.auth import require_auth, require_role
from app.settings import settings

router = APIRouter(prefix="/ai", tags=["ai"])

INCIDENT_SUMMARY_PROMPT_MAX_CHARS = 4200
INCIDENT_SUMMARY_MAX_TOKENS = 260

FINDING_EXPLAIN_EVIDENCE_LIMIT = 900
FINDING_EXPLAIN_PROMPT_MAX_CHARS = 3600
FINDING_EXPLAIN_MAX_TOKENS = 180
FINDING_EXPLAIN_RETRY_MAX_TOKENS = 90
FINDING_EXPLAIN_PRIMARY_TIMEOUT_SECONDS = 25
FINDING_EXPLAIN_RETRY_TIMEOUT_SECONDS = 100


class GenerateBody(BaseModel):
    force: bool = False


class DetectAnomaliesBody(BaseModel):
    persist: bool = True


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def _serialize_row(row) -> dict:
    out = dict(row)
    for key, value in list(out.items()):
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    if isinstance(out.get("context_json"), str):
        try:
            out["context_json"] = json.loads(out["context_json"])
        except json.JSONDecodeError:
            out["context_json"] = {}
    return out


def _incident_context(db: Session, incident_id: int) -> dict:
    row = (
        db.execute(
            text(
                """
            SELECT id, incident_key, title, severity, status, assigned_to,
                   created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata
            FROM incidents
            WHERE id = :id
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = (
        db.execute(
            text(
                """
            SELECT asset_key, added_at, added_by
            FROM incident_alerts
            WHERE incident_id = :id
            ORDER BY added_at ASC
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .all()
    )
    timeline = (
        db.execute(
            text(
                """
            SELECT event_type, author, body, details, created_at
            FROM incident_notes
            WHERE incident_id = :id
            ORDER BY created_at ASC
            LIMIT 20
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .all()
    )
    context = {
        "incident": {
            "id": row["id"],
            "incident_key": row.get("incident_key"),
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "assigned_to": row.get("assigned_to"),
            "created_at": _iso(row.get("created_at")),
            "updated_at": _iso(row.get("updated_at")),
            "resolved_at": _iso(row.get("resolved_at")),
            "closed_at": _iso(row.get("closed_at")),
            "sla_due_at": _iso(row.get("sla_due_at")),
            "metadata": row.get("metadata") or {},
        },
        "alerts": [
            {
                "asset_key": a.get("asset_key"),
                "added_at": _iso(a.get("added_at")),
                "added_by": a.get("added_by"),
            }
            for a in alerts
        ],
        "timeline": [
            {
                "event_type": t.get("event_type"),
                "author": t.get("author"),
                "body": (t.get("body") or "")[:220],
                "details": t.get("details") or {},
                "created_at": _iso(t.get("created_at")),
            }
            for t in timeline
        ],
    }
    return context


def _finding_context(
    db: Session,
    finding_id: int,
    *,
    include_evidence: bool = True,
    evidence_limit: int = FINDING_EXPLAIN_EVIDENCE_LIMIT,
) -> dict:
    row = (
        db.execute(
            text(
                """
            SELECT
              f.finding_id, f.finding_key, COALESCE(f.status, 'open') AS status,
              f.severity, f.confidence, f.category, f.title, f.evidence, f.remediation, f.source,
              f.risk_score, f.risk_level, f.risk_factors_json,
              f.first_seen, f.last_seen, f.accepted_risk_reason, f.accepted_risk_expires_at,
              a.asset_key, a.name AS asset_name, a.type AS asset_type, a.environment, a.criticality,
              a.owner, a.verified
            FROM findings f
            LEFT JOIN assets a ON a.asset_id = f.asset_id
            WHERE f.finding_id = :id
            """
            ),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    evidence = row.get("evidence") or ""
    if not include_evidence:
        evidence = ""
    remediation = (row.get("remediation") or "")[:700]
    return {
        "finding": {
            "finding_id": row.get("finding_id"),
            "finding_key": row.get("finding_key"),
            "status": row.get("status"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "category": row.get("category"),
            "title": row.get("title"),
            "risk_score": row.get("risk_score"),
            "risk_level": row.get("risk_level"),
            "risk_factors_json": row.get("risk_factors_json") or {},
            "evidence": evidence[: max(0, evidence_limit)],
            "remediation": remediation,
            "source": row.get("source"),
            "first_seen": _iso(row.get("first_seen")),
            "last_seen": _iso(row.get("last_seen")),
            "accepted_risk_reason": row.get("accepted_risk_reason"),
            "accepted_risk_expires_at": _iso(row.get("accepted_risk_expires_at")),
        },
        "asset": {
            "asset_key": row.get("asset_key"),
            "asset_name": row.get("asset_name"),
            "asset_type": row.get("asset_type"),
            "environment": row.get("environment"),
            "criticality": row.get("criticality"),
            "owner": row.get("owner"),
            "verified": row.get("verified"),
        },
    }


def _incident_summary_prompt(context: dict) -> tuple[str, str]:
    system = (
        "You are a SOC executive reporting assistant. "
        "Write concise, factual incident summaries for leadership. "
        "Avoid speculation and include impact, affected assets, current status, and clear next actions."
    )
    user = (
        "Summarize this incident for executive leadership in under 180 words.\n"
        "Format:\n"
        "1) Impact\n2) Affected assets\n3) Current severity/status\n4) Immediate recommended actions\n\n"
        f"Incident context JSON:\n{compact_json(context, max_chars=INCIDENT_SUMMARY_PROMPT_MAX_CHARS)}"
    )
    return system, user


def _finding_explanation_prompt(context: dict) -> tuple[str, str]:
    system = (
        "You are a security triage copilot for AppSec and cloud posture teams. "
        "Explain technical risks clearly and provide actionable remediation."
    )
    user = (
        "Explain this finding in practical terms in under 120 words.\n"
        "Return sections:\n"
        "- What this means\n"
        "- How it can be exploited\n"
        "- Why it matters in this environment\n"
        "- Remediation steps\n"
        "- Optional quick patch/config snippet if applicable\n\n"
        f"Finding context JSON:\n{compact_json(context, max_chars=FINDING_EXPLAIN_PROMPT_MAX_CHARS)}"
    )
    return system, user


def _is_timeout_error(err: AIClientError) -> bool:
    msg = str(err).lower()
    return (
        "timed out" in msg
        or "timeout" in msg
        or "read operation timed out" in msg
        or "connect timeout" in msg
    )


def _is_recoverable_ai_error(err: AIClientError) -> bool:
    msg = str(err).lower()
    if "ai_disabled" in msg:
        return False
    if "unsupported_ai_provider" in msg:
        return False
    return "api_key_missing" not in msg


def _fallback_incident_summary(context: dict) -> str:
    incident = context.get("incident") or {}
    alerts = context.get("alerts") or []
    asset_keys = [a.get("asset_key") for a in alerts if a.get("asset_key")]
    affected = ", ".join(asset_keys[:5]) if asset_keys else "No linked assets recorded"
    severity = (incident.get("severity") or "unknown").upper()
    status = incident.get("status") or "unknown"
    title = incident.get("title") or "Untitled incident"
    return (
        "1) Impact\n"
        f"{title} is currently tracked as {severity} severity and status '{status}'.\n\n"
        "2) Affected assets\n"
        f"{affected}\n\n"
        "3) Current severity/status\n"
        f"Severity: {severity}. Status: {status}. Assigned to: {incident.get('assigned_to') or 'unassigned'}.\n\n"
        "4) Immediate recommended actions\n"
        "Validate exposure, contain affected assets, assign clear ownership, and track remediation to closure."
    )


def _fallback_finding_explanation(context: dict) -> str:
    finding = context.get("finding") or {}
    asset = context.get("asset") or {}
    title = finding.get("title") or "Security finding"
    severity = (finding.get("severity") or "unknown").upper()
    category = finding.get("category") or "general"
    env = asset.get("environment") or "unknown"
    criticality = asset.get("criticality") or "unknown"
    remediation = finding.get("remediation") or "Apply vendor guidance and hardening controls."
    return (
        "- What this means\n"
        f"{title} indicates a {category} weakness with {severity} severity.\n\n"
        "- How it can be exploited\n"
        "Attackers may use this gap to increase access or reduce defensive visibility.\n\n"
        "- Why it matters in this environment\n"
        f"The asset runs in {env} with criticality {criticality}, so blast radius may be meaningful.\n\n"
        "- Remediation steps\n"
        f"{remediation}"
    )


def _existing_incident_summary(db: Session, incident_id: int):
    return (
        db.execute(
            text(
                """
            SELECT incident_id, summary_text, provider, model, generated_by, generated_at, context_json
            FROM incident_ai_summaries
            WHERE incident_id = :id
            """
            ),
            {"id": incident_id},
        )
        .mappings()
        .first()
    )


def _existing_finding_explanation(db: Session, finding_id: int):
    return (
        db.execute(
            text(
                """
            SELECT finding_id, explanation_text, remediation_patch, provider, model, generated_by, generated_at, context_json
            FROM finding_ai_explanations
            WHERE finding_id = :id
            """
            ),
            {"id": finding_id},
        )
        .mappings()
        .first()
    )


@router.get("/incidents/{incident_id}/summary")
def get_incident_summary(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = _existing_incident_summary(db, incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="AI summary not found")
    return _serialize_row(row)


@router.post("/incidents/{incident_id}/summary/generate")
def generate_incident_summary(
    incident_id: int,
    body: GenerateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    existing = _existing_incident_summary(db, incident_id)
    if existing and not body.force:
        out = _serialize_row(existing)
        out["cached"] = True
        return out
    context = _incident_context(db, incident_id)
    system_prompt, user_prompt = _incident_summary_prompt(context)
    generated_provider = provider_name()
    generated_model = model_name()
    try:
        summary = generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=INCIDENT_SUMMARY_MAX_TOKENS,
        )
    except AIClientError as e:
        if _is_recoverable_ai_error(e):
            summary = _fallback_incident_summary(context)
            generated_provider = f"{generated_provider}-fallback"
            generated_model = "template-v1"
        else:
            raise HTTPException(
                status_code=503, detail=f"AI summary generation unavailable: {e}"
            ) from e

    params = {
        "incident_id": incident_id,
        "summary_text": summary.strip(),
        "provider": generated_provider,
        "model": generated_model,
        "generated_by": user,
        "context_json": json.dumps({"generated_from": context.get("incident", {}), "source": "ai"}),
    }
    row = (
        db.execute(
            text(
                """
            INSERT INTO incident_ai_summaries (incident_id, summary_text, provider, model, generated_by, context_json)
            VALUES (:incident_id, :summary_text, :provider, :model, :generated_by, CAST(:context_json AS jsonb))
            ON CONFLICT (incident_id) DO UPDATE SET
              summary_text = EXCLUDED.summary_text,
              provider = EXCLUDED.provider,
              model = EXCLUDED.model,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW(),
              context_json = EXCLUDED.context_json
            RETURNING incident_id, summary_text, provider, model, generated_by, generated_at, context_json
            """
            ),
            params,
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "incident_ai_summary_generate",
        user_name=user,
        details={
            "incident_id": incident_id,
            "provider": generated_provider,
            "model": generated_model,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = _serialize_row(row)
    out["cached"] = False
    return out


@router.get("/findings/{finding_id}/explanation")
def get_finding_explanation(
    finding_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = _existing_finding_explanation(db, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="AI explanation not found")
    return _serialize_row(row)


@router.post("/findings/{finding_id}/explain")
def generate_finding_explanation(
    finding_id: int,
    body: GenerateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    existing = _existing_finding_explanation(db, finding_id)
    if existing and not body.force:
        out = _serialize_row(existing)
        out["cached"] = True
        return out
    context = _finding_context(db, finding_id, include_evidence=True)
    stored_context = context
    generated_provider = provider_name()
    generated_model = model_name()
    system_prompt, user_prompt = _finding_explanation_prompt(context)
    try:
        explanation = generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=FINDING_EXPLAIN_MAX_TOKENS,
            timeout_seconds=min(
                float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                float(FINDING_EXPLAIN_PRIMARY_TIMEOUT_SECONDS),
            ),
        )
    except AIClientError as e:
        if not _is_recoverable_ai_error(e):
            raise HTTPException(
                status_code=503, detail=f"AI explanation generation unavailable: {e}"
            ) from e
        compact_context = _finding_context(db, finding_id, include_evidence=False, evidence_limit=0)
        compact_system, compact_user = _finding_explanation_prompt(compact_context)
        try:
            explanation = generate_text(
                system_prompt=compact_system,
                user_prompt=compact_user,
                max_tokens=FINDING_EXPLAIN_RETRY_MAX_TOKENS,
                timeout_seconds=min(
                    float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                    float(FINDING_EXPLAIN_RETRY_TIMEOUT_SECONDS),
                ),
            )
            stored_context = compact_context
        except AIClientError as retry_error:
            if _is_recoverable_ai_error(retry_error):
                explanation = _fallback_finding_explanation(compact_context)
                stored_context = compact_context
                generated_provider = f"{generated_provider}-fallback"
                generated_model = "template-v1"
            else:
                raise HTTPException(
                    status_code=503,
                    detail=f"AI explanation generation unavailable: {retry_error}",
                ) from retry_error

    params = {
        "finding_id": finding_id,
        "explanation_text": explanation.strip(),
        "provider": generated_provider,
        "model": generated_model,
        "generated_by": user,
        "context_json": json.dumps(
            {"generated_from": stored_context.get("finding", {}), "source": "ai"}
        ),
    }
    row = (
        db.execute(
            text(
                """
            INSERT INTO finding_ai_explanations (
              finding_id, explanation_text, provider, model, generated_by, context_json
            )
            VALUES (
              :finding_id, :explanation_text, :provider, :model, :generated_by, CAST(:context_json AS jsonb)
            )
            ON CONFLICT (finding_id) DO UPDATE SET
              explanation_text = EXCLUDED.explanation_text,
              provider = EXCLUDED.provider,
              model = EXCLUDED.model,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW(),
              context_json = EXCLUDED.context_json
            RETURNING finding_id, explanation_text, remediation_patch, provider, model, generated_by, generated_at, context_json
            """
            ),
            params,
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "finding_ai_explain_generate",
        user_name=user,
        details={
            "finding_id": finding_id,
            "provider": generated_provider,
            "model": generated_model,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = _serialize_row(row)
    out["cached"] = False
    return out


def _snapshot_series(db: Session, metric: str) -> list[SeriesPoint]:
    if metric not in {"red", "posture_score_avg", "avg_latency_ms"}:
        return []
    rows = (
        db.execute(
            text(
                f"""
            SELECT created_at, {metric} AS value
            FROM posture_report_snapshots
            WHERE created_at >= NOW() - interval '45 days'
            ORDER BY created_at ASC
            """
            )
        )
        .mappings()
        .all()
    )
    out: list[SeriesPoint] = []
    for r in rows:
        if r.get("value") is None:
            continue
        ts = r.get("created_at")
        if not hasattr(ts, "isoformat"):
            continue
        out.append(SeriesPoint(ts=ts, value=float(r["value"])))
    return out


def _daily_count_series(
    db: Session, table: str, time_expr: str, where_clause: str = "1=1"
) -> list[SeriesPoint]:
    rows = (
        db.execute(
            text(
                f"""
            SELECT date_trunc('day', {time_expr}) AS day, COUNT(*) AS value
            FROM {table}
            WHERE {where_clause}
              AND {time_expr} >= NOW() - interval '45 days'
            GROUP BY day
            ORDER BY day ASC
            """
            )
        )
        .mappings()
        .all()
    )
    out: list[SeriesPoint] = []
    for r in rows:
        ts = r.get("day")
        if not hasattr(ts, "isoformat"):
            continue
        out.append(SeriesPoint(ts=ts, value=float(r["value"] or 0)))
    return out


def _detect_anomalies(db: Session) -> list[dict]:
    anomalies: list[dict] = []

    checks: list[tuple[str, list[SeriesPoint], str]] = [
        ("red_assets_count", _snapshot_series(db, "red"), "higher"),
        ("posture_score_avg", _snapshot_series(db, "posture_score_avg"), "lower"),
        ("avg_latency_ms", _snapshot_series(db, "avg_latency_ms"), "higher"),
        (
            "new_findings_daily",
            _daily_count_series(db, "findings", "COALESCE(first_seen, time, NOW())"),
            "higher",
        ),
        (
            "failed_jobs_daily",
            _daily_count_series(
                db,
                "scan_jobs",
                "COALESCE(finished_at, created_at)",
                "status = 'failed'",
            ),
            "higher",
        ),
    ]

    for metric, points, direction in checks:
        anomaly = detect_latest_anomaly(
            metric=metric,
            points=points,
            direction=direction,
            min_points=6,
            lookback=14,
            z_threshold=2.5,
        )
        if not anomaly:
            continue
        anomalies.append(
            {
                "metric": anomaly.metric,
                "severity": anomaly.severity,
                "current_value": round(anomaly.current_value, 2),
                "baseline_mean": round(anomaly.baseline_mean, 2),
                "baseline_std": round(anomaly.baseline_std, 2),
                "z_score": round(anomaly.z_score, 2) if anomaly.z_score is not None else None,
                "window_size": anomaly.window_size,
                "context_json": anomaly.context,
            }
        )
    return anomalies


@router.post("/posture/anomalies/detect")
def detect_posture_anomalies(
    body: DetectAnomaliesBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    items = _detect_anomalies(db)
    inserted = 0
    if body.persist and items:
        for item in items:
            db.execute(
                text(
                    """
                    INSERT INTO posture_anomalies (
                      metric, severity, current_value, baseline_mean, baseline_std, z_score, window_size, context_json
                    )
                    VALUES (
                      :metric, :severity, :current_value, :baseline_mean, :baseline_std, :z_score, :window_size, CAST(:context_json AS jsonb)
                    )
                    """
                ),
                {
                    **item,
                    "context_json": json.dumps(item.get("context_json") or {}),
                },
            )
            inserted += 1
        log_audit(
            db,
            "posture_anomaly_detect",
            user_name=user,
            details={"detected": len(items), "persisted": inserted},
            request_id=request_id_ctx.get(None),
        )
        db.commit()
    return {
        "detected_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "detected": len(items),
        "persisted": inserted,
        "items": items,
    }


@router.get("/posture/anomalies")
def list_posture_anomalies(
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
            SELECT id, detected_at, metric, severity, current_value, baseline_mean, baseline_std, z_score, window_size, context_json
            FROM posture_anomalies
            ORDER BY detected_at DESC, id DESC
            LIMIT :limit
            """
            ),
            {"limit": limit},
        )
        .mappings()
        .all()
    )
    return {"items": [_serialize_row(r) for r in rows]}
