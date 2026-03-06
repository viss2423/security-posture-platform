"""AI enrichment endpoints: incident summaries, finding explanations, anomaly detection."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai_anomaly import SeriesPoint, detect_latest_anomaly
from app.ai_client import AIClientError, compact_json, generate_text, model_name, provider_name
from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.routers.alerts import _load_alert_enrichment
from app.routers.auth import require_auth, require_role
from app.routers.posture import (
    _events_for_asset,
    _get_asset_metadata_batch,
    _opensearch_get,
    _recommendations,
)
from app.schemas.posture import raw_to_asset_state
from app.settings import settings

router = APIRouter(prefix="/ai", tags=["ai"])

INCIDENT_SUMMARY_PROMPT_MAX_CHARS = 4200
INCIDENT_SUMMARY_MAX_TOKENS = 260
ASSET_DIAGNOSIS_PROMPT_MAX_CHARS = 4200
ASSET_DIAGNOSIS_MAX_TOKENS = 160
ASSET_DIAGNOSIS_RETRY_MAX_TOKENS = 120
ASSET_DIAGNOSIS_TIMEOUT_SECONDS = 180
ASSET_DIAGNOSIS_RETRY_TIMEOUT_SECONDS = 240
POLICY_EVALUATION_SUMMARY_PROMPT_MAX_CHARS = 4200
POLICY_EVALUATION_SUMMARY_MAX_TOKENS = 180
POLICY_EVALUATION_SUMMARY_RETRY_MAX_TOKENS = 130
POLICY_EVALUATION_SUMMARY_TIMEOUT_SECONDS = 120
POLICY_EVALUATION_SUMMARY_RETRY_TIMEOUT_SECONDS = 180
JOB_TRIAGE_PROMPT_MAX_CHARS = 4200
JOB_TRIAGE_LOG_MAX_CHARS = 1800
JOB_TRIAGE_MAX_TOKENS = 160
JOB_TRIAGE_RETRY_MAX_TOKENS = 120
JOB_TRIAGE_TIMEOUT_SECONDS = 120
JOB_TRIAGE_RETRY_TIMEOUT_SECONDS = 180
ALERT_GUIDANCE_PROMPT_MAX_CHARS = 4200
ALERT_GUIDANCE_MAX_TOKENS = 180
ALERT_GUIDANCE_RETRY_MAX_TOKENS = 130
ALERT_GUIDANCE_TIMEOUT_SECONDS = 150
ALERT_GUIDANCE_RETRY_TIMEOUT_SECONDS = 210

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


def _asset_diagnosis_context(
    db: Session,
    asset_key: str,
    *,
    hours: int = 24,
    event_limit: int = 20,
    findings_limit: int = 5,
) -> dict:
    try:
        data = _opensearch_get(f"/_doc/{asset_key}")
    except httpx.HTTPStatusError as e:
        if e.response is not None and e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Asset not found in posture index") from e
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e}") from e
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e}") from e

    if not data.get("found"):
        raise HTTPException(status_code=404, detail="Asset not found in posture index")

    raw = data.get("_source") or {}
    raw["asset_key"] = raw.get("asset_key") or asset_key
    state = raw_to_asset_state(raw)
    meta = _get_asset_metadata_batch(db, [asset_key]).get(asset_key)
    if meta:
        updates = {
            k: meta[k] for k in ("owner", "criticality", "name", "environment") if meta.get(k)
        }
        if updates:
            state = state.model_copy(update=updates)

    timeline = _events_for_asset(asset_key, hours=hours, size=max(1, event_limit))
    evidence = timeline[0] if timeline else None
    latency_slo_ms = getattr(settings, "LATENCY_SLO_MS", 200)
    last_latency = evidence.get("latency_ms") if evidence else None
    latency_slo_ok = last_latency is None or (
        isinstance(last_latency, (int, float)) and last_latency <= latency_slo_ms
    )
    recommendations = _recommendations(
        state, latency_slo_ok=latency_slo_ok, latency_slo_ms=latency_slo_ms
    )

    total_events = len(timeline)
    non_200_events = 0
    unhealthy_events = 0
    latency_spike_events = 0
    latest_statuses: list[str] = []
    for ev in timeline:
        code = ev.get("code")
        status = str(ev.get("status") or "").strip().lower()
        latency_ms = ev.get("latency_ms")
        if isinstance(code, int) and code >= 400:
            non_200_events += 1
        if status not in ("", "up", "ok"):
            unhealthy_events += 1
        if isinstance(latency_ms, (int, float)) and latency_ms > latency_slo_ms:
            latency_spike_events += 1
        if len(latest_statuses) < 8 and status:
            latest_statuses.append(status)

    findings_rows = (
        db.execute(
            text(
                """
            SELECT
              f.finding_id,
              f.finding_key,
              COALESCE(f.status, 'open') AS status,
              f.severity,
              f.category,
              f.title,
              f.source,
              f.risk_score,
              f.risk_level,
              f.last_seen,
              f.time
            FROM findings f
            LEFT JOIN assets a ON a.asset_id = f.asset_id
            WHERE a.asset_key = :asset_key
              AND COALESCE(f.status, 'open') IN ('open', 'in_progress', 'accepted_risk')
            ORDER BY COALESCE(f.risk_score, 0) DESC, COALESCE(f.last_seen, f.time) DESC
            LIMIT :limit
            """
            ),
            {"asset_key": asset_key, "limit": findings_limit},
        )
        .mappings()
        .all()
    )
    findings = [
        {
            "finding_id": r.get("finding_id"),
            "finding_key": r.get("finding_key"),
            "status": r.get("status"),
            "severity": r.get("severity"),
            "category": r.get("category"),
            "title": r.get("title"),
            "source": r.get("source"),
            "risk_score": r.get("risk_score"),
            "risk_level": r.get("risk_level"),
            "last_seen": _iso(r.get("last_seen") or r.get("time")),
        }
        for r in findings_rows
    ]

    state_dict = state.model_dump(mode="json")
    return {
        "asset": {
            "asset_key": state_dict.get("asset_key") or state_dict.get("asset_id") or asset_key,
            "name": state_dict.get("name"),
            "status": state_dict.get("status"),
            "reason": state_dict.get("reason"),
            "criticality": state_dict.get("criticality"),
            "owner": state_dict.get("owner"),
            "environment": state_dict.get("environment"),
            "posture_score": state_dict.get("posture_score"),
            "last_seen": state_dict.get("last_seen"),
            "staleness_seconds": state_dict.get("staleness_seconds"),
        },
        "signals": {
            "window_hours": hours,
            "latency_slo_ms": latency_slo_ms,
            "latency_slo_ok": latency_slo_ok,
            "total_events": total_events,
            "non_200_events": non_200_events,
            "unhealthy_events": unhealthy_events,
            "latency_spike_events": latency_spike_events,
            "latest_statuses": latest_statuses,
            "latest_event": {
                "@timestamp": _iso(evidence.get("@timestamp")) if evidence else None,
                "status": evidence.get("status") if evidence else None,
                "code": evidence.get("code") if evidence else None,
                "latency_ms": evidence.get("latency_ms") if evidence else None,
            },
        },
        "findings": findings,
        "recommendations": recommendations,
    }


def _policy_violation_theme(violation: dict) -> dict:
    rule_type = str(violation.get("rule_type") or "unknown").strip().lower()
    evidence = violation.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    if rule_type == "require_header":
        header = str(evidence.get("required_header") or "security header").strip().lower()
        return {
            "key": f"missing_header:{header}",
            "label": f"Missing {header}",
            "remediation": f"Add and validate the {header} header on affected assets.",
        }
    if rule_type in {"no_open_findings", "no_critical_findings"}:
        severity = str(evidence.get("severity") or "high").strip().lower()
        return {
            "key": f"open_findings:{severity}",
            "label": f"Open {severity} findings",
            "remediation": f"Remediate, suppress, or accept-risk the {severity} findings driving the failures.",
        }
    if rule_type == "posture_score_min":
        minimum = evidence.get("required_min_score")
        return {
            "key": "posture_score_min",
            "label": f"Assets below posture score {minimum}"
            if minimum is not None
            else "Assets below posture threshold",
            "remediation": "Improve availability, latency, and linked finding posture on the failing assets.",
        }
    if rule_type == "asset_status":
        actual = str(evidence.get("actual_status") or "non-compliant").strip().lower()
        return {
            "key": f"asset_status:{actual}",
            "label": f"Asset status not compliant ({actual})",
            "remediation": "Restore asset health and clear the underlying reason before re-evaluating policy.",
        }
    if rule_type == "tls_min_version":
        minimum = str(evidence.get("required_min_version") or "1.2").strip()
        return {
            "key": f"tls_min_version:{minimum}",
            "label": f"TLS version below {minimum}",
            "remediation": f"Upgrade TLS configuration to at least version {minimum} on the affected endpoints.",
        }
    return {
        "key": f"rule_type:{rule_type}",
        "label": f"Rule failures: {rule_type}",
        "remediation": "Review the failing rule evidence and correct the underlying control gap.",
    }


def _policy_violation_evidence_preview(violation: dict) -> str:
    evidence = violation.get("evidence") or {}
    if not isinstance(evidence, dict):
        return "No structured evidence available."
    for key in (
        "required_header",
        "actual_status",
        "required_min_score",
        "actual_posture_score",
        "required_min_version",
        "actual_version",
        "severity",
        "reason",
    ):
        value = evidence.get(key)
        if value not in (None, ""):
            return f"{key}={value}"
    open_findings = evidence.get("open_findings")
    if isinstance(open_findings, list) and open_findings:
        first = open_findings[0] or {}
        if isinstance(first, dict):
            return f"open finding: {first.get('title') or first.get('category') or 'finding'}"
    return "Structured evidence available in evaluation record."


def _policy_evaluation_context(db: Session, evaluation_id: int) -> dict:
    row = (
        db.execute(
            text(
                """
            SELECT
              per.id AS evaluation_id,
              per.bundle_id,
              per.evaluated_at,
              per.evaluated_by,
              per.bundle_approved_by,
              per.score,
              per.violations_count,
              per.result_json,
              pb.name AS bundle_name,
              pb.description AS bundle_description
            FROM policy_evaluation_runs per
            JOIN policy_bundles pb ON pb.id = per.bundle_id
            WHERE per.id = :evaluation_id
            """
            ),
            {"evaluation_id": evaluation_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Policy evaluation not found")

    result = row.get("result_json") or {}
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError:
            result = {}
    if not isinstance(result, dict):
        result = {}

    rules = result.get("rules") or []
    violations = result.get("violations") or []
    evaluated_assets = max(
        [int(rule.get("total") or 0) for rule in rules if isinstance(rule, dict)] or [0]
    )
    failed_rules = [
        {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "type": rule.get("type"),
            "failed": int(rule.get("failed") or 0),
            "total": int(rule.get("total") or 0),
            "pass_pct": float(rule.get("pass_pct") or 0.0),
        }
        for rule in rules
        if isinstance(rule, dict) and int(rule.get("failed") or 0) > 0
    ]
    failed_rules.sort(key=lambda item: (-item["failed"], item["pass_pct"], item["name"] or ""))

    asset_counter = Counter()
    theme_map: dict[str, dict] = {}
    sample_violations: list[dict] = []
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        asset_key = str(violation.get("asset_key") or "").strip()
        if asset_key:
            asset_counter[asset_key] += 1
        theme = _policy_violation_theme(violation)
        bucket = theme_map.setdefault(
            theme["key"],
            {
                "key": theme["key"],
                "label": theme["label"],
                "count": 0,
                "rule_types": set(),
                "assets": set(),
                "remediation": theme["remediation"],
            },
        )
        bucket["count"] += 1
        bucket["rule_types"].add(str(violation.get("rule_type") or "unknown"))
        if asset_key:
            bucket["assets"].add(asset_key)
        if len(sample_violations) < 5:
            sample_violations.append(
                {
                    "rule_name": violation.get("rule_name"),
                    "rule_type": violation.get("rule_type"),
                    "asset_key": asset_key,
                    "evidence_preview": _policy_violation_evidence_preview(violation),
                }
            )

    top_assets = [
        {"asset_key": asset_key, "violation_count": count}
        for asset_key, count in asset_counter.most_common(5)
    ]
    top_themes = [
        {
            "label": bucket["label"],
            "count": int(bucket["count"]),
            "rule_types": sorted(bucket["rule_types"])[:3],
            "assets": sorted(bucket["assets"])[:3],
            "remediation": bucket["remediation"],
        }
        for bucket in sorted(theme_map.values(), key=lambda item: (-item["count"], item["label"]))
    ][:5]
    remediation_priorities = [theme["remediation"] for theme in top_themes[:3]]

    return {
        "evaluation": {
            "evaluation_id": row.get("evaluation_id"),
            "bundle_id": row.get("bundle_id"),
            "bundle_name": row.get("bundle_name"),
            "bundle_description": row.get("bundle_description"),
            "evaluated_at": _iso(row.get("evaluated_at")),
            "evaluated_by": row.get("evaluated_by"),
            "bundle_approved_by": row.get("bundle_approved_by"),
            "score": float(row.get("score") or 0.0),
            "violations_count": int(row.get("violations_count") or 0),
            "evaluated_assets": evaluated_assets,
            "rules_count": len(rules),
            "failed_rules_count": len(failed_rules),
        },
        "failed_rules": failed_rules[:5],
        "top_assets": top_assets,
        "violation_themes": top_themes,
        "remediation_priorities": remediation_priorities,
        "sample_violations": sample_violations,
    }


def _trim_job_log(raw: str | None, *, max_chars: int = JOB_TRIAGE_LOG_MAX_CHARS) -> str:
    text_value = (raw or "").strip()
    if not text_value:
        return ""
    if len(text_value) <= max_chars:
        return text_value
    lines = [line.rstrip() for line in text_value.splitlines() if line.strip()]
    if not lines:
        return text_value[:max_chars]
    kept: list[str] = []
    total = 0
    for line in reversed(lines):
        addition = len(line) + 1
        if total + addition > max_chars:
            break
        kept.append(line)
        total += addition
    kept.reverse()
    trimmed = "\n".join(kept)
    return trimmed if trimmed else text_value[-max_chars:]


def _job_failure_signals(job: dict, asset: dict, log_excerpt: str, recent_jobs: list[dict]) -> dict:
    haystack = " ".join(
        [
            str(job.get("status") or ""),
            str(job.get("error") or ""),
            log_excerpt,
        ]
    ).lower()

    patterns: list[str] = []
    cause_category = "unknown"
    retryable_hint = False
    next_action_hint = (
        "Inspect the most recent log lines and the target asset configuration before retrying."
    )

    if "domain not verified" in haystack:
        cause_category = "verification"
        retryable_hint = False
        patterns.append("domain_not_verified")
        next_action_hint = "Complete domain verification for the asset, then retry the job."
    elif "target is not external_web" in haystack:
        cause_category = "asset_type_mismatch"
        retryable_hint = False
        patterns.append("asset_type_mismatch")
        next_action_hint = "Retarget this job to an asset with type external_web."
    elif "asset not found" in haystack:
        cause_category = "asset_missing"
        retryable_hint = False
        patterns.append("asset_not_found")
        next_action_hint = "Check that the asset still exists and the target asset ID is correct."
    elif "recovered_stale_running_job" in haystack or "stale running job" in haystack:
        cause_category = "worker_recovery"
        retryable_hint = True
        patterns.append("stale_recovery")
        next_action_hint = "Retry the job and inspect worker health if this pattern repeats."
    elif any(token in haystack for token in ("timeout", "timed out")):
        cause_category = "timeout"
        retryable_hint = True
        patterns.append("timeout")
        next_action_hint = "Retry once and inspect worker, network, or target responsiveness if the timeout repeats."
    elif any(
        token in haystack
        for token in ("name or service not known", "temporary failure in name resolution", "dns")
    ):
        cause_category = "dns_or_name_resolution"
        retryable_hint = True
        patterns.append("dns")
        next_action_hint = (
            "Validate DNS resolution for the target host from the worker environment."
        )
    elif any(
        token in haystack
        for token in (
            "connection refused",
            "unable to connect",
            "connection error",
            "connection reset",
        )
    ):
        cause_category = "network_connectivity"
        retryable_hint = True
        patterns.append("connectivity")
        next_action_hint = "Check target reachability and service availability before retrying."
    elif any(token in haystack for token in ("tls", "ssl", "certificate")):
        cause_category = "tls_or_certificate"
        retryable_hint = False
        patterns.append("tls")
        next_action_hint = "Fix certificate or TLS configuration issues before retrying."
    elif any(token in haystack for token in ("postgres", "redis", "opensearch", "database")):
        cause_category = "platform_dependency"
        retryable_hint = True
        patterns.append("dependency")
        next_action_hint = (
            "Check dependent platform services and only retry after they are healthy."
        )

    if job.get("job_type") == "web_exposure" and asset.get("asset_verified") is False:
        patterns.append("asset_unverified")
        if cause_category == "unknown":
            cause_category = "verification"
            retryable_hint = False
            next_action_hint = "Verify the asset before rerunning the web exposure job."
    if job.get("job_type") == "web_exposure" and str(asset.get("asset_type") or "") not in (
        "",
        "external_web",
    ):
        patterns.append("asset_type_non_external_web")
        if cause_category == "unknown":
            cause_category = "asset_type_mismatch"
            retryable_hint = False
            next_action_hint = "Use a web exposure job only on external_web assets."

    recent_failures = sum(1 for item in recent_jobs if str(item.get("status") or "") == "failed")
    return {
        "cause_category": cause_category,
        "retryable_hint": retryable_hint,
        "next_action_hint": next_action_hint,
        "matched_patterns": patterns,
        "recent_related_failures": recent_failures,
        "log_line_count": len([line for line in log_excerpt.splitlines() if line.strip()]),
        "has_log_output": bool(log_excerpt.strip()),
    }


def _job_triage_context(db: Session, job_id: int) -> dict:
    row = (
        db.execute(
            text(
                """
            SELECT
              j.job_id,
              j.job_type,
              j.target_asset_id,
              j.requested_by,
              j.status,
              j.created_at,
              j.started_at,
              j.finished_at,
              j.error,
              j.log_output,
              j.retry_count,
              a.asset_key,
              a.name AS asset_name,
              a.type AS asset_type,
              a.environment AS asset_environment,
              a.criticality AS asset_criticality,
              a.verified AS asset_verified
            FROM scan_jobs j
            LEFT JOIN assets a ON a.asset_id = j.target_asset_id
            WHERE j.job_id = :job_id
            """
            ),
            {"job_id": job_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    started_at = row.get("started_at")
    finished_at = row.get("finished_at")
    duration_seconds = None
    if hasattr(started_at, "timestamp") and hasattr(finished_at, "timestamp"):
        duration_seconds = max(0.0, round(finished_at.timestamp() - started_at.timestamp(), 2))

    asset = {
        "asset_id": row.get("target_asset_id"),
        "asset_key": row.get("asset_key"),
        "asset_name": row.get("asset_name"),
        "asset_type": row.get("asset_type"),
        "asset_environment": row.get("asset_environment"),
        "asset_criticality": row.get("asset_criticality"),
        "asset_verified": row.get("asset_verified"),
    }
    log_excerpt = _trim_job_log(row.get("log_output"))
    recent_rows = (
        db.execute(
            text(
                """
            SELECT
              job_id,
              job_type,
              status,
              error,
              retry_count,
              created_at,
              finished_at
            FROM scan_jobs
            WHERE job_id <> :job_id
              AND (
                (:target_asset_id IS NOT NULL AND target_asset_id = :target_asset_id)
                OR job_type = :job_type
              )
            ORDER BY created_at DESC
            LIMIT 4
            """
            ),
            {
                "job_id": job_id,
                "target_asset_id": row.get("target_asset_id"),
                "job_type": row.get("job_type"),
            },
        )
        .mappings()
        .all()
    )
    recent_jobs = [
        {
            "job_id": r.get("job_id"),
            "job_type": r.get("job_type"),
            "status": r.get("status"),
            "error": r.get("error"),
            "retry_count": r.get("retry_count"),
            "created_at": _iso(r.get("created_at")),
            "finished_at": _iso(r.get("finished_at")),
        }
        for r in recent_rows
    ]
    job = {
        "job_id": row.get("job_id"),
        "job_type": row.get("job_type"),
        "status": row.get("status"),
        "requested_by": row.get("requested_by"),
        "created_at": _iso(row.get("created_at")),
        "started_at": _iso(started_at),
        "finished_at": _iso(finished_at),
        "duration_seconds": duration_seconds,
        "error": row.get("error"),
        "retry_count": row.get("retry_count"),
    }
    failure_signals = _job_failure_signals(job, asset, log_excerpt, recent_jobs)
    return {
        "job": job,
        "asset": asset,
        "failure_signals": failure_signals,
        "recent_related_jobs": recent_jobs,
        "log_excerpt": log_excerpt,
    }


def _alert_timeline_signals(events: list[dict]) -> dict:
    latency_slo_ms = int(getattr(settings, "LATENCY_SLO_MS", 200) or 200)
    unhealthy_events = 0
    healthy_events = 0
    non_200_events = 0
    latency_spike_events = 0
    timeout_events = 0
    statuses: list[str] = []
    previous_group = None
    flap_events = 0
    consecutive_unhealthy = 0

    for event in events:
        status = str(event.get("status") or "").strip().lower()
        code = event.get("code")
        unhealthy = (code is not None and code >= 400) or status not in ("", "ok", "up")
        if unhealthy:
            unhealthy_events += 1
        else:
            healthy_events += 1
        if code is not None and code >= 400:
            non_200_events += 1
        latency = event.get("latency_ms")
        if isinstance(latency, (int, float)) and latency > latency_slo_ms:
            latency_spike_events += 1
        if "timeout" in status:
            timeout_events += 1
        group = "unhealthy" if unhealthy else "healthy"
        if previous_group and previous_group != group:
            flap_events += 1
        previous_group = group
        statuses.append(status or (f"http_{code}" if code is not None else "unknown"))

    for event in events:
        status = str(event.get("status") or "").strip().lower()
        code = event.get("code")
        unhealthy = (code is not None and code >= 400) or status not in ("", "ok", "up")
        if unhealthy:
            consecutive_unhealthy += 1
        else:
            break

    return {
        "window_hours": 8,
        "event_count": len(events),
        "unhealthy_events": unhealthy_events,
        "healthy_events": healthy_events,
        "non_200_events": non_200_events,
        "latency_spike_events": latency_spike_events,
        "timeout_events": timeout_events,
        "consecutive_unhealthy_events": consecutive_unhealthy,
        "flap_events": flap_events,
        "latest_statuses": [
            {
                "timestamp": event.get("@timestamp"),
                "status": event.get("status"),
                "code": event.get("code"),
            }
            for event in events[:5]
        ],
    }


def _alert_top_findings(db: Session, asset_key: str, *, limit: int = 5) -> list[dict]:
    rows = (
        db.execute(
            text(
                """
            SELECT
              f.finding_id, f.finding_key, COALESCE(f.status, 'open') AS status,
              f.title, f.severity, f.confidence, f.source, f.risk_score, f.risk_level,
              COALESCE(f.last_seen, f.time) AS last_seen
            FROM findings f
            JOIN assets a ON a.asset_id = f.asset_id
            WHERE a.asset_key = :asset_key
              AND COALESCE(f.status, 'open') <> 'remediated'
            ORDER BY COALESCE(f.risk_score, 0) DESC, COALESCE(f.last_seen, f.time) DESC
            LIMIT :limit
            """
            ),
            {"asset_key": asset_key, "limit": limit},
        )
        .mappings()
        .all()
    )
    return [
        {
            "finding_id": row.get("finding_id"),
            "finding_key": row.get("finding_key"),
            "status": row.get("status"),
            "title": row.get("title"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "source": row.get("source"),
            "risk_score": row.get("risk_score"),
            "risk_level": row.get("risk_level"),
            "last_seen": _iso(row.get("last_seen")),
        }
        for row in rows
    ]


def _alert_open_incidents(db: Session, asset_key: str, *, limit: int = 3) -> list[dict]:
    rows = (
        db.execute(
            text(
                """
            SELECT
              i.id,
              i.incident_key,
              i.title,
              i.severity,
              i.status,
              i.assigned_to,
              i.created_at
            FROM incident_alerts ia
            JOIN incidents i ON i.id = ia.incident_id
            WHERE ia.asset_key = :asset_key
              AND i.status NOT IN ('resolved', 'closed')
            ORDER BY i.created_at DESC
            LIMIT :limit
            """
            ),
            {"asset_key": asset_key, "limit": limit},
        )
        .mappings()
        .all()
    )
    return [
        {
            "id": row.get("id"),
            "incident_key": row.get("incident_key"),
            "title": row.get("title"),
            "severity": row.get("severity"),
            "status": row.get("status"),
            "assigned_to": row.get("assigned_to"),
            "created_at": _iso(row.get("created_at")),
        }
        for row in rows
    ]


def _alert_state_row(db: Session, asset_key: str) -> dict | None:
    row = (
        db.execute(
            text(
                """
            SELECT asset_key, state, ack_reason, acked_by, acked_at, suppressed_until, assigned_to, resolved_at, updated_at
            FROM alert_states
            WHERE asset_key = :asset_key
            """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    return _serialize_row(row)


def _alert_response_bias(base: dict, state: dict | None) -> str:
    if base.get("maintenance_active") or base.get("suppression_rule_active"):
        return "suppress_or_monitor"
    if base.get("open_incident_count"):
        return "assign_or_monitor_existing_incident"
    if state and state.get("state") == "acked":
        return "assign_or_monitor"
    if (base.get("top_risk_score") or 0) >= 90 and base.get("criticality") == "high":
        return "escalate"
    if (base.get("top_risk_score") or 0) >= 85 and (
        base.get("environment") or ""
    ).lower() == "prod":
        return "escalate"
    if (base.get("active_finding_count") or 0) >= 3:
        return "assign_or_escalate"
    return "ack_or_assign"


def _alert_guidance_context(
    db: Session,
    asset_key: str,
    *,
    hours: int = 8,
    event_limit: int = 10,
    findings_limit: int = 5,
    incident_limit: int = 3,
) -> dict:
    base = _load_alert_enrichment(db, [asset_key]).get(asset_key) or {}
    state_row = _alert_state_row(db, asset_key)
    if not (
        base.get("posture_status")
        or base.get("asset_name")
        or base.get("owner")
        or base.get("active_finding_count")
        or state_row
    ):
        raise HTTPException(status_code=404, detail="Alert not found")

    events = _events_for_asset(asset_key, hours=hours, size=max(1, event_limit))
    timeline_signals = _alert_timeline_signals(events)
    current_state = (
        "suppressed"
        if base.get("maintenance_active") or base.get("suppression_rule_active")
        else (state_row or {}).get("state")
        or ("firing" if base.get("posture_status") == "red" else "resolved")
    )

    context = {
        "alert": {
            "asset_key": asset_key,
            "current_state": current_state,
            "assigned_to": (state_row or {}).get("assigned_to"),
            "ack_reason": (state_row or {}).get("ack_reason"),
            "acked_by": (state_row or {}).get("acked_by"),
            "acked_at": (state_row or {}).get("acked_at"),
            "suppressed_until": (state_row or {}).get("suppressed_until"),
            "resolved_at": (state_row or {}).get("resolved_at"),
            "updated_at": (state_row or {}).get("updated_at"),
        },
        "asset": {
            "asset_key": asset_key,
            "asset_name": base.get("asset_name"),
            "owner": base.get("owner"),
            "environment": base.get("environment"),
            "criticality": base.get("criticality"),
            "asset_type": base.get("asset_type"),
            "verified": base.get("verified"),
            "posture_status": base.get("posture_status"),
            "posture_score": base.get("posture_score"),
            "reason": base.get("reason"),
            "last_seen": base.get("last_seen"),
            "staleness_seconds": base.get("staleness_seconds"),
        },
        "maintenance": {
            "active": bool(base.get("maintenance_active")),
            "reason": base.get("maintenance_reason"),
            "ends_at": base.get("maintenance_end_at"),
        },
        "suppression": {
            "active": bool(base.get("suppression_rule_active")),
            "reason": base.get("suppression_reason"),
            "ends_at": base.get("suppression_end_at"),
        },
        "finding_summary": {
            "active_finding_count": base.get("active_finding_count") or 0,
            "top_risk_score": base.get("top_risk_score"),
            "top_risk_level": base.get("top_risk_level"),
        },
        "open_incidents": _alert_open_incidents(db, asset_key, limit=incident_limit),
        "top_findings": _alert_top_findings(db, asset_key, limit=findings_limit),
        "recent_events": [
            {
                "timestamp": event.get("@timestamp"),
                "status": event.get("status"),
                "code": event.get("code"),
                "latency_ms": event.get("latency_ms"),
            }
            for event in events[:event_limit]
        ],
        "timeline_signals": timeline_signals,
        "decision_signals": {
            "currently_down": base.get("posture_status") == "red",
            "production": (base.get("environment") or "").lower() == "prod",
            "high_criticality": base.get("criticality") == "high",
            "has_open_incident": (base.get("open_incident_count") or 0) > 0,
            "assigned": bool((state_row or {}).get("assigned_to")),
            "response_bias": _alert_response_bias(base, state_row),
        },
    }
    return context


def _alert_context_signature(context: dict) -> str:
    source = dict(context or {})
    alert = dict(source.get("alert") or {})
    asset = dict(source.get("asset") or {})
    maintenance = dict(source.get("maintenance") or {})
    suppression = dict(source.get("suppression") or {})
    finding_summary = dict(source.get("finding_summary") or {})
    timeline_signals = dict(source.get("timeline_signals") or {})
    decision_signals = dict(source.get("decision_signals") or {})

    # Keep only decision-driving fields; ignore volatile values such as runtime
    # staleness counters and mutable scoring internals.
    normalized = {
        "alert": {
            "asset_key": alert.get("asset_key"),
            "current_state": alert.get("current_state"),
            "assigned_to": alert.get("assigned_to"),
            "suppressed_until": alert.get("suppressed_until"),
            "resolved_at": alert.get("resolved_at"),
        },
        "asset": {
            "asset_key": asset.get("asset_key"),
            "posture_status": asset.get("posture_status"),
            "posture_score": asset.get("posture_score"),
            "criticality": asset.get("criticality"),
            "environment": asset.get("environment"),
        },
        "maintenance": {
            "active": maintenance.get("active"),
            "ends_at": maintenance.get("ends_at"),
            "reason": maintenance.get("reason"),
        },
        "suppression": {
            "active": suppression.get("active"),
            "ends_at": suppression.get("ends_at"),
            "reason": suppression.get("reason"),
        },
        "finding_summary": {
            "active_finding_count": finding_summary.get("active_finding_count"),
        },
        "top_findings": [
            {
                "finding_key": item.get("finding_key"),
                "status": item.get("status"),
                "severity": item.get("severity"),
            }
            for item in (source.get("top_findings") or [])
        ],
        "recent_events": [
            {
                "status": item.get("status"),
                "code": item.get("code"),
            }
            for item in (source.get("recent_events") or [])
        ],
        "timeline_signals": {
            "event_count": timeline_signals.get("event_count"),
            "unhealthy_events": timeline_signals.get("unhealthy_events"),
            "non_200_events": timeline_signals.get("non_200_events"),
            "timeout_events": timeline_signals.get("timeout_events"),
            "consecutive_unhealthy_events": timeline_signals.get("consecutive_unhealthy_events"),
            "flap_events": timeline_signals.get("flap_events"),
        },
        "decision_signals": {
            "currently_down": decision_signals.get("currently_down"),
            "production": decision_signals.get("production"),
            "high_criticality": decision_signals.get("high_criticality"),
            "assigned": decision_signals.get("assigned"),
        },
    }
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compact_asset_diagnosis_context(context: dict) -> dict:
    asset = dict(context.get("asset") or {})
    signals = dict(context.get("signals") or {})
    latest_statuses = signals.get("latest_statuses") or []
    signals["latest_statuses"] = latest_statuses[:4]
    findings = [dict(item) for item in (context.get("findings") or [])[:3]]
    recommendations = list(context.get("recommendations") or [])[:3]
    return {
        "asset": asset,
        "signals": signals,
        "findings": findings,
        "recommendations": recommendations,
    }


def _compact_job_triage_context(context: dict) -> dict:
    job = dict(context.get("job") or {})
    asset = dict(context.get("asset") or {})
    failure_signals = dict(context.get("failure_signals") or {})
    recent_related_jobs = [dict(item) for item in (context.get("recent_related_jobs") or [])[:2]]
    log_excerpt = _trim_job_log(context.get("log_excerpt") or "", max_chars=700)
    failure_signals["log_line_count"] = len(
        [line for line in log_excerpt.splitlines() if line.strip()]
    )
    failure_signals["has_log_output"] = bool(log_excerpt.strip())
    return {
        "job": job,
        "asset": asset,
        "failure_signals": failure_signals,
        "recent_related_jobs": recent_related_jobs,
        "log_excerpt": log_excerpt,
    }


def _compact_policy_evaluation_context(context: dict) -> dict:
    evaluation = dict(context.get("evaluation") or {})
    failed_rules = [dict(item) for item in (context.get("failed_rules") or [])[:3]]
    top_assets = [dict(item) for item in (context.get("top_assets") or [])[:3]]
    violation_themes = [dict(item) for item in (context.get("violation_themes") or [])[:3]]
    remediation_priorities = list(context.get("remediation_priorities") or [])[:3]
    sample_violations = [dict(item) for item in (context.get("sample_violations") or [])[:3]]
    return {
        "evaluation": evaluation,
        "failed_rules": failed_rules,
        "top_assets": top_assets,
        "violation_themes": violation_themes,
        "remediation_priorities": remediation_priorities,
        "sample_violations": sample_violations,
    }


def _compact_alert_guidance_context(context: dict) -> dict:
    return {
        "alert": dict(context.get("alert") or {}),
        "asset": dict(context.get("asset") or {}),
        "maintenance": dict(context.get("maintenance") or {}),
        "suppression": dict(context.get("suppression") or {}),
        "finding_summary": dict(context.get("finding_summary") or {}),
        "open_incidents": [dict(item) for item in (context.get("open_incidents") or [])[:2]],
        "top_findings": [dict(item) for item in (context.get("top_findings") or [])[:3]],
        "recent_events": [dict(item) for item in (context.get("recent_events") or [])[:4]],
        "timeline_signals": dict(context.get("timeline_signals") or {}),
        "decision_signals": dict(context.get("decision_signals") or {}),
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


def _asset_diagnosis_prompt(context: dict) -> tuple[str, str]:
    system = (
        "You are a security and reliability diagnostics assistant. "
        "Use only the supplied telemetry. Separate observations from likely causes and keep the output operational."
    )
    user = (
        "Analyze this asset in under 140 words.\n"
        "Return sections:\n"
        "1) Current state\n"
        "2) Most likely causes\n"
        "3) Evidence signals\n"
        "4) Next actions\n\n"
        f"Asset diagnostic context JSON:\n{compact_json(context, max_chars=ASSET_DIAGNOSIS_PROMPT_MAX_CHARS)}"
    )
    return system, user


def _job_triage_prompt(context: dict) -> tuple[str, str]:
    system = (
        "You are an operations and security job triage assistant. "
        "Classify the likely failure cause, say whether retrying is reasonable, and give exact next steps."
    )
    user = (
        "Triage this job in under 120 words.\n"
        "Return sections:\n"
        "1) Likely cause\n"
        "2) Retry guidance\n"
        "3) Next steps\n"
        "4) Evidence used\n\n"
        f"Job triage context JSON:\n{compact_json(context, max_chars=JOB_TRIAGE_PROMPT_MAX_CHARS)}"
    )
    return system, user


def _policy_evaluation_summary_prompt(context: dict) -> tuple[str, str]:
    system = (
        "You are a security compliance remediation assistant. "
        "Use only the supplied evaluation data. Prioritize operational clarity and remediation impact."
    )
    user = (
        "Summarize this policy evaluation in under 160 words.\n"
        "Return sections:\n"
        "1) Overall posture\n"
        "2) Main failure themes\n"
        "3) Highest-impact assets\n"
        "4) Remediation priorities\n\n"
        f"Policy evaluation context JSON:\n"
        f"{compact_json(context, max_chars=POLICY_EVALUATION_SUMMARY_PROMPT_MAX_CHARS)}"
    )
    return system, user


def _alert_response_guidance_prompt(context: dict) -> tuple[str, str]:
    system = (
        "You are a SOC alert response assistant. "
        "Recommend the single best next operator action for this alert using only the supplied context. "
        "Valid actions are: ack, suppress, assign, escalate, resolve, monitor."
    )
    user = (
        "Analyze this alert in under 160 words.\n"
        "Return exactly this format:\n"
        "Recommended action: <ack|suppress|assign|escalate|resolve|monitor>\n"
        "Urgency: <critical|high|medium|low>\n"
        "Why:\n"
        "- bullet\n"
        "- bullet\n"
        "Next steps:\n"
        "- bullet\n"
        "- bullet\n"
        "Escalate if:\n"
        "- bullet\n"
        "- bullet\n\n"
        f"Alert response context JSON:\n{compact_json(context, max_chars=ALERT_GUIDANCE_PROMPT_MAX_CHARS)}"
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


def _parse_tagged_line(text: str, label: str) -> str | None:
    prefix = label.lower()
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("-* ").strip()
        if len(line) > 2 and line[0].isdigit() and line[1] in (")", "."):
            line = line[2:].strip()
        lower_line = line.lower()
        if lower_line.startswith(prefix):
            value = line.split(":", 1)[1].strip() if ":" in line else ""
            return value or None
    return None


def _normalize_alert_action(value: str | None) -> str | None:
    if not value:
        return None
    text_value = value.strip().lower()
    mapping = {
        "ack": "ack",
        "acknowledge": "ack",
        "acknowledged": "ack",
        "suppress": "suppress",
        "suppressed": "suppress",
        "assign": "assign",
        "assigned": "assign",
        "escalate": "escalate",
        "escalation": "escalate",
        "resolve": "resolve",
        "resolved": "resolve",
        "monitor": "monitor",
    }
    for key, normalized in mapping.items():
        if text_value.startswith(key):
            return normalized
    return None


def _normalize_alert_urgency(value: str | None) -> str | None:
    if not value:
        return None
    text_value = value.strip().lower()
    for urgency in ("critical", "high", "medium", "low"):
        if text_value.startswith(urgency):
            return urgency
    return None


def _alert_guidance_labels(guidance_text: str) -> tuple[str | None, str | None]:
    action = _normalize_alert_action(_parse_tagged_line(guidance_text, "recommended action"))
    urgency = _normalize_alert_urgency(_parse_tagged_line(guidance_text, "urgency"))
    return action, urgency


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


def _fallback_asset_diagnosis(context: dict) -> str:
    asset = context.get("asset") or {}
    signals = context.get("signals") or {}
    findings = context.get("findings") or []
    recommendations = context.get("recommendations") or []

    status = (asset.get("status") or "unknown").upper()
    reason = asset.get("reason") or "no explicit failure reason recorded"
    posture_score = asset.get("posture_score")
    unhealthy_events = int(signals.get("unhealthy_events") or 0)
    non_200_events = int(signals.get("non_200_events") or 0)
    latency_spikes = int(signals.get("latency_spike_events") or 0)
    finding_count = len(findings)
    top_finding = findings[0] if findings else None

    likely_causes = [reason]
    if latency_spikes > 0:
        likely_causes.append("repeated latency spikes above the SLO")
    if non_200_events > 0:
        likely_causes.append("application responses returning non-200 status codes")
    if top_finding and top_finding.get("title"):
        likely_causes.append(f"an active related finding: {top_finding['title']}")

    next_actions = recommendations[:3] or [
        "Review the most recent asset events and linked findings."
    ]
    evidence_bits = [
        f"posture score {posture_score}" if posture_score is not None else None,
        f"{unhealthy_events} unhealthy event(s) in the last {signals.get('window_hours') or 24}h",
        f"{non_200_events} non-200 response(s)" if non_200_events else None,
        f"{latency_spikes} latency spike(s) above {signals.get('latency_slo_ms') or 200}ms"
        if latency_spikes
        else None,
        f"{finding_count} active linked finding(s)" if finding_count else None,
    ]
    evidence_line = (
        "; ".join(bit for bit in evidence_bits if bit) or "No recent telemetry available."
    )

    return (
        "1) Current state\n"
        f"{asset.get('asset_key') or 'Asset'} is currently {status} with reason '{reason}'.\n\n"
        "2) Most likely causes\n"
        + "\n".join(f"- {cause}" for cause in likely_causes[:3])
        + "\n\n3) Evidence signals\n"
        + evidence_line
        + "\n\n4) Next actions\n"
        + "\n".join(f"- {action}" for action in next_actions)
    )


def _fallback_job_triage(context: dict) -> str:
    job = context.get("job") or {}
    asset = context.get("asset") or {}
    signals = context.get("failure_signals") or {}
    recent = context.get("recent_related_jobs") or []
    likely_cause = signals.get("cause_category") or "unknown"
    retryable = bool(signals.get("retryable_hint"))
    next_action = signals.get("next_action_hint") or "Inspect the latest job logs before retrying."
    matched_patterns = signals.get("matched_patterns") or []
    evidence: list[str] = []
    if job.get("error"):
        evidence.append(f"job error: {job['error']}")
    if matched_patterns:
        evidence.append(f"matched patterns: {', '.join(matched_patterns)}")
    if asset.get("asset_key"):
        evidence.append(f"target asset: {asset['asset_key']}")
    if recent:
        failed_count = sum(1 for item in recent if item.get("status") == "failed")
        evidence.append(f"{failed_count} related recent failure(s)")
    evidence_text = "; ".join(evidence) or "No structured error message was recorded."
    retry_text = (
        "A retry is reasonable once the suspected underlying issue is checked."
        if retryable
        else "Do not retry immediately; correct the underlying configuration or target issue first."
    )
    return (
        "1) Likely cause\n"
        f"The job most likely failed due to {likely_cause.replace('_', ' ')}.\n\n"
        "2) Retry guidance\n"
        f"{retry_text}\n\n"
        "3) Next steps\n"
        f"- {next_action}\n"
        "- Review the last worker log lines and confirm the target asset settings.\n\n"
        "4) Evidence used\n"
        f"{evidence_text}"
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


def _existing_policy_evaluation_summary(db: Session, evaluation_id: int):
    return (
        db.execute(
            text(
                """
            SELECT evaluation_id, summary_text, provider, model, generated_by, generated_at, context_json
            FROM policy_evaluation_ai_summaries
            WHERE evaluation_id = :evaluation_id
            """
            ),
            {"evaluation_id": evaluation_id},
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


def _existing_asset_diagnosis(db: Session, asset_key: str):
    return (
        db.execute(
            text(
                """
            SELECT asset_key, diagnosis_text, provider, model, generated_by, generated_at, context_json
            FROM asset_ai_diagnoses
            WHERE asset_key = :asset_key
            """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )


def _existing_job_triage(db: Session, job_id: int):
    return (
        db.execute(
            text(
                """
            SELECT job_id, triage_text, provider, model, generated_by, generated_at, context_json
            FROM job_ai_triages
            WHERE job_id = :job_id
            """
            ),
            {"job_id": job_id},
        )
        .mappings()
        .first()
    )


def _existing_alert_guidance(db: Session, asset_key: str):
    return (
        db.execute(
            text(
                """
            SELECT
              asset_key,
              guidance_text,
              recommended_action,
              urgency,
              provider,
              model,
              generated_by,
              generated_at,
              context_signature,
              context_json
            FROM alert_ai_guidance
            WHERE asset_key = :asset_key
            """
            ),
            {"asset_key": asset_key},
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


@router.get("/policy/evaluations/{evaluation_id}/summary")
def get_policy_evaluation_summary(
    evaluation_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = _existing_policy_evaluation_summary(db, evaluation_id)
    if not row:
        raise HTTPException(status_code=404, detail="AI summary not found")
    return _serialize_row(row)


@router.post("/policy/evaluations/{evaluation_id}/summary/generate")
def generate_policy_evaluation_summary(
    evaluation_id: int,
    body: GenerateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    existing = _existing_policy_evaluation_summary(db, evaluation_id)
    if existing and not body.force:
        out = _serialize_row(existing)
        out["cached"] = True
        return out

    context = _policy_evaluation_context(db, evaluation_id)
    stored_context = context
    generated_provider = provider_name()
    generated_model = model_name()
    system_prompt, user_prompt = _policy_evaluation_summary_prompt(context)
    try:
        summary = generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=POLICY_EVALUATION_SUMMARY_MAX_TOKENS,
            timeout_seconds=max(
                float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                float(POLICY_EVALUATION_SUMMARY_TIMEOUT_SECONDS),
            ),
        )
    except AIClientError as e:
        if not _is_recoverable_ai_error(e):
            raise HTTPException(
                status_code=503, detail=f"AI summary generation unavailable: {e}"
            ) from e
        compact_context = _compact_policy_evaluation_context(context)
        compact_system, compact_user = _policy_evaluation_summary_prompt(compact_context)
        try:
            summary = generate_text(
                system_prompt=compact_system,
                user_prompt=compact_user,
                max_tokens=POLICY_EVALUATION_SUMMARY_RETRY_MAX_TOKENS,
                timeout_seconds=max(
                    float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                    float(POLICY_EVALUATION_SUMMARY_RETRY_TIMEOUT_SECONDS),
                ),
            )
            stored_context = compact_context
        except AIClientError as retry_error:
            raise HTTPException(
                status_code=503,
                detail=f"AI summary generation unavailable: {retry_error}",
            ) from retry_error

    params = {
        "evaluation_id": evaluation_id,
        "summary_text": summary.strip(),
        "provider": generated_provider,
        "model": generated_model,
        "generated_by": user,
        "context_json": json.dumps({"generated_from": stored_context, "source": "ai"}),
    }
    row = (
        db.execute(
            text(
                """
            INSERT INTO policy_evaluation_ai_summaries (
              evaluation_id, summary_text, provider, model, generated_by, context_json
            )
            VALUES (
              :evaluation_id, :summary_text, :provider, :model, :generated_by, CAST(:context_json AS jsonb)
            )
            ON CONFLICT (evaluation_id) DO UPDATE SET
              summary_text = EXCLUDED.summary_text,
              provider = EXCLUDED.provider,
              model = EXCLUDED.model,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW(),
              context_json = EXCLUDED.context_json
            RETURNING evaluation_id, summary_text, provider, model, generated_by, generated_at, context_json
            """
            ),
            params,
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "policy_evaluation_ai_summary_generate",
        user_name=user,
        details={
            "evaluation_id": evaluation_id,
            "provider": generated_provider,
            "model": generated_model,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = _serialize_row(row)
    out["cached"] = False
    return out


@router.get("/alerts/{asset_key}/guidance")
def get_alert_guidance(
    asset_key: str,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = _existing_alert_guidance(db, asset_key)
    if not row:
        raise HTTPException(status_code=404, detail="AI guidance not found")
    out = _serialize_row(row)
    out["stale"] = False
    try:
        current_signature = _alert_context_signature(_alert_guidance_context(db, asset_key))
        out["stale"] = current_signature != row.get("context_signature")
    except HTTPException:
        out["stale"] = False
    return out


@router.post("/alerts/{asset_key}/guidance/generate")
def generate_alert_guidance(
    asset_key: str,
    body: GenerateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    existing = _existing_alert_guidance(db, asset_key)
    context = _alert_guidance_context(db, asset_key)
    context_signature = _alert_context_signature(context)
    if existing and not body.force and existing.get("context_signature") == context_signature:
        out = _serialize_row(existing)
        out["cached"] = True
        out["stale"] = False
        return out

    stored_context = context
    generated_provider = provider_name()
    generated_model = model_name()
    system_prompt, user_prompt = _alert_response_guidance_prompt(context)
    try:
        guidance_text = generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=ALERT_GUIDANCE_MAX_TOKENS,
            timeout_seconds=max(
                float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                float(ALERT_GUIDANCE_TIMEOUT_SECONDS),
            ),
        )
    except AIClientError as e:
        if not _is_recoverable_ai_error(e):
            raise HTTPException(
                status_code=503, detail=f"AI guidance generation unavailable: {e}"
            ) from e
        compact_context = _compact_alert_guidance_context(context)
        compact_system, compact_user = _alert_response_guidance_prompt(compact_context)
        try:
            guidance_text = generate_text(
                system_prompt=compact_system,
                user_prompt=compact_user,
                max_tokens=ALERT_GUIDANCE_RETRY_MAX_TOKENS,
                timeout_seconds=max(
                    float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                    float(ALERT_GUIDANCE_RETRY_TIMEOUT_SECONDS),
                ),
            )
            stored_context = compact_context
            context_signature = _alert_context_signature(compact_context)
        except AIClientError as retry_error:
            raise HTTPException(
                status_code=503,
                detail=f"AI guidance generation unavailable: {retry_error}",
            ) from retry_error

    recommended_action, urgency = _alert_guidance_labels(guidance_text)
    params = {
        "asset_key": asset_key,
        "guidance_text": guidance_text.strip(),
        "recommended_action": recommended_action,
        "urgency": urgency,
        "provider": generated_provider,
        "model": generated_model,
        "generated_by": user,
        "context_signature": context_signature,
        "context_json": json.dumps({"generated_from": stored_context, "source": "ai"}),
    }
    row = (
        db.execute(
            text(
                """
            INSERT INTO alert_ai_guidance (
              asset_key,
              guidance_text,
              recommended_action,
              urgency,
              provider,
              model,
              generated_by,
              context_signature,
              context_json
            )
            VALUES (
              :asset_key,
              :guidance_text,
              :recommended_action,
              :urgency,
              :provider,
              :model,
              :generated_by,
              :context_signature,
              CAST(:context_json AS jsonb)
            )
            ON CONFLICT (asset_key) DO UPDATE SET
              guidance_text = EXCLUDED.guidance_text,
              recommended_action = EXCLUDED.recommended_action,
              urgency = EXCLUDED.urgency,
              provider = EXCLUDED.provider,
              model = EXCLUDED.model,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW(),
              context_signature = EXCLUDED.context_signature,
              context_json = EXCLUDED.context_json
            RETURNING
              asset_key,
              guidance_text,
              recommended_action,
              urgency,
              provider,
              model,
              generated_by,
              generated_at,
              context_signature,
              context_json
            """
            ),
            params,
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "alert_ai_guidance_generate",
        user_name=user,
        details={
            "asset_key": asset_key,
            "provider": generated_provider,
            "model": generated_model,
            "recommended_action": recommended_action,
            "urgency": urgency,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = _serialize_row(row)
    out["cached"] = False
    out["stale"] = False
    return out


@router.get("/jobs/{job_id}/triage")
def get_job_triage(
    job_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = _existing_job_triage(db, job_id)
    if not row:
        raise HTTPException(status_code=404, detail="AI triage not found")
    return _serialize_row(row)


@router.post("/jobs/{job_id}/triage/generate")
def generate_job_triage(
    job_id: int,
    body: GenerateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    existing = _existing_job_triage(db, job_id)
    if existing and not body.force:
        out = _serialize_row(existing)
        out["cached"] = True
        return out

    context = _job_triage_context(db, job_id)
    stored_context = context
    generated_provider = provider_name()
    generated_model = model_name()
    system_prompt, user_prompt = _job_triage_prompt(context)
    try:
        triage_text = generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=JOB_TRIAGE_MAX_TOKENS,
            timeout_seconds=max(
                float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                float(JOB_TRIAGE_TIMEOUT_SECONDS),
            ),
        )
    except AIClientError as e:
        if not _is_recoverable_ai_error(e):
            raise HTTPException(
                status_code=503, detail=f"AI triage generation unavailable: {e}"
            ) from e
        compact_context = _compact_job_triage_context(context)
        compact_system, compact_user = _job_triage_prompt(compact_context)
        try:
            triage_text = generate_text(
                system_prompt=compact_system,
                user_prompt=compact_user,
                max_tokens=JOB_TRIAGE_RETRY_MAX_TOKENS,
                timeout_seconds=max(
                    float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                    float(JOB_TRIAGE_RETRY_TIMEOUT_SECONDS),
                ),
            )
            stored_context = compact_context
        except AIClientError as retry_error:
            raise HTTPException(
                status_code=503,
                detail=f"AI triage generation unavailable: {retry_error}",
            ) from retry_error

    params = {
        "job_id": job_id,
        "triage_text": triage_text.strip(),
        "provider": generated_provider,
        "model": generated_model,
        "generated_by": user,
        "context_json": json.dumps(
            {
                "generated_from": {
                    "job": stored_context.get("job") or {},
                    "asset": stored_context.get("asset") or {},
                    "failure_signals": stored_context.get("failure_signals") or {},
                    "recent_related_jobs": stored_context.get("recent_related_jobs") or [],
                },
                "source": "ai",
            }
        ),
    }
    row = (
        db.execute(
            text(
                """
            INSERT INTO job_ai_triages (
              job_id, triage_text, provider, model, generated_by, context_json
            )
            VALUES (
              :job_id, :triage_text, :provider, :model, :generated_by, CAST(:context_json AS jsonb)
            )
            ON CONFLICT (job_id) DO UPDATE SET
              triage_text = EXCLUDED.triage_text,
              provider = EXCLUDED.provider,
              model = EXCLUDED.model,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW(),
              context_json = EXCLUDED.context_json
            RETURNING job_id, triage_text, provider, model, generated_by, generated_at, context_json
            """
            ),
            params,
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "job_ai_triage_generate",
        user_name=user,
        details={
            "job_id": job_id,
            "provider": generated_provider,
            "model": generated_model,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = _serialize_row(row)
    out["cached"] = False
    return out


@router.get("/assets/{asset_key}/diagnosis")
def get_asset_diagnosis(
    asset_key: str,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = _existing_asset_diagnosis(db, asset_key)
    if not row:
        raise HTTPException(status_code=404, detail="AI diagnosis not found")
    return _serialize_row(row)


@router.post("/assets/{asset_key}/diagnose")
def generate_asset_diagnosis(
    asset_key: str,
    body: GenerateBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    existing = _existing_asset_diagnosis(db, asset_key)
    if existing and not body.force:
        out = _serialize_row(existing)
        out["cached"] = True
        return out

    context = _asset_diagnosis_context(db, asset_key)
    stored_context = context
    generated_provider = provider_name()
    generated_model = model_name()
    system_prompt, user_prompt = _asset_diagnosis_prompt(context)
    try:
        diagnosis = generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=ASSET_DIAGNOSIS_MAX_TOKENS,
            timeout_seconds=max(
                float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                float(ASSET_DIAGNOSIS_TIMEOUT_SECONDS),
            ),
        )
    except AIClientError as e:
        if not _is_recoverable_ai_error(e):
            raise HTTPException(
                status_code=503, detail=f"AI diagnosis generation unavailable: {e}"
            ) from e
        compact_context = _compact_asset_diagnosis_context(context)
        compact_system, compact_user = _asset_diagnosis_prompt(compact_context)
        try:
            diagnosis = generate_text(
                system_prompt=compact_system,
                user_prompt=compact_user,
                max_tokens=ASSET_DIAGNOSIS_RETRY_MAX_TOKENS,
                timeout_seconds=max(
                    float(getattr(settings, "AI_TIMEOUT_SECONDS", 60)),
                    float(ASSET_DIAGNOSIS_RETRY_TIMEOUT_SECONDS),
                ),
            )
            stored_context = compact_context
        except AIClientError as retry_error:
            raise HTTPException(
                status_code=503,
                detail=f"AI diagnosis generation unavailable: {retry_error}",
            ) from retry_error

    params = {
        "asset_key": asset_key,
        "diagnosis_text": diagnosis.strip(),
        "provider": generated_provider,
        "model": generated_model,
        "generated_by": user,
        "context_json": json.dumps(
            {
                "generated_from": {
                    "asset": stored_context.get("asset") or {},
                    "signals": stored_context.get("signals") or {},
                    "findings": stored_context.get("findings") or [],
                    "recommendations": stored_context.get("recommendations") or [],
                },
                "source": "ai",
            }
        ),
    }
    row = (
        db.execute(
            text(
                """
            INSERT INTO asset_ai_diagnoses (
              asset_key, diagnosis_text, provider, model, generated_by, context_json
            )
            VALUES (
              :asset_key, :diagnosis_text, :provider, :model, :generated_by, CAST(:context_json AS jsonb)
            )
            ON CONFLICT (asset_key) DO UPDATE SET
              diagnosis_text = EXCLUDED.diagnosis_text,
              provider = EXCLUDED.provider,
              model = EXCLUDED.model,
              generated_by = EXCLUDED.generated_by,
              generated_at = NOW(),
              context_json = EXCLUDED.context_json
            RETURNING asset_key, diagnosis_text, provider, model, generated_by, generated_at, context_json
            """
            ),
            params,
        )
        .mappings()
        .first()
    )
    log_audit(
        db,
        "asset_ai_diagnosis_generate",
        user_name=user,
        details={
            "asset_key": asset_key,
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
