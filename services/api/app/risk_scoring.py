"""Contextual risk scoring for findings."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .risk_features import (
    EXTERNALLY_OBSERVED_SOURCES,
    age_adjustment,
    extract_risk_primitives,
    iso,
)
from .risk_model import get_risk_model_signature, predict_ml_risk

RISK_SCORING_VERSION = 3

SEVERITY_BASE = {
    "critical": 82,
    "high": 68,
    "medium": 48,
    "low": 24,
    "info": 10,
}

CONFIDENCE_ADJUST = {
    "high": 8,
    "medium": 4,
    "low": -4,
}

CRITICALITY_ADJUST = {
    "high": 12,
    "medium": 6,
    "low": 0,
}

ENVIRONMENT_ADJUST = {
    "prod": 10,
    "production": 10,
    "staging": 5,
    "stage": 5,
    "qa": -2,
    "test": -4,
    "dev": -6,
    "development": -6,
}


def current_risk_scoring_signature() -> str:
    return f"v{RISK_SCORING_VERSION}:{get_risk_model_signature() or 'heuristic'}"


def _risk_level_for_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def compute_finding_risk(context: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Compute a contextual risk score for one finding+asset pair."""
    now = now or datetime.now(UTC)
    primitives = extract_risk_primitives(context, now=now)
    finding = primitives["finding"]
    asset = primitives["asset"]
    severity = primitives["severity"]
    confidence = primitives["confidence"]
    status = primitives["status"]
    criticality = primitives["criticality"]
    environment = primitives["environment"]
    source = primitives["source"]
    verified = primitives["verified"]
    is_active = primitives["is_active"]
    internet_facing = primitives["internet_facing"]
    first_seen = primitives["first_seen"]
    accepted_until = primitives["accepted_until"]
    accepted_reason = primitives["accepted_reason"]

    score = SEVERITY_BASE.get(severity, 48)
    breakdown: dict[str, int] = {"severity_base": score}
    drivers: list[str] = []

    confidence_adj = CONFIDENCE_ADJUST.get(confidence, 0)
    if confidence_adj:
        breakdown["confidence_adjustment"] = confidence_adj
        score += confidence_adj
        if confidence_adj > 0:
            drivers.append(f"{confidence}_confidence")

    criticality_adj = CRITICALITY_ADJUST.get(criticality, 0)
    if criticality_adj:
        breakdown["criticality_adjustment"] = criticality_adj
        score += criticality_adj
        if criticality == "high":
            drivers.append("high_criticality")

    environment_adj = ENVIRONMENT_ADJUST.get(environment, 0)
    if environment_adj:
        breakdown["environment_adjustment"] = environment_adj
        score += environment_adj
        if environment_adj > 0:
            drivers.append(f"{environment}_environment")

    if internet_facing:
        breakdown["exposure_adjustment"] = 14
        score += 14
        drivers.append("internet_facing")

    if verified and internet_facing:
        breakdown["verified_asset_adjustment"] = 3
        score += 3
        drivers.append("verified_external_asset")

    if source in EXTERNALLY_OBSERVED_SOURCES:
        breakdown["source_adjustment"] = 4
        score += 4
        drivers.append(f"{source}_observed")

    age_adj, age_driver = age_adjustment(first_seen, now=now)
    if age_adj:
        breakdown["age_adjustment"] = age_adj
        score += age_adj
        if age_driver:
            drivers.append(age_driver)

    if not is_active:
        breakdown["inactive_asset_adjustment"] = -8
        score -= 8

    if status == "in_progress":
        breakdown["status_adjustment"] = -8
        score -= 8
    elif status == "accepted_risk":
        breakdown["status_adjustment"] = -18
        score -= 18
        drivers.append("accepted_risk")
        if accepted_until and accepted_until < now:
            breakdown["accepted_risk_expired_adjustment"] = 10
            score += 10
            drivers.append("accepted_risk_expired")
        elif accepted_reason:
            drivers.append("compensating_controls_noted")
    elif status == "remediated":
        breakdown["status_adjustment"] = -85
        score -= 85
        drivers.append("remediated")

    heuristic_score = max(0, min(100, int(round(score))))
    if status == "remediated":
        heuristic_score = min(heuristic_score, 5)

    ml_prediction = predict_ml_risk(context, now=now)
    final_score = heuristic_score
    score_source = "heuristic"
    model_details: dict[str, Any] | None = None
    if ml_prediction:
        final_score = ml_prediction["risk_score"]
        score_source = ml_prediction["score_source"]
        model_details = {
            **ml_prediction["metadata"],
            "probability": round(float(ml_prediction["probability"]), 4),
            "top_contributors": ml_prediction["top_contributors"],
        }
    if status == "remediated":
        final_score = min(final_score, 5)

    level = _risk_level_for_score(final_score)

    return {
        "risk_score": final_score,
        "risk_level": level,
        "risk_factors_json": {
            "version": RISK_SCORING_VERSION,
            "scoring_signature": current_risk_scoring_signature(),
            "score_source": score_source,
            "heuristic_score": heuristic_score,
            "heuristic_level": _risk_level_for_score(heuristic_score),
            "drivers": drivers[:8],
            "breakdown": breakdown,
            "model": model_details,
            "asset_snapshot": {
                "asset_key": asset.get("asset_key"),
                "type": asset.get("type"),
                "asset_type": asset.get("asset_type"),
                "criticality": criticality,
                "environment": environment,
                "verified": verified,
                "internet_facing": internet_facing,
            },
            "finding_snapshot": {
                "finding_key": finding.get("finding_key"),
                "severity": severity,
                "confidence": confidence,
                "status": status,
                "source": source,
                "first_seen": iso(first_seen),
                "accepted_risk_expires_at": iso(accepted_until),
            },
        },
    }


RISK_CONTEXT_SQL = """
SELECT
  f.finding_id,
  f.finding_key,
  COALESCE(f.status, 'open') AS status,
  f.severity,
  f.confidence,
  f.source,
  f.first_seen,
  f.accepted_risk_reason,
  f.accepted_risk_expires_at,
  a.asset_id,
  a.asset_key,
  a.type,
  a.asset_type,
  a.environment,
  a.criticality,
  a.verified,
  a.is_active,
  a.tags,
  a.metadata
FROM findings f
LEFT JOIN assets a ON a.asset_id = f.asset_id
WHERE {where_clause}
"""


def _row_to_context(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding": {
            "finding_id": row.get("finding_id"),
            "finding_key": row.get("finding_key"),
            "status": row.get("status"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "source": row.get("source"),
            "first_seen": row.get("first_seen"),
            "accepted_risk_reason": row.get("accepted_risk_reason"),
            "accepted_risk_expires_at": row.get("accepted_risk_expires_at"),
        },
        "asset": {
            "asset_id": row.get("asset_id"),
            "asset_key": row.get("asset_key"),
            "type": row.get("type"),
            "asset_type": row.get("asset_type"),
            "environment": row.get("environment"),
            "criticality": row.get("criticality"),
            "verified": row.get("verified"),
            "is_active": row.get("is_active"),
            "tags": row.get("tags"),
            "metadata": row.get("metadata"),
        },
    }


def _update_finding_risk(conn: Any, finding_id: int, computed: dict[str, Any]) -> None:
    from sqlalchemy import text

    conn.execute(
        text(
            """
            UPDATE findings
            SET risk_score = :risk_score,
                risk_level = :risk_level,
                risk_factors_json = CAST(:risk_factors_json AS jsonb)
            WHERE finding_id = :finding_id
            """
        ),
        {
            "finding_id": finding_id,
            "risk_score": computed["risk_score"],
            "risk_level": computed["risk_level"],
            "risk_factors_json": json.dumps(computed["risk_factors_json"]),
        },
    )


def recompute_finding_risk(conn: Any, finding_id: int) -> dict[str, Any] | None:
    from sqlalchemy import text

    row = (
        conn.execute(
            text(RISK_CONTEXT_SQL.format(where_clause="f.finding_id = :finding_id")),
            {"finding_id": finding_id},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    computed = compute_finding_risk(_row_to_context(dict(row)))
    _update_finding_risk(conn, finding_id, computed)
    return computed


def recompute_asset_findings_risk(conn: Any, asset_id: int) -> int:
    from sqlalchemy import text

    rows = (
        conn.execute(
            text(RISK_CONTEXT_SQL.format(where_clause="f.asset_id = :asset_id")),
            {"asset_id": asset_id},
        )
        .mappings()
        .all()
    )
    updated = 0
    for row in rows:
        finding_id = int(row["finding_id"])
        computed = compute_finding_risk(_row_to_context(dict(row)))
        _update_finding_risk(conn, finding_id, computed)
        updated += 1
    return updated


def backfill_finding_risk_scores(conn: Any) -> int:
    from sqlalchemy import text

    signature = current_risk_scoring_signature()
    rows = (
        conn.execute(
            text(
                RISK_CONTEXT_SQL.format(
                    where_clause="""
                f.risk_score IS NULL
                OR f.risk_level IS NULL
                OR COALESCE((f.risk_factors_json ->> 'version')::integer, 0) <> :version
                OR COALESCE(f.risk_factors_json ->> 'scoring_signature', '') <> :signature
                """
                )
            ),
            {"version": RISK_SCORING_VERSION, "signature": signature},
        )
        .mappings()
        .all()
    )
    updated = 0
    for row in rows:
        finding_id = int(row["finding_id"])
        computed = compute_finding_risk(_row_to_context(dict(row)))
        _update_finding_risk(conn, finding_id, computed)
        updated += 1
    return updated
