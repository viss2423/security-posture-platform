"""Entity-level risk scoring and trend snapshot helpers."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import text

CRITICALITY_BASE = {"high": 24, "medium": 14, "low": 7}
INCIDENT_SEVERITY_BASE = {"critical": 80, "high": 65, "medium": 45, "low": 25, "info": 12}
def _risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _safe_json(value: Any, *, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return default
        if isinstance(parsed, type(default)):
            return parsed
    return default


def _top_drivers(driver_map: dict[str, float], *, limit: int = 3) -> list[dict[str, Any]]:
    ranked = sorted(driver_map.items(), key=lambda item: abs(float(item[1])), reverse=True)
    return [
        {"name": name, "impact": round(float(impact), 2)}
        for name, impact in ranked[: max(1, int(limit))]
        if abs(float(impact)) > 0
    ]


def _driver_breakdown(driver_map: dict[str, float]) -> dict[str, list[str]]:
    increased = [name for name, impact in driver_map.items() if float(impact) > 0]
    reduced = [name for name, impact in driver_map.items() if float(impact) < 0]
    return {"increased_by": increased[:6], "reduced_by": reduced[:6]}


def compute_asset_risk_rows(conn: Any, *, limit: int = 5000) -> list[dict[str, Any]]:
    rows = (
        conn.execute(
            text(
                """
                SELECT
                  a.asset_id,
                  a.asset_key,
                  a.name,
                  a.environment,
                  a.criticality,
                  COALESCE(MAX(f.risk_score), 0) AS top_finding_risk,
                  COUNT(*) FILTER (
                    WHERE COALESCE(f.status, 'open') IN ('open', 'in_progress', 'accepted_risk')
                  ) AS active_findings,
                  COUNT(*) FILTER (
                    WHERE COALESCE(f.risk_level, 'low') IN ('critical', 'high')
                      AND COALESCE(f.status, 'open') IN ('open', 'in_progress', 'accepted_risk')
                  ) AS high_findings,
                  COUNT(*) FILTER (WHERE sa.status IN ('firing', 'acked')) AS active_alerts,
                  COUNT(*) FILTER (
                    WHERE sa.status IN ('firing', 'acked')
                      AND COALESCE(sa.severity, 'low') IN ('critical', 'high')
                  ) AS high_alerts,
                  COALESCE(MAX(exp.exposure_score), 0) AS exposure_score,
                  COALESCE(MAX(exp.internet_exposed::int), 0) AS internet_exposed_int,
                  COALESCE(MAX(ans.anomaly_score), 0) AS anomaly_score
                FROM assets a
                LEFT JOIN findings f ON f.asset_id = a.asset_id
                LEFT JOIN security_alerts sa ON sa.asset_key = a.asset_key
                LEFT JOIN attack_surface_exposures exp ON exp.asset_key = a.asset_key
                LEFT JOIN LATERAL (
                  SELECT anomaly_score
                  FROM asset_anomaly_scores
                  WHERE asset_key = a.asset_key
                  ORDER BY computed_at DESC
                  LIMIT 1
                ) ans ON TRUE
                WHERE COALESCE(a.is_active, TRUE) = TRUE
                GROUP BY a.asset_id, a.asset_key, a.name, a.environment, a.criticality
                ORDER BY a.asset_id ASC
                LIMIT :limit
                """
            ),
            {"limit": max(1, min(int(limit), 5000))},
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        criticality = str(row.get("criticality") or "medium").strip().lower()
        top_finding_risk = float(row.get("top_finding_risk") or 0)
        active_findings = int(row.get("active_findings") or 0)
        high_findings = int(row.get("high_findings") or 0)
        active_alerts = int(row.get("active_alerts") or 0)
        high_alerts = int(row.get("high_alerts") or 0)
        exposure_score = float(row.get("exposure_score") or 0)
        internet_exposed = bool(int(row.get("internet_exposed_int") or 0))
        anomaly_score = float(row.get("anomaly_score") or 0)

        driver_map = {
            "asset_criticality": float(CRITICALITY_BASE.get(criticality, 12)),
            "finding_risk": min(35.0, top_finding_risk * 0.35 + active_findings * 3 + high_findings * 4),
            "alert_pressure": min(22.0, active_alerts * 2.5 + high_alerts * 5),
            "internet_exposure": min(25.0, exposure_score * 0.25) + (8.0 if internet_exposed else 0.0),
            "anomaly_score": min(12.0, max(0.0, anomaly_score) * 2.2),
        }
        if active_findings == 0 and active_alerts == 0:
            driver_map["quiet_asset_reduction"] = -12.0

        score = int(round(sum(driver_map.values())))
        score = max(0, min(100, score))
        level = _risk_level(score)
        breakdown = _driver_breakdown(driver_map)
        top_drivers = _top_drivers(driver_map, limit=3)
        items.append(
            {
                "entity_type": "asset",
                "entity_key": str(row.get("asset_key") or ""),
                "entity_name": row.get("name"),
                "asset_id": row.get("asset_id"),
                "environment": row.get("environment"),
                "criticality": criticality,
                "score": score,
                "level": level,
                "top_drivers": top_drivers,
                "increased_by": breakdown["increased_by"],
                "reduced_by": breakdown["reduced_by"],
                "metrics": {
                    "top_finding_risk": int(round(top_finding_risk)),
                    "active_findings": active_findings,
                    "high_findings": high_findings,
                    "active_alerts": active_alerts,
                    "high_alerts": high_alerts,
                    "exposure_score": int(round(exposure_score)),
                    "internet_exposed": internet_exposed,
                    "anomaly_score": round(anomaly_score, 3),
                },
                "driver_map": {k: round(float(v), 2) for k, v in driver_map.items()},
            }
        )
    return sorted(items, key=lambda item: (int(item["score"]), item["entity_key"]), reverse=True)


def compute_incident_risk_rows(conn: Any, *, limit: int = 300) -> list[dict[str, Any]]:
    asset_rows = compute_asset_risk_rows(conn, limit=5000)
    asset_score_by_key = {str(item["entity_key"]): int(item["score"]) for item in asset_rows}

    rows = (
        conn.execute(
            text(
                """
                SELECT
                  i.id,
                  i.title,
                  i.severity,
                  i.status,
                  i.created_at,
                  COUNT(DISTINCT ia.asset_key) AS linked_assets,
                  COUNT(DISTINCT ia.alert_id) FILTER (WHERE ia.alert_id IS NOT NULL) AS linked_alerts,
                  STRING_AGG(DISTINCT ia.asset_key, ',' ORDER BY ia.asset_key) AS asset_keys
                FROM incidents i
                LEFT JOIN incident_alerts ia ON ia.incident_id = i.id
                GROUP BY i.id, i.title, i.severity, i.status, i.created_at
                ORDER BY i.created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": max(1, min(int(limit), 2000))},
        )
        .mappings()
        .all()
    )
    now = datetime.now(UTC)
    items: list[dict[str, Any]] = []
    for row in rows:
        severity = str(row.get("severity") or "medium").strip().lower()
        status = str(row.get("status") or "new").strip().lower()
        linked_assets = int(row.get("linked_assets") or 0)
        linked_alerts = int(row.get("linked_alerts") or 0)
        created_at = row.get("created_at")
        age_days = 0.0
        if hasattr(created_at, "astimezone"):
            age_days = max(0.0, (now - created_at.astimezone(UTC)).total_seconds() / 86400.0)
        asset_keys = [item for item in str(row.get("asset_keys") or "").split(",") if item]
        asset_scores = [asset_score_by_key[key] for key in asset_keys if key in asset_score_by_key]
        mean_asset_score = sum(asset_scores) / len(asset_scores) if asset_scores else 0.0

        driver_map = {
            "incident_severity": float(INCIDENT_SEVERITY_BASE.get(severity, 45)),
            "linked_alert_chain": min(18.0, linked_alerts * 4.5),
            "linked_asset_context": min(14.0, linked_assets * 3.5),
            "asset_risk_context": min(16.0, mean_asset_score * 0.2),
            "age_pressure": min(10.0, age_days * 1.5) if status not in {"resolved", "closed"} else -12.0,
        }
        if status in {"resolved", "closed"}:
            driver_map["resolved_reduction"] = -20.0

        score = int(round(sum(driver_map.values())))
        score = max(0, min(100, score))
        level = _risk_level(score)
        breakdown = _driver_breakdown(driver_map)
        top_drivers = _top_drivers(driver_map, limit=3)
        items.append(
            {
                "entity_type": "incident",
                "entity_key": str(row.get("id") or ""),
                "entity_name": row.get("title"),
                "incident_id": row.get("id"),
                "severity": severity,
                "status": status,
                "score": score,
                "level": level,
                "top_drivers": top_drivers,
                "increased_by": breakdown["increased_by"],
                "reduced_by": breakdown["reduced_by"],
                "metrics": {
                    "linked_assets": linked_assets,
                    "linked_alerts": linked_alerts,
                    "mean_asset_score": round(mean_asset_score, 2),
                    "age_days": round(age_days, 2),
                },
                "driver_map": {k: round(float(v), 2) for k, v in driver_map.items()},
            }
        )
    return sorted(items, key=lambda item: (int(item["score"]), item["entity_key"]), reverse=True)


def compute_environment_risk_rows(conn: Any) -> list[dict[str, Any]]:
    asset_rows = compute_asset_risk_rows(conn, limit=5000)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in asset_rows:
        environment = str(row.get("environment") or "unknown").strip().lower() or "unknown"
        buckets.setdefault(environment, []).append(row)

    items: list[dict[str, Any]] = []
    for environment, rows in buckets.items():
        asset_count = len(rows)
        mean_score = sum(int(item["score"]) for item in rows) / max(1, asset_count)
        high_or_critical = sum(1 for item in rows if str(item["level"]) in {"high", "critical"})
        exposure_count = sum(
            1 for item in rows if bool((item.get("metrics") or {}).get("internet_exposed"))
        )
        driver_map = {
            "average_asset_risk": mean_score * 0.7,
            "high_risk_asset_density": min(20.0, high_or_critical * 4.0),
            "internet_exposed_asset_density": min(16.0, exposure_count * 3.5),
            "asset_volume": min(10.0, asset_count * 1.2),
        }
        score = int(round(sum(driver_map.values()) / 1.6))
        score = max(0, min(100, score))
        level = _risk_level(score)
        breakdown = _driver_breakdown(driver_map)
        top_drivers = _top_drivers(driver_map, limit=3)
        items.append(
            {
                "entity_type": "environment",
                "entity_key": environment,
                "entity_name": environment,
                "score": score,
                "level": level,
                "top_drivers": top_drivers,
                "increased_by": breakdown["increased_by"],
                "reduced_by": breakdown["reduced_by"],
                "metrics": {
                    "asset_count": asset_count,
                    "mean_asset_score": round(mean_score, 2),
                    "high_or_critical_assets": high_or_critical,
                    "internet_exposed_assets": exposure_count,
                },
                "driver_map": {k: round(float(v), 2) for k, v in driver_map.items()},
            }
        )
    return sorted(items, key=lambda item: int(item["score"]), reverse=True)


def persist_risk_snapshots(
    conn: Any,
    *,
    asset_rows: list[dict[str, Any]],
    incident_rows: list[dict[str, Any]],
    environment_rows: list[dict[str, Any]],
    snapshot_date: date | None = None,
) -> None:
    target_date = snapshot_date or datetime.now(UTC).date()
    all_rows = [*asset_rows, *incident_rows, *environment_rows]
    for row in all_rows:
        conn.execute(
            text(
                """
                INSERT INTO risk_entity_snapshots (
                  entity_type,
                  entity_key,
                  entity_name,
                  snapshot_date,
                  score,
                  level,
                  drivers_json,
                  metadata_json
                )
                VALUES (
                  :entity_type,
                  :entity_key,
                  :entity_name,
                  :snapshot_date,
                  :score,
                  :level,
                  CAST(:drivers_json AS jsonb),
                  CAST(:metadata_json AS jsonb)
                )
                ON CONFLICT (entity_type, entity_key, snapshot_date) DO UPDATE
                SET
                  entity_name = EXCLUDED.entity_name,
                  score = EXCLUDED.score,
                  level = EXCLUDED.level,
                  drivers_json = EXCLUDED.drivers_json,
                  metadata_json = EXCLUDED.metadata_json,
                  updated_at = NOW()
                """
            ),
            {
                "entity_type": str(row.get("entity_type") or ""),
                "entity_key": str(row.get("entity_key") or ""),
                "entity_name": str(row.get("entity_name") or "") or None,
                "snapshot_date": target_date,
                "score": int(row.get("score") or 0),
                "level": str(row.get("level") or "low"),
                "drivers_json": json.dumps(
                    {
                        "top_drivers": row.get("top_drivers") or [],
                        "increased_by": row.get("increased_by") or [],
                        "reduced_by": row.get("reduced_by") or [],
                        "driver_map": row.get("driver_map") or {},
                    }
                ),
                "metadata_json": json.dumps(row.get("metrics") or {}),
            },
        )


def _trend_change(conn: Any, *, entity_type: str, entity_key: str, days: int) -> int | None:
    if days < 1:
        return None
    rows = (
        conn.execute(
            text(
                """
                SELECT snapshot_date, score
                FROM risk_entity_snapshots
                WHERE entity_type = :entity_type
                  AND entity_key = :entity_key
                  AND snapshot_date >= (CURRENT_DATE - CAST(:days AS integer))
                ORDER BY snapshot_date ASC
                """
            ),
            {"entity_type": entity_type, "entity_key": entity_key, "days": int(days)},
        )
        .mappings()
        .all()
    )
    if len(rows) < 2:
        return None
    first = int(rows[0].get("score") or 0)
    last = int(rows[-1].get("score") or 0)
    return last - first


def attach_trend_delta(
    conn: Any,
    rows: list[dict[str, Any]],
    *,
    days: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["trend_delta"] = _trend_change(
            conn,
            entity_type=str(item.get("entity_type") or ""),
            entity_key=str(item.get("entity_key") or ""),
            days=days,
        )
        out.append(item)
    return out


def get_risk_trends(
    conn: Any,
    *,
    entity_type: str,
    entity_key: str | None = None,
    days: int = 30,
    limit: int = 30,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "entity_type": entity_type,
        "days": max(1, min(int(days), 180)),
        "limit": max(1, min(int(limit), 200)),
    }
    where = [
        "entity_type = :entity_type",
        "snapshot_date >= (CURRENT_DATE - CAST(:days AS integer))",
    ]
    if entity_key:
        where.append("entity_key = :entity_key")
        params["entity_key"] = entity_key
    where_sql = " AND ".join(where)
    rows = (
        conn.execute(
            text(
                f"""
                SELECT
                  entity_type,
                  entity_key,
                  entity_name,
                  snapshot_date,
                  score,
                  level,
                  drivers_json,
                  metadata_json
                FROM risk_entity_snapshots
                WHERE {where_sql}
                ORDER BY snapshot_date ASC, entity_key ASC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row)
        snapshot_date = payload.get("snapshot_date")
        if hasattr(snapshot_date, "isoformat"):
            payload["snapshot_date"] = snapshot_date.isoformat()
        payload["drivers_json"] = _safe_json(payload.get("drivers_json"), default={})
        payload["metadata_json"] = _safe_json(payload.get("metadata_json"), default={})
        items.append(payload)
    return items


def get_risk_priorities(conn: Any, *, limit: int = 50) -> list[dict[str, Any]]:
    rows = (
        conn.execute(
            text(
                """
                SELECT
                  f.finding_id,
                  f.finding_key,
                  f.title,
                  f.severity,
                  f.risk_score,
                  f.risk_level,
                  f.status,
                  a.asset_key,
                  a.name AS asset_name,
                  a.environment,
                  a.criticality,
                  COALESCE(exp.exposure_score, 0) AS exposure_score,
                  COALESCE(exp.exposure_level, 'low') AS exposure_level
                FROM findings f
                LEFT JOIN assets a ON a.asset_id = f.asset_id
                LEFT JOIN attack_surface_exposures exp ON exp.asset_key = a.asset_key
                WHERE COALESCE(f.status, 'open') IN ('open', 'in_progress', 'accepted_risk')
                ORDER BY COALESCE(f.risk_score, 0) DESC, f.finding_id DESC
                LIMIT :limit
                """
            ),
            {"limit": max(1, min(int(limit), 500))},
        )
        .mappings()
        .all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        risk_score = int(row.get("risk_score") or 0)
        exposure_score = int(row.get("exposure_score") or 0)
        criticality = str(row.get("criticality") or "medium").strip().lower()
        expected_reduction = float(risk_score) * 0.7 + float(exposure_score) * 0.35
        if criticality == "high":
            expected_reduction += 8.0
        recommendation = "Prioritize patch and containment"
        if str(row.get("status") or "") == "accepted_risk":
            recommendation = "Review risk acceptance and expiry"
        elif str(row.get("severity") or "") in {"low", "info"}:
            recommendation = "Schedule remediation in regular patch cycle"
        items.append(
            {
                "finding_id": int(row.get("finding_id") or 0),
                "finding_key": row.get("finding_key"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "risk_score": risk_score,
                "risk_level": row.get("risk_level"),
                "status": row.get("status"),
                "asset_key": row.get("asset_key"),
                "asset_name": row.get("asset_name"),
                "environment": row.get("environment"),
                "criticality": criticality,
                "exposure_score": exposure_score,
                "exposure_level": row.get("exposure_level"),
                "expected_risk_reduction": round(expected_reduction, 2),
                "recommendation": recommendation,
            }
        )
    return sorted(items, key=lambda item: float(item["expected_risk_reduction"]), reverse=True)


def build_full_risk_snapshot(conn: Any, *, persist: bool = True) -> dict[str, Any]:
    asset_rows = compute_asset_risk_rows(conn)
    incident_rows = compute_incident_risk_rows(conn)
    environment_rows = compute_environment_risk_rows(conn)
    if persist:
        persist_risk_snapshots(
            conn,
            asset_rows=asset_rows,
            incident_rows=incident_rows,
            environment_rows=environment_rows,
        )
    return {
        "assets": asset_rows,
        "incidents": incident_rows,
        "environments": environment_rows,
        "computed_at": datetime.now(UTC).isoformat(),
    }
