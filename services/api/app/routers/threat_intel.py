import json
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..db import get_db
from .auth import require_auth

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


def _serialize_datetime(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _latest_jobs(db: Session) -> list[dict[str, Any]]:
    rows = (
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
                  job_params_json
                FROM scan_jobs
                WHERE job_type = 'threat_intel_refresh'
                ORDER BY created_at DESC
                LIMIT 5
                """
            )
        )
        .mappings()
        .all()
    )
    items = []
    for row in rows:
        item = dict(row)
        for key in ("created_at", "started_at", "finished_at"):
            item[key] = _serialize_datetime(item.get(key))
        if isinstance(item.get("job_params_json"), str):
            try:
                item["job_params_json"] = json.loads(item["job_params_json"])
            except json.JSONDecodeError:
                item["job_params_json"] = {}
        items.append(item)
    return items


@router.get("/summary")
def get_threat_intel_summary(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    totals = (
        db.execute(
            text(
                """
                SELECT
                  COUNT(*) FILTER (WHERE is_active = TRUE) AS total_indicators,
                  COUNT(DISTINCT source) FILTER (WHERE is_active = TRUE) AS source_count,
                  MAX(last_seen_at) FILTER (WHERE is_active = TRUE) AS last_refreshed_at
                FROM threat_iocs
                """
            )
        )
        .mappings()
        .first()
    ) or {}
    sources = (
        db.execute(
            text(
                """
                SELECT
                  source,
                  COALESCE(feed_url, '') AS feed_url,
                  COUNT(*) FILTER (WHERE is_active = TRUE) AS indicator_count,
                  COUNT(*) FILTER (WHERE is_active = TRUE AND indicator_type = 'ip') AS ip_count,
                  COUNT(*) FILTER (WHERE is_active = TRUE AND indicator_type = 'domain') AS domain_count,
                  MAX(last_seen_at) FILTER (WHERE is_active = TRUE) AS last_seen_at
                FROM threat_iocs
                GROUP BY source, COALESCE(feed_url, '')
                ORDER BY indicator_count DESC, source ASC
                """
            )
        )
        .mappings()
        .all()
    )
    source_items = [
        {
            "source": row.get("source"),
            "feed_url": row.get("feed_url") or None,
            "indicator_count": int(row.get("indicator_count") or 0),
            "by_type": {
                "ip": int(row.get("ip_count") or 0),
                "domain": int(row.get("domain_count") or 0),
            },
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
        }
        for row in sources
    ]
    asset_rows = (
        db.execute(
            text(
                """
                SELECT
                  m.asset_key,
                  a.name AS asset_name,
                  a.environment,
                  a.criticality,
                  COUNT(*) AS match_count,
                  ARRAY_AGG(DISTINCT t.indicator ORDER BY t.indicator) AS indicators
                FROM threat_ioc_asset_matches m
                JOIN threat_iocs t ON t.id = m.threat_ioc_id
                JOIN assets a ON a.asset_id = m.asset_id
                WHERE t.is_active = TRUE
                GROUP BY m.asset_key, a.name, a.environment, a.criticality
                ORDER BY match_count DESC, m.asset_key ASC
                LIMIT 8
                """
            )
        )
        .mappings()
        .all()
    )
    matched_assets = [
        {
            "asset_key": row.get("asset_key"),
            "asset_name": row.get("asset_name"),
            "environment": row.get("environment"),
            "criticality": row.get("criticality"),
            "match_count": int(row.get("match_count") or 0),
            "indicators": list(row.get("indicators") or [])[:5],
        }
        for row in asset_rows
    ]
    match_totals = (
        db.execute(
            text(
                """
                SELECT
                  COUNT(*) AS total_asset_matches,
                  COUNT(DISTINCT asset_key) AS matched_asset_count
                FROM threat_ioc_asset_matches
                """
            )
        )
        .mappings()
        .first()
    ) or {}
    recent_rows = (
        db.execute(
            text(
                """
                SELECT source, indicator, indicator_type, last_seen_at
                FROM threat_iocs
                WHERE is_active = TRUE
                ORDER BY last_seen_at DESC, id DESC
                LIMIT 8
                """
            )
        )
        .mappings()
        .all()
    )
    recent_indicators = [
        {
            "source": row.get("source"),
            "indicator": row.get("indicator"),
            "indicator_type": row.get("indicator_type"),
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
        }
        for row in recent_rows
    ]
    return {
        "total_indicators": int(totals.get("total_indicators") or 0),
        "source_count": int(totals.get("source_count") or 0),
        "total_asset_matches": int(match_totals.get("total_asset_matches") or 0),
        "matched_asset_count": int(match_totals.get("matched_asset_count") or 0),
        "last_refreshed_at": _serialize_datetime(totals.get("last_refreshed_at")),
        "sources": source_items,
        "matched_assets": matched_assets,
        "recent_indicators": recent_indicators,
        "latest_jobs": _latest_jobs(db),
    }


@router.get("/assets/{asset_key}")
def get_threat_intel_asset_matches(
    asset_key: str,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = (
        db.execute(
            text(
                """
                SELECT
                  m.asset_key,
                  a.name AS asset_name,
                  m.match_field,
                  m.matched_value,
                  t.source,
                  t.indicator,
                  t.indicator_type,
                  m.last_seen_at
                FROM threat_ioc_asset_matches m
                JOIN threat_iocs t ON t.id = m.threat_ioc_id
                JOIN assets a ON a.asset_id = m.asset_id
                WHERE m.asset_key = :asset_key
                  AND t.is_active = TRUE
                ORDER BY m.last_seen_at DESC, t.source ASC, t.indicator ASC
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .all()
    )
    items = [
        {
            "asset_key": row.get("asset_key"),
            "asset_name": row.get("asset_name"),
            "match_field": row.get("match_field"),
            "matched_value": row.get("matched_value"),
            "source": row.get("source"),
            "indicator": row.get("indicator"),
            "indicator_type": row.get("indicator_type"),
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
        }
        for row in rows
    ]
    return {"asset_key": asset_key, "total": len(items), "items": items}
