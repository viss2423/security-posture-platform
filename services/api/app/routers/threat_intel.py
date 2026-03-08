import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..audit import log_audit
from ..campaign_tracker import normalize_campaign_tag, normalize_confidence_label
from ..db import get_db
from ..intel_confidence_service import (
    blended_confidence,
    confidence_label,
    normalize_confidence_score,
    normalize_source_priority,
)
from ..request_context import request_id_ctx
from .auth import require_auth, require_role

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


def _serialize_datetime(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _safe_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


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
        item["job_params_json"] = _safe_json(item.get("job_params_json"))
        items.append(item)
    return items


def _source_summary_rows(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.execute(
            text(
                """
                SELECT
                  source,
                  COALESCE(feed_url, '') AS feed_url,
                  COUNT(*) FILTER (WHERE is_active = TRUE) AS indicator_count,
                  COUNT(*) FILTER (WHERE is_active = TRUE AND indicator_type = 'ip') AS ip_count,
                  COUNT(*) FILTER (WHERE is_active = TRUE AND indicator_type = 'domain') AS domain_count,
                  ROUND(AVG(confidence_score) FILTER (WHERE is_active = TRUE)::numeric, 4) AS avg_confidence,
                  MAX(source_priority) FILTER (WHERE is_active = TRUE) AS max_source_priority,
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
    return [dict(row) for row in rows]


def _campaign_rows(db: Session, *, active_only: bool = True) -> list[dict[str, Any]]:
    where = "WHERE c.is_active = TRUE" if active_only else ""
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  c.campaign_id,
                  c.campaign_tag,
                  c.title,
                  c.description,
                  c.confidence_weight,
                  c.source_priority,
                  c.confidence_label,
                  c.is_active,
                  c.created_by,
                  c.created_at,
                  c.updated_at,
                  COUNT(t.id) FILTER (WHERE t.is_active = TRUE) AS ioc_count,
                  COUNT(DISTINCT m.asset_key) FILTER (WHERE t.is_active = TRUE) AS matched_asset_count
                FROM threat_ioc_campaigns c
                LEFT JOIN threat_iocs t ON t.campaign_tag = c.campaign_tag
                LEFT JOIN threat_ioc_asset_matches m ON m.threat_ioc_id = t.id
                {where}
                GROUP BY
                  c.campaign_id, c.campaign_tag, c.title, c.description, c.confidence_weight,
                  c.source_priority, c.confidence_label, c.is_active, c.created_by, c.created_at, c.updated_at
                ORDER BY matched_asset_count DESC, ioc_count DESC, c.campaign_tag ASC
                """
            )
        )
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


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
                  COUNT(*) FILTER (WHERE is_active = TRUE AND confidence_score >= 0.85) AS high_confidence_indicators,
                  MAX(last_seen_at) FILTER (WHERE is_active = TRUE) AS last_refreshed_at
                FROM threat_iocs
                """
            )
        )
        .mappings()
        .first()
    ) or {}
    source_items = [
        {
            "source": row.get("source"),
            "feed_url": row.get("feed_url") or None,
            "indicator_count": int(row.get("indicator_count") or 0),
            "by_type": {
                "ip": int(row.get("ip_count") or 0),
                "domain": int(row.get("domain_count") or 0),
            },
            "avg_confidence": float(row.get("avg_confidence") or 0.0),
            "max_source_priority": int(row.get("max_source_priority") or 0),
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
        }
        for row in _source_summary_rows(db)
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
                  ARRAY_AGG(DISTINCT t.indicator ORDER BY t.indicator) AS indicators,
                  MAX(t.confidence_score) AS max_confidence,
                  ARRAY_REMOVE(ARRAY_AGG(DISTINCT t.campaign_tag), NULL) AS campaign_tags
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
            "max_confidence": float(row.get("max_confidence") or 0.0),
            "campaign_tags": [str(item) for item in (row.get("campaign_tags") or []) if str(item or "").strip()],
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
                SELECT source, indicator, indicator_type, confidence_score, confidence_label,
                       campaign_tag, last_match_count, last_seen_at
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
            "confidence_score": float(row.get("confidence_score") or 0.0),
            "confidence_label": row.get("confidence_label") or confidence_label(float(row.get("confidence_score") or 0.0)),
            "campaign_tag": row.get("campaign_tag"),
            "last_match_count": int(row.get("last_match_count") or 0),
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
        }
        for row in recent_rows
    ]
    top_sightings_rows = (
        db.execute(
            text(
                """
                SELECT
                  s.sighting_id,
                  s.asset_key,
                  a.name AS asset_name,
                  i.indicator,
                  i.indicator_type,
                  i.source,
                  i.confidence_score,
                  i.confidence_label,
                  i.campaign_tag,
                  s.match_field,
                  s.matched_value,
                  s.sighted_at
                FROM threat_ioc_sightings s
                JOIN threat_iocs i ON i.id = s.threat_ioc_id
                LEFT JOIN assets a ON a.asset_id = s.asset_id
                ORDER BY s.sighted_at DESC, s.sighting_id DESC
                LIMIT 10
                """
            )
        )
        .mappings()
        .all()
    )
    top_sightings = [
        {
            "sighting_id": int(row.get("sighting_id") or 0),
            "asset_key": row.get("asset_key"),
            "asset_name": row.get("asset_name"),
            "indicator": row.get("indicator"),
            "indicator_type": row.get("indicator_type"),
            "source": row.get("source"),
            "confidence_score": float(row.get("confidence_score") or 0.0),
            "confidence_label": row.get("confidence_label") or "medium",
            "campaign_tag": row.get("campaign_tag"),
            "match_field": row.get("match_field"),
            "matched_value": row.get("matched_value"),
            "sighted_at": _serialize_datetime(row.get("sighted_at")),
        }
        for row in top_sightings_rows
    ]
    campaigns = [
        {
            "campaign_id": int(row.get("campaign_id") or 0),
            "campaign_tag": row.get("campaign_tag"),
            "title": row.get("title"),
            "description": row.get("description"),
            "confidence_weight": float(row.get("confidence_weight") or 1.0),
            "source_priority": int(row.get("source_priority") or 50),
            "confidence_label": row.get("confidence_label") or "medium",
            "is_active": bool(row.get("is_active")),
            "ioc_count": int(row.get("ioc_count") or 0),
            "matched_asset_count": int(row.get("matched_asset_count") or 0),
            "updated_at": _serialize_datetime(row.get("updated_at")),
        }
        for row in _campaign_rows(db, active_only=True)[:6]
    ]
    return {
        "total_indicators": int(totals.get("total_indicators") or 0),
        "high_confidence_indicators": int(totals.get("high_confidence_indicators") or 0),
        "source_count": int(totals.get("source_count") or 0),
        "total_asset_matches": int(match_totals.get("total_asset_matches") or 0),
        "matched_asset_count": int(match_totals.get("matched_asset_count") or 0),
        "campaign_count": len(campaigns),
        "last_refreshed_at": _serialize_datetime(totals.get("last_refreshed_at")),
        "sources": source_items,
        "matched_assets": matched_assets,
        "recent_indicators": recent_indicators,
        "top_sightings": top_sightings,
        "campaigns": campaigns,
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
                  t.confidence_score,
                  t.confidence_label,
                  t.campaign_tag,
                  m.last_seen_at
                FROM threat_ioc_asset_matches m
                JOIN threat_iocs t ON t.id = m.threat_ioc_id
                JOIN assets a ON a.asset_id = m.asset_id
                WHERE m.asset_key = :asset_key
                  AND t.is_active = TRUE
                ORDER BY m.last_seen_at DESC, t.confidence_score DESC, t.source ASC, t.indicator ASC
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
            "confidence_score": float(row.get("confidence_score") or 0.0),
            "confidence_label": row.get("confidence_label") or "medium",
            "campaign_tag": row.get("campaign_tag"),
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
        }
        for row in rows
    ]
    return {"asset_key": asset_key, "total": len(items), "items": items}


@router.get("/iocs")
def list_threat_iocs(
    q: str | None = Query(None),
    source: str | None = Query(None),
    indicator_type: str | None = Query(None),
    campaign_tag: str | None = Query(None),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    active_only: bool = Query(True),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["1=1", "t.confidence_score >= :min_confidence"]
    params: dict[str, Any] = {"min_confidence": float(min_confidence), "limit": int(limit)}
    if active_only:
        clauses.append("t.is_active = TRUE")
    if q:
        clauses.append("t.indicator ILIKE :q")
        params["q"] = f"%{q.strip()}%"
    if source:
        clauses.append("t.source = :source")
        params["source"] = source.strip().lower()
    if indicator_type:
        normalized_type = indicator_type.strip().lower()
        if normalized_type not in {"ip", "domain"}:
            raise HTTPException(status_code=400, detail="indicator_type must be ip or domain")
        clauses.append("t.indicator_type = :indicator_type")
        params["indicator_type"] = normalized_type
    if campaign_tag:
        normalized_campaign = normalize_campaign_tag(campaign_tag)
        if not normalized_campaign:
            raise HTTPException(status_code=400, detail="campaign_tag is invalid")
        clauses.append("t.campaign_tag = :campaign_tag")
        params["campaign_tag"] = normalized_campaign
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  t.id,
                  t.source,
                  t.indicator,
                  t.indicator_type,
                  t.feed_url,
                  t.first_seen_at,
                  t.last_seen_at,
                  t.is_active,
                  t.confidence_score,
                  t.confidence_label,
                  t.source_priority,
                  t.campaign_tag,
                  t.expires_at,
                  t.last_match_count,
                  t.metadata,
                  COUNT(DISTINCT m.asset_key) AS matched_asset_count
                FROM threat_iocs t
                LEFT JOIN threat_ioc_asset_matches m ON m.threat_ioc_id = t.id
                WHERE {where}
                GROUP BY t.id
                ORDER BY t.confidence_score DESC, t.last_match_count DESC, t.last_seen_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    items = []
    for row in rows:
        items.append(
            {
                "id": int(row.get("id") or 0),
                "source": row.get("source"),
                "indicator": row.get("indicator"),
                "indicator_type": row.get("indicator_type"),
                "feed_url": row.get("feed_url"),
                "is_active": bool(row.get("is_active")),
                "confidence_score": float(row.get("confidence_score") or 0.0),
                "confidence_label": row.get("confidence_label") or "medium",
                "source_priority": int(row.get("source_priority") or 0),
                "campaign_tag": row.get("campaign_tag"),
                "expires_at": _serialize_datetime(row.get("expires_at")),
                "first_seen_at": _serialize_datetime(row.get("first_seen_at")),
                "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
                "last_match_count": int(row.get("last_match_count") or 0),
                "matched_asset_count": int(row.get("matched_asset_count") or 0),
                "metadata": _safe_json(row.get("metadata")),
            }
        )
    return {"items": items}


@router.get("/iocs/{ioc_id}")
def get_threat_ioc_detail(
    ioc_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    row = (
        db.execute(
            text(
                """
                SELECT *
                FROM threat_iocs
                WHERE id = :ioc_id
                """
            ),
            {"ioc_id": int(ioc_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")
    asset_rows = (
        db.execute(
            text(
                """
                SELECT
                  m.asset_key,
                  a.name AS asset_name,
                  a.environment,
                  a.criticality,
                  m.match_field,
                  m.matched_value,
                  m.last_seen_at
                FROM threat_ioc_asset_matches m
                LEFT JOIN assets a ON a.asset_id = m.asset_id
                WHERE m.threat_ioc_id = :ioc_id
                ORDER BY m.last_seen_at DESC, m.asset_key ASC
                LIMIT 50
                """
            ),
            {"ioc_id": int(ioc_id)},
        )
        .mappings()
        .all()
    )
    sightings_rows = (
        db.execute(
            text(
                """
                SELECT
                  sighting_id,
                  asset_key,
                  match_field,
                  matched_value,
                  source_event_ref,
                  source_tool,
                  sighted_at,
                  context_json
                FROM threat_ioc_sightings
                WHERE threat_ioc_id = :ioc_id
                ORDER BY sighted_at DESC, sighting_id DESC
                LIMIT 30
                """
            ),
            {"ioc_id": int(ioc_id)},
        )
        .mappings()
        .all()
    )
    return {
        "ioc": {
            "id": int(row.get("id") or 0),
            "source": row.get("source"),
            "indicator": row.get("indicator"),
            "indicator_type": row.get("indicator_type"),
            "feed_url": row.get("feed_url"),
            "is_active": bool(row.get("is_active")),
            "confidence_score": float(row.get("confidence_score") or 0.0),
            "confidence_label": row.get("confidence_label") or "medium",
            "source_priority": int(row.get("source_priority") or 0),
            "campaign_tag": row.get("campaign_tag"),
            "expires_at": _serialize_datetime(row.get("expires_at")),
            "last_match_count": int(row.get("last_match_count") or 0),
            "first_seen_at": _serialize_datetime(row.get("first_seen_at")),
            "last_seen_at": _serialize_datetime(row.get("last_seen_at")),
            "metadata": _safe_json(row.get("metadata")),
        },
        "assets": [
            {
                "asset_key": item.get("asset_key"),
                "asset_name": item.get("asset_name"),
                "environment": item.get("environment"),
                "criticality": item.get("criticality"),
                "match_field": item.get("match_field"),
                "matched_value": item.get("matched_value"),
                "last_seen_at": _serialize_datetime(item.get("last_seen_at")),
            }
            for item in asset_rows
        ],
        "sightings": [
            {
                "sighting_id": int(item.get("sighting_id") or 0),
                "asset_key": item.get("asset_key"),
                "match_field": item.get("match_field"),
                "matched_value": item.get("matched_value"),
                "source_event_ref": item.get("source_event_ref"),
                "source_tool": item.get("source_tool"),
                "sighted_at": _serialize_datetime(item.get("sighted_at")),
                "context_json": _safe_json(item.get("context_json")),
            }
            for item in sightings_rows
        ],
    }


@router.get("/sightings")
def list_threat_ioc_sightings(
    asset_key: str | None = Query(None),
    source: str | None = Query(None),
    campaign_tag: str | None = Query(None),
    since_hours: int = Query(168, ge=1, le=24 * 365),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    clauses = ["s.sighted_at >= NOW() - (:since_hours * interval '1 hour')"]
    params: dict[str, Any] = {"since_hours": int(since_hours), "limit": int(limit)}
    if asset_key:
        clauses.append("s.asset_key = :asset_key")
        params["asset_key"] = asset_key
    if source:
        clauses.append("i.source = :source")
        params["source"] = source.strip().lower()
    if campaign_tag:
        normalized_campaign = normalize_campaign_tag(campaign_tag)
        if not normalized_campaign:
            raise HTTPException(status_code=400, detail="campaign_tag is invalid")
        clauses.append("i.campaign_tag = :campaign_tag")
        params["campaign_tag"] = normalized_campaign
    where = " AND ".join(clauses)
    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  s.sighting_id,
                  s.asset_key,
                  a.name AS asset_name,
                  s.match_field,
                  s.matched_value,
                  s.source_event_id,
                  s.source_event_ref,
                  s.source_tool,
                  s.sighted_at,
                  i.id AS ioc_id,
                  i.source,
                  i.indicator,
                  i.indicator_type,
                  i.confidence_score,
                  i.confidence_label,
                  i.campaign_tag,
                  i.last_match_count
                FROM threat_ioc_sightings s
                JOIN threat_iocs i ON i.id = s.threat_ioc_id
                LEFT JOIN assets a ON a.asset_id = s.asset_id
                WHERE {where}
                ORDER BY s.sighted_at DESC, s.sighting_id DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    items = [
        {
            "sighting_id": int(row.get("sighting_id") or 0),
            "ioc_id": int(row.get("ioc_id") or 0),
            "source": row.get("source"),
            "indicator": row.get("indicator"),
            "indicator_type": row.get("indicator_type"),
            "confidence_score": float(row.get("confidence_score") or 0.0),
            "confidence_label": row.get("confidence_label") or "medium",
            "campaign_tag": row.get("campaign_tag"),
            "asset_key": row.get("asset_key"),
            "asset_name": row.get("asset_name"),
            "match_field": row.get("match_field"),
            "matched_value": row.get("matched_value"),
            "source_event_id": row.get("source_event_id"),
            "source_event_ref": row.get("source_event_ref"),
            "source_tool": row.get("source_tool"),
            "last_match_count": int(row.get("last_match_count") or 0),
            "sighted_at": _serialize_datetime(row.get("sighted_at")),
        }
        for row in rows
    ]
    return {"items": items}


@router.get("/campaigns")
def list_threat_ioc_campaigns(
    active_only: bool = Query(True),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    rows = _campaign_rows(db, active_only=bool(active_only))
    items = []
    for row in rows:
        items.append(
            {
                "campaign_id": int(row.get("campaign_id") or 0),
                "campaign_tag": row.get("campaign_tag"),
                "title": row.get("title"),
                "description": row.get("description"),
                "confidence_weight": float(row.get("confidence_weight") or 1.0),
                "source_priority": int(row.get("source_priority") or 50),
                "confidence_label": row.get("confidence_label") or "medium",
                "is_active": bool(row.get("is_active")),
                "created_by": row.get("created_by"),
                "created_at": _serialize_datetime(row.get("created_at")),
                "updated_at": _serialize_datetime(row.get("updated_at")),
                "ioc_count": int(row.get("ioc_count") or 0),
                "matched_asset_count": int(row.get("matched_asset_count") or 0),
            }
        )
    return {"items": items}


class CampaignUpsertBody(BaseModel):
    campaign_tag: str
    title: str
    description: str | None = None
    confidence_weight: float = 1.0
    source_priority: int = 50
    confidence_label: str = "medium"
    is_active: bool = True


@router.post("/campaigns")
def upsert_threat_ioc_campaign(
    body: CampaignUpsertBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    campaign_tag = normalize_campaign_tag(body.campaign_tag)
    if not campaign_tag:
        raise HTTPException(status_code=400, detail="campaign_tag is required")
    title = str(body.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    confidence_weight = max(0.2, min(1.8, float(body.confidence_weight)))
    source_priority = normalize_source_priority(body.source_priority, default=50)
    confidence_lbl = normalize_confidence_label(body.confidence_label, default="medium")
    row = (
        db.execute(
            text(
                """
                INSERT INTO threat_ioc_campaigns(
                  campaign_tag, title, description, confidence_weight, source_priority,
                  confidence_label, is_active, created_by, created_at, updated_at
                )
                VALUES (
                  :campaign_tag, :title, :description, :confidence_weight, :source_priority,
                  :confidence_label, :is_active, :created_by, NOW(), NOW()
                )
                ON CONFLICT (campaign_tag) DO UPDATE
                SET title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    confidence_weight = EXCLUDED.confidence_weight,
                    source_priority = EXCLUDED.source_priority,
                    confidence_label = EXCLUDED.confidence_label,
                    is_active = EXCLUDED.is_active,
                    updated_at = NOW()
                RETURNING
                  campaign_id,
                  campaign_tag,
                  title,
                  description,
                  confidence_weight,
                  source_priority,
                  confidence_label,
                  is_active,
                  created_by,
                  created_at,
                  updated_at
                """
            ),
            {
                "campaign_tag": campaign_tag,
                "title": title,
                "description": (body.description or "").strip() or None,
                "confidence_weight": confidence_weight,
                "source_priority": source_priority,
                "confidence_label": confidence_lbl,
                "is_active": bool(body.is_active),
                "created_by": user,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="Failed to upsert campaign")
    log_audit(
        db,
        "threat_intel.campaign.upsert",
        user_name=user,
        details={
            "campaign_tag": campaign_tag,
            "confidence_weight": confidence_weight,
            "source_priority": source_priority,
            "confidence_label": confidence_lbl,
            "is_active": bool(body.is_active),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = dict(row)
    out["campaign_id"] = int(out.get("campaign_id") or 0)
    out["confidence_weight"] = float(out.get("confidence_weight") or 1.0)
    out["source_priority"] = int(out.get("source_priority") or 50)
    out["created_at"] = _serialize_datetime(out.get("created_at"))
    out["updated_at"] = _serialize_datetime(out.get("updated_at"))
    return out


class CampaignAssignBody(BaseModel):
    ioc_ids: list[int]


@router.post("/campaigns/{campaign_tag}/assign")
def assign_iocs_to_campaign(
    campaign_tag: str,
    body: CampaignAssignBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    normalized_tag = normalize_campaign_tag(campaign_tag)
    if not normalized_tag:
        raise HTTPException(status_code=400, detail="campaign_tag is invalid")
    if not body.ioc_ids:
        raise HTTPException(status_code=400, detail="ioc_ids is required")
    campaign = (
        db.execute(
            text(
                """
                SELECT campaign_tag, confidence_weight, source_priority, confidence_label
                FROM threat_ioc_campaigns
                WHERE campaign_tag = :campaign_tag
                """
            ),
            {"campaign_tag": normalized_tag},
        )
        .mappings()
        .first()
    )
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    confidence_weight = float(campaign.get("confidence_weight") or 1.0)
    priority = normalize_source_priority(campaign.get("source_priority"), default=50)
    confidence_lbl = normalize_confidence_label(campaign.get("confidence_label"), default="medium")

    updated = 0
    normalized_ids = sorted({int(ioc_id) for ioc_id in body.ioc_ids if int(ioc_id) > 0})
    for ioc_id in normalized_ids:
        existing = (
            db.execute(
                text("SELECT confidence_score FROM threat_iocs WHERE id = :ioc_id"),
                {"ioc_id": ioc_id},
            )
            .mappings()
            .first()
        )
        if not existing:
            continue
        new_score = blended_confidence(
            base_score=normalize_confidence_score(existing.get("confidence_score"), default=0.6),
            source_priority=priority,
            campaign_weight=confidence_weight,
        )
        db.execute(
            text(
                """
                UPDATE threat_iocs
                   SET campaign_tag = :campaign_tag,
                       confidence_score = :confidence_score,
                       confidence_label = :confidence_label,
                       source_priority = :source_priority,
                       updated_at = NOW()
                 WHERE id = :ioc_id
                """
            ),
            {
                "ioc_id": ioc_id,
                "campaign_tag": normalized_tag,
                "confidence_score": new_score,
                "confidence_label": confidence_lbl or confidence_label(new_score),
                "source_priority": priority,
            },
        )
        updated += 1
    log_audit(
        db,
        "threat_intel.campaign.assign",
        user_name=user,
        details={
            "campaign_tag": normalized_tag,
            "ioc_ids": normalized_ids,
            "updated": updated,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {"campaign_tag": normalized_tag, "updated": updated}
