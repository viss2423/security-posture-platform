"""Posture API: single source of truth for asset state. Reads from OpenSearch, returns canonical schema. Enriches with Postgres owner/criticality when available."""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.settings import settings
from app.db import get_db
from app.routers.auth import require_auth, require_role
from app.schemas.posture import (
    AssetState,
    AssetDetailResponse,
    DataCompleteness,
    PostureSummary,
    ReportSummary,
    raw_to_asset_state,
)

router = APIRouter(prefix="/posture", tags=["posture"])

STATUS_INDEX = "secplat-asset-status"
EVENTS_INDEX = "secplat-events"
OPENSEARCH_BASE = lambda idx: f"{settings.OPENSEARCH_URL.rstrip('/')}/{idx}"


def _criticality_text(v) -> str | None:
    """Normalize DB criticality (TEXT or int 1–5) to high|medium|low."""
    if v is None:
        return None
    if isinstance(v, int):
        if v <= 2:
            return "high"
        if v <= 3:
            return "medium"
        return "low"
    s = (v or "").strip().lower()
    if s in ("high", "medium", "low"):
        return s
    return "medium" if s else None


def _get_asset_metadata_batch(db: Session, asset_keys: list[str]) -> dict[str, dict]:
    """Fetch owner, criticality, name, environment from Postgres by asset_key. Returns dict asset_key -> {owner, criticality, name, environment}."""
    if not asset_keys:
        return {}
    placeholders = ", ".join(f":k{i}" for i in range(len(asset_keys)))
    params = {f"k{i}": k for i, k in enumerate(asset_keys)}
    q = text(f"""
      SELECT asset_key, name, owner, environment, criticality
      FROM assets
      WHERE asset_key IN ({placeholders})
    """)
    rows = db.execute(q, params).mappings().all()
    out = {}
    for r in rows:
        key = r["asset_key"]
        out[key] = {
            "name": r.get("name"),
            "owner": r.get("owner"),
            "environment": r.get("environment"),
            "criticality": _criticality_text(r.get("criticality")),
        }
    return out


def _opensearch_get(path: str, index: str = STATUS_INDEX):
    url = f"{OPENSEARCH_BASE(index)}{path}"
    with httpx.Client(timeout=10.0) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.json()


def _opensearch_post(path: str, body: dict, index: str = STATUS_INDEX):
    url = f"{OPENSEARCH_BASE(index)}{path}"
    with httpx.Client(timeout=10.0) as client:
        r = client.post(url, json=body)
        r.raise_for_status()
        return r.json()


def _events_for_asset(asset_key: str, hours: int = 24, size: int = 50) -> list[dict]:
    """Query secplat-events for this asset (health events), newest first."""
    # time range: now - hours
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [{"term": {"level": "health"}}],
                "should": [
                    {"term": {"asset.keyword": asset_key}},
                    {"match": {"asset": asset_key}},
                    {"term": {"service.keyword": asset_key}},
                    {"match": {"service": asset_key}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    if hours > 0:
        body["query"]["bool"]["filter"].append(
            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
        )
    try:
        data = _opensearch_post("/_search", body, EVENTS_INDEX)
    except Exception:
        return []
    hits = data.get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def _recommendations(state: AssetState, latency_slo_ok: bool = True, latency_slo_ms: int = 200) -> list[str]:
    """Derive recommended actions from current state. Uses STALE_THRESHOLD from settings conceptually (300s)."""
    stale_threshold = getattr(settings, "STALE_THRESHOLD_SECONDS", 300)
    recs: list[str] = []
    if state.status == "red":
        recs.append("Asset is down — check connectivity and service health.")
        if state.reason == "api_timeout":
            recs.append("API health check is timing out; verify endpoint and network.")
        elif state.reason == "port_closed":
            recs.append("Connection refused — service may be stopped or port blocked.")
        elif state.reason == "tls_fail":
            recs.append("TLS/certificate failure — verify certificate and chain.")
        elif state.reason == "http_error":
            recs.append("HTTP error — check application logs and status codes.")
    if state.staleness_seconds is not None and state.staleness_seconds > stale_threshold:
        mins = state.staleness_seconds // 60
        recs.append(f"No data in {mins} minutes — ingestion or checks may have stopped.")
    if not latency_slo_ok:
        recs.append(f"Latency exceeds SLO (< {latency_slo_ms}ms); investigate slow responses.")
    if state.status == "amber":
        recs.append("Asset in warning state — review recent events and thresholds.")
    if not recs:
        recs.append("No actions required — asset is healthy.")
    return recs


def _fetch_posture_list_raw():
    body = {
        "size": 1000,
        "query": {"match_all": {}},
        "sort": [{"status_num": "desc"}, {"posture_score": "asc"}],
    }
    try:
        data = _opensearch_post("/_search", body, STATUS_INDEX)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e!s}")
    hits = data.get("hits", {})
    total = hits.get("total", {})
    if isinstance(total, dict):
        total = total.get("value", 0)
    items = [h["_source"] for h in hits.get("hits", [])]
    return total, items


def _raw_list_to_states(raw_items: list[dict]) -> list[AssetState]:
    states = []
    for raw in raw_items:
        try:
            states.append(raw_to_asset_state(raw))
        except (ValueError, KeyError):
            continue
    return states


def _merge_posture_with_db(state_dict: dict, meta: dict | None) -> dict:
    """Overlay Postgres metadata (owner, criticality, name, environment) onto state dict. meta is from _get_asset_metadata_batch."""
    if not meta:
        return state_dict
    key = state_dict.get("asset_id")
    if key not in meta:
        return state_dict
    m = meta[key]
    out = {**state_dict}
    if m.get("owner") is not None:
        out["owner"] = m["owner"]
    if m.get("criticality") is not None:
        out["criticality"] = m["criticality"]
    if m.get("name") is not None:
        out["name"] = m["name"]
    if m.get("environment") is not None:
        out["environment"] = m["environment"]
    return out


def _parse_multi_param(val: str | None) -> list[str] | None:
    """Parse optional query param: None = no filter, else comma-separated list (e.g. 'dev,prod' -> ['dev','prod'])."""
    if val is None or (isinstance(val, str) and not val.strip()):
        return None
    return [v.strip().lower() for v in val.split(",") if v.strip()]


def _apply_filters(
    items: list[dict],
    environment: list[str] | None,
    criticality: list[str] | None,
    owner: list[str] | None,
    status: list[str] | None,
) -> list[dict]:
    """Filter merged posture items by optional environment, criticality, owner, status (any match in list)."""
    out = items
    if environment:
        out = [d for d in out if (d.get("environment") or "").strip().lower() in environment]
    if criticality:
        out = [d for d in out if (d.get("criticality") or "").strip().lower() in criticality]
    if owner:
        out = [d for d in out if (d.get("owner") or "").strip().lower() in [o.lower() for o in owner]]
    if status:
        out = [d for d in out if (d.get("status") or "").strip().lower() in status]
    return out


def _get_filtered_posture_list(
    db: Session,
    environment: str | None = None,
    criticality: str | None = None,
    owner: str | None = None,
    status: str | None = None,
) -> list[dict]:
    """Fetch posture list from OpenSearch, merge with Postgres metadata, apply filters. Returns list of merged dicts."""
    _, raw_items = _fetch_posture_list_raw()
    states = _raw_list_to_states(raw_items)
    meta = _get_asset_metadata_batch(db, [s.asset_id for s in states])
    items = [_merge_posture_with_db(s.model_dump(mode="json"), meta) for s in states]
    env_list = _parse_multi_param(environment)
    crit_list = _parse_multi_param(criticality)
    owner_list = _parse_multi_param(owner)
    status_list = _parse_multi_param(status)
    return _apply_filters(items, env_list, crit_list, owner_list, status_list)


@router.get("", response_model=None)
def list_posture(
    format: str | None = Query(None, alias="format"),
    environment: str | None = Query(None, description="Filter by environment (comma-separated)"),
    criticality: str | None = Query(None, description="Filter by criticality (high,medium,low)"),
    owner: str | None = Query(None, description="Filter by owner"),
    status: str | None = Query(None, description="Filter by status (green,amber,red)"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List current posture for all assets (canonical schema). Enriched with Postgres. Optional filters: environment, criticality, owner, status. ?format=csv for CSV export."""
    items = _get_filtered_posture_list(db, environment=environment, criticality=criticality, owner=owner, status=status)
    if format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["asset_id", "status", "last_seen", "reason", "criticality", "name", "owner", "environment", "posture_score"])
        for d in items:
            writer.writerow([
                d.get("asset_id"), d.get("status"), d.get("last_seen") or "", d.get("reason") or "",
                d.get("criticality"), d.get("name") or "", d.get("owner") or "", d.get("environment") or "", d.get("posture_score") or "",
            ])
        return PlainTextResponse(out.getvalue(), media_type="text/csv")
    return {"total": len(items), "items": items}


def _avg_latency_24h() -> float | None:
    """Average latency (ms) across all health events in last 24h."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"level": "health"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                ]
            }
        },
        "aggs": {"avg_latency": {"avg": {"field": "latency_ms"}}},
    }
    try:
        data = _opensearch_post("/_search", body, EVENTS_INDEX)
        val = data.get("aggregations", {}).get("avg_latency", {}).get("value")
        return round(float(val), 1) if val is not None else None
    except Exception:
        return None


def _build_report_summary(period: str) -> ReportSummary:
    """Build ReportSummary from current OpenSearch state. Used by reports/summary and reports/snapshot."""
    _, raw_items = _fetch_posture_list_raw()
    states = _raw_list_to_states(raw_items)
    total = len(states)
    by_state: dict[str, int] = {"green": 0, "amber": 0, "red": 0}
    scores: list[float] = []
    down_assets: list[str] = []
    for s in states:
        by_state[s.status] = by_state.get(s.status, 0) + 1
        if s.posture_score is not None:
            scores.append(float(s.posture_score))
        if s.status == "red":
            down_assets.append(s.asset_id)
    uptime_pct = round(100.0 * by_state.get("green", 0) / total, 1) if total else 0.0
    avg_score = round(sum(scores) / len(scores), 1) if scores else None
    avg_latency = _avg_latency_24h() if period == "24h" else _avg_latency_24h()
    return ReportSummary(
        period=period,
        uptime_pct=uptime_pct,
        posture_score_avg=avg_score,
        avg_latency_ms=avg_latency,
        top_incidents=down_assets[:10],
        total_assets=total,
        green=by_state.get("green", 0),
        amber=by_state.get("amber", 0),
        red=by_state.get("red", 0),
    )


@router.get("/overview")
def posture_overview(
    environment: str | None = Query(None),
    criticality: str | None = Query(None),
    owner: str | None = Query(None),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """
    Executive overview: strip (score, assets, alerts, trend vs yesterday), top drivers (worst assets, by reason, recently updated).
    Same filters as /posture and /summary.
    """
    items = _get_filtered_posture_list(db, environment=environment, criticality=criticality, owner=owner, status=status)
    total_assets = len(items)
    by_state: dict[str, int] = {"green": 0, "amber": 0, "red": 0}
    scores: list[float] = []
    down_assets: list[str] = []
    for d in items:
        st = (d.get("status") or "amber").lower()
        if st in by_state:
            by_state[st] += 1
        sc = d.get("posture_score")
        if sc is not None:
            try:
                scores.append(float(sc))
            except (TypeError, ValueError):
                pass
        if st == "red":
            down_assets.append(d.get("asset_id") or d.get("asset_key") or "")
    posture_score_avg = round(sum(scores) / len(scores), 1) if scores else None
    alerts_firing = len(down_assets)

    # Trend vs yesterday: compare to snapshot closest to now()-24h
    score_trend_vs_yesterday: str | None = None  # "up" | "down" | "same" | null
    risk_change_24h: int | None = None  # delta red count
    q_snap = text("""
      SELECT posture_score_avg, red, created_at
      FROM posture_report_snapshots
      WHERE created_at <= now() - interval '23 hours'
      ORDER BY created_at DESC
      LIMIT 1
    """)
    row = db.execute(q_snap).mappings().first()
    if row:
        prev_score = row.get("posture_score_avg")
        prev_red = row.get("red") or 0
        if posture_score_avg is not None and prev_score is not None:
            if posture_score_avg > prev_score:
                score_trend_vs_yesterday = "up"
            elif posture_score_avg < prev_score:
                score_trend_vs_yesterday = "down"
            else:
                score_trend_vs_yesterday = "same"
        risk_change_24h = by_state.get("red", 0) - prev_red

    # Top drivers: worst 5 by score, by reason counts, recently updated (last_seen desc)
    worst_assets = sorted(
        [d for d in items if d.get("posture_score") is not None],
        key=lambda x: (float(x.get("posture_score") or 0)),
    )[:5]
    worst_assets = [{"asset_id": d.get("asset_id") or d.get("asset_key"), "name": d.get("name"), "posture_score": d.get("posture_score"), "status": d.get("status")} for d in worst_assets]

    by_reason: dict[str, int] = {}
    for d in items:
        r = (d.get("reason") or "unknown").strip() or "unknown"
        by_reason[r] = by_reason.get(r, 0) + 1
    by_reason_list = [{"reason": k, "count": v} for k, v in sorted(by_reason.items(), key=lambda x: -x[1])[:5]]

    recently_updated = sorted(
        items,
        key=lambda x: (x.get("last_seen") or "") or "",
        reverse=True,
    )[:5]
    recently_updated = [{"asset_id": d.get("asset_id") or d.get("asset_key"), "name": d.get("name"), "last_seen": d.get("last_seen")} for d in recently_updated]

    return {
        "executive_strip": {
            "posture_score_avg": posture_score_avg,
            "total_assets": total_assets,
            "alerts_firing": alerts_firing,
            "score_trend_vs_yesterday": score_trend_vs_yesterday,
            "risk_change_24h": risk_change_24h,
            "green": by_state.get("green", 0),
            "amber": by_state.get("amber", 0),
            "red": by_state.get("red", 0),
            "down_assets": down_assets,
        },
        "top_drivers": {
            "worst_assets": worst_assets,
            "by_reason": by_reason_list,
            "recently_updated": recently_updated,
        },
    }


@router.get("/trend")
def posture_trend(
    range: str = Query("7d", description="24h, 7d, or 30d"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Time series of posture from report snapshots for charts. Points: created_at, posture_score_avg, green, amber, red."""
    interval = "24 hours" if range == "24h" else "7 days" if range == "7d" else "30 days"
    q = text("""
      SELECT id, created_at, posture_score_avg, green, amber, red
      FROM posture_report_snapshots
      WHERE created_at >= now() - CAST(:interval AS interval)
      ORDER BY created_at ASC
    """)
    rows = db.execute(q, {"interval": interval}).mappings().all()
    points = [
        {
            "created_at": r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"]),
            "posture_score_avg": r.get("posture_score_avg"),
            "green": r.get("green"),
            "amber": r.get("amber"),
            "red": r.get("red"),
        }
        for r in rows
    ]
    return {"range": range, "points": points}


@router.get("/reports/summary", response_model=ReportSummary)
def reports_summary(
    period: str = Query("24h", description="24h or 7d"),
    _user: str = Depends(require_auth),
):
    """Weekly/summary report: uptime %, posture score, avg latency, top incidents (down assets). Unfiltered."""
    return _build_report_summary(period)


@router.post("/reports/snapshot")
def reports_snapshot(
    period: str = Query("24h", description="24h or 7d"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_role(["admin", "analyst"])),
):
    """Save current report summary as a snapshot in DB. Returns stored row with id and created_at."""
    report = _build_report_summary(period)
    q = text("""
      INSERT INTO posture_report_snapshots
        (period, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents)
      VALUES
        (:period, :uptime_pct, :posture_score_avg, :avg_latency_ms, :total_assets, :green, :amber, :red, CAST(:top_incidents AS jsonb))
      RETURNING id, period, created_at, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents
    """)
    params = {
        "period": report.period,
        "uptime_pct": report.uptime_pct,
        "posture_score_avg": report.posture_score_avg,
        "avg_latency_ms": report.avg_latency_ms,
        "total_assets": report.total_assets,
        "green": report.green,
        "amber": report.amber,
        "red": report.red,
        "top_incidents": json.dumps(report.top_incidents),
    }
    row = db.execute(q, params).mappings().first()
    db.commit()
    return dict(row)


@router.get("/reports/history")
def reports_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List stored report snapshots, newest first."""
    q = text("""
      SELECT id, period, created_at, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents
      FROM posture_report_snapshots
      ORDER BY created_at DESC
      LIMIT :limit
    """)
    rows = db.execute(q, {"limit": limit}).mappings().all()
    return {"items": [dict(r) for r in rows]}


@router.get("/reports/history/{snapshot_id}")
def reports_history_one(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Get one stored report snapshot by id."""
    q = text("""
      SELECT id, period, created_at, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents
      FROM posture_report_snapshots
      WHERE id = :id
    """)
    row = db.execute(q, {"id": snapshot_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return dict(row)


def _draw_pdf_header(c, width: float, height: float, org: str, env: str, period: str, generated_ts: str, report_id: str) -> None:
    """Draw corporate header on current page."""
    c.setFont("Helvetica-Bold", 10)
    c.drawString(72, height - 36, "SecPlat — Security Posture Snapshot")
    c.setFont("Helvetica", 9)
    c.drawString(72, height - 48, f"Org: {org} | Env: {env} | Period: {period}")
    c.drawString(72, height - 58, f"Generated: {generated_ts}")
    c.drawString(72, height - 68, f"Report ID: {report_id}")
    c.line(72, height - 74, width - 72, height - 74)


def _draw_pdf_footer(c, width: float, height: float, page_num: int, total_pages: int) -> None:
    """Draw footer on current page."""
    c.setFont("Helvetica", 8)
    c.drawString(72, 36, f"Page {page_num}/{total_pages}")
    c.drawCentredString(width / 2, 36, "Internal use only")
    c.drawRightString(width - 72, 36, f"{page_num}/{total_pages}")


def _build_executive_pdf_bytes(
    report: ReportSummary,
    *,
    created_at=None,
    snapshot_id: int | None = None,
    report_id: str,
    generated_ts: str,
    org: str,
    env: str,
    trend_score_delta: float | None = None,
    trend_red_delta: int | None = None,
    top_incidents_detail: list[dict] | None = None,
    top_recommendations: list[str] | None = None,
    red_assets: list[dict] | None = None,
    amber_assets: list[dict] | None = None,
    trend_7d: list[dict] | None = None,
) -> bytes:
    """Generate multi-page Executive Security Posture Report (corporate format)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    margin = 72
    y = height - margin - 50
    total_pages = 1 + (1 if (red_assets or amber_assets) else 0) + (1 if trend_7d else 0)
    total_pages = max(1, total_pages)
    page_num = 1

    # ----- Page 1: Executive Summary -----
    _draw_pdf_header(c, width, height, org, env, report.period, generated_ts, report_id)
    y = height - margin - 80

    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "Page 1 — Executive Summary")
    y -= 24

    # Score + trend
    score_str = str(report.posture_score_avg) if report.posture_score_avg is not None else "–"
    trend_str = ""
    if trend_score_delta is not None:
        if trend_score_delta > 0:
            trend_str = " ↑"
        elif trend_score_delta < 0:
            trend_str = " ↓"
        else:
            trend_str = " →"
    c.setFont("Helvetica", 11)
    c.drawString(margin, y, f"Posture score (0–100): {score_str}{trend_str}")
    if trend_red_delta is not None and trend_red_delta != 0:
        c.drawString(margin + 280, y, f"(Red count: {'+' if trend_red_delta > 0 else ''}{trend_red_delta} vs previous)")
    y -= 18

    c.drawString(margin, y, f"Assets monitored: {report.total_assets}")
    y -= 14
    c.drawString(margin, y, f"Uptime: {report.uptime_pct}%  |  Latency (avg): {report.avg_latency_ms if report.avg_latency_ms is not None else '–'} ms")
    y -= 14
    c.drawString(margin, y, f"Green / Amber / Red: {report.green} / {report.amber} / {report.red}")
    y -= 28

    # Top incidents (max 5)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Top incidents (max 5)")
    y -= 16
    c.setFont("Helvetica", 9)
    if top_incidents_detail:
        for row in top_incidents_detail[:5]:
            asset = row.get("asset_id") or row.get("name") or "–"
            reason = row.get("reason") or "–"
            since = row.get("last_seen") or "–"
            owner = row.get("owner") or "–"
            c.drawString(margin, y, f"  {asset} | {reason} | {since} | {owner}")
            y -= 12
        y -= 8
    elif report.top_incidents:
        for aid in report.top_incidents[:5]:
            c.drawString(margin, y, f"  {aid} (from snapshot)")
            y -= 12
        y -= 8
    else:
        c.drawString(margin, y, "  None")
        y -= 20

    # Top recommendations (max 5)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Top recommendations (max 5)")
    y -= 16
    c.setFont("Helvetica", 9)
    if top_recommendations:
        for rec in top_recommendations[:5]:
            c.drawString(margin, y, f"  • {rec[:80]}{'…' if len(rec) > 80 else ''}")
            y -= 12
        y -= 8
    else:
        c.drawString(margin, y, "  None")
        y -= 16

    _draw_pdf_footer(c, width, height, page_num, total_pages)
    page_num += 1

    # ----- Page 2: Assets at Risk -----
    if red_assets or amber_assets:
        c.showPage()
        _draw_pdf_header(c, width, height, org, env, report.period, generated_ts, report_id)
        y = height - margin - 80
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin, y, "Page 2 — Assets at Risk")
        y -= 28

        def _draw_asset_table(title: str, rows: list[dict], col_w: list[float]) -> float:
            c.setFont("Helvetica-Bold", 10)
            c.drawString(margin, y, title)
            y2 = y - 14
            c.setFont("Helvetica", 8)
            for r in rows:
                cells = [
                    str(r.get("asset_id") or r.get("asset_key") or "–")[:20],
                    str(r.get("name") or "–")[:18],
                    str(r.get("owner") or "–")[:14],
                    str(r.get("reason") or "–")[:18],
                    str(r.get("last_seen") or "–")[:22],
                ]
                for i, cell in enumerate(cells):
                    c.drawString(margin + sum(col_w[:i]), y2, cell[:col_w[i] // 7] if col_w[i] < 200 else cell)
                y2 -= 11
                if y2 < margin + 50:
                    break
            return y2 - 16

        col_widths = [90, 70, 60, 80, 100]
        if red_assets:
            y = _draw_asset_table("Red assets (down)", red_assets, col_widths)
        if amber_assets:
            y = _draw_asset_table("Amber assets (stale / warning)", amber_assets, col_widths)

        _draw_pdf_footer(c, width, height, page_num, total_pages)
        page_num += 1

    # ----- Page 3: Trends -----
    if trend_7d:
        c.showPage()
        _draw_pdf_header(c, width, height, org, env, report.period, generated_ts, report_id)
        y = height - margin - 80
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin, y, "Page 3 — Trends (last 7 days)")
        y -= 24
        c.setFont("Helvetica", 9)
        c.drawString(margin, y, "Date / Time")
        c.drawString(margin + 100, y, "Score")
        c.drawString(margin + 160, y, "G")
        c.drawString(margin + 190, y, "A")
        c.drawString(margin + 220, y, "R")
        y -= 14
        for pt in trend_7d[-14:]:  # last 14 points if many
            ts = pt.get("created_at") or ""
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M")
            elif isinstance(ts, str) and len(ts) > 16:
                ts = ts[:16].replace("T", " ")
            c.drawString(margin, y, str(ts)[:18])
            c.drawString(margin + 100, y, str(pt.get("posture_score_avg") if pt.get("posture_score_avg") is not None else "–"))
            c.drawString(margin + 160, y, str(pt.get("green") or "–"))
            c.drawString(margin + 190, y, str(pt.get("amber") or "–"))
            c.drawString(margin + 220, y, str(pt.get("red") or "–"))
            y -= 12
            if y < margin + 50:
                break
        _draw_pdf_footer(c, width, height, page_num, total_pages)

    c.save()
    return buf.getvalue()


def _get_previous_snapshot_for_trend(db: Session, before_ts=None) -> dict | None:
    """Get the most recent snapshot before given timestamp (or now() if None). Returns row dict or None."""
    if before_ts is None:
        q = text("""
          SELECT posture_score_avg, red, created_at FROM posture_report_snapshots
          ORDER BY created_at DESC LIMIT 2
        """)
        rows = db.execute(q).mappings().all()
        if len(rows) < 2:
            return None
        return dict(rows[1])
    q = text("""
      SELECT posture_score_avg, red, created_at FROM posture_report_snapshots
      WHERE created_at < :before ORDER BY created_at DESC LIMIT 1
    """)
    row = db.execute(q, {"before": before_ts}).mappings().first()
    return dict(row) if row else None


def _get_trend_7d(db: Session) -> list[dict]:
    """Last 7 days of snapshots for trends page."""
    q = text("""
      SELECT created_at, posture_score_avg, green, amber, red
      FROM posture_report_snapshots
      WHERE created_at >= now() - interval '7 days'
      ORDER BY created_at ASC
    """)
    return [dict(r) for r in db.execute(q).mappings().all()]


@router.get("/reports/executive.pdf", response_class=Response)
def reports_executive_pdf(
    snapshot_id: int | None = Query(None, description="Use this snapshot; if omitted, use current 24h summary"),
    period: str = Query("24h", description="24h or 7d (used when snapshot_id is not set)"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Download Executive Security Posture Report (corporate format): Page 1 summary + trend, Page 2 red/amber, Page 3 trends."""
    report_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    generated_ts = now.strftime("%Y-%m-%d %H:%M (%Z)")
    org = getattr(settings, "REPORT_ORG_NAME", "SecPlat") or "SecPlat"
    env = getattr(settings, "REPORT_ENV", "All") or "All"

    if snapshot_id is not None:
        q = text("""
          SELECT id, period, created_at, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents
          FROM posture_report_snapshots WHERE id = :id
        """)
        row = db.execute(q, {"id": snapshot_id}).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        top_incidents = row.get("top_incidents") or []
        if hasattr(top_incidents, "tolist"):
            top_incidents = top_incidents.tolist()
        report = ReportSummary(
            period=row.get("period") or "24h",
            uptime_pct=float(row.get("uptime_pct") or 0),
            posture_score_avg=row.get("posture_score_avg"),
            avg_latency_ms=row.get("avg_latency_ms"),
            total_assets=int(row.get("total_assets") or 0),
            green=int(row.get("green") or 0),
            amber=int(row.get("amber") or 0),
            red=int(row.get("red") or 0),
            top_incidents=top_incidents,
        )
        created_at = row.get("created_at")
        sid = row.get("id")
        prev = _get_previous_snapshot_for_trend(db, before_ts=created_at)
        items = None
    else:
        report = _build_report_summary(period)
        created_at = None
        sid = None
        prev = _get_previous_snapshot_for_trend(db, before_ts=None)
        items = _get_filtered_posture_list(db)

    trend_score_delta = None
    trend_red_delta = None
    if prev:
        prev_score = prev.get("posture_score_avg")
        prev_red = prev.get("red") or 0
        if report.posture_score_avg is not None and prev_score is not None:
            trend_score_delta = round(report.posture_score_avg - float(prev_score), 1)
        trend_red_delta = report.red - prev_red

    top_incidents_detail = None
    top_recommendations = None
    red_assets = None
    amber_assets = None
    if items is not None:
        red_assets = [d for d in items if (d.get("status") or "").lower() == "red"]
        amber_assets = [d for d in items if (d.get("status") or "").lower() == "amber"]
        top_incidents_detail = []
        for d in red_assets[:5]:
            top_incidents_detail.append({
                "asset_id": d.get("asset_id") or d.get("asset_key"),
                "name": d.get("name"),
                "owner": d.get("owner"),
                "reason": d.get("reason"),
                "last_seen": d.get("last_seen"),
            })
        recs = []
        _, raw_items = _fetch_posture_list_raw()
        states = _raw_list_to_states(raw_items)
        latency_slo = getattr(settings, "LATENCY_SLO_MS", 200)
        for s in states:
            if s.status in ("red", "amber"):
                rlist = _recommendations(s, latency_slo_ok=True, latency_slo_ms=latency_slo)
                for rec in rlist:
                    if rec and rec not in recs and "No actions required" not in rec:
                        recs.append(rec)
                        if len(recs) >= 5:
                            break
            if len(recs) >= 5:
                break
        top_recommendations = recs[:5] if recs else ["No actions required — all assets healthy."]

    trend_7d = _get_trend_7d(db)

    pdf_bytes = _build_executive_pdf_bytes(
        report,
        created_at=created_at,
        snapshot_id=sid,
        report_id=report_id,
        generated_ts=generated_ts,
        org=org,
        env=env,
        trend_score_delta=trend_score_delta,
        trend_red_delta=trend_red_delta,
        top_incidents_detail=top_incidents_detail,
        top_recommendations=top_recommendations,
        red_assets=red_assets,
        amber_assets=amber_assets,
        trend_7d=trend_7d,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=secplat-executive.pdf"},
    )


def run_scheduled_snapshot() -> None:
    """Save current 24h report as a snapshot. Uses its own DB session. Call from background task (e.g. scheduler)."""
    from app.db import SessionLocal
    db = SessionLocal()
    try:
        report = _build_report_summary("24h")
        q = text("""
          INSERT INTO posture_report_snapshots
            (period, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents)
          VALUES
            (:period, :uptime_pct, :posture_score_avg, :avg_latency_ms, :total_assets, :green, :amber, :red, CAST(:top_incidents AS jsonb))
        """)
        params = {
            "period": report.period,
            "uptime_pct": report.uptime_pct,
            "posture_score_avg": report.posture_score_avg,
            "avg_latency_ms": report.avg_latency_ms,
            "total_assets": report.total_assets,
            "green": report.green,
            "amber": report.amber,
            "red": report.red,
            "top_incidents": json.dumps(report.top_incidents),
        }
        db.execute(q, params)
        db.commit()
    finally:
        db.close()


def _snapshot_row_to_summary(row) -> tuple[ReportSummary, list]:
    """Convert DB row to ReportSummary and list of top_incidents."""
    top = row.get("top_incidents") or []
    if hasattr(top, "tolist"):
        top = top.tolist()
    report = ReportSummary(
        period=row.get("period") or "24h",
        uptime_pct=float(row.get("uptime_pct") or 0),
        posture_score_avg=row.get("posture_score_avg"),
        avg_latency_ms=row.get("avg_latency_ms"),
        total_assets=int(row.get("total_assets") or 0),
        green=int(row.get("green") or 0),
        amber=int(row.get("amber") or 0),
        red=int(row.get("red") or 0),
        top_incidents=top,
    )
    return report, top


@router.get("/reports/what-changed")
def reports_what_changed(
    from_id: int = Query(..., description="Snapshot id to compare from"),
    to_id: int | None = Query(None, description="Snapshot id to compare to; omit for current state"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Compare two snapshots or a snapshot vs current. Returns deltas and incidents added/removed."""
    q_one = text("""
      SELECT id, period, created_at, uptime_pct, posture_score_avg, avg_latency_ms, total_assets, green, amber, red, top_incidents
      FROM posture_report_snapshots
      WHERE id = :id
    """)
    from_row = db.execute(q_one, {"id": from_id}).mappings().first()
    if not from_row:
        raise HTTPException(status_code=404, detail=f"Snapshot {from_id} not found")

    from_report, from_incidents = _snapshot_row_to_summary(from_row)
    from_set = set(from_incidents)

    if to_id is None:
        to_report = _build_report_summary("24h")
        to_incidents = to_report.top_incidents
        to_created_at = None
        to_id_display = "current"
    else:
        to_row = db.execute(q_one, {"id": to_id}).mappings().first()
        if not to_row:
            raise HTTPException(status_code=404, detail=f"Snapshot {to_id} not found")
        to_report, to_incidents = _snapshot_row_to_summary(to_row)
        to_created_at = to_row.get("created_at")
        to_id_display = to_id

    to_set = set(to_incidents)
    incidents_added = sorted(to_set - from_set)
    incidents_removed = sorted(from_set - to_set)

    score_a = from_report.posture_score_avg
    score_b = to_report.posture_score_avg
    score_delta = None
    if score_a is not None and score_b is not None:
        score_delta = round(score_b - score_a, 1)

    def row_summary(r, created_at=None, id_label=None):
        d = {
            "period": r.period,
            "uptime_pct": r.uptime_pct,
            "posture_score_avg": r.posture_score_avg,
            "total_assets": r.total_assets,
            "green": r.green,
            "amber": r.amber,
            "red": r.red,
        }
        if created_at is not None:
            d["created_at"] = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)
        if id_label is not None:
            d["id"] = id_label
        return d

    return {
        "from": row_summary(from_report, created_at=from_row.get("created_at"), id_label=from_id),
        "to": row_summary(to_report, created_at=to_created_at, id_label=to_id_display),
        "score_delta": score_delta,
        "green_delta": to_report.green - from_report.green,
        "amber_delta": to_report.amber - from_report.amber,
        "red_delta": to_report.red - from_report.red,
        "incidents_added": incidents_added,
        "incidents_removed": incidents_removed,
    }


def _get_down_assets() -> list[str]:
    """Return list of asset_ids (asset_key) that are currently red. Used by alert action."""
    _, raw_items = _fetch_posture_list_raw()
    states = _raw_list_to_states(raw_items)
    return [s.asset_id for s in states if s.status == "red"]


def _send_slack_alert(down_assets: list[str]) -> bool:
    """POST to Slack webhook. Only call when down_assets is non-empty. Returns True if request succeeded."""
    url = getattr(settings, "SLACK_WEBHOOK_URL", None) or None
    if not url or not url.strip():
        return False
    text = f"*SecPlat alert:* {len(down_assets)} asset(s) down: {', '.join(down_assets)}"
    payload = {"text": text}
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.post(url.strip(), json=payload)
            r.raise_for_status()
        return True
    except Exception:
        return False


def _send_whatsapp_alert(down_assets: list[str]) -> bool:
    """Send alert via Twilio WhatsApp. Returns True if request succeeded."""
    sid = getattr(settings, "TWILIO_ACCOUNT_SID", None) or ""
    token = getattr(settings, "TWILIO_AUTH_TOKEN", None) or ""
    from_ = (getattr(settings, "TWILIO_WHATSAPP_FROM", None) or "").strip()
    to = (getattr(settings, "WHATSAPP_ALERT_TO", None) or "").strip()
    if not sid or not token or not from_ or not to:
        return False
    if not from_.startswith("whatsapp:"):
        from_ = f"whatsapp:{from_}"
    if not to.startswith("whatsapp:"):
        to = f"whatsapp:{to}"
    body = f"SecPlat alert: {len(down_assets)} asset(s) down: {', '.join(down_assets)}"
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    auth = (sid, token)
    data = {"From": from_, "To": to, "Body": body}
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(url, auth=auth, data=data)
            r.raise_for_status()
        return True
    except Exception:
        return False


@router.get("/summary", response_model=PostureSummary)
def posture_summary(
    environment: str | None = Query(None),
    criticality: str | None = Query(None),
    owner: str | None = Query(None),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Summary counts and down_assets. Optional filters: environment, criticality, owner, status."""
    items = _get_filtered_posture_list(db, environment=environment, criticality=criticality, owner=owner, status=status)
    by_state: dict[str, int] = {"green": 0, "amber": 0, "red": 0}
    scores: list[float] = []
    down_assets: list[str] = []
    for d in items:
        st = (d.get("status") or "amber").lower()
        if st in by_state:
            by_state[st] += 1
        sc = d.get("posture_score")
        if sc is not None:
            try:
                scores.append(float(sc))
            except (TypeError, ValueError):
                pass
        if st == "red":
            down_assets.append(d.get("asset_id") or d.get("asset_key") or "")
    avg = round(sum(scores) / len(scores), 1) if scores else None
    return PostureSummary(
        green=by_state.get("green", 0),
        amber=by_state.get("amber", 0),
        red=by_state.get("red", 0),
        posture_score_avg=avg,
        down_assets=down_assets,
    )


@router.post("/alert/send")
def posture_alert_send(_user: str = Depends(require_auth)):
    """
    Check current posture; if any assets are down, send notification to Slack and/or WhatsApp (whichever is configured).
    Call from cron or manually. Only sends when down_assets is non-empty.
    """
    down_assets = _get_down_assets()
    if not down_assets:
        return {"sent": False, "down_assets": [], "message": "No down assets; no notification sent."}

    slack_ok = _send_slack_alert(down_assets)
    whatsapp_ok = _send_whatsapp_alert(down_assets)
    any_ok = slack_ok or whatsapp_ok
    channels = []
    if slack_ok:
        channels.append("Slack")
    if whatsapp_ok:
        channels.append("WhatsApp")
    if not (getattr(settings, "SLACK_WEBHOOK_URL", None) or getattr(settings, "WHATSAPP_ALERT_TO", None)):
        return {
            "sent": False,
            "down_assets": down_assets,
            "message": "No alert channel configured (set SLACK_WEBHOOK_URL and/or TWILIO_* + WHATSAPP_ALERT_TO).",
        }
    return {
        "sent": any_ok,
        "down_assets": down_assets,
        "channels": channels,
        "message": f"Notification {'sent' if any_ok else 'failed'} to {', '.join(channels) or 'none'} for {len(down_assets)} down asset(s).",
    }


@router.get("/{asset_key}/detail", response_model=AssetDetailResponse)
def get_posture_detail(
    asset_key: str,
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Extended detail: state + timeline + evidence + recommendations + completeness/SLO. State enriched with Postgres owner/criticality."""
    try:
        data = _opensearch_get(f"/_doc/{asset_key}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Asset not found in posture index")
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e!s}")

    if not data.get("found"):
        raise HTTPException(status_code=404, detail="Asset not found in posture index")
    raw = data.get("_source", {})
    raw["asset_key"] = raw.get("asset_key") or asset_key
    state = raw_to_asset_state(raw)
    meta = _get_asset_metadata_batch(db, [asset_key])
    if meta.get(asset_key):
        m = meta[asset_key]
        updates = {k: m[k] for k in ("owner", "criticality", "name", "environment") if m.get(k) is not None}
        if updates:
            state = state.model_copy(update=updates)

    interval_sec = getattr(settings, "EXPECTED_CHECK_INTERVAL_SECONDS", 60)
    latency_slo_ms = getattr(settings, "LATENCY_SLO_MS", 200)

    timeline = _events_for_asset(asset_key, hours=hours)
    evidence = timeline[0] if timeline else None

    # SLO: last check latency
    last_latency = evidence.get("latency_ms") if evidence else None
    latency_slo_ok = last_latency is None or (isinstance(last_latency, (int, float)) and last_latency <= latency_slo_ms)

    # Data completeness (24h and 1h)
    expected_24h = (86400 // interval_sec) if interval_sec else 0
    expected_1h = (3600 // interval_sec) if interval_sec else 0
    checks = len(timeline)
    pct_24h = round(100.0 * checks / expected_24h, 1) if expected_24h else None
    pct_1h = round(100.0 * min(checks, expected_1h) / expected_1h, 1) if expected_1h and checks else None
    completeness = DataCompleteness(
        checks=checks,
        expected=expected_24h,
        label_24h=f"{checks}/{expected_24h}",
        label_1h=f"{min(checks, expected_1h)}/{expected_1h}",
        pct_24h=pct_24h,
        pct_1h=pct_1h,
    )

    # Error rate (24h): non-200 or status != up/ok
    errors = 0
    for ev in timeline:
        code = ev.get("code")
        st = (ev.get("status") or "").lower()
        if (code is not None and code >= 400) or st not in ("up", "ok", ""):
            errors += 1
    error_rate_24h = round(100.0 * errors / checks, 1) if checks else 0.0

    reason_display = state.reason or ("latency_slo_breach" if not latency_slo_ok else None)
    recommendations = _recommendations(state, latency_slo_ok=latency_slo_ok, latency_slo_ms=latency_slo_ms)

    return AssetDetailResponse(
        state=state,
        timeline=timeline,
        evidence=evidence,
        recommendations=recommendations,
        expected_interval_sec=interval_sec,
        data_completeness=completeness,
        latency_slo_ms=latency_slo_ms,
        latency_slo_ok=latency_slo_ok,
        error_rate_24h=error_rate_24h,
        reason_display=reason_display,
    )


@router.get("/{asset_key}", response_model=AssetState)
def get_posture(asset_key: str, db: Session = Depends(get_db), _user: str = Depends(require_auth)):
    """Get current posture for one asset (canonical schema). Enriched with Postgres owner/criticality."""
    try:
        data = _opensearch_get(f"/_doc/{asset_key}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Asset not found in posture index")
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e!s}")

    if not data.get("found"):
        raise HTTPException(status_code=404, detail="Asset not found in posture index")
    raw = data.get("_source", {})
    raw["asset_key"] = raw.get("asset_key") or asset_key
    state = raw_to_asset_state(raw)
    meta = _get_asset_metadata_batch(db, [asset_key])
    if meta.get(asset_key):
        m = meta[asset_key]
        for key in ("owner", "criticality", "name", "environment"):
            if m.get(key) is not None:
                state = state.model_copy(update={key: m[key]})
    return state
