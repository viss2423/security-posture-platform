"""Posture API: single source of truth for asset state. Reads from OpenSearch, returns canonical schema. Enriches with Postgres owner/criticality when available."""

import csv
import io
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.settings import settings
from app.db import get_db
from app.routers.auth import require_auth
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


@router.get("", response_model=None)
def list_posture(
    format: str | None = Query(None, alias="format"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """List current posture for all assets (canonical schema). Enriched with Postgres owner/criticality. ?format=csv for CSV export."""
    total, raw_items = _fetch_posture_list_raw()
    if format == "csv":
        out = io.StringIO()
        if not raw_items:
            return PlainTextResponse(
                "asset_id,status,last_seen,reason,criticality,name,owner,environment,posture_score\n",
                media_type="text/csv",
            )
        states = _raw_list_to_states(raw_items)
        meta = _get_asset_metadata_batch(db, [s.asset_id for s in states])
        writer = csv.writer(out)
        writer.writerow(["asset_id", "status", "last_seen", "reason", "criticality", "name", "owner", "environment", "posture_score"])
        for s in states:
            d = s.model_dump(mode="json")
            d = _merge_posture_with_db(d, meta)
            writer.writerow([
                d.get("asset_id"), d.get("status"), d.get("last_seen") or "", d.get("reason") or "",
                d.get("criticality"), d.get("name") or "", d.get("owner") or "", d.get("environment") or "", d.get("posture_score") or "",
            ])
        return PlainTextResponse(out.getvalue(), media_type="text/csv")
    states = _raw_list_to_states(raw_items)
    meta = _get_asset_metadata_batch(db, [s.asset_id for s in states])
    items = [_merge_posture_with_db(s.model_dump(mode="json"), meta) for s in states]
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


@router.get("/reports/summary", response_model=ReportSummary)
def reports_summary(
    period: str = Query("24h", description="24h or 7d"),
    _user: str = Depends(require_auth),
):
    """Weekly/summary report: uptime %, posture score, avg latency, top incidents (down assets)."""
    return _build_report_summary(period)


@router.post("/reports/snapshot")
def reports_snapshot(
    period: str = Query("24h", description="24h or 7d"),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
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


@router.get("/summary", response_model=PostureSummary)
def posture_summary(_user: str = Depends(require_auth)):
    """Summary counts and down_assets. Computed by FastAPI (source of truth)."""
    _, raw_items = _fetch_posture_list_raw()
    states = _raw_list_to_states(raw_items)
    by_state: dict[str, int] = {"green": 0, "amber": 0, "red": 0}
    scores: list[float] = []
    down_assets: list[str] = []
    for s in states:
        by_state[s.status] = by_state.get(s.status, 0) + 1
        if s.posture_score is not None:
            scores.append(float(s.posture_score))
        if s.status == "red":
            down_assets.append(s.asset_id)
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
    Check current posture; if any assets are down and SLACK_WEBHOOK_URL is set, send a Slack message.
    Call from cron or manually. Only sends when down_assets is non-empty.
    """
    down_assets = _get_down_assets()
    webhook = getattr(settings, "SLACK_WEBHOOK_URL", None) or None
    if not down_assets:
        return {"sent": False, "down_assets": [], "message": "No down assets; no notification sent."}
    if not webhook or not webhook.strip():
        return {
            "sent": False,
            "down_assets": down_assets,
            "message": "SLACK_WEBHOOK_URL not configured; no notification sent.",
        }
    ok = _send_slack_alert(down_assets)
    return {
        "sent": ok,
        "down_assets": down_assets,
        "message": f"Slack notification {'sent' if ok else 'failed'} for {len(down_assets)} down asset(s).",
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
