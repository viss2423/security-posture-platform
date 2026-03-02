"""
Canonical asset state schema. This is the single source of truth for:
- Website display
- Alerts (what is "down" / "failing")
- Grafana should visualize this, not derive its own logic.
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, computed_field


AssetStatusLevel = Literal["green", "amber", "red"]
CriticalityLevel = Literal["high", "medium", "low"]


def _criticality_from_int(c: int | None) -> CriticalityLevel:
    if c is None:
        return "medium"
    if c <= 2:
        return "high"
    if c <= 3:
        return "medium"
    return "low"


def _reason_from_status(status: str | None, code: int | None) -> str | None:
    """Controlled list when not green: no_data_received, http_error, api_timeout, port_closed, tls_fail, health_check_failed, latency_slo_breach (latter set in detail from evidence)."""
    if not status or status in ("ok", "up"):
        return None
    s = (status or "").lower()
    if "timeout" in s:
        return "api_timeout"
    if "refused" in s or "connection" in s:
        return "port_closed"
    if "tls" in s or "ssl" in s or "certificate" in s:
        return "tls_fail"
    if "stale" in s:
        return "no_data_received"
    if "down" in s or s == "down":
        return "health_check_failed"
    if code and code >= 400:
        return "http_error"
    return s or None


class AssetState(BaseModel):
    """Single canonical asset state. All consumers (website, alerts, Grafana) use this."""

    asset_id: str = Field(..., description="Unique asset identifier (asset_key)")
    status: AssetStatusLevel = Field(..., description="green | amber | red")
    last_seen: datetime | None = Field(None, description="Last time we got a signal")
    reason: str | None = Field(None, description="e.g. api_timeout, tls_fail, port_closed")
    criticality: CriticalityLevel = Field("medium", description="high | medium | low")

    # Optional metadata (from Postgres or OpenSearch)
    name: str | None = None
    owner: str | None = None
    environment: str | None = None
    posture_score: int | None = None
    staleness_seconds: int | None = None
    last_status_change: datetime | None = None

    @computed_field
    @property
    def asset_key(self) -> str:
        """Alias for asset_id so frontend/consumers can keep using asset_key."""
        return self.asset_id

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": "juice-shop",
                "status": "green",
                "last_seen": "2026-02-06T12:00:00Z",
                "reason": None,
                "criticality": "high",
                "name": "Juice Shop",
                "owner": "security-team",
                "environment": "prod",
                "posture_score": 100,
                "staleness_seconds": 0,
            }
        }


class DataCompleteness(BaseModel):
    """How many checks we got vs expected in the window."""
    checks: int = 0
    expected: int = 0
    label_24h: str = ""  # e.g. "42/1440"
    label_1h: str = ""   # e.g. "42/60"
    pct_24h: float | None = None
    pct_1h: float | None = None


class AssetDetailResponse(BaseModel):
    """Extended asset detail: state + timeline + evidence + recommendations + SLO/completeness."""

    state: AssetState
    timeline: list[dict] = Field(default_factory=list, description="Recent events (newest first)")
    evidence: dict | None = Field(None, description="Last check payload (raw event)")
    recommendations: list[str] = Field(default_factory=list, description="Suggested actions")

    # Trust / completeness (explains gaps)
    expected_interval_sec: int = 60
    data_completeness: DataCompleteness = Field(default_factory=DataCompleteness)
    latency_slo_ms: int = 200
    latency_slo_ok: bool = True
    error_rate_24h: float = 0.0
    reason_display: str | None = None  # state.reason or "latency_slo_breach" when SLO breached


class ReportSummary(BaseModel):
    """Weekly/summary report: exec-facing metrics."""
    period: str = "24h"
    uptime_pct: float = 0.0
    posture_score_avg: float | None = None
    avg_latency_ms: float | None = None
    top_incidents: list[str] = Field(default_factory=list, description="Asset IDs currently down or with most errors")
    total_assets: int = 0
    green: int = 0
    amber: int = 0
    red: int = 0


class PostureSummary(BaseModel):
    """Org-level summary. Computed by FastAPI from asset states."""

    green: int = 0
    amber: int = 0
    red: int = 0
    posture_score_avg: float | None = None
    down_assets: list[str] = Field(default_factory=list, description="asset_ids currently red (down)")

    class Config:
        json_schema_extra = {
            "example": {
                "green": 4,
                "amber": 0,
                "red": 0,
                "posture_score_avg": 100.0,
                "down_assets": [],
            }
        }


def raw_to_asset_state(raw: dict) -> AssetState:
    """Map OpenSearch secplat-asset-status hit to canonical AssetState."""
    asset_key = raw.get("asset_key") or raw.get("asset_id")
    if not asset_key:
        raise ValueError("raw doc missing asset_key")
    posture_state = (raw.get("posture_state") or "amber").lower()
    if posture_state not in ("green", "amber", "red"):
        posture_state = "amber"
    crit_raw = raw.get("criticality")
    if isinstance(crit_raw, str) and crit_raw in ("high", "medium", "low"):
        criticality = crit_raw
    else:
        criticality = _criticality_from_int(int(crit_raw) if crit_raw is not None else 3)
    last_seen = raw.get("last_seen")
    if isinstance(last_seen, str):
        try:
            last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except Exception:
            pass
    reason = _reason_from_status(raw.get("status"), raw.get("code"))
    return AssetState(
        asset_id=str(asset_key),
        status=posture_state,
        last_seen=last_seen,
        reason=reason,
        criticality=criticality,
        name=raw.get("name"),
        owner=raw.get("owner"),
        environment=raw.get("environment"),
        posture_score=raw.get("posture_score"),
        staleness_seconds=raw.get("staleness_seconds"),
        last_status_change=None,  # keep as optional; could parse raw.get("last_status_change") if needed
    )
