"""Shared feature extraction for heuristic and ML risk scoring."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

EXTERNALLY_OBSERVED_SOURCES = {
    "tls_scan",
    "header_scan",
    "web_probe",
    "smoke_test",
}

PUBLIC_TAGS = {
    "public",
    "internet",
    "internet-facing",
    "internet_facing",
    "edge",
    "external",
}


def normalized(value: Any, default: str = "") -> str:
    return str(value or default).strip().lower()


def normalized_criticality(value: Any, default: str = "medium") -> str:
    normalized_value = normalized(value, default)
    if normalized_value in {"high", "medium", "low"}:
        return normalized_value
    try:
        numeric = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if numeric <= 2:
        return "high"
    if numeric <= 3:
        return "medium"
    return "low"


def coerce_tags(value: Any) -> set[str]:
    if isinstance(value, list):
        return {normalized(v) for v in value if normalized(v)}
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return set()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {normalized(v) for v in raw.split(",") if normalized(v)}
        if isinstance(parsed, list):
            return {normalized(v) for v in parsed if normalized(v)}
    return set()


def coerce_metadata(value: Any) -> dict[str, Any]:
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


def iso(value: Any) -> str | None:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value) if value is not None else None


def parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def is_internet_facing(asset: dict[str, Any]) -> bool:
    tags = coerce_tags(asset.get("tags"))
    metadata = coerce_metadata(asset.get("metadata"))
    if normalized(asset.get("type")) == "external_web":
        return True
    if normalized(asset.get("asset_type")) in {"external", "public", "internet", "edge", "ingress"}:
        return True
    if tags & PUBLIC_TAGS:
        return True
    return bool(
        metadata.get("internet_facing")
        or metadata.get("public_exposure")
        or metadata.get("externally_accessible")
    )


def age_adjustment(first_seen: datetime | None, *, now: datetime) -> tuple[int, str | None]:
    if not first_seen:
        return (0, None)
    age_days = max(0, (now - first_seen).days)
    if age_days >= 30:
        return (6, "long_lived_finding")
    if age_days >= 7:
        return (3, "persistent_finding")
    return (0, None)


def finding_age_days(first_seen: datetime | None, *, now: datetime) -> int:
    if not first_seen:
        return 0
    return max(0, int((now - first_seen).days))


def finding_age_bucket(age_days: int) -> str:
    if age_days >= 90:
        return "90d_plus"
    if age_days >= 30:
        return "30_89d"
    if age_days >= 7:
        return "7_29d"
    if age_days >= 1:
        return "1_6d"
    return "same_day"


def extract_risk_primitives(
    context: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    finding = context.get("finding") or {}
    asset = context.get("asset") or {}

    severity = normalized(finding.get("severity"), "medium")
    confidence = normalized(finding.get("confidence"), "high")
    status = normalized(finding.get("status"), "open")
    criticality = normalized_criticality(asset.get("criticality"), "medium")
    environment = normalized(asset.get("environment"), "dev")
    source = normalized(finding.get("source"))
    verified = bool(asset.get("verified"))
    is_active = bool(asset.get("is_active", True))
    internet_facing = is_internet_facing(asset)
    first_seen = parse_dt(finding.get("first_seen"))
    accepted_until = parse_dt(finding.get("accepted_risk_expires_at"))
    accepted_reason = normalized(finding.get("accepted_risk_reason"))
    age_days = finding_age_days(first_seen, now=now)
    age_bucket = finding_age_bucket(age_days)
    tags = coerce_tags(asset.get("tags"))
    telemetry_events_24h = int(
        finding.get("telemetry_events_24h") or asset.get("telemetry_events_24h") or 0
    )
    ioc_hits_24h = int(finding.get("ioc_hits_24h") or asset.get("ioc_hits_24h") or 0)
    suricata_high_alerts_24h = int(
        finding.get("suricata_high_alerts_24h") or asset.get("suricata_high_alerts_24h") or 0
    )
    zeek_events_24h = int(finding.get("zeek_events_24h") or asset.get("zeek_events_24h") or 0)
    cowrie_events_24h = int(finding.get("cowrie_events_24h") or asset.get("cowrie_events_24h") or 0)
    try:
        anomaly_score = float(
            finding.get("anomaly_score")
            if finding.get("anomaly_score") is not None
            else (asset.get("anomaly_score") or 0.0)
        )
    except (TypeError, ValueError):
        anomaly_score = 0.0

    return {
        "finding": finding,
        "asset": asset,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "criticality": criticality,
        "environment": environment,
        "source": source,
        "verified": verified,
        "is_active": is_active,
        "internet_facing": internet_facing,
        "first_seen": first_seen,
        "accepted_until": accepted_until,
        "accepted_reason": accepted_reason,
        "accepted_risk_expired": bool(accepted_until and accepted_until < now),
        "age_days": age_days,
        "age_bucket": age_bucket,
        "tags": tags,
        "telemetry_events_24h": telemetry_events_24h,
        "ioc_hits_24h": ioc_hits_24h,
        "suricata_high_alerts_24h": suricata_high_alerts_24h,
        "zeek_events_24h": zeek_events_24h,
        "cowrie_events_24h": cowrie_events_24h,
        "anomaly_score": anomaly_score,
        "metadata": coerce_metadata(asset.get("metadata")),
        "asset_type": normalized(asset.get("asset_type")) or "unknown",
        "asset_kind": normalized(asset.get("type")) or "unknown",
        "now": now,
    }


def build_risk_feature_vector(
    context: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    primitives = extract_risk_primitives(context, now=now)
    prod_environment = primitives["environment"] in {"prod", "production"}

    return {
        "severity": primitives["severity"],
        "confidence": primitives["confidence"],
        "status": primitives["status"],
        "source": primitives["source"] or "unknown",
        "criticality": primitives["criticality"],
        "environment": primitives["environment"],
        "asset_type": primitives["asset_type"],
        "asset_kind": primitives["asset_kind"],
        "severity_confidence": (f"{primitives['severity']}:{primitives['confidence']}"),
        "status_environment": (f"{primitives['status']}:{primitives['environment']}"),
        "age_days": primitives["age_days"],
        "age_bucket": primitives["age_bucket"],
        "internet_facing": int(primitives["internet_facing"]),
        "verified": int(primitives["verified"]),
        "is_active": int(primitives["is_active"]),
        "accepted_risk_active": int(
            primitives["status"] == "accepted_risk" and not primitives["accepted_risk_expired"]
        ),
        "accepted_risk_expired": int(primitives["accepted_risk_expired"]),
        "source_external_observation": int(primitives["source"] in EXTERNALLY_OBSERVED_SOURCES),
        "has_public_tag": int(bool(primitives["tags"] & PUBLIC_TAGS)),
        "prod_internet_facing": int(prod_environment and primitives["internet_facing"]),
        "high_criticality_external": int(
            primitives["criticality"] == "high" and primitives["internet_facing"]
        ),
        "verified_external": int(primitives["verified"] and primitives["internet_facing"]),
        "telemetry_events_24h": primitives["telemetry_events_24h"],
        "ioc_hits_24h": primitives["ioc_hits_24h"],
        "suricata_high_alerts_24h": primitives["suricata_high_alerts_24h"],
        "zeek_events_24h": primitives["zeek_events_24h"],
        "cowrie_events_24h": primitives["cowrie_events_24h"],
        "anomaly_score": round(float(primitives["anomaly_score"]), 4),
        "ioc_hit_present": int(primitives["ioc_hits_24h"] > 0),
        "high_anomaly": int(float(primitives["anomaly_score"]) >= 2.5),
        "honeypot_activity_present": int(primitives["cowrie_events_24h"] > 0),
    }
