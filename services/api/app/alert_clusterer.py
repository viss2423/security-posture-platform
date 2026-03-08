"""Alert clustering helpers for grouped analyst views."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from .alerts_v2 import normalize_alert_severity

_SEVERITY_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                return {}
            if isinstance(parsed, dict):
                return parsed
    return {}


def _safe_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
        return [part.strip() for part in raw.split(",") if part.strip()]
    return []


def _cluster_keys(alert: dict[str, Any], mode: str) -> list[str]:
    if mode == "asset":
        key = str(alert.get("asset_key") or "").strip()
        return [key] if key else ["asset:unknown"]
    if mode == "source_ip":
        payload = _safe_dict(alert.get("payload_json"))
        context = _safe_dict(alert.get("context_json"))
        candidates = [
            payload.get("src_ip"),
            payload.get("source_ip"),
            context.get("source_ip"),
            context.get("src_ip"),
        ]
        for candidate in candidates:
            value = str(candidate or "").strip()
            if value:
                return [value]
        return ["source_ip:unknown"]
    if mode == "technique":
        techniques = _safe_list(alert.get("mitre_techniques"))
        return techniques or ["technique:unmapped"]
    if mode == "campaign":
        context = _safe_dict(alert.get("context_json"))
        payload = _safe_dict(alert.get("payload_json"))
        campaign = str(
            context.get("campaign")
            or context.get("campaign_id")
            or payload.get("campaign")
            or payload.get("campaign_id")
            or ""
        ).strip()
        return [campaign] if campaign else ["campaign:unknown"]
    return ["unknown"]


def cluster_alert_rows(
    rows: list[dict[str, Any]],
    *,
    mode: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "cluster_key": "",
            "cluster_type": mode,
            "alert_count": 0,
            "event_count": 0,
            "first_seen_at": None,
            "last_seen_at": None,
            "max_severity": "info",
            "asset_keys": set(),
            "source_ips": set(),
            "techniques": set(),
            "campaigns": set(),
            "alert_ids": [],
        }
    )

    for row in rows:
        for cluster_key in _cluster_keys(row, mode):
            bucket = buckets[cluster_key]
            bucket["cluster_key"] = cluster_key
            bucket["alert_count"] += 1
            bucket["event_count"] += max(1, int(row.get("event_count") or 1))
            bucket["alert_ids"].append(int(row.get("alert_id") or 0))

            severity = normalize_alert_severity(row.get("severity"))
            if _SEVERITY_WEIGHT[severity] > _SEVERITY_WEIGHT[bucket["max_severity"]]:
                bucket["max_severity"] = severity

            first_seen = row.get("first_seen_at")
            last_seen = row.get("last_seen_at")
            if isinstance(first_seen, datetime) and (
                bucket["first_seen_at"] is None or first_seen < bucket["first_seen_at"]
            ):
                bucket["first_seen_at"] = first_seen
            if isinstance(last_seen, datetime) and (
                bucket["last_seen_at"] is None or last_seen > bucket["last_seen_at"]
            ):
                bucket["last_seen_at"] = last_seen

            asset_key = str(row.get("asset_key") or "").strip()
            if asset_key:
                bucket["asset_keys"].add(asset_key)
            payload = _safe_dict(row.get("payload_json"))
            context = _safe_dict(row.get("context_json"))
            src_ip = str(
                payload.get("src_ip")
                or payload.get("source_ip")
                or context.get("src_ip")
                or context.get("source_ip")
                or ""
            ).strip()
            if src_ip:
                bucket["source_ips"].add(src_ip)
            for technique in _safe_list(row.get("mitre_techniques")):
                bucket["techniques"].add(technique)
            campaign = str(
                context.get("campaign")
                or context.get("campaign_id")
                or payload.get("campaign")
                or payload.get("campaign_id")
                or ""
            ).strip()
            if campaign:
                bucket["campaigns"].add(campaign)

    results: list[dict[str, Any]] = []
    for bucket in buckets.values():
        results.append(
            {
                "cluster_key": bucket["cluster_key"],
                "cluster_type": bucket["cluster_type"],
                "alert_count": bucket["alert_count"],
                "event_count": bucket["event_count"],
                "first_seen_at": bucket["first_seen_at"].isoformat()
                if hasattr(bucket["first_seen_at"], "isoformat")
                else None,
                "last_seen_at": bucket["last_seen_at"].isoformat()
                if hasattr(bucket["last_seen_at"], "isoformat")
                else None,
                "max_severity": bucket["max_severity"],
                "asset_keys": sorted(bucket["asset_keys"]),
                "source_ips": sorted(bucket["source_ips"]),
                "techniques": sorted(bucket["techniques"]),
                "campaigns": sorted(bucket["campaigns"]),
                "alert_ids": [alert_id for alert_id in bucket["alert_ids"] if alert_id > 0],
            }
        )

    results.sort(key=lambda item: (item["alert_count"], item["event_count"]), reverse=True)
    return results[: max(1, int(limit))]


__all__ = ["cluster_alert_rows"]
