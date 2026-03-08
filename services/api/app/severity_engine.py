"""Alert severity scoring helpers."""

from __future__ import annotations

from typing import Any

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_SEVERITY_TO_SCORE = {
    "info": 15,
    "low": 30,
    "medium": 50,
    "high": 75,
    "critical": 92,
}


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in _SEVERITY_TO_SCORE:
        return text
    if text.isdigit():
        numeric = int(text)
        if numeric <= 1:
            return "critical"
        if numeric == 2:
            return "high"
        if numeric == 3:
            return "medium"
        if numeric == 4:
            return "low"
        return "info"
    return "medium"


def _normalize_criticality(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"high", "medium", "low"}:
        return text
    if text.isdigit():
        numeric = int(text)
        if numeric <= 2:
            return "high"
        if numeric <= 3:
            return "medium"
        return "low"
    return "medium"


def _severity_from_score(score: int) -> str:
    bounded = max(0, min(int(score), 100))
    if bounded >= 90:
        return "critical"
    if bounded >= 75:
        return "high"
    if bounded >= 50:
        return "medium"
    if bounded >= 25:
        return "low"
    return "info"


def compute_effective_alert_severity(
    *,
    base_severity: Any,
    asset_criticality: Any = None,
    ti_match: bool = False,
    anomaly_score: float | int | None = None,
    recurrence_count: int | None = None,
    top_risk_score: int | None = None,
    active_finding_count: int | None = None,
    open_incident_count: int | None = None,
    maintenance_active: bool = False,
    suppression_active: bool = False,
) -> dict[str, Any]:
    """Return effective severity with a simple, explainable scoring model."""

    normalized_base = _normalize_severity(base_severity)
    score = _SEVERITY_TO_SCORE[normalized_base]
    drivers: list[dict[str, Any]] = []

    def apply(delta: int, code: str, detail: str) -> None:
        nonlocal score
        score += int(delta)
        drivers.append({"code": code, "delta": int(delta), "detail": detail})

    criticality = _normalize_criticality(asset_criticality)
    if criticality == "high":
        apply(10, "asset_criticality", "High-criticality asset")
    elif criticality == "low":
        apply(-5, "asset_criticality", "Low-criticality asset")

    if ti_match:
        apply(12, "threat_intel_match", "Threat intel indicator matched")

    if top_risk_score is not None:
        bounded_risk = max(0, min(int(top_risk_score), 100))
        if bounded_risk >= 85:
            apply(10, "risk_score", "High asset risk score")
        elif bounded_risk <= 30:
            apply(-4, "risk_score", "Low asset risk score")

    findings = max(0, int(active_finding_count or 0))
    if findings >= 5:
        apply(8, "active_findings", "Many active findings")
    elif findings == 0:
        apply(-3, "active_findings", "No active findings")

    incidents = max(0, int(open_incident_count or 0))
    if incidents >= 1:
        apply(6, "open_incidents", "Asset has open incidents")

    recurrence = max(1, int(recurrence_count or 1))
    if recurrence >= 25:
        apply(10, "recurrence", "Alert is frequently recurring")
    elif recurrence >= 10:
        apply(6, "recurrence", "Alert recurrence is elevated")
    elif recurrence >= 3:
        apply(3, "recurrence", "Alert has recurred")

    if anomaly_score is not None:
        try:
            anomaly = float(anomaly_score)
        except (TypeError, ValueError):
            anomaly = 0.0
        if anomaly >= 0.85:
            apply(8, "anomaly_score", "High anomaly score")
        elif anomaly <= 0.25:
            apply(-3, "anomaly_score", "Low anomaly score")

    if maintenance_active or suppression_active:
        apply(-12, "suppression_context", "Under maintenance/suppression window")

    bounded = max(0, min(int(round(score)), 100))
    effective = _severity_from_score(bounded)
    top_drivers = sorted(drivers, key=lambda item: abs(int(item.get("delta") or 0)), reverse=True)[
        :3
    ]

    return {
        "base_severity": normalized_base,
        "effective_severity": effective,
        "effective_score": bounded,
        "criticality": criticality,
        "recurrence_count": recurrence,
        "drivers": drivers,
        "top_drivers": top_drivers,
    }


__all__ = ["compute_effective_alert_severity"]
