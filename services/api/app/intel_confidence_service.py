"""Threat-intel confidence and source-priority helpers."""

from __future__ import annotations

from typing import Any


def _to_float(value: Any, *, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _to_int(value: Any, *, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def clamp(value: float, *, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def normalize_source_priority(value: Any, *, default: int = 50) -> int:
    priority = _to_int(value, fallback=default)
    if priority < 0:
        return 0
    if priority > 100:
        return 100
    return priority


def normalize_confidence_score(value: Any, *, default: float = 0.6) -> float:
    score = _to_float(value, fallback=default)
    return clamp(score, minimum=0.0, maximum=1.0)


def confidence_label(score: float) -> str:
    normalized = normalize_confidence_score(score, default=0.6)
    if normalized >= 0.85:
        return "high"
    if normalized >= 0.55:
        return "medium"
    return "low"


def blended_confidence(
    *,
    base_score: Any,
    source_priority: Any,
    campaign_weight: Any = 1.0,
) -> float:
    base = normalize_confidence_score(base_score, default=0.6)
    priority = normalize_source_priority(source_priority, default=50)
    weight = clamp(_to_float(campaign_weight, fallback=1.0), minimum=0.2, maximum=1.8)
    adjusted = ((base * 0.7) + ((priority / 100.0) * 0.3)) * weight
    return clamp(adjusted, minimum=0.0, maximum=1.0)
