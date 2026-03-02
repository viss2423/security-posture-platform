"""Simple anomaly detection helpers for posture/security trend metrics."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SeriesPoint:
    ts: datetime
    value: float


@dataclass
class Anomaly:
    metric: str
    severity: str
    current_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float | None
    window_size: int
    context: dict


def detect_latest_anomaly(
    *,
    metric: str,
    points: list[SeriesPoint],
    direction: str,
    min_points: int = 6,
    lookback: int = 14,
    z_threshold: float = 2.5,
) -> Anomaly | None:
    """
    Compare latest point against a rolling baseline.
    direction: "higher" detects spikes, "lower" detects drops.
    """
    cleaned = [p for p in points if isinstance(p.value, (int, float))]
    if len(cleaned) < min_points:
        return None
    latest = cleaned[-1]
    history = cleaned[:-1][-lookback:]
    if len(history) < (min_points - 1):
        return None

    baseline_values = [float(p.value) for p in history]
    baseline_mean = sum(baseline_values) / len(baseline_values)
    variance = sum((v - baseline_mean) ** 2 for v in baseline_values) / len(baseline_values)
    baseline_std = math.sqrt(max(variance, 0.0))
    current_value = float(latest.value)
    delta = current_value - baseline_mean
    z_score = (delta / baseline_std) if baseline_std > 0 else None

    is_anomaly = False
    if direction == "higher":
        if baseline_std == 0:
            is_anomaly = current_value > (baseline_mean + max(1.0, baseline_mean * 0.5))
        else:
            is_anomaly = (z_score or 0.0) >= z_threshold
    elif direction == "lower":
        if baseline_std == 0:
            is_anomaly = current_value < (baseline_mean - max(1.0, abs(baseline_mean) * 0.3))
        else:
            is_anomaly = (z_score or 0.0) <= -z_threshold
    else:
        raise ValueError(f"invalid_direction:{direction}")

    if not is_anomaly:
        return None

    sev = _severity(
        z_score=z_score,
        baseline_std=baseline_std,
        delta=delta,
    )
    return Anomaly(
        metric=metric,
        severity=sev,
        current_value=current_value,
        baseline_mean=baseline_mean,
        baseline_std=baseline_std,
        z_score=z_score,
        window_size=len(history),
        context={
            "direction": direction,
            "latest_ts": latest.ts.isoformat(),
            "history_start_ts": history[0].ts.isoformat(),
            "history_end_ts": history[-1].ts.isoformat(),
        },
    )


def _severity(*, z_score: float | None, baseline_std: float, delta: float) -> str:
    if z_score is not None:
        az = abs(z_score)
        if az >= 4.0:
            return "high"
        if az >= 2.5:
            return "medium"
        return "low"
    if baseline_std == 0 and abs(delta) >= 5:
        return "medium"
    return "low"
