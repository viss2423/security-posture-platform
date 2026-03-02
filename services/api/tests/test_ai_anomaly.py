from datetime import UTC, datetime, timedelta

from app.ai_anomaly import SeriesPoint, detect_latest_anomaly


def _make_series(values: list[float]) -> list[SeriesPoint]:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    return [SeriesPoint(ts=base + timedelta(days=i), value=v) for i, v in enumerate(values)]


def test_detects_higher_spike():
    points = _make_series([2, 2, 3, 2, 3, 2, 12])
    out = detect_latest_anomaly(metric="failed_jobs_daily", points=points, direction="higher")
    assert out is not None
    assert out.metric == "failed_jobs_daily"
    assert out.severity in {"medium", "high"}
    assert out.current_value == 12


def test_detects_lower_drop():
    points = _make_series([94, 95, 94, 95, 94, 95, 70])
    out = detect_latest_anomaly(metric="posture_score_avg", points=points, direction="lower")
    assert out is not None
    assert out.metric == "posture_score_avg"
    assert out.current_value == 70


def test_returns_none_when_normal():
    points = _make_series([10, 11, 10, 11, 10, 11, 10])
    out = detect_latest_anomaly(metric="red_assets_count", points=points, direction="higher")
    assert out is None
