from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.stability import _aggregate_runtime_boundary_rows, _filter_stale_runtime_rows


def test_runtime_snapshot_aggregation_uses_recent_counter_deltas():
    summary = _aggregate_runtime_boundary_rows(
        [
            {
                "latest_snapshot_id": 22,
                "oldest_snapshot_id": 20,
                "latest_request_count": 125,
                "oldest_request_count": 100,
                "latest_server_error_count": 3,
                "oldest_server_error_count": 3,
                "api_p95_latency_ms": 180.0,
                "captured_at": None,
            },
            {
                "latest_snapshot_id": 7,
                "oldest_snapshot_id": 7,
                "latest_request_count": 8,
                "oldest_request_count": 8,
                "latest_server_error_count": 1,
                "oldest_server_error_count": 1,
                "api_p95_latency_ms": 90.0,
                "captured_at": None,
            },
        ]
    )
    assert summary["instance_count"] == 2
    assert summary["request_count"] == 33
    assert summary["server_error_count"] == 1
    assert summary["api_availability"] == pytest.approx(32.0 / 33.0, rel=1e-6)
    assert summary["api_p95_latency_ms"] == 180.0


def test_runtime_snapshot_filter_drops_stale_instances_after_restart():
    now = datetime.now(UTC)
    rows = [
        {
            "latest_snapshot_id": 22,
            "oldest_snapshot_id": 20,
            "latest_request_count": 125,
            "oldest_request_count": 100,
            "latest_server_error_count": 3,
            "oldest_server_error_count": 3,
            "api_p95_latency_ms": 980.0,
            "captured_at": now - timedelta(minutes=4),
        },
        {
            "latest_snapshot_id": 30,
            "oldest_snapshot_id": 28,
            "latest_request_count": 240,
            "oldest_request_count": 200,
            "latest_server_error_count": 1,
            "oldest_server_error_count": 1,
            "api_p95_latency_ms": 32.0,
            "captured_at": now,
        },
    ]

    filtered = _filter_stale_runtime_rows(rows, active_grace_seconds=90)

    assert len(filtered) == 1
    assert filtered[0]["api_p95_latency_ms"] == 32.0
