from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import SessionLocal
from app.main import app
from app.routers import platform as platform_router
from app.stability import persist_sli_sample, sample_needs_refresh

TEST_SAMPLE_SOURCE = "platform_test_observability"


@pytest.fixture(autouse=True)
def _cleanup_test_sli_rows():
    db = SessionLocal()
    try:
        db.execute(
            text(
                """
                DELETE FROM platform_sli_samples
                WHERE source IN (
                  :test_source,
                  'platform_release_gate_current_override'
                )
                """
            ),
            {"test_source": TEST_SAMPLE_SOURCE},
        )
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.execute(
            text(
                """
                DELETE FROM platform_sli_samples
                WHERE source IN (
                  :test_source,
                  'platform_release_gate_current_override'
                )
                """
            ),
            {"test_source": TEST_SAMPLE_SOURCE},
        )
        db.commit()
    finally:
        db.close()


def _seed_sample() -> None:
    db = SessionLocal()
    try:
        persist_sli_sample(
            db,
            source=TEST_SAMPLE_SOURCE,
            measurements={
                "api_availability": 0.999,
                "api_p95_latency_ms": 120.0,
                "ingestion_visibility_seconds": 45.0,
                "alert_creation_seconds": 60.0,
                "background_job_freshness_minutes": 5.0,
            },
        )
    finally:
        db.close()


def test_current_sli_snapshot_exposes_durable_api_measurements():
    _seed_sample()
    c = TestClient(app)
    # Generate a few requests so middleware records counters/latencies.
    c.get("/health")
    c.get("/health")
    r = c.get("/platform/sli/current")
    assert r.status_code == 200
    body = r.json()
    api = body["api"]
    assert api["source"] == "durable_runtime_snapshots"
    assert api["instance_count"] >= 1
    assert api["request_count"] >= 2
    assert 0.0 <= float(api["api_availability"]) <= 1.0
    assert float(api["api_p95_latency_ms"]) >= 0.0
    assert "sample" in body
    assert body["sample"]["sample_id"] >= 1
    assert "captured_at" in body["sample"]
    measurements = body["measurements"]
    assert "ingestion_visibility_seconds" in measurements
    assert "alert_creation_seconds" in measurements
    assert "background_job_freshness_minutes" in measurements


def test_current_release_gate_uses_durable_api_sli_and_optional_measurements():
    _seed_sample()
    c = TestClient(app)
    c.get("/health")
    r = c.get(
        "/platform/release-gate/current",
        params={
            "ingestion_visibility_seconds": 100,
            "alert_creation_seconds": 120,
            "background_job_freshness_minutes": 15,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "api_snapshot" in body
    assert "sample" in body
    assert "latest_sample" in body
    assert "measurements" in body
    assert body["api_snapshot"]["source"] == "durable_runtime_snapshots"
    assert body["sample"]["source"] == "platform_release_gate_current_override"
    assert isinstance(body["gate_passed"], bool)


def test_current_release_gate_blocks_overrides_when_durable_evidence_required(monkeypatch):
    _seed_sample()
    c = TestClient(app)
    monkeypatch.setattr(
        platform_router.settings, "PLATFORM_REQUIRE_DURABLE_SLI", True, raising=False
    )
    r = c.get(
        "/platform/release-gate/current",
        params={"ingestion_visibility_seconds": 100},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["gate_passed"] is False
    assert body["action"] == "release_blocked"
    assert body["strict_missing"] is True
    assert "override parameters are disabled" in body["message"]


def test_sample_needs_refresh_when_stale_or_incomplete():
    assert sample_needs_refresh(None) is True
    fresh_complete = {
        "sample_id": 1,
        "captured_at": "2999-01-01T00:00:00+00:00",
        "window_hours": 24,
        "api_availability": 0.999,
        "api_p95_latency_ms": 120.0,
        "ingestion_visibility_seconds": 12.0,
        "alert_creation_seconds": 15.0,
        "background_job_freshness_minutes": 2.0,
    }
    assert sample_needs_refresh(fresh_complete, lookback_hours=24, require_complete=True) is False
    stale = dict(fresh_complete)
    stale["captured_at"] = "2000-01-01T00:00:00+00:00"
    assert sample_needs_refresh(stale, lookback_hours=24) is True
    incomplete = dict(fresh_complete)
    incomplete["ingestion_visibility_seconds"] = None
    assert sample_needs_refresh(incomplete, lookback_hours=24, require_complete=True) is True


def test_current_release_gate_refreshes_stale_incomplete_sample(monkeypatch):
    _seed_sample()
    c = TestClient(app)
    stale_sample = {
        "sample_id": 22,
        "captured_at": "2000-01-01T00:00:00+00:00",
        "window_hours": 24,
        "source": "stale_sample",
        "api_availability": 0.999,
        "api_p95_latency_ms": 900.0,
        "ingestion_visibility_seconds": None,
        "alert_creation_seconds": None,
        "background_job_freshness_minutes": None,
    }
    refreshed_sample = {
        "sample_id": 23,
        "captured_at": "2099-01-01T00:00:00+00:00",
        "window_hours": 24,
        "source": "platform_release_gate_current",
        "api_availability": 0.999,
        "api_p95_latency_ms": 120.0,
        "ingestion_visibility_seconds": 45.0,
        "alert_creation_seconds": 60.0,
        "background_job_freshness_minutes": 5.0,
    }

    def _fake_materialize(*_args, **_kwargs):
        return (
            {
                "source": "durable_runtime_snapshots",
                "instance_count": 1,
                "request_count": 10,
                "server_error_count": 0,
                "api_availability": 0.999,
                "api_p95_latency_ms": 120.0,
                "captured_at": "2099-01-01T00:00:00+00:00",
                "max_age_seconds": 300,
            },
            {
                "api_availability": 0.999,
                "api_p95_latency_ms": 120.0,
                "ingestion_visibility_seconds": 45.0,
                "alert_creation_seconds": 60.0,
                "background_job_freshness_minutes": 5.0,
            },
            refreshed_sample,
        )

    monkeypatch.setattr(
        platform_router,
        "latest_sli_sample",
        lambda _db, **_kwargs: stale_sample,
    )
    monkeypatch.setattr(platform_router, "materialize_sli_sample", _fake_materialize)

    r = c.get("/platform/release-gate/current", params={"strict_missing": True})
    assert r.status_code == 200
    body = r.json()
    assert body["sample"]["sample_id"] == refreshed_sample["sample_id"]
    assert body["sample"]["source"] == "platform_release_gate_current"
    assert body["measurements"]["ingestion_visibility_seconds"] == 45.0
