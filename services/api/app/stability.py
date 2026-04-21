"""Stability contract and release gate evaluation helpers."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from . import metrics
from .db import migration_engine
from .settings import settings

CRITICAL_BACKGROUND_JOB_TYPES = (
    "telemetry_import",
    "network_anomaly_score",
    "threat_intel_refresh",
    "detection_rule_schedule",
    "correlation_pass",
)
SAMPLE_MEASUREMENT_KEYS = (
    "api_availability",
    "api_p95_latency_ms",
    "ingestion_visibility_seconds",
    "alert_creation_seconds",
    "background_job_freshness_minutes",
)
PLATFORM_SLI_SAMPLES_DDL = """
CREATE TABLE IF NOT EXISTS platform_sli_samples (
  sample_id                        BIGSERIAL PRIMARY KEY,
  captured_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  window_hours                     INTEGER NOT NULL DEFAULT 24,
  source                           TEXT NOT NULL DEFAULT 'platform_runtime',
  api_availability                 DOUBLE PRECISION,
  api_p95_latency_ms               DOUBLE PRECISION,
  ingestion_visibility_seconds     DOUBLE PRECISION,
  alert_creation_seconds           DOUBLE PRECISION,
  background_job_freshness_minutes DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_platform_sli_samples_captured
  ON platform_sli_samples(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_sli_samples_source
  ON platform_sli_samples(source, captured_at DESC);
"""
PLATFORM_API_RUNTIME_SNAPSHOTS_DDL = """
CREATE TABLE IF NOT EXISTS platform_api_runtime_snapshots (
  snapshot_id         BIGSERIAL PRIMARY KEY,
  captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source              TEXT NOT NULL DEFAULT 'api_runtime',
  service_name        TEXT NOT NULL DEFAULT 'secplat-api',
  service_instance_id TEXT NOT NULL,
  request_count       BIGINT NOT NULL DEFAULT 0,
  server_error_count  BIGINT NOT NULL DEFAULT 0,
  api_availability    DOUBLE PRECISION,
  api_p95_latency_ms  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_platform_api_runtime_snapshots_captured
  ON platform_api_runtime_snapshots(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_api_runtime_snapshots_instance
  ON platform_api_runtime_snapshots(service_instance_id, captured_at DESC);
"""
_initialized_runtime_tables: set[str] = set()


@dataclass(frozen=True)
class ServiceObjective:
    name: str
    title: str
    unit: str
    comparator: str  # gte | lte
    target: float
    error_budget: bool = False


def _default_objectives() -> list[ServiceObjective]:
    return [
        ServiceObjective(
            name="api_availability",
            title="API availability",
            unit="ratio",
            comparator="gte",
            target=float(settings.API_AVAILABILITY_SLO_TARGET),
            error_budget=True,
        ),
        ServiceObjective(
            name="api_p95_latency_ms",
            title="API p95 latency",
            unit="ms",
            comparator="lte",
            target=float(settings.API_P95_LATENCY_SLO_MS),
        ),
        ServiceObjective(
            name="ingestion_visibility_seconds",
            title="Ingestion-to-search latency",
            unit="seconds",
            comparator="lte",
            target=float(settings.INGESTION_VISIBILITY_SLO_SECONDS),
        ),
        ServiceObjective(
            name="alert_creation_seconds",
            title="Alert creation latency",
            unit="seconds",
            comparator="lte",
            target=float(settings.ALERT_CREATION_SLO_SECONDS),
        ),
        ServiceObjective(
            name="background_job_freshness_minutes",
            title="Background job freshness",
            unit="minutes",
            comparator="lte",
            target=float(settings.BACKGROUND_JOB_FRESHNESS_SLO_MINUTES),
        ),
    ]


def build_stability_contract() -> dict[str, Any]:
    objectives = _default_objectives()
    return {
        "contract_version": "2026-03-08",
        "window_days": int(settings.ERROR_BUDGET_WINDOW_DAYS),
        "service_objectives": [
            {
                "name": objective.name,
                "title": objective.title,
                "unit": objective.unit,
                "comparator": objective.comparator,
                "target": objective.target,
                "error_budget": objective.error_budget,
            }
            for objective in objectives
        ],
        "release_policy": {
            "freeze_threshold": float(settings.ERROR_BUDGET_FREEZE_THRESHOLD),
            "policy": (
                "When an error budget is exhausted, feature releases are paused and only "
                "reliability/security fixes may ship until budget recovers."
            ),
        },
        "partial_failure_behaviors": [
            {"dependency": "postgres", "mode": "API not-ready; fail closed for writes"},
            {"dependency": "opensearch", "mode": "API not-ready; return degraded with 503"},
            {"dependency": "redis", "mode": "Queue features degrade to best-effort sync path"},
        ],
    }


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _counter_delta(
    latest_value: Any,
    oldest_value: Any,
    *,
    same_snapshot: bool = False,
) -> int:
    latest = int(latest_value or 0)
    oldest = int(oldest_value or 0)
    if same_snapshot or latest < oldest:
        return latest
    return max(0, latest - oldest)


def _aggregate_runtime_boundary_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    instance_count = 0
    request_count = 0
    server_error_count = 0
    captured_at: datetime | None = None
    api_p95_latency_ms = 0.0

    for row in rows:
        instance_count += 1
        latest_snapshot_id = int(row.get("latest_snapshot_id") or 0)
        oldest_snapshot_id = int(row.get("oldest_snapshot_id") or 0)
        same_snapshot = latest_snapshot_id > 0 and latest_snapshot_id == oldest_snapshot_id
        request_count += _counter_delta(
            row.get("latest_request_count"),
            row.get("oldest_request_count"),
            same_snapshot=same_snapshot,
        )
        server_error_count += _counter_delta(
            row.get("latest_server_error_count"),
            row.get("oldest_server_error_count"),
            same_snapshot=same_snapshot,
        )
        api_p95_latency_ms = max(api_p95_latency_ms, float(row.get("api_p95_latency_ms") or 0.0))
        row_captured_at = row.get("captured_at")
        if isinstance(row_captured_at, datetime) and (
            captured_at is None or row_captured_at > captured_at
        ):
            captured_at = row_captured_at

    availability = 1.0
    if request_count > 0:
        availability = max(0.0, 1.0 - (server_error_count / float(request_count)))

    return {
        "instance_count": instance_count,
        "request_count": request_count,
        "server_error_count": server_error_count,
        "api_availability": round(availability, 6),
        "api_p95_latency_ms": round(api_p95_latency_ms, 3),
        "captured_at": captured_at.isoformat() if hasattr(captured_at, "isoformat") else None,
    }


def _as_utc_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    return None


def _filter_stale_runtime_rows(
    rows: list[dict[str, Any]],
    *,
    active_grace_seconds: int | None = None,
) -> list[dict[str, Any]]:
    if len(rows) <= 1:
        return rows
    freshest = max(
        (_as_utc_datetime(row.get("captured_at")) for row in rows),
        default=None,
    )
    if freshest is None:
        return rows
    effective_grace_seconds = max(
        30,
        int(
            active_grace_seconds
            or max(
                getattr(settings, "PLATFORM_SLI_MATERIALIZATION_INTERVAL_SECONDS", 60) * 2,
                60,
            )
        ),
    )
    cutoff = freshest - timedelta(seconds=effective_grace_seconds)
    filtered = [
        row for row in rows if (_as_utc_datetime(row.get("captured_at")) or cutoff) >= cutoff
    ]
    return filtered or rows


def _serialize_sample_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    out = dict(row)
    if hasattr(out.get("captured_at"), "isoformat"):
        out["captured_at"] = out["captured_at"].isoformat()
    for key in SAMPLE_MEASUREMENT_KEYS:
        out[key] = _to_float(out.get(key))
    return out


def sample_measurements(sample: dict[str, Any] | None) -> dict[str, float | None]:
    row = _serialize_sample_row(sample) or {}
    return {key: _to_float(row.get(key)) for key in SAMPLE_MEASUREMENT_KEYS}


def sample_needs_refresh(
    sample: dict[str, Any] | None,
    *,
    lookback_hours: int | None = None,
    max_age_seconds: int | None = None,
    require_complete: bool = False,
) -> bool:
    row = _serialize_sample_row(sample)
    if not row:
        return True
    effective_lookback_hours = max(
        1,
        int(lookback_hours or getattr(settings, "TELEMETRY_DEFAULT_LOOKBACK_HOURS", 24)),
    )
    try:
        sample_window_hours = int(row.get("window_hours") or 0)
    except (TypeError, ValueError):
        sample_window_hours = 0
    if sample_window_hours != effective_lookback_hours:
        return True

    captured_at_raw = row.get("captured_at")
    captured_at: datetime | None = None
    if isinstance(captured_at_raw, datetime):
        captured_at = captured_at_raw.astimezone(UTC)
    elif isinstance(captured_at_raw, str) and captured_at_raw.strip():
        try:
            captured_at = datetime.fromisoformat(captured_at_raw.replace("Z", "+00:00")).astimezone(
                UTC
            )
        except ValueError:
            captured_at = None
    effective_max_age_seconds = max(
        30,
        int(
            max_age_seconds
            or max(
                getattr(settings, "PLATFORM_SLI_MATERIALIZATION_INTERVAL_SECONDS", 60) * 2,
                60,
            )
        ),
    )
    if captured_at is None:
        return True
    age_seconds = (datetime.now(UTC) - captured_at).total_seconds()
    if age_seconds > effective_max_age_seconds:
        return True
    return require_complete and any(value is None for value in sample_measurements(row).values())


def _ensure_sli_samples_table(db: Session) -> None:
    _ensure_table(db, "platform_sli_samples", PLATFORM_SLI_SAMPLES_DDL)


def _ensure_runtime_snapshots_table(db: Session) -> None:
    _ensure_table(db, "platform_api_runtime_snapshots", PLATFORM_API_RUNTIME_SNAPSHOTS_DDL)


def _table_exists(db: Session, table_name: str) -> bool:
    return bool(
        db.execute(
            text("SELECT to_regclass(:table_name)"), {"table_name": f"public.{table_name}"}
        ).scalar()
    )


def _run_ddl(engine, ddl: str) -> None:
    with engine.begin() as conn:
        for stmt in ddl.strip().split(";"):
            statement = stmt.strip()
            if statement:
                conn.execute(text(statement))


def _ensure_table(db: Session, table_name: str, ddl: str) -> None:
    if table_name in _initialized_runtime_tables:
        return
    if _table_exists(db, table_name):
        _initialized_runtime_tables.add(table_name)
        return
    _run_ddl(migration_engine, ddl)
    _initialized_runtime_tables.add(table_name)


def _service_instance_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def capture_api_runtime_snapshot(
    db: Session,
    *,
    source: str = "api_runtime",
) -> dict[str, Any]:
    _ensure_runtime_snapshots_table(db)
    api_snapshot = metrics.get_sli_snapshot()
    row = (
        db.execute(
            text(
                """
                INSERT INTO platform_api_runtime_snapshots(
                  source,
                  service_name,
                  service_instance_id,
                  request_count,
                  server_error_count,
                  api_availability,
                  api_p95_latency_ms
                )
                VALUES(
                  :source,
                  'secplat-api',
                  :service_instance_id,
                  :request_count,
                  :server_error_count,
                  :api_availability,
                  :api_p95_latency_ms
                )
                RETURNING *
                """
            ),
            {
                "source": str(source or "api_runtime"),
                "service_instance_id": _service_instance_id(),
                "request_count": int(api_snapshot.get("request_count") or 0),
                "server_error_count": int(api_snapshot.get("server_error_count") or 0),
                "api_availability": _to_float(api_snapshot.get("api_availability")),
                "api_p95_latency_ms": _to_float(api_snapshot.get("api_p95_latency_ms")),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    out = dict(row or {})
    if hasattr(out.get("captured_at"), "isoformat"):
        out["captured_at"] = out["captured_at"].isoformat()
    return out


def durable_api_snapshot(
    db: Session,
    *,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    _ensure_runtime_snapshots_table(db)
    effective_max_age = max(
        30,
        int(max_age_seconds or getattr(settings, "PLATFORM_SLI_RUNTIME_MAX_AGE_SECONDS", 300)),
    )
    rows = (
        db.execute(
            text(
                """
                WITH ranked AS (
                  SELECT
                    snapshot_id,
                    captured_at,
                    source,
                    service_name,
                    service_instance_id,
                    request_count,
                    server_error_count,
                    api_availability,
                    api_p95_latency_ms,
                    ROW_NUMBER() OVER (
                      PARTITION BY service_instance_id
                      ORDER BY captured_at ASC, snapshot_id ASC
                    ) AS rn_asc,
                    ROW_NUMBER() OVER (
                      PARTITION BY service_instance_id
                      ORDER BY captured_at DESC, snapshot_id DESC
                    ) AS rn
                  FROM platform_api_runtime_snapshots
                  WHERE captured_at >= NOW() - (:max_age_seconds * INTERVAL '1 second')
                )
                SELECT
                  service_instance_id,
                  MAX(CASE WHEN rn = 1 THEN snapshot_id END) AS latest_snapshot_id,
                  MAX(CASE WHEN rn_asc = 1 THEN snapshot_id END) AS oldest_snapshot_id,
                  MAX(CASE WHEN rn = 1 THEN captured_at END) AS captured_at,
                  MAX(CASE WHEN rn = 1 THEN request_count END) AS latest_request_count,
                  MAX(CASE WHEN rn_asc = 1 THEN request_count END) AS oldest_request_count,
                  MAX(CASE WHEN rn = 1 THEN server_error_count END) AS latest_server_error_count,
                  MAX(CASE WHEN rn_asc = 1 THEN server_error_count END) AS oldest_server_error_count,
                  MAX(CASE WHEN rn = 1 THEN api_p95_latency_ms END) AS api_p95_latency_ms
                FROM ranked
                GROUP BY service_instance_id
                """
            ),
            {"max_age_seconds": effective_max_age},
        )
        .mappings()
        .all()
    )
    filtered_rows = _filter_stale_runtime_rows([dict(row) for row in rows])
    aggregate = _aggregate_runtime_boundary_rows(filtered_rows)
    return {
        "source": "durable_runtime_snapshots",
        "instance_count": int(aggregate.get("instance_count") or 0),
        "request_count": int(aggregate.get("request_count") or 0),
        "server_error_count": int(aggregate.get("server_error_count") or 0),
        "api_availability": float(aggregate.get("api_availability") or 0.0),
        "api_p95_latency_ms": float(aggregate.get("api_p95_latency_ms") or 0.0),
        "captured_at": aggregate.get("captured_at"),
        "max_age_seconds": effective_max_age,
    }


def compute_operational_sli_measurements(
    db: Session,
    *,
    lookback_hours: int | None = None,
) -> dict[str, float | None]:
    effective_lookback_hours = max(
        1,
        int(lookback_hours or getattr(settings, "TELEMETRY_DEFAULT_LOOKBACK_HOURS", 24)),
    )
    params = {"lookback_hours": effective_lookback_hours}
    ingestion_row = (
        db.execute(
            text(
                """
                SELECT
                  percentile_cont(0.95) WITHIN GROUP (ORDER BY ingest_lag_seconds)
                    AS ingestion_visibility_seconds
                FROM security_events
                WHERE ingest_lag_seconds IS NOT NULL
                  AND event_time >= NOW() - (:lookback_hours * INTERVAL '1 hour')
                """
            ),
            params,
        )
        .mappings()
        .first()
        or {}
    )
    alert_row = (
        db.execute(
            text(
                """
                SELECT
                  percentile_cont(0.95) WITHIN GROUP (
                    ORDER BY GREATEST(
                      EXTRACT(EPOCH FROM (created_at - first_seen_at)),
                      0
                    )
                  ) AS alert_creation_seconds
                FROM security_alerts
                WHERE first_seen_at IS NOT NULL
                  AND created_at >= NOW() - (:lookback_hours * INTERVAL '1 hour')
                """
            ),
            params,
        )
        .mappings()
        .first()
        or {}
    )
    job_row = (
        db.execute(
            text(
                """
                SELECT
                  EXTRACT(
                    EPOCH FROM (
                      NOW() - MAX(COALESCE(finished_at, created_at))
                    )
                  ) / 60.0 AS background_job_freshness_minutes
                FROM scan_jobs
                WHERE status IN ('done', 'running')
                  AND job_type = ANY(:job_types)
                """
            ),
            {"job_types": list(CRITICAL_BACKGROUND_JOB_TYPES)},
        )
        .mappings()
        .first()
        or {}
    )
    return {
        "ingestion_visibility_seconds": _to_float(
            ingestion_row.get("ingestion_visibility_seconds")
        ),
        "alert_creation_seconds": _to_float(alert_row.get("alert_creation_seconds")),
        "background_job_freshness_minutes": _to_float(
            job_row.get("background_job_freshness_minutes")
        ),
    }


def build_live_measurements(
    db: Session,
    *,
    lookback_hours: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    api_snapshot = metrics.get_sli_snapshot()
    operational = compute_operational_sli_measurements(db, lookback_hours=lookback_hours)
    measurements: dict[str, Any] = {
        "api_availability": _to_float(api_snapshot.get("api_availability")),
        "api_p95_latency_ms": _to_float(api_snapshot.get("api_p95_latency_ms")),
        "ingestion_visibility_seconds": _to_float(operational.get("ingestion_visibility_seconds")),
        "alert_creation_seconds": _to_float(operational.get("alert_creation_seconds")),
        "background_job_freshness_minutes": _to_float(
            operational.get("background_job_freshness_minutes")
        ),
    }
    return api_snapshot, measurements


def build_durable_measurements(
    db: Session,
    *,
    lookback_hours: int | None = None,
    max_age_seconds: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    api_snapshot = durable_api_snapshot(db, max_age_seconds=max_age_seconds)
    operational = compute_operational_sli_measurements(db, lookback_hours=lookback_hours)
    measurements: dict[str, Any] = {
        "api_availability": _to_float(api_snapshot.get("api_availability")),
        "api_p95_latency_ms": _to_float(api_snapshot.get("api_p95_latency_ms")),
        "ingestion_visibility_seconds": _to_float(operational.get("ingestion_visibility_seconds")),
        "alert_creation_seconds": _to_float(operational.get("alert_creation_seconds")),
        "background_job_freshness_minutes": _to_float(
            operational.get("background_job_freshness_minutes")
        ),
    }
    return api_snapshot, measurements


def materialize_sli_sample(
    db: Session,
    *,
    lookback_hours: int | None = None,
    source: str = "platform_materializer",
    max_age_seconds: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    api_snapshot, measurements = build_durable_measurements(
        db,
        lookback_hours=lookback_hours,
        max_age_seconds=max_age_seconds,
    )
    sample = persist_sli_sample(
        db,
        measurements=measurements,
        lookback_hours=lookback_hours,
        source=source,
    )
    return api_snapshot, measurements, sample


def persist_sli_sample(
    db: Session,
    *,
    measurements: dict[str, Any],
    source: str = "platform_runtime",
    lookback_hours: int | None = None,
) -> dict[str, Any]:
    _ensure_sli_samples_table(db)
    effective_lookback_hours = max(
        1,
        int(lookback_hours or getattr(settings, "TELEMETRY_DEFAULT_LOOKBACK_HOURS", 24)),
    )
    row = (
        db.execute(
            text(
                """
                INSERT INTO platform_sli_samples(
                  window_hours,
                  source,
                  api_availability,
                  api_p95_latency_ms,
                  ingestion_visibility_seconds,
                  alert_creation_seconds,
                  background_job_freshness_minutes
                )
                VALUES (
                  :window_hours,
                  :source,
                  :api_availability,
                  :api_p95_latency_ms,
                  :ingestion_visibility_seconds,
                  :alert_creation_seconds,
                  :background_job_freshness_minutes
                )
                RETURNING *
                """
            ),
            {
                "window_hours": effective_lookback_hours,
                "source": str(source or "platform_runtime"),
                "api_availability": _to_float(measurements.get("api_availability")),
                "api_p95_latency_ms": _to_float(measurements.get("api_p95_latency_ms")),
                "ingestion_visibility_seconds": _to_float(
                    measurements.get("ingestion_visibility_seconds")
                ),
                "alert_creation_seconds": _to_float(measurements.get("alert_creation_seconds")),
                "background_job_freshness_minutes": _to_float(
                    measurements.get("background_job_freshness_minutes")
                ),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    return _serialize_sample_row(dict(row) if row else {}) or {}


def latest_sli_sample(
    db: Session,
    *,
    source_prefix: str | None = None,
    exclude_suffixes: tuple[str, ...] = (),
) -> dict[str, Any] | None:
    _ensure_sli_samples_table(db)
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if source_prefix:
        clauses.append("source LIKE :source_prefix")
        params["source_prefix"] = f"{source_prefix}%"
    for idx, suffix in enumerate(exclude_suffixes):
        key = f"exclude_suffix_{idx}"
        clauses.append(f"source NOT LIKE :{key}")
        params[key] = f"%{suffix}"
    where_clause = ""
    if clauses:
        where_clause = "WHERE " + " AND ".join(clauses)
    row = (
        db.execute(
            text(  # nosemgrep
                f"""
                SELECT *
                FROM platform_sli_samples
                {where_clause}
                ORDER BY captured_at DESC, sample_id DESC
                LIMIT 1
                """
            ),
            params,
        )
        .mappings()
        .first()
    )
    return _serialize_sample_row(dict(row) if row else None)


def _objective_result(
    objective: ServiceObjective,
    measurements: dict[str, Any],
    *,
    strict_missing: bool,
) -> dict[str, Any]:
    observed = _to_float(measurements.get(objective.name))
    if observed is None:
        return {
            "name": objective.name,
            "status": "missing",
            "passed": not strict_missing,
            "observed": None,
            "target": objective.target,
            "comparator": objective.comparator,
            "error_budget_consumed": None,
        }

    if objective.comparator == "gte":
        passed = observed >= objective.target
    else:
        passed = observed <= objective.target

    error_budget_consumed = None
    if objective.error_budget:
        budget = max(1.0 - objective.target, 1e-9)
        observed_error = max(0.0, 1.0 - observed)
        error_budget_consumed = observed_error / budget

    return {
        "name": objective.name,
        "status": "ok" if passed else "breach",
        "passed": passed,
        "observed": observed,
        "target": objective.target,
        "comparator": objective.comparator,
        "error_budget_consumed": error_budget_consumed,
    }


def evaluate_release_gate(
    measurements: dict[str, Any],
    *,
    strict_missing: bool = True,
    window_days: int | None = None,
) -> dict[str, Any]:
    contract = build_stability_contract()
    objectives = _default_objectives()
    objective_results = [
        _objective_result(
            objective,
            measurements,
            strict_missing=strict_missing,
        )
        for objective in objectives
    ]
    freeze_threshold = float(settings.ERROR_BUDGET_FREEZE_THRESHOLD)
    error_budget_exhausted = any(
        (item.get("error_budget_consumed") or 0.0) > freeze_threshold for item in objective_results
    )
    gate_passed = all(item["passed"] for item in objective_results) and not error_budget_exhausted
    return {
        "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "window_days": int(window_days or contract["window_days"]),
        "strict_missing": bool(strict_missing),
        "gate_passed": gate_passed,
        "action": (
            "ship_allowed"
            if gate_passed
            else "reliability_fixes_only"
            if error_budget_exhausted
            else "release_blocked"
        ),
        "error_budget_exhausted": error_budget_exhausted,
        "results": objective_results,
    }
