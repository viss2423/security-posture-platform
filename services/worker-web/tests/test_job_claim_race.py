"""
Regression test for worker DB claim race:
- concurrent fetch_job() calls must never claim the same queued row twice.

Run:
  POSTGRES_DSN=postgresql://secplat:secplat@localhost:5433/secplat ^
  pytest services/worker-web/tests/test_job_claim_race.py -v
"""

from __future__ import annotations

import importlib.util
import os
import threading
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row


def _normalize_dsn(raw: str | None) -> str | None:
    if not raw:
        return None
    return raw.replace("postgresql+psycopg://", "postgresql://")


POSTGRES_DSN = _normalize_dsn(os.getenv("POSTGRES_DSN"))

pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; worker race test requires Postgres",
)


@pytest.fixture(scope="module")
def worker_module():
    # worker.py reads POSTGRES_DSN at import time.
    os.environ["POSTGRES_DSN"] = POSTGRES_DSN or ""
    worker_path = Path(__file__).resolve().parents[1] / "worker.py"
    spec = importlib.util.spec_from_file_location("secplat_worker_web_worker", worker_path)
    assert spec and spec.loader, "Failed to load worker.py module spec"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _set_search_path(conn: psycopg.Connection, schema_name: str) -> None:
    with conn.cursor() as cur:
        cur.execute(sql.SQL("SET search_path TO {}, public").format(sql.Identifier(schema_name)))


def _create_isolated_scan_jobs_table(dsn: str, schema_name: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name)))
            cur.execute(
                sql.SQL(
                    """
                    CREATE TABLE {}.scan_jobs (
                      job_id BIGSERIAL PRIMARY KEY,
                      job_type TEXT NOT NULL,
                      target_asset_id INTEGER,
                      requested_by TEXT,
                      status TEXT NOT NULL DEFAULT 'queued',
                      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                      started_at TIMESTAMPTZ,
                      finished_at TIMESTAMPTZ,
                      error TEXT,
                      log_output TEXT,
                      retry_count INTEGER NOT NULL DEFAULT 0
                    )
                    """
                ).format(sql.Identifier(schema_name))
            )


def _drop_schema(dsn: str, schema_name: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name))
            )


def test_fetch_job_claim_is_single_winner_under_concurrency(worker_module):
    schema_name = f"worker_race_{uuid.uuid4().hex[:8]}"
    _create_isolated_scan_jobs_table(POSTGRES_DSN, schema_name)

    try:
        with psycopg.connect(POSTGRES_DSN, row_factory=dict_row, autocommit=True) as conn:
            _set_search_path(conn, schema_name)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scan_jobs(job_type, target_asset_id, requested_by, status)
                    VALUES ('web_exposure', 123, 'pytest', 'queued')
                    RETURNING job_id
                    """
                )
                inserted_job_id = cur.fetchone()["job_id"]

        barrier = threading.Barrier(2)
        results: list[int | None] = []
        lock = threading.Lock()

        def _claim_once() -> None:
            conn = psycopg.connect(POSTGRES_DSN, row_factory=dict_row, autocommit=True)
            try:
                _set_search_path(conn, schema_name)
                barrier.wait(timeout=5)
                row = worker_module.fetch_job(conn)
                claimed = row["job_id"] if row else None
                with lock:
                    results.append(claimed)
            finally:
                conn.close()

        t1 = threading.Thread(target=_claim_once)
        t2 = threading.Thread(target=_claim_once)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert not t1.is_alive() and not t2.is_alive(), "Threads did not complete"

        assert len(results) == 2
        assert results.count(inserted_job_id) == 1, f"expected single winner, got {results}"
        assert results.count(None) == 1, f"expected one loser, got {results}"

        with psycopg.connect(POSTGRES_DSN, row_factory=dict_row, autocommit=True) as conn:
            _set_search_path(conn, schema_name)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, started_at
                    FROM scan_jobs
                    WHERE job_id = %s
                    """,
                    (inserted_job_id,),
                )
                row = cur.fetchone()
                assert row is not None
                assert row["status"] == "running"
                assert row["started_at"] is not None
    finally:
        _drop_schema(POSTGRES_DSN, schema_name)
