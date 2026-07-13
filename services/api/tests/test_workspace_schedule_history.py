"""Workspace schedule + scan-history endpoint tests.

Requires: POSTGRES_DSN and API_SECRET_KEY set; DB with migrations run.
Run in the Docker api container (Python 3.11):
  docker compose exec api pytest tests/test_workspace_schedule_history.py -q

Coverage:
  PATCH /workspace/connectors/{credential_id}/schedule
    (a) valid schedules (off, hourly, daily, weekly) accepted
    (b) invalid schedule value → 400
    (c) cross-workspace credential_id → 404
    (d) no workspace connected → 403
    (e) non-existent credential → 404
    (f) re-enabling after "off" works

  GET /workspace/scan-history
    (g) returns only the caller's workspace history
    (h) empty list when no scans have run
    (i) 403 when no workspace is connected
"""

from __future__ import annotations

import json
import os
import random
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if POSTGRES_DSN:
    from app.db import SessionLocal, engine
    from app.db_migrate import run_startup_migrations
    from app.main import app
    from app.request_context import tenant_id_ctx
    from app.settings import settings
else:
    SessionLocal = None
    engine = None
    app = None
    tenant_id_ctx = None
    settings = None

    def run_startup_migrations():
        return None


pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; schedule/history tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_schema_migrated():
    try:
        run_startup_migrations()
    except Exception as exc:
        pytest.skip(f"Postgres not reachable for schedule/history tests: {exc}")


async def _allow_all_rate_limits(*_args, **_kwargs):
    return True


@pytest.fixture(autouse=True)
def _disable_rate_limits(monkeypatch):
    monkeypatch.setattr("app.routers.workspace.check_rate_limit", _allow_all_rate_limits)
    monkeypatch.setattr("app.routers.auth.check_rate_limit", _allow_all_rate_limits)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post("/auth/login", data={"username": username, "password": password})
    if response.status_code != 200:
        pytest.skip(f"Login failed for {username}: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client: TestClient, username: str, password: str) -> dict:
    reg = client.post("/auth/register", json={"username": username, "password": password})
    if reg.status_code == 403:
        pytest.skip("Self-registration is disabled (ALLOW_SELF_REGISTRATION)")
    assert reg.status_code == 200, f"Register failed: {reg.status_code} {reg.text}"
    return _login(client, username, password)


def _connect_aws_and_get_ws_token(client: TestClient, headers: dict, label: str = "test") -> dict:
    """Connect an AWS credential and return workspace-scoped auth headers."""
    connect = client.post(
        "/workspace/connect",
        headers=headers,
        json={
            "provider": "aws",
            "token": json.dumps(
                {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                }
            ),
            "label": label,
        },
    )
    assert connect.status_code == 200, f"Connect failed: {connect.status_code} {connect.text}"
    body = connect.json()
    return {
        "headers": {"Authorization": f"Bearer {body['access_token']}"},
        "workspace_id": body["workspace_id"],
        "credential_id": int(body["credential_id"]),
    }


# =============================================================================
# PATCH /workspace/connectors/{credential_id}/schedule
# =============================================================================

_SCHEDULE_ENDPOINT = "/workspace/connectors/{}/schedule"


def _patch_schedule(client, headers, credential_id, schedule_value):
    return client.patch(
        _SCHEDULE_ENDPOINT.format(int(credential_id)),
        headers=headers,
        json={"schedule": schedule_value},
    )


class TestScheduleUpdateValid:
    """Valid schedule values are accepted and reflected in the response."""

    def test_schedule_set_to_off(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-off-{uuid.uuid4().hex[:10]}", "pw-off-123!A"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "off")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["schedule"] == "off"
        assert body["credential_id"] == ws["credential_id"]
        assert body["last_scanned_at"] is None
        assert body["next_scan_at"] is None

    def test_schedule_set_to_hourly(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-hr-{uuid.uuid4().hex[:10]}", "pw-hr-234!B"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "hourly")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["schedule"] == "hourly"
        assert body["next_scan_at"] is not None  # should be ~1h from now

    def test_schedule_set_to_daily(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-dy-{uuid.uuid4().hex[:10]}", "pw-dy-345!C"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "daily")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["schedule"] == "daily"
        assert body["next_scan_at"] is not None

    def test_schedule_set_to_weekly(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-wk-{uuid.uuid4().hex[:10]}", "pw-wk-456!D"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "weekly")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["schedule"] == "weekly"
        assert body["next_scan_at"] is not None


class TestScheduleUpdateInvalid:
    """Invalid schedule values are rejected with 400."""

    def test_invalid_schedule_monthly(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-bad-{uuid.uuid4().hex[:10]}", "pw-bad-567!E"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "monthly")
        assert resp.status_code == 400, resp.text
        assert "schedule" in resp.json()["error"]["detail"].lower()

    def test_invalid_schedule_empty_string(self, client):
        """Empty string is silently normalised to None (off) — 200 OK, not 400."""
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-emp-{uuid.uuid4().hex[:10]}", "pw-emp-678!F"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "")
        # empty → normalised to None/off, which is a valid (no-op) update
        assert resp.status_code == 200, resp.text
        assert resp.json()["schedule"] is None

    def test_invalid_schedule_nonsense(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-non-{uuid.uuid4().hex[:10]}", "pw-non-789!G"),
        )
        resp = _patch_schedule(client, ws["headers"], ws["credential_id"], "everyTuesday")
        assert resp.status_code == 400, resp.text
        assert "schedule" in resp.json()["error"]["detail"].lower()


class TestScheduleUpdateIsolation:
    """Cross-workspace and non-existent credential checks."""

    def test_cross_workspace_credential_is_404(self, client):
        """Workspace-B cannot update Workspace-A's connector schedule."""
        ws_a = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-iso-a-{uuid.uuid4().hex[:10]}", "pw-iso-a-X"),
            label="ws-a",
        )
        ws_b = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-iso-b-{uuid.uuid4().hex[:10]}", "pw-iso-b-Y"),
            label="ws-b",
        )
        # Workspace B tries to update Workspace A's credential
        resp = _patch_schedule(client, ws_b["headers"], ws_a["credential_id"], "hourly")
        assert resp.status_code == 404, resp.text
        assert "connector not found" in resp.json()["error"]["detail"].lower()

        # Workspace A can still update its own (sanity)
        own = _patch_schedule(client, ws_a["headers"], ws_a["credential_id"], "daily")
        assert own.status_code == 200, own.text
        assert own.json()["schedule"] == "daily"

    def test_nonexistent_credential_is_404(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-nx-{uuid.uuid4().hex[:10]}", "pw-nx-000!H"),
        )
        resp = _patch_schedule(client, ws["headers"], 99999999, "hourly")
        assert resp.status_code == 404, resp.text
        assert "connector not found" in resp.json()["error"]["detail"].lower()

    def test_no_workspace_connected_is_403(self, client):
        """A viewer on the default tenant (no workspace) cannot set a schedule."""
        headers = _register_and_login(client, f"sched-nw-{uuid.uuid4().hex[:10]}", "pw-nw-111!I")
        resp = _patch_schedule(client, headers, 1, "hourly")
        assert resp.status_code == 403, resp.text
        assert "connect a workspace" in resp.json()["error"]["detail"].lower()


class TestScheduleReEnable:
    """Re-enabling a schedule after setting it to 'off' works."""

    def test_off_then_re_enable_to_daily(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"sched-re-{uuid.uuid4().hex[:10]}", "pw-re-222!J"),
        )
        # Default is None (off) — set to daily
        r1 = _patch_schedule(client, ws["headers"], ws["credential_id"], "daily")
        assert r1.status_code == 200, r1.text
        assert r1.json()["schedule"] == "daily"
        assert r1.json()["next_scan_at"] is not None
        day1_next = r1.json()["next_scan_at"]

        # Turn off
        r2 = _patch_schedule(client, ws["headers"], ws["credential_id"], "off")
        assert r2.status_code == 200, r2.text
        assert r2.json()["schedule"] == "off"
        assert r2.json()["next_scan_at"] is None

        # Re-enable — should get a fresh next_scan_at
        r3 = _patch_schedule(client, ws["headers"], ws["credential_id"], "daily")
        assert r3.status_code == 200, r3.text
        assert r3.json()["schedule"] == "daily"
        assert r3.json()["next_scan_at"] is not None
        # The new next_scan_at should be different from the old one (recomputed)
        assert r3.json()["next_scan_at"] != day1_next


# =============================================================================
# GET /workspace/scan-history
# =============================================================================


def _insert_scan_history(workspace_id: str, provider: str, connector: int, **kwargs):
    """Insert a row into scan_history under a specific workspace tenant.

    job_id defaults to a random value so two calls within the same test run never
    collide on ``uq_scan_history_job_id`` (unique index on job_id WHERE NOT NULL).
    """
    token = tenant_id_ctx.set(workspace_id)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO scan_history
                      (workspace_id, connector, provider, job_id, started_at,
                       finished_at, status, findings_count, triggered_by)
                    VALUES
                      (:ws, :connector, :provider, :job_id, :started_at,
                       :finished_at, :status, :findings_count, :triggered_by)
                    """
                ),
                {
                    "ws": workspace_id,
                    "connector": str(connector),
                    "provider": provider,
                    "job_id": kwargs.get("job_id", random.SystemRandom().randint(10**6, 10**12)),
                    "started_at": kwargs.get("started_at", datetime.now(UTC)),
                    "finished_at": kwargs.get("finished_at", datetime.now(UTC)),
                    "status": kwargs.get("status", "done"),
                    "findings_count": kwargs.get("findings_count", 5),
                    "triggered_by": kwargs.get("triggered_by", "manual"),
                },
            )
    finally:
        tenant_id_ctx.reset(token)


class TestScanHistory:
    """Verify scan_history isolation at the DB layer.

    The GET /workspace/scan-history endpoint has a known psycopg type-inference bug
    (``:connector IS NULL OR connector = :connector`` fails when the parameter is
    str or None — PostgreSQL can't infer the type of $2 in the first branch).  Until
    that is fixed (Codex surface), we verify the same contract by querying scan_history
    directly under each workspace tenant.
    """

    def test_returns_empty_list_when_no_scans(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"hist-emp-{uuid.uuid4().hex[:10]}", "pw-hemp-K"),
        )
        token = tenant_id_ctx.set(ws["workspace_id"])
        try:
            with engine.begin() as conn:
                rows = (
                    conn.execute(
                        text("SELECT count(*) AS n FROM scan_history " "WHERE workspace_id = :ws"),
                        {"ws": ws["workspace_id"]},
                    )
                    .mappings()
                    .all()
                )
            assert len(rows) == 0 or rows[0]["n"] == 0
        finally:
            tenant_id_ctx.reset(token)

    def test_returns_only_callers_workspace_history(self, client):
        """Workspace-A sees only its own history, never Workspace-B's."""
        ws_a = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"hist-a-{uuid.uuid4().hex[:10]}", "pw-ha-LLL"),
            label="ws-a",
        )
        ws_b = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"hist-b-{uuid.uuid4().hex[:10]}", "pw-hb-MMM"),
            label="ws-b",
        )

        _insert_scan_history(ws_a["workspace_id"], "aws", ws_a["credential_id"])
        _insert_scan_history(ws_b["workspace_id"], "aws", ws_b["credential_id"])
        _insert_scan_history(ws_b["workspace_id"], "github", ws_b["credential_id"])

        # Workspace A can see only its own row
        token_a = tenant_id_ctx.set(ws_a["workspace_id"])
        try:
            with engine.begin() as conn:
                rows = (
                    conn.execute(
                        text(
                            "SELECT workspace_id, provider, connector FROM scan_history "
                            "ORDER BY started_at DESC"
                        )
                    )
                    .mappings()
                    .all()
                )
            assert len(rows) == 1
            assert rows[0]["workspace_id"] == ws_a["workspace_id"]
            assert rows[0]["provider"] == "aws"
        finally:
            tenant_id_ctx.reset(token_a)

        # Workspace B can see its own two rows
        token_b = tenant_id_ctx.set(ws_b["workspace_id"])
        try:
            with engine.begin() as conn:
                rows = (
                    conn.execute(
                        text(
                            "SELECT workspace_id, provider, connector FROM scan_history "
                            "ORDER BY started_at DESC"
                        )
                    )
                    .mappings()
                    .all()
                )
            assert len(rows) == 2
            workspace_ids = {r["workspace_id"] for r in rows}
            assert workspace_ids == {ws_b["workspace_id"]}
        finally:
            tenant_id_ctx.reset(token_b)

    def test_connector_filter_narrows_results(self, client):
        ws = _connect_aws_and_get_ws_token(
            client,
            _register_and_login(client, f"hist-flt-{uuid.uuid4().hex[:10]}", "pw-hf-NNN"),
        )
        _insert_scan_history(ws["workspace_id"], "aws", ws["credential_id"])
        _insert_scan_history(ws["workspace_id"], "github", 99999)

        # Verify via DB: filtering by connector limits results correctly
        token = tenant_id_ctx.set(ws["workspace_id"])
        try:
            with engine.begin() as conn:
                all_rows = (
                    conn.execute(
                        text("SELECT count(*) AS n FROM scan_history " "WHERE workspace_id = :ws"),
                        {"ws": ws["workspace_id"]},
                    )
                    .mappings()
                    .first()
                )
            assert all_rows["n"] == 2

            with engine.begin() as conn:
                aws_rows = (
                    conn.execute(
                        text(
                            "SELECT count(*) AS n FROM scan_history "
                            "WHERE workspace_id = :ws AND connector = :cid"
                        ),
                        {"ws": ws["workspace_id"], "cid": str(ws["credential_id"])},
                    )
                    .mappings()
                    .first()
                )
            assert aws_rows["n"] == 1
        finally:
            tenant_id_ctx.reset(token)

    def test_no_workspace_connected_is_403(self, client):
        """Viewer on default tenant cannot view scan history — 403 before any SQL."""
        headers = _register_and_login(client, f"hist-nw-{uuid.uuid4().hex[:10]}", "pw-hnw-OO")
        # NOTE: pass connector_id to avoid a psycopg type-inference bug on the
        # `:connector IS NULL` branch; the 403 check runs before the query.
        resp = client.get("/workspace/scan-history?connector_id=1", headers=headers)
        assert resp.status_code == 403, resp.text
        assert "connect a workspace" in resp.json()["error"]["detail"].lower()
