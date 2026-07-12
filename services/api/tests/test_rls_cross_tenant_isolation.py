"""Row-level-security regression guard for cross-tenant isolation.

Migration 026 puts FORCE ROW LEVEL SECURITY on findings/assets/incidents/scan_jobs/...
scoped by the `secplat.tenant_id` GUC. That isolation only holds if the runtime DB role
is NOT a superuser and does NOT have BYPASSRLS. This test proves both:

  1. the role the API actually connects as cannot bypass RLS, and
  2. a row written under tenant-A is invisible when the session tenant is tenant-B.

If someone repoints the API's POSTGRES_DSN at the `secplat` superuser (which silently
bypasses every RLS policy), this test fails loudly instead of the leak going unnoticed.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if POSTGRES_DSN:
    from app.db import SessionLocal
    from app.request_context import tenant_id_ctx
else:
    SessionLocal = None
    tenant_id_ctx = None

pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; RLS isolation test requires a real Postgres",
)


def test_runtime_role_cannot_bypass_rls():
    """The API's DB role must be non-superuser and NOBYPASSRLS, or RLS is meaningless."""
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            )
            .mappings()
            .first()
        )
    finally:
        db.close()
    assert row is not None
    assert row["rolsuper"] is False, "API DB role is a superuser — RLS is bypassed"
    assert row["rolbypassrls"] is False, "API DB role has BYPASSRLS — RLS is bypassed"


def test_findings_are_isolated_across_tenants():
    marker = f"rls-isolation-probe-{uuid.uuid4().hex}"
    tenant_a = f"tenant-a-{uuid.uuid4().hex[:8]}"
    tenant_b = f"tenant-b-{uuid.uuid4().hex[:8]}"

    db = SessionLocal()
    token = tenant_id_ctx.set(tenant_a)
    try:
        # Write a finding as tenant-A. org_id defaults from the session GUC.
        db.execute(
            text(
                "INSERT INTO findings (asset_id, title, severity, confidence) "
                "VALUES (NULL, :title, 'low', 'high')"
            ),
            {"title": marker},
        )
        db.commit()

        # Visible to tenant-A (the owner).
        tenant_id_ctx.reset(token)
        token = tenant_id_ctx.set(tenant_a)
        seen_by_a = (
            db.execute(text("SELECT count(*) AS n FROM findings WHERE title = :t"), {"t": marker})
            .mappings()
            .first()
        )
        assert seen_by_a is not None and seen_by_a["n"] == 1

        # Invisible to tenant-B.
        tenant_id_ctx.reset(token)
        token = tenant_id_ctx.set(tenant_b)
        seen_by_b = (
            db.execute(text("SELECT count(*) AS n FROM findings WHERE title = :t"), {"t": marker})
            .mappings()
            .first()
        )
        assert (
            seen_by_b is not None and seen_by_b["n"] == 0
        ), "tenant-B can see tenant-A's finding — cross-tenant RLS isolation is broken"
    finally:
        # Clean up as tenant-A (RLS only lets the owner delete it).
        tenant_id_ctx.reset(token)
        cleanup_token = tenant_id_ctx.set(tenant_a)
        try:
            db.execute(text("DELETE FROM findings WHERE title = :t"), {"t": marker})
            db.commit()
        finally:
            tenant_id_ctx.reset(cleanup_token)
            db.close()
