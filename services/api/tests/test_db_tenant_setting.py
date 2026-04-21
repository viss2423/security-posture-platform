from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if POSTGRES_DSN:
    from app.db import SessionLocal, bind_tenant_context
    from app.request_context import tenant_id_ctx
else:
    SessionLocal = None
    bind_tenant_context = None
    tenant_id_ctx = None


pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="POSTGRES_DSN not set; tenant GUC persistence test requires Postgres",
)


def test_tenant_guc_persists_after_commit():
    db = SessionLocal()
    try:
        initial = (
            db.execute(text("SELECT current_setting('secplat.tenant_id', true) AS tenant"))
            .mappings()
            .first()
        )
        assert initial is not None
        assert initial["tenant"] == "default"

        db.execute(text("SELECT 1"))
        db.commit()

        after_commit = (
            db.execute(text("SELECT current_setting('secplat.tenant_id', true) AS tenant"))
            .mappings()
            .first()
        )
        assert after_commit is not None
        assert after_commit["tenant"] == "default"
    finally:
        db.close()


def test_bind_tenant_context_applies_current_request_tenant():
    token = tenant_id_ctx.set("tenant-phase5-gamma")
    db = SessionLocal()
    try:
        applied = bind_tenant_context(db)
        current = (
            db.execute(text("SELECT current_setting('secplat.tenant_id', true) AS tenant"))
            .mappings()
            .first()
        )
    finally:
        db.close()
        tenant_id_ctx.reset(token)
    assert applied == "tenant-phase5-gamma"
    assert current is not None
    assert current["tenant"] == "tenant-phase5-gamma"
