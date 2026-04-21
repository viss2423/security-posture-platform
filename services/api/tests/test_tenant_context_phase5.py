from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app import queue
from app.main import app
from app.request_context import tenant_id_ctx


class _DummyRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def xadd(self, stream: str, msg: dict[str, str], maxlen: int):
        self.calls.append((stream, msg, maxlen))
        return "1-0"


def test_platform_tenant_context_reflects_header():
    c = TestClient(app)
    r = c.get("/platform/tenant-context", headers={"x-tenant-id": "acme"})
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == "acme"


def test_queue_envelope_uses_tenant_context_for_org_id(monkeypatch):
    dummy = _DummyRedis()
    monkeypatch.setattr(queue, "_client", lambda: dummy)
    token = tenant_id_ctx.set("tenant-blue")
    try:
        ok = queue.publish_notify(["asset-1"], trace_id="trace-1")
    finally:
        tenant_id_ctx.reset(token)
    assert ok is True
    assert len(dummy.calls) == 1
    _stream, msg, _maxlen = dummy.calls[0]
    assert msg["org_id"] == "tenant-blue"
    payload = json.loads(msg["payload"])
    assert payload["type"] == "down_assets"


def test_db_enforces_tenant_isolation_via_rls():
    migration_path = (
        Path(__file__).resolve().parents[3]
        / "infra"
        / "postgres"
        / "migrations"
        / "026_tenant_enforcement.sql"
    )
    sql = migration_path.read_text(encoding="utf-8")
    assert "ALTER TABLE assets ADD COLUMN IF NOT EXISTS org_id TEXT;" in sql
    assert "ALTER TABLE assets ENABLE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE assets FORCE ROW LEVEL SECURITY;" in sql
    assert "CREATE POLICY secplat_tenant_assets" in sql
    assert "org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default')" in sql
