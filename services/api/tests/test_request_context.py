from __future__ import annotations

from app.request_context import current_tenant_id, tenant_id_ctx


def test_current_tenant_id_defaults_to_default():
    assert current_tenant_id() == "default"


def test_current_tenant_id_uses_context_value():
    token = tenant_id_ctx.set("tenant-blue")
    try:
        assert current_tenant_id() == "tenant-blue"
    finally:
        tenant_id_ctx.reset(token)
