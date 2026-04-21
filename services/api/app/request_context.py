"""Context vars for request-scoped data (e.g. request_id) so routers can use in audit logs."""

from contextvars import ContextVar

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
tenant_id_ctx: ContextVar[str] = ContextVar("tenant_id", default="default")


def current_tenant_id() -> str:
    return (tenant_id_ctx.get("default") or "default").strip() or "default"
