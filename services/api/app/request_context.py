"""Context vars for request-scoped data (e.g. request_id) so routers can use in audit logs."""
from contextvars import ContextVar

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
