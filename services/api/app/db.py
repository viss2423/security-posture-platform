import time

from sqlalchemy import create_engine, text
from sqlalchemy import event as sa_event
from sqlalchemy.orm import sessionmaker

from .otel import start_span
from .request_context import tenant_id_ctx
from .settings import settings

engine = create_engine(settings.POSTGRES_DSN, pool_pre_ping=True)
_migrations_dsn = str(getattr(settings, "MIGRATIONS_POSTGRES_DSN", "") or "").strip()
if _migrations_dsn and _migrations_dsn != settings.POSTGRES_DSN:
    migration_engine = create_engine(_migrations_dsn, pool_pre_ping=True)
else:
    migration_engine = engine
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

_SPAN_KEY = "_secplat_span"
_SPAN_CM_KEY = "_secplat_span_cm"
_SPAN_STARTED_KEY = "_secplat_span_started_at"


def _active_tenant_id() -> str:
    return (tenant_id_ctx.get("default") or "default").strip() or "default"


def bind_tenant_context(db) -> str:
    tenant_id = _active_tenant_id()
    conn = db.connection()
    db.execute(
        text("SELECT set_config('secplat.tenant_id', :tenant_id, false)"), {"tenant_id": tenant_id}
    )
    conn.info["secplat.tenant_id"] = tenant_id
    return tenant_id


def _statement_preview(statement: str | None) -> str:
    compact = " ".join(str(statement or "").split())
    return compact[:512]


def _close_span(context: object, exc: BaseException | None = None) -> None:
    span = getattr(context, _SPAN_KEY, None)
    span_cm = getattr(context, _SPAN_CM_KEY, None)
    started = getattr(context, _SPAN_STARTED_KEY, None)
    if span is not None and started is not None:
        span.set_attribute("db.client.duration_ms", round((time.monotonic() - started) * 1000.0, 3))
        if exc is not None and isinstance(exc, Exception):
            span.record_exception(exc)
            span.set_attribute("db.error", True)
    if span_cm is not None:
        if exc is not None:
            span_cm.__exit__(type(exc), exc, exc.__traceback__)
        else:
            span_cm.__exit__(None, None, None)
    for key in (_SPAN_KEY, _SPAN_CM_KEY, _SPAN_STARTED_KEY):
        if hasattr(context, key):
            delattr(context, key)


@sa_event.listens_for(engine.pool, "checkout")
def _checkout_connection(
    dbapi_connection, connection_record, connection_proxy
):  # pragma: no cover - integration path
    connection_record.info.pop("secplat.tenant_id", None)


@sa_event.listens_for(engine, "before_cursor_execute")
def _before_cursor_execute(
    conn, cursor, statement, parameters, context, executemany
):  # pragma: no cover - integration path
    tenant_id = _active_tenant_id()
    try:
        if conn.info.get("secplat.tenant_id") != tenant_id:
            # Use a session-level GUC so tenant context survives commit boundaries.
            cursor.execute("SELECT set_config('secplat.tenant_id', %s, false)", (tenant_id,))
            conn.info["secplat.tenant_id"] = tenant_id
    except Exception:
        # Best-effort only; queries still run without tenant GUC on non-Postgres drivers.
        pass
    span_cm = start_span(
        "db.query",
        attributes={
            "db.system": "postgresql",
            "db.operation": str(statement or "").strip().split(" ", 1)[0].upper(),
            "db.statement": _statement_preview(statement),
            "db.sqlalchemy.executemany": bool(executemany),
            "secplat.tenant_id": tenant_id,
        },
    )
    span = span_cm.__enter__()
    setattr(context, _SPAN_KEY, span)
    setattr(context, _SPAN_CM_KEY, span_cm)
    setattr(context, _SPAN_STARTED_KEY, time.monotonic())


@sa_event.listens_for(engine, "after_cursor_execute")
def _after_cursor_execute(
    conn, cursor, statement, parameters, context, executemany
):  # pragma: no cover - integration path
    span = getattr(context, _SPAN_KEY, None)
    if span is not None and hasattr(cursor, "rowcount"):
        try:
            span.set_attribute("db.response.row_count", int(cursor.rowcount))
        except Exception:
            pass
    _close_span(context)


@sa_event.listens_for(engine, "handle_error")
def _handle_error(exception_context):  # pragma: no cover - integration path
    context = getattr(exception_context, "execution_context", None)
    if context is None:
        return
    _close_span(context, getattr(exception_context, "original_exception", None))


def get_db():
    db = SessionLocal()
    try:
        bind_tenant_context(db)
        yield db
    finally:
        db.close()
