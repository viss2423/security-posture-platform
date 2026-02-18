import asyncio
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from . import metrics
from .db_migrate import run_startup_migrations
from .logging_config import configure_logging
from .request_context import request_id_ctx
from .routers import (
    alerts,
    assets,
    auth,
    findings,
    health,
    incidents,
    integrations,
    jobs,
    policy,
    posture,
    retention,
    suppression,
)
from .routers import audit as audit_router
from .settings import settings

configure_logging()
logger = logging.getLogger("secplat")


async def _scheduled_snapshot_loop():
    """Background loop: save snapshot every N hours when ENABLE_SCHEDULED_SNAPSHOTS (Phase A.3)."""
    if not getattr(settings, "ENABLE_SCHEDULED_SNAPSHOTS", False):
        return
    interval_sec = max(60, int(getattr(settings, "SCHEDULED_SNAPSHOT_INTERVAL_HOURS", 24.0) * 3600))
    await asyncio.sleep(300)  # first run after 5 min
    while True:
        try:
            await asyncio.to_thread(posture.run_scheduled_snapshot)
            logger.info("scheduled_snapshot completed")
        except Exception as e:
            logger.exception("scheduled_snapshot failed: %s", e)
        await asyncio.sleep(interval_sec)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure audit_events + alert_states exist (e.g. existing DB from before those tables were in init.sql)
    await asyncio.to_thread(run_startup_migrations)
    asyncio.create_task(_scheduled_snapshot_loop())
    yield


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request_id_ctx.set(request_id)
        response = await call_next(request)
        logger.info(
            "request_id=%s method=%s path=%s status=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
        )
        response.headers["x-request-id"] = request_id
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        metrics.record_request(request.method, request.url.path, response.status_code)
        return response


app = FastAPI(title="Security Posture Platform API", lifespan=lifespan)
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestLogMiddleware)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(posture.router)
app.include_router(retention.router)
app.include_router(audit_router.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
app.include_router(findings.router, prefix="/findings", tags=["findings"])
app.include_router(policy.router)
app.include_router(integrations.router)
app.include_router(suppression.router)
