import asyncio
import logging
import uuid

from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .routers import health, assets, jobs, findings, posture, auth, retention, audit as audit_router, alerts, incidents
from . import metrics
from .db_migrate import run_startup_migrations
from .logging_config import configure_logging
from .request_context import request_id_ctx

configure_logging()
logger = logging.getLogger("secplat")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure audit_events + alert_states exist (e.g. existing DB from before those tables were in init.sql)
    await asyncio.to_thread(run_startup_migrations)
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
