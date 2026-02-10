import logging
import uuid

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .routers import health, assets, jobs, findings, posture, auth, retention
from . import metrics
from .logging_config import configure_logging
from .request_context import request_id_ctx

configure_logging()
logger = logging.getLogger("secplat")


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


app = FastAPI(title="Security Posture Platform API")
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestLogMiddleware)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(posture.router)
app.include_router(retention.router)
app.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
app.include_router(findings.router, prefix="/findings", tags=["findings"])
