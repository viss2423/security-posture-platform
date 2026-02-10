"""Liveness (/health), readiness (/ready), and metrics for load balancers and orchestrators."""
import httpx
from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from app.settings import settings
from app.db import engine
from app import metrics as metrics_module

router = APIRouter()


@router.get("/health")
def health():
    """Liveness: API process is up. No dependencies checked."""
    return {"status": "ok"}


@router.get("/ready")
def ready(response: Response):
    """
    Readiness: API can serve traffic. Checks Postgres and OpenSearch.
    Returns 503 if any dependency is down so the orchestrator can stop sending traffic.
    """
    out = {"status": "ok", "checks": {}}
    status = 200

    # Postgres
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        out["checks"]["postgres"] = "ok"
    except Exception as e:
        out["checks"]["postgres"] = str(e)
        status = 503

    # OpenSearch
    try:
        url = f"{settings.OPENSEARCH_URL.rstrip('/')}/_cluster/health"
        with httpx.Client(timeout=5.0) as client:
            r = client.get(url)
            r.raise_for_status()
        out["checks"]["opensearch"] = "ok"
    except Exception as e:
        out["checks"]["opensearch"] = str(e)
        status = 503

    if status != 200:
        out["status"] = "degraded"
        response.status_code = status
    return out


@router.get("/metrics", response_class=PlainTextResponse)
def metrics():
    """Prometheus text exposition format: http_requests_total, process_uptime_seconds."""
    return PlainTextResponse(
        metrics_module.format_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
