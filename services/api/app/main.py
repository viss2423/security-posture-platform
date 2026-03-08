import asyncio
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from . import metrics
from .db_migrate import run_startup_migrations
from .demo_seed import maybe_seed_cyberlab_demo
from .errors import register_error_handlers
from .logging_config import configure_logging
from .request_context import request_id_ctx
from .routers import (
    ai,
    ai_feedback,
    alerts,
    automation,
    assets,
    attack_surface,
    attack_graph,
    attack_lab,
    auth,
    cyber_range,
    detections,
    findings,
    health,
    incidents,
    integrations,
    jobs,
    policy,
    posture,
    retention,
    risk,
    risk_ml,
    suppression,
    telemetry,
    threat_intel,
)
from .routers import audit as audit_router
from .settings import settings
from .telemetry import (
    enqueue_network_anomaly_job,
    enqueue_telemetry_import_job,
    ensure_recent_telemetry_activity,
)

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


async def _scheduled_network_anomaly_loop():
    """Background loop: enqueue anomaly scoring on a fixed interval."""
    if not getattr(settings, "ENABLE_SCHEDULED_NETWORK_ANOMALY", True):
        return
    interval_sec = max(
        300,
        int(getattr(settings, "SCHEDULED_NETWORK_ANOMALY_INTERVAL_MINUTES", 60) * 60),
    )
    await asyncio.sleep(90)
    while True:
        try:
            job_id = await asyncio.to_thread(
                enqueue_network_anomaly_job,
                requested_by="system-scheduler",
                lookback_hours=int(getattr(settings, "TELEMETRY_DEFAULT_LOOKBACK_HOURS", 24)),
                threshold=float(getattr(settings, "NETWORK_ANOMALY_THRESHOLD", 2.5)),
            )
            logger.info("scheduled_network_anomaly queued job_id=%s", job_id)
        except Exception as e:
            logger.exception("scheduled_network_anomaly failed: %s", e)
        await asyncio.sleep(interval_sec)


def _scheduled_telemetry_sources() -> list[str]:
    raw = str(getattr(settings, "TELEMETRY_SCHEDULED_SOURCES", "") or "").strip()
    parsed: list[str] = []
    for part in raw.split(","):
        candidate = part.strip().lower()
        if (
            candidate in {"suricata", "zeek", "auditd", "authlog", "cowrie", "custom"}
            and candidate not in parsed
        ):
            parsed.append(candidate)
    return parsed or ["suricata", "zeek", "auditd", "cowrie"]


async def _scheduled_telemetry_import_loop():
    """Background loop: continuously import telemetry logs from configured source files."""
    if not getattr(settings, "ENABLE_SCHEDULED_TELEMETRY_IMPORT", False):
        return
    interval_sec = max(
        60,
        int(getattr(settings, "SCHEDULED_TELEMETRY_IMPORT_INTERVAL_SECONDS", 300)),
    )
    await asyncio.sleep(45)
    while True:
        for source in _scheduled_telemetry_sources():
            try:
                job_id = await asyncio.to_thread(
                    enqueue_telemetry_import_job,
                    source=source,
                    requested_by="system-scheduler",
                    create_alerts=True,
                    skip_if_running=True,
                )
                if job_id:
                    logger.info(
                        "scheduled_telemetry_import queued source=%s job_id=%s",
                        source,
                        job_id,
                    )
            except Exception as e:
                logger.exception("scheduled_telemetry_import failed source=%s error=%s", source, e)
        await asyncio.sleep(interval_sec)


async def _scheduled_telemetry_keepalive_loop():
    """Background loop: inject low-volume telemetry when a source is quiet."""
    if not getattr(settings, "ENABLE_TELEMETRY_KEEPALIVE", True):
        return
    interval_sec = max(
        30,
        int(getattr(settings, "TELEMETRY_KEEPALIVE_INTERVAL_SECONDS", 120)),
    )
    max_silence_minutes = max(
        1,
        int(getattr(settings, "TELEMETRY_KEEPALIVE_MAX_SILENCE_MINUTES", 3)),
    )
    create_alerts = bool(getattr(settings, "TELEMETRY_KEEPALIVE_CREATE_ALERTS", False))
    default_asset_key = str(getattr(settings, "TELEMETRY_KEEPALIVE_ASSET_KEY", "") or "").strip()
    if not default_asset_key:
        default_asset_key = str(getattr(settings, "CYBERLAB_DEMO_ASSET_KEY", "") or "").strip()
    await asyncio.sleep(60)
    while True:
        try:
            result = await asyncio.to_thread(
                ensure_recent_telemetry_activity,
                sources=_scheduled_telemetry_sources(),
                max_silence_minutes=max_silence_minutes,
                asset_key=default_asset_key or None,
                create_alerts=create_alerts,
            )
            injected_events = int(result.get("injected_events") or 0)
            if injected_events > 0:
                logger.info(
                    "scheduled_telemetry_keepalive injected=%s by_source=%s",
                    injected_events,
                    result.get("injected_by_source") or {},
                )
        except Exception as e:
            logger.exception("scheduled_telemetry_keepalive failed: %s", e)
        await asyncio.sleep(interval_sec)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure audit_events + alert_states exist (e.g. existing DB from before those tables were in init.sql)
    await asyncio.to_thread(run_startup_migrations)
    await asyncio.to_thread(maybe_seed_cyberlab_demo)
    asyncio.create_task(_scheduled_snapshot_loop())
    asyncio.create_task(_scheduled_network_anomaly_loop())
    asyncio.create_task(_scheduled_telemetry_import_loop())
    asyncio.create_task(_scheduled_telemetry_keepalive_loop())
    yield


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        token = request_id_ctx.set(request_id)
        try:
            response = await call_next(request)
            logger.info(
                "http_request",
                extra={
                    "action": "http_request",
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                },
            )
            response.headers["x-request-id"] = request_id
            return response
        finally:
            request_id_ctx.reset(token)


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        metrics.record_request(request.method, request.url.path, response.status_code)
        return response


app = FastAPI(title="Security Posture Platform API", lifespan=lifespan)
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestLogMiddleware)
register_error_handlers(app)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(posture.router)
app.include_router(retention.router)
app.include_router(audit_router.router)
app.include_router(alerts.router)
app.include_router(automation.router)
app.include_router(attack_surface.router)
app.include_router(attack_graph.router)
app.include_router(incidents.router)
app.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
app.include_router(findings.router, prefix="/findings", tags=["findings"])
app.include_router(policy.router)
app.include_router(integrations.router)
app.include_router(suppression.router)
app.include_router(threat_intel.router)
app.include_router(telemetry.router)
app.include_router(risk.router)
app.include_router(attack_lab.router)
app.include_router(cyber_range.router)
app.include_router(detections.router)
app.include_router(ai.router)
app.include_router(ai_feedback.router)
app.include_router(risk_ml.router)
