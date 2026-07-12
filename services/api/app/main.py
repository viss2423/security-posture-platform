import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import metrics
from .db import SessionLocal
from .db_migrate import run_startup_migrations
from .demo_seed import maybe_seed_cyberlab_demo
from .errors import register_error_handlers
from .logging_config import configure_logging
from .otel import configure_otel, start_span
from .request_context import request_id_ctx, tenant_id_ctx
from .routers import (
    ai,
    ai_feedback,
    alerts,
    assets,
    attack_graph,
    attack_lab,
    attack_surface,
    auth,
    automation,
    compliance,
    cyber_range,
    detections,
    findings,
    health,
    incidents,
    integrations,
    jobs,
    platform,
    policy,
    posture,
    privacy,
    retention,
    risk,
    risk_ml,
    security,
    suppression,
    telemetry,
    threat_intel,
    workspace,
)
from .routers import audit as audit_router
from .routers.auth import decode_token_payload, require_role
from .settings import settings
from .stability import capture_api_runtime_snapshot, materialize_sli_sample
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


def _materialize_platform_sli_sample() -> None:
    db = SessionLocal()
    try:
        capture_api_runtime_snapshot(db, source="platform_runtime_loop_capture")
        materialize_sli_sample(
            db,
            source="platform_runtime_loop",
        )
    finally:
        db.close()


async def _scheduled_sli_materialization_loop():
    interval_sec = max(
        15,
        int(getattr(settings, "PLATFORM_SLI_MATERIALIZATION_INTERVAL_SECONDS", 60)),
    )
    await asyncio.sleep(min(interval_sec, 15))
    while True:
        try:
            await asyncio.to_thread(_materialize_platform_sli_sample)
            logger.info("scheduled_sli_materialization completed")
        except Exception as e:
            logger.exception("scheduled_sli_materialization failed: %s", e)
        await asyncio.sleep(interval_sec)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_otel(service_name="secplat-api")
    # Ensure audit_events + alert_states exist (e.g. existing DB from before those tables were in init.sql)
    await asyncio.to_thread(run_startup_migrations)
    await asyncio.to_thread(maybe_seed_cyberlab_demo)
    tasks = [
        asyncio.create_task(_scheduled_snapshot_loop()),
        asyncio.create_task(_scheduled_network_anomaly_loop()),
        asyncio.create_task(_scheduled_telemetry_import_loop()),
        asyncio.create_task(_scheduled_telemetry_keepalive_loop()),
        asyncio.create_task(_scheduled_sli_materialization_loop()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        header_tenant = (request.headers.get("x-tenant-id") or "").strip()
        mode = str(getattr(settings, "TENANCY_MODE", "single") or "single").strip().lower()
        default_tenant = str(getattr(settings, "DEFAULT_TENANT_ID", "default") or "default").strip()
        # A signed `ws` (workspace) claim pins the tenant for self-serve workspace users
        # and is authoritative over any client-supplied x-tenant-id header — the header
        # must never let a workspace user read another tenant's rows. Operator/admin
        # tokens carry no `ws` claim and keep the existing header-or-default behavior.
        workspace_tenant = _workspace_tenant_from_request(request)
        if workspace_tenant:
            tenant_id = workspace_tenant
        else:
            tenant_id = header_tenant or default_tenant
            if (
                mode == "multi"
                and getattr(settings, "REQUIRE_TENANT_HEADER", False)
                and not header_tenant
            ):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "x-tenant-id header required in multi-tenant mode"},
                )
        token = request_id_ctx.set(request_id)
        tenant_token = tenant_id_ctx.set(tenant_id)
        started = time.monotonic()
        try:
            with start_span(
                "http.server.request",
                attributes={
                    "http.request.method": request.method,
                    "http.route": request.url.path,
                    "url.path": request.url.path,
                    "secplat.request_id": request_id,
                    "secplat.tenant_id": tenant_id,
                },
                context_carrier=dict(request.headers),
            ) as span:
                response = await call_next(request)
                span.set_attribute("http.response.status_code", response.status_code)
            latency_ms = round((time.monotonic() - started) * 1000.0, 3)
            logger.info(
                "http_request",
                extra={
                    "action": "http_request",
                    "request_id": request_id,
                    "trace_id": request_id,
                    "tenant_id": tenant_id,
                    "http.method": request.method,
                    "url.path": request.url.path,
                    "http.status_code": response.status_code,
                    "http.latency_ms": latency_ms,
                },
            )
            response.headers["x-request-id"] = request_id
            response.headers["x-tenant-id"] = tenant_id
            return response
        finally:
            request_id_ctx.reset(token)
            tenant_id_ctx.reset(tenant_token)


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - started) * 1000.0
        metrics.record_request(
            request.method,
            request.url.path,
            response.status_code,
            duration_ms=duration_ms,
        )
        return response


def _empty_viewer_telemetry_summary() -> dict:
    return {
        "totals": {
            "events": 0,
            "ti_matches": 0,
            "assets": 0,
            "sources": 0,
            "traceable_events": 0,
            "traceability_coverage_pct": 0.0,
            "ingest_lag_seconds_avg": None,
            "ingest_lag_seconds_p95": None,
            "ingest_lag_seconds_max": None,
        },
        "sources": [],
        "recent_alerts": [],
        "latest_anomaly_scores": [],
        "capabilities": {"viewer_scoped": True, "restricted": True},
    }


def _empty_viewer_compliance_evidence() -> dict:
    return {
        "report_id": "viewer",
        "generated_at": None,
        "source": "",
        "sources": [],
        "scan_ran": False,
        "frameworks": [],
        "scope": {
            "asset_count": 0,
            "total_findings": 0,
            "open_findings": 0,
            "remediated_findings": 0,
        },
        "score": {
            "pass": 0,
            "fail": 0,
            "not_applicable": 0,
            "percentage": None,
        },
        "controls": [],
        "capabilities": {"viewer_scoped": True, "restricted": True},
    }


_VIEWER_EMPTY_RESPONSES = {
    "/telemetry/summary": _empty_viewer_telemetry_summary,
    "/incidents": lambda: {
        "total": 0,
        "items": [],
        "capabilities": {"viewer_scoped": True, "restricted": True},
    },
    "/compliance/evidence": _empty_viewer_compliance_evidence,
    "/compliance/soc2/evidence": _empty_viewer_compliance_evidence,
    "/detections/rules": lambda: {
        "items": [],
        "capabilities": {"viewer_scoped": True, "restricted": True},
    },
    "/alerts": lambda: {
        "firing": [],
        "acked": [],
        "suppressed": [],
        "resolved": [],
        "capabilities": {"viewer_scoped": True, "restricted": True},
    },
}


def _viewer_role_from_request(request: Request) -> bool:
    auth_header = request.headers.get("authorization") or ""
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return False
    payload = decode_token_payload(token.strip())
    return bool(payload and (payload.get("role") or "admin").lower() == "viewer")


def _workspace_tenant_from_request(request: Request) -> str | None:
    """Return the signed `ws` (workspace tenant) claim from the bearer token, if any.

    decode_token_payload verifies the signature and expiry, so a client cannot forge
    or tamper with this value. Returns None for operator/admin tokens (no `ws` claim),
    leaving their tenant derivation unchanged.
    """
    auth_header = request.headers.get("authorization") or ""
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    payload = decode_token_payload(token.strip())
    if not payload:
        return None
    ws = payload.get("ws")
    if not isinstance(ws, str):
        return None
    ws = ws.strip()
    return ws or None


class ViewerReadOnlyFallbackMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        payload_factory = _VIEWER_EMPTY_RESPONSES.get(request.url.path.rstrip("/") or "/")
        if (
            request.method == "GET"
            and response.status_code == 403
            and payload_factory
            and _viewer_role_from_request(request)
        ):
            return JSONResponse(status_code=200, content=payload_factory())
        return response


app = FastAPI(title="Security Posture Platform API", lifespan=lifespan)
app.add_middleware(ViewerReadOnlyFallbackMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestLogMiddleware)
register_error_handlers(app)

# Routers below are mounted in two tiers:
#  - Open tier: available to every authenticated user (viewers get demo-scoped data
#    inside the endpoints themselves — see posture/assets/findings).
#  - Operator tier: the operator's real security data (alerts, incidents, telemetry,
#    jobs, audit, compliance evidence, ...). Gated to analyst/admin at mount time so
#    no individual endpoint inside these routers can be forgotten.
_operator_only = [Depends(require_role(["admin", "analyst"]))]

app.include_router(health.router)
app.include_router(platform.router)
app.include_router(security.router)
app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(posture.router)
# Open tier: self-serve users (viewers) must reach /workspace/connect to activate their
# workspace; the endpoint authenticates the caller and scopes writes to their own tenant.
app.include_router(workspace.router)
app.include_router(retention.router)
app.include_router(privacy.router)
app.include_router(audit_router.router, dependencies=_operator_only)
app.include_router(alerts.router, dependencies=_operator_only)
app.include_router(automation.router, dependencies=_operator_only)
app.include_router(attack_surface.router, dependencies=_operator_only)
app.include_router(attack_graph.router, dependencies=_operator_only)
app.include_router(incidents.router, dependencies=_operator_only)
app.include_router(jobs.router, prefix="/jobs", tags=["jobs"], dependencies=_operator_only)
app.include_router(jobs.internal_router)
app.include_router(findings.router, prefix="/findings", tags=["findings"])
app.include_router(policy.router, dependencies=_operator_only)
app.include_router(integrations.router, dependencies=_operator_only)
app.include_router(suppression.router, dependencies=_operator_only)
app.include_router(threat_intel.router, dependencies=_operator_only)
app.include_router(telemetry.router, dependencies=_operator_only)
app.include_router(risk.router, dependencies=_operator_only)
app.include_router(attack_lab.router, dependencies=_operator_only)
app.include_router(compliance.router, dependencies=_operator_only)
app.include_router(cyber_range.router, dependencies=_operator_only)
app.include_router(detections.router, dependencies=_operator_only)
app.include_router(ai.router, dependencies=_operator_only)
app.include_router(ai_feedback.router, dependencies=_operator_only)
app.include_router(risk_ml.router, dependencies=_operator_only)
