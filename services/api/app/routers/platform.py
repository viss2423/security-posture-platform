"""Platform stability contract and release gate endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.demo_seed import get_cyberlab_demo_status, reset_cyberlab_demo, run_cyberlab_auto_seed
from app.readiness import build_readiness_contract
from app.release_policy import build_upgrade_policy_contract
from app.request_context import tenant_id_ctx
from app.routers.auth import require_auth, require_role
from app.routers.posture import _reset_posture_cache
from app.settings import settings
from app.stability import (
    build_stability_contract,
    capture_api_runtime_snapshot,
    durable_api_snapshot,
    evaluate_release_gate,
    latest_sli_sample,
    materialize_sli_sample,
    persist_sli_sample,
    sample_measurements,
    sample_needs_refresh,
)

router = APIRouter(prefix="/platform", tags=["platform"])
_DURABLE_SAMPLE_PREFIX = "platform_"
_DURABLE_EXCLUDED_SUFFIXES = ("_override",)


class ReleaseGateEvaluateRequest(BaseModel):
    measurements: dict[str, Any] = Field(default_factory=dict)
    strict_missing: bool = True
    window_days: int | None = None


class DemoSeedRequest(BaseModel):
    force: bool = False


@router.get("/stability-contract")
def get_stability_contract() -> dict[str, Any]:
    return build_stability_contract()


@router.get("/upgrade-policy")
def get_upgrade_policy_contract() -> dict[str, Any]:
    return build_upgrade_policy_contract()


@router.get("/tenant-context")
def tenant_context() -> dict[str, Any]:
    return {
        "mode": str(getattr(settings, "TENANCY_MODE", "single") or "single"),
        "tenant_id": tenant_id_ctx.get("default"),
        "default_tenant_id": str(getattr(settings, "DEFAULT_TENANT_ID", "default") or "default"),
        "require_tenant_header": bool(getattr(settings, "REQUIRE_TENANT_HEADER", False)),
    }


@router.get("/recovery-contract")
def recovery_contract() -> dict[str, Any]:
    return {
        "rpo_hours": int(getattr(settings, "BACKUP_TARGET_RPO_HOURS", 24)),
        "rto_hours": int(getattr(settings, "BACKUP_TARGET_RTO_HOURS", 4)),
        "verification": {
            "script": "services/api/scripts/verify_backup_restore.py",
            "supports_dry_run": True,
            "supports_non_dry_run": True,
        },
        "controls": [
            "scheduled backups",
            "restore verification reports",
            "retention policy enforcement",
        ],
    }


@router.get("/readiness-contract")
def readiness_contract() -> dict[str, Any]:
    return build_readiness_contract()


@router.get("/demo/status")
def demo_status(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
) -> dict[str, Any]:
    return get_cyberlab_demo_status(db)


@router.post("/demo/seed")
def seed_demo_environment(
    body: DemoSeedRequest,
    user: str = Depends(require_role(["admin"])),
) -> dict[str, Any]:
    return {
        "requested_by": user,
        "result": run_cyberlab_auto_seed(
            force=bool(body.force),
            tenant_id=tenant_id_ctx.get("default"),
        ),
    }


@router.post("/demo/reset")
def reset_demo_environment(
    user: str = Depends(require_role(["admin"])),
) -> dict[str, Any]:
    result = reset_cyberlab_demo(tenant_id=tenant_id_ctx.get("default"))
    _reset_posture_cache()
    result["requested_by"] = user
    return result


@router.post("/release-gate/evaluate")
def evaluate_release_gate_endpoint(body: ReleaseGateEvaluateRequest) -> dict[str, Any]:
    return evaluate_release_gate(
        dict(body.measurements),
        strict_missing=body.strict_missing,
        window_days=body.window_days,
    )


@router.get("/sli/current")
def current_sli_snapshot(
    lookback_hours: int | None = Query(None, ge=1, le=720),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    capture_api_runtime_snapshot(db, source="platform_sli_current_capture")
    api_snapshot = durable_api_snapshot(db)
    sample = latest_sli_sample(
        db,
        source_prefix=_DURABLE_SAMPLE_PREFIX,
        exclude_suffixes=_DURABLE_EXCLUDED_SUFFIXES,
    )
    if sample_needs_refresh(sample, lookback_hours=lookback_hours):
        api_snapshot, measurements, sample = materialize_sli_sample(
            db,
            lookback_hours=lookback_hours,
            source="platform_sli_current",
        )
    else:
        measurements = sample_measurements(sample)
    return {
        "api": api_snapshot,
        "measurements": measurements,
        "sample": sample,
    }


@router.get("/release-gate/current")
def evaluate_current_release_gate(
    lookback_hours: int | None = Query(None, ge=1, le=720),
    ingestion_visibility_seconds: float | None = Query(None),
    alert_creation_seconds: float | None = Query(None),
    background_job_freshness_minutes: float | None = Query(None),
    strict_missing: bool = Query(False),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    capture_api_runtime_snapshot(db, source="platform_release_gate_capture")
    durable_required = bool(getattr(settings, "DURABLE_SLI_REQUIRED", False))
    api_snapshot, measurements, sample = materialize_sli_sample(
        db,
        lookback_hours=lookback_hours,
        source="platform_release_gate_current",
    )
    if durable_required and any(
        value is not None
        for value in (
            ingestion_visibility_seconds,
            alert_creation_seconds,
            background_job_freshness_minutes,
        )
    ):
        return {
            "gate_passed": False,
            "action": "release_blocked",
            "error_budget_exhausted": False,
            "strict_missing": True,
            "message": "override parameters are disabled when durable SLI evidence is required",
            "api_snapshot": api_snapshot,
            "measurements": measurements,
            "sample": sample,
            "latest_sample": latest_sli_sample(
                db,
                source_prefix=_DURABLE_SAMPLE_PREFIX,
                exclude_suffixes=_DURABLE_EXCLUDED_SUFFIXES,
            ),
        }
    if not durable_required:
        if ingestion_visibility_seconds is not None:
            measurements["ingestion_visibility_seconds"] = float(ingestion_visibility_seconds)
        if alert_creation_seconds is not None:
            measurements["alert_creation_seconds"] = float(alert_creation_seconds)
        if background_job_freshness_minutes is not None:
            measurements["background_job_freshness_minutes"] = float(
                background_job_freshness_minutes
            )
        if any(
            value is not None
            for value in (
                ingestion_visibility_seconds,
                alert_creation_seconds,
                background_job_freshness_minutes,
            )
        ):
            sample = persist_sli_sample(
                db,
                measurements=measurements,
                lookback_hours=lookback_hours,
                source="platform_release_gate_current_override",
            )
    out = evaluate_release_gate(
        sample,
        strict_missing=True if durable_required else strict_missing,
    )
    out["api_snapshot"] = api_snapshot
    out["measurements"] = measurements
    out["sample"] = sample
    out["latest_sample"] = latest_sli_sample(
        db,
        source_prefix=_DURABLE_SAMPLE_PREFIX,
        exclude_suffixes=_DURABLE_EXCLUDED_SUFFIXES,
    )
    return out
