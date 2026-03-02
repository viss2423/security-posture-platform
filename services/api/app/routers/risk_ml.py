"""Risk-model lifecycle endpoints: status, tuning, snapshots, weak-label bootstrap, and training."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.request_context import request_id_ctx
from app.risk_scoring import backfill_finding_risk_scores
from app.risk_training import (
    bootstrap_risk_labels,
    create_risk_model_snapshot,
    evaluate_risk_model,
    get_risk_model_snapshot,
    get_risk_model_status,
    list_risk_model_snapshots,
    set_risk_model_threshold,
    train_risk_model_from_db,
)
from app.routers.auth import require_auth, require_role
from app.settings import settings

router = APIRouter(prefix="/ai/risk-scoring", tags=["ai"])


class TrainRiskModelBody(BaseModel):
    random_state: int = 42
    test_size: float = 0.25


class ThresholdBody(BaseModel):
    threshold: float
    source: str = "manual"


class SnapshotBody(BaseModel):
    threshold: float | None = None


@router.get("/status")
def get_status(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    return get_risk_model_status(db)


@router.get("/evaluation")
def get_evaluation(
    threshold: float | None = None,
    review_limit: int = 12,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    try:
        return evaluate_risk_model(
            db,
            threshold=threshold,
            review_limit=review_limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/snapshots")
def get_snapshots(
    limit: int = 20,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    return {"items": list_risk_model_snapshots(db, limit=limit)}


@router.get("/snapshots/{snapshot_id}")
def get_snapshot(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    payload = get_risk_model_snapshot(db, snapshot_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return payload


@router.post("/snapshots")
def create_snapshot(
    body: SnapshotBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    try:
        payload = create_risk_model_snapshot(
            db,
            actor=user,
            event_type="manual",
            threshold=body.threshold,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit(
        db,
        "risk_model_snapshot",
        user_name=user,
        details={
            "snapshot_id": payload["snapshot_id"],
            "threshold": payload["threshold"],
            "event_type": payload["event_type"],
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return payload


@router.post("/threshold")
def update_threshold(
    body: ThresholdBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    try:
        metadata = set_risk_model_threshold(
            threshold=body.threshold,
            actor=user,
            source=body.source or "manual",
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    rescored_findings = backfill_finding_risk_scores(db) if settings.RISK_MODEL_ENABLED else 0
    log_audit(
        db,
        "risk_model_threshold_update",
        user_name=user,
        details={
            "threshold": metadata.get("active_threshold"),
            "threshold_source": metadata.get("threshold_source"),
            "rescored_findings": rescored_findings,
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return {
        "active_threshold": metadata.get("active_threshold"),
        "recommended_threshold": metadata.get("recommended_threshold"),
        "threshold_source": metadata.get("threshold_source"),
        "rescored_findings": rescored_findings,
        "model_metadata": metadata,
    }


@router.post("/bootstrap-labels")
def bootstrap_labels(
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin", "analyst"])),
):
    out = bootstrap_risk_labels(db, actor=user)
    log_audit(
        db,
        "risk_model_bootstrap_labels",
        user_name=user,
        details={
            "inserted_positive": out["inserted_positive"],
            "inserted_negative": out["inserted_negative"],
            "inserted_total": out["inserted_total"],
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out


@router.post("/train")
def train_model(
    body: TrainRiskModelBody,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(["admin"])),
):
    try:
        out = train_risk_model_from_db(
            db,
            random_state=body.random_state,
            test_size=body.test_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rescored_findings = backfill_finding_risk_scores(db) if settings.RISK_MODEL_ENABLED else 0
    snapshot = create_risk_model_snapshot(
        db,
        actor=user,
        event_type="train",
        threshold=out["metadata"].get("active_threshold"),
    )
    out["rescored_findings"] = rescored_findings
    out["snapshot_id"] = snapshot["snapshot_id"]
    log_audit(
        db,
        "risk_model_train",
        user_name=user,
        details={
            "artifact_path": out["artifact_path"],
            "training_rows": out["training_rows"],
            "rescored_findings": rescored_findings,
            "snapshot_id": snapshot["snapshot_id"],
            "algorithm": out["metadata"].get("algorithm"),
            "test_auc": out["metadata"].get("test_auc"),
        },
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    return out
