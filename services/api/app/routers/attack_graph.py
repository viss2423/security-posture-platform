"""Attack graph API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.attack_graph import build_asset_attack_graph, build_incident_attack_graph
from app.db import get_db
from app.routers.auth import require_auth

router = APIRouter(prefix="/attack-graph", tags=["attack-graph"])


@router.get("/incidents/{incident_id}")
def get_incident_attack_graph(
    incident_id: int,
    lookback_hours: int = 72,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    graph = build_incident_attack_graph(db, incident_id=incident_id, lookback_hours=lookback_hours)
    if not graph["nodes"]:
        raise HTTPException(status_code=404, detail="Incident graph not found")
    return graph


class AttackGraphQueryBody(BaseModel):
    incident_id: int | None = None
    asset_key: str | None = None
    lookback_hours: int = 72


@router.post("/query")
def query_attack_graph(
    body: AttackGraphQueryBody,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    lookback = max(1, min(int(body.lookback_hours), 720))
    if body.incident_id is not None:
        graph = build_incident_attack_graph(db, incident_id=int(body.incident_id), lookback_hours=lookback)
        if graph["nodes"]:
            return graph
    if body.asset_key:
        graph = build_asset_attack_graph(db, asset_key=str(body.asset_key), lookback_hours=lookback)
        if graph["nodes"]:
            return graph
    raise HTTPException(status_code=404, detail="No graph data found for query")

