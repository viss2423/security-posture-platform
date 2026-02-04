"""Posture API: read current asset posture from OpenSearch secplat-asset-status."""

from fastapi import APIRouter, HTTPException
import httpx
from app.settings import settings

router = APIRouter(prefix="/posture", tags=["posture"])

STATUS_INDEX = "secplat-asset-status"


def _opensearch_get(path: str):
    url = f"{settings.OPENSEARCH_URL.rstrip('/')}/{STATUS_INDEX}{path}"
    with httpx.Client(timeout=10.0) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.json()


def _opensearch_post(path: str, json: dict):
    url = f"{settings.OPENSEARCH_URL.rstrip('/')}/{STATUS_INDEX}{path}"
    with httpx.Client(timeout=10.0) as client:
        r = client.post(url, json=json)
        r.raise_for_status()
        return r.json()


@router.get("")
def list_posture():
    """List current posture for all assets (from secplat-asset-status)."""
    try:
        body = {
            "size": 1000,
            "query": {"match_all": {}},
            "sort": [{"status_num": "desc"}, {"posture_score": "asc"}],
        }
        data = _opensearch_get("/_search", json=body)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e!s}")

    hits = data.get("hits", {})
    total = hits.get("total", {})
    if isinstance(total, dict):
        total = total.get("value", 0)
    items = [h["_source"] for h in hits.get("hits", [])]
    return {"total": total, "items": items}


@router.get("/summary")
def posture_summary():
    """Summary counts: green, amber, red, and overall score (mean)."""
    try:
        body = {
            "size": 0,
            "aggs": {
                "by_state": {"terms": {"field": "posture_state", "size": 10}},
                "avg_score": {"avg": {"field": "posture_score"}},
            },
        }
        data = _opensearch_post("/_search", body)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e!s}")

    aggs = data.get("aggregations", {})
    by_state = {b["key"]: b["doc_count"] for b in aggs.get("by_state", {}).get("buckets", [])}
    avg_score = aggs.get("avg_score", {}).get("value")
    return {
        "green": by_state.get("green", 0),
        "amber": by_state.get("amber", 0),
        "red": by_state.get("red", 0),
        "posture_score_avg": round(avg_score, 1) if avg_score is not None else None,
    }


@router.get("/{asset_key}")
def get_posture(asset_key: str):
    """Get current posture for one asset by asset_key."""
    try:
        data = _opensearch_get(f"/_doc/{asset_key}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Asset not found in posture index")
        raise HTTPException(status_code=502, detail=f"OpenSearch error: {e.response.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OpenSearch unreachable: {e!s}")

    if not data.get("found"):
        raise HTTPException(status_code=404, detail="Asset not found in posture index")
    return data.get("_source", {})
