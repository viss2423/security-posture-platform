"""
secplat-deriver (Phase 2.1): Read secplat-events, derive posture per asset, write to secplat-asset-status.
Replaces build_asset_status.sh. Runs in a loop (e.g. every 60s).
"""

import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

import httpx

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("deriver")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")
ASSETS_INDEX = os.environ.get("ASSETS_INDEX", "secplat-assets")
EVENTS_INDEX = os.environ.get("EVENTS_INDEX", "secplat-events")
STATUS_INDEX = os.environ.get("STATUS_INDEX", "secplat-asset-status")
STALE_THRESHOLD_SECONDS = int(os.environ.get("STALE_THRESHOLD_SECONDS", "300"))
DERIVER_INTERVAL_SECONDS = int(os.environ.get("DERIVER_INTERVAL_SECONDS", "60"))


def _get(path: str, **kwargs: Any) -> dict:
    url = f"{OPENSEARCH_URL}{path}"
    with httpx.Client(timeout=30.0) as client:
        r = client.get(url, **kwargs)
        r.raise_for_status()
        return r.json()


def _put(path: str, json: dict) -> dict:
    url = f"{OPENSEARCH_URL}{path}"
    with httpx.Client(timeout=30.0) as client:
        r = client.put(url, json=json)
        r.raise_for_status()
        return r.json()


def _post(path: str, json: dict | None = None) -> dict:
    url = f"{OPENSEARCH_URL}{path}"
    with httpx.Client(timeout=30.0) as client:
        r = client.post(url, json=json or {})
        r.raise_for_status()
        return r.json()


def ensure_status_index() -> None:
    try:
        _get(f"/{STATUS_INDEX}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            raise
        logger.info("creating index %s", STATUS_INDEX)
        _put(
            f"/{STATUS_INDEX}",
            {
                "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "asset_key": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "environment": {"type": "keyword"},
                        "criticality": {"type": "integer"},
                        "owner": {"type": "keyword"},
                        "owner_team": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "status_num": {"type": "integer"},
                        "code": {"type": "integer"},
                        "latency_ms": {"type": "integer"},
                        "last_seen": {"type": "date"},
                        "source_event_timestamp": {"type": "date"},
                        "staleness_seconds": {"type": "integer"},
                        "posture_score": {"type": "integer"},
                        "posture_state": {"type": "keyword"},
                        "last_status_change": {"type": "date"},
                    }
                },
            },
        )


def fetch_assets() -> list[dict]:
    body = {"size": 1000, "query": {"match_all": {}}}
    data = _post(f"/{ASSETS_INDEX}/_search", json=body)
    hits = data.get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def fetch_latest_health_event(asset_key: str) -> dict | None:
    body = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [{"term": {"level": "health"}}],
                "should": [
                    {"term": {"asset.keyword": asset_key}},
                    {"match": {"asset": asset_key}},
                    {"term": {"service.keyword": asset_key}},
                    {"match": {"service": asset_key}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    data = _post(f"/{EVENTS_INDEX}/_search", json=body)
    hits = data.get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else None


def fetch_example_com_event() -> dict | None:
    body = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"level": "health"}},
                    {"term": {"asset.keyword": "example-com"}},
                ]
            }
        },
    }
    data = _post(f"/{EVENTS_INDEX}/_search", json=body)
    hits = data.get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else None


def get_prev_status(asset_key: str) -> tuple[str | None, str | None]:
    try:
        data = _get(f"/{STATUS_INDEX}/_doc/{asset_key}")
        if data.get("found"):
            src = data.get("_source", {})
            return (
                str(src.get("status_num")) if src.get("status_num") is not None else None,
                src.get("last_status_change"),
            )
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            raise
    return (None, None)


def iso_to_epoch(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        return None


def run_derivation() -> None:
    now = datetime.now(UTC)
    now_iso = now.isoformat().replace("+00:00", "Z")
    now_epoch = int(now.timestamp())

    assets = fetch_assets()
    logger.info("deriving status for %d assets", len(assets))

    example_com_event = fetch_example_com_event()
    example_com_down_recent = False
    if example_com_event:
        st = example_com_event.get("status")
        ts = example_com_event.get("@timestamp")
        ep = iso_to_epoch(ts)
        if st == "down" and ep:
            if (now_epoch - ep) < STALE_THRESHOLD_SECONDS * 2:
                example_com_down_recent = True

    for asset in assets:
        asset_key = asset.get("asset_key") or ""
        if not asset_key:
            continue
        name = asset.get("name") or ""
        atype = asset.get("type") or ""
        env = asset.get("environment") or "dev"
        crit = asset.get("criticality", 3)
        if isinstance(crit, str):
            try:
                crit = int(crit)
            except ValueError:
                crit = 3
        owner = asset.get("owner") or ""
        owner_team = asset.get("owner_team") or ""

        event = fetch_latest_health_event(asset_key)
        status = "unknown"
        status_num = -1
        code = None
        latency_ms = None
        last_seen = None
        event_ts = None
        last_seen_epoch = None

        if event:
            raw_status = event.get("status", "unknown")
            code = event.get("code")
            latency_ms = event.get("latency_ms")
            last_seen = event.get("@timestamp")
            event_ts = last_seen
            last_seen_epoch = iso_to_epoch(last_seen)

            if last_seen_epoch is not None:
                age = now_epoch - last_seen_epoch
                if age > STALE_THRESHOLD_SECONDS:
                    status = "stale"
                    status_num = 0
                    if asset_key == "juice-shop" and example_com_down_recent:
                        status = "down"
                        status_num = -2
                else:
                    if code == 200 or raw_status == "up":
                        status = "up"
                        status_num = 1
                    else:
                        status = "down"
                        status_num = -2
            else:
                status = "unknown"
                status_num = -1

        staleness_seconds = (now_epoch - last_seen_epoch) if last_seen_epoch else 0
        posture_score = 100
        posture_state = "green"
        if status_num == -2 or status_num == -1:
            posture_score = 0
            posture_state = "red"
        elif staleness_seconds > 300:
            posture_score = 60
            posture_state = "amber"

        prev_status_num, prev_last_change = get_prev_status(asset_key)
        last_status_change = prev_last_change or last_seen
        if prev_status_num is not None and str(status_num) != prev_status_num:
            last_status_change = last_seen

        doc = {
            "@timestamp": now_iso,
            "asset_key": asset_key,
            "name": name,
            "type": atype,
            "environment": env,
            "criticality": crit,
            "owner": owner,
            "owner_team": owner_team,
            "status": status,
            "status_num": status_num,
            "code": code,
            "latency_ms": latency_ms,
            "last_seen": last_seen,
            "source_event_timestamp": event_ts,
            "staleness_seconds": staleness_seconds,
            "posture_score": posture_score,
            "posture_state": posture_state,
            "last_status_change": last_status_change,
        }
        try:
            _put(f"/{STATUS_INDEX}/_doc/{asset_key}", doc)
        except Exception as e:
            logger.warning("upsert %s failed: %s", asset_key, e)
    try:
        _post(f"/{STATUS_INDEX}/_refresh")
    except Exception as e:
        logger.warning("refresh failed: %s", e)
    logger.info("derivation done")


def main() -> None:
    logger.info(
        "secplat-deriver started. OPENSEARCH_URL=%s interval=%ss",
        OPENSEARCH_URL,
        DERIVER_INTERVAL_SECONDS,
    )
    ensure_status_index()
    while True:
        try:
            run_derivation()
        except Exception as e:
            logger.exception("derivation error: %s", e)
        time.sleep(DERIVER_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
