"""secplat-correlator: Phase 3.1. Consume secplat.events.correlation and create/update incidents via API."""

import json
import logging
import os
import time

import httpx
import redis

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("correlator")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
STREAM = "secplat.events.correlation"
GROUP = "correlators"
CONSUMER = os.environ.get("CORRELATOR_CONSUMER", "correlator-1")
API_URL = (os.environ.get("API_URL") or "http://api:8000").rstrip("/")
CORRELATOR_USER = os.environ.get("CORRELATOR_USER") or os.environ.get("ADMIN_USERNAME", "admin")
CORRELATOR_PASSWORD = os.environ.get("CORRELATOR_PASSWORD") or os.environ.get(
    "ADMIN_PASSWORD", "admin"
)
BLOCK_MS = 5000

_token: str | None = None


def get_token() -> str | None:
    global _token
    if _token:
        return _token
    try:
        r = httpx.post(
            f"{API_URL}/auth/login",
            data={"username": CORRELATOR_USER, "password": CORRELATOR_PASSWORD},
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json()
        _token = data.get("access_token")
        return _token
    except Exception as e:
        logger.warning("login failed: %s", e)
        return None


def create_incident(
    title: str, severity: str = "medium", asset_keys: list[str] | None = None
) -> dict | None:
    token = get_token()
    if not token:
        return None
    try:
        r = httpx.post(
            f"{API_URL}/incidents",
            json={"title": title, "severity": severity, "asset_keys": asset_keys or []},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning("create_incident failed: %s", e)
        return None


def handle_event(payload: dict, r: redis.Redis, mid: str) -> None:
    event_type = (payload.get("event_type") or "").strip()
    if not event_type:
        r.xack(STREAM, GROUP, mid)
        return

    if event_type == "finding.created":
        asset_key = (payload.get("asset_key") or "").strip()
        finding_key = (payload.get("finding_key") or "").strip()
        severity = (payload.get("severity") or "medium").strip() or "medium"
        logger.info(
            "processing event_type=finding.created asset_key=%s finding_key=%s",
            asset_key,
            finding_key,
        )
        if not asset_key:
            r.xack(STREAM, GROUP, mid)
            return
        title = f"Finding: {finding_key or 'unknown'} on {asset_key}"
        inc = create_incident(title=title, severity=severity, asset_keys=[asset_key])
        if inc:
            logger.info("created incident id=%s title=%s", inc.get("id"), title)
        else:
            logger.warning("failed to create incident for finding.created asset_key=%s", asset_key)
        r.xack(STREAM, GROUP, mid)
        return

    if event_type == "alert.triggered":
        raw = payload.get("down_assets")
        if isinstance(raw, str):
            try:
                down_assets = json.loads(raw)
            except json.JSONDecodeError:
                if raw.strip().startswith("["):
                    s = raw.strip()[1:-1]
                    down_assets = [
                        x.strip().strip('"').strip("'") for x in s.split(",") if x.strip()
                    ]
                else:
                    down_assets = [raw] if raw.strip() else []
        elif isinstance(raw, list):
            down_assets = raw
        else:
            down_assets = []
        if not down_assets:
            r.xack(STREAM, GROUP, mid)
            return
        logger.info("processing event_type=alert.triggered down_assets=%s", down_assets[:5])
        title = f"Assets down: {', '.join(down_assets[:5])}{' ...' if len(down_assets) > 5 else ''}"
        inc = create_incident(title=title, severity="high", asset_keys=down_assets)
        if inc:
            logger.info("created incident id=%s assets=%s", inc.get("id"), len(down_assets))
        else:
            logger.warning(
                "failed to create incident for alert.triggered assets=%s", len(down_assets)
            )
        r.xack(STREAM, GROUP, mid)
        return

    logger.warning("unknown event_type=%s, acking", event_type)
    r.xack(STREAM, GROUP, mid)


def main() -> None:
    logger.info("secplat-correlator started stream=%s group=%s api=%s", STREAM, GROUP, API_URL)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("created group %s on %s", GROUP, STREAM)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            logger.warning("xgroup_create: %s", e)

    while True:
        try:
            streams = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=1, block=BLOCK_MS)
            if not streams:
                continue
            for _sname, messages in streams:
                for mid, fields in messages:
                    payload = dict(fields)
                    try:
                        handle_event(payload, r, mid)
                    except Exception as e:
                        logger.exception("handle_event failed id=%s: %s", mid, e)
        except redis.ConnectionError as e:
            logger.warning("redis connection error: %s", e)
            time.sleep(5)


if __name__ == "__main__":
    main()
