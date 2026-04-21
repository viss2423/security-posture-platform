"""Thin Redis cache layer with per-tenant keys and graceful no-op fallback."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("secplat.cache")

_redis_client = None


def _client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    from app.settings import settings

    url = str(getattr(settings, "REDIS_URL", "") or "").strip()
    if not url:
        return None
    try:
        import redis

        _redis_client = redis.from_url(url, decode_responses=True)
        return _redis_client
    except Exception as e:
        logger.debug("cache client init failed: %s", e)
        return None


def cache_get(key: str) -> Any | None:
    r = _client()
    if r is None:
        return None
    try:
        raw = r.get(key)
        return json.loads(raw) if raw is not None else None
    except Exception as e:
        logger.debug("cache get failed key=%s: %s", key, e)
        return None


def cache_set(key: str, value: Any, ttl_seconds: int = 30) -> None:
    r = _client()
    if r is None:
        return
    try:
        r.set(key, json.dumps(value, default=str), ex=ttl_seconds)
    except Exception as e:
        logger.debug("cache set failed key=%s: %s", key, e)


def cache_delete_prefix(prefix: str) -> None:
    r = _client()
    if r is None:
        return
    try:
        keys = list(r.scan_iter(f"{prefix}*", count=100))
        if keys:
            r.delete(*keys)
    except Exception as e:
        logger.debug("cache delete_prefix failed prefix=%s: %s", prefix, e)
