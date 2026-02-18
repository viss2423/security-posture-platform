"""Redis Streams: publish, consume with consumer group, retry + DLQ."""

import json
import logging
import os
import time
from collections.abc import Callable
from typing import Any

import redis

logger = logging.getLogger("secplat.queue")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
DEFAULT_MAX_RETRIES = 5
DLQ_SUFFIX = ".dlq"


def _client() -> redis.Redis:
    return redis.from_url(REDIS_URL, decode_responses=True)


def publish(stream: str, message: dict[str, Any]) -> str:
    """Add message to stream. Returns message id."""
    r = _client()
    msg = {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in message.items()}
    mid = r.xadd(stream, msg, maxlen=100_000)
    logger.info("published stream=%s id=%s", stream, mid)
    return mid


def ensure_group(stream: str, group: str, start_id: str = "0") -> None:
    """Create consumer group if not exists. start_id='0' for new, '$' for only new."""
    r = _client()
    try:
        r.xgroup_create(stream, group, id=start_id, mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def consume(
    stream: str,
    group: str,
    consumer: str,
    handler: Callable[[dict], None],
    *,
    block_ms: int = 5000,
    max_retries: int = DEFAULT_MAX_RETRIES,
    dlq_stream: str | None = None,
) -> None:
    """
    Read from stream in group; call handler(msg). On exception: retry with backoff;
    after max_retries move to DLQ (stream name + .dlq) and ACK.
    handler receives dict of field -> value (values are strings; decode JSON if needed).
    """
    r = _client()
    dlq = dlq_stream or stream + DLQ_SUFFIX
    ensure_group(stream, group)
    while True:
        try:
            streams = r.xreadgroup(group, consumer, {stream: ">"}, count=1, block=block_ms)
            if not streams:
                continue
            for _sname, messages in streams:
                for mid, fields in messages:
                    payload = dict(fields)
                    retries = 0
                    while retries <= max_retries:
                        try:
                            handler(payload)
                            r.xack(stream, group, mid)
                            break
                        except Exception as e:
                            retries += 1
                            logger.warning(
                                "handler failed stream=%s id=%s attempt=%s: %s",
                                stream,
                                mid,
                                retries,
                                e,
                            )
                            if retries > max_retries:
                                r.xadd(
                                    dlq,
                                    {"original_stream": stream, "original_id": mid, **payload},
                                    maxlen=10_000,
                                )
                                r.xack(stream, group, mid)
                                logger.error("moved to DLQ stream=%s id=%s", dlq, mid)
                            else:
                                time.sleep(2**retries)
        except redis.ConnectionError as e:
            logger.warning("redis connection error: %s", e)
            time.sleep(5)
