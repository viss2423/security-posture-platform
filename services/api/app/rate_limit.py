"""In-memory rate limiting by key (e.g. IP). Sliding window; not distributed."""
import asyncio
import time
from collections import defaultdict

_store: dict[str, list[float]] = defaultdict(list)
_lock = asyncio.Lock()


async def check_rate_limit(key: str, max_count: int, window_seconds: float) -> bool:
    """
    Record one attempt for key. Return True if under limit, False if over (caller should 429).
    Prunes old entries inside window_seconds.
    """
    now = time.monotonic()
    async with _lock:
        cutoff = now - window_seconds
        _store[key] = [t for t in _store[key] if t > cutoff]
        if len(_store[key]) >= max_count:
            return False
        _store[key].append(now)
    return True
