"""Prometheus-style metrics: in-memory counters updated by middleware."""

import math
import time
from collections import defaultdict, deque
from typing import Any

# (method, path_template, status_class) -> count. path_template normalizes path (e.g. /assets/{id} -> /assets/).
_request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
_request_latencies_ms: deque[float] = deque(maxlen=5000)
_request_totals = 0
_server_error_totals = 0
_start_time = time.monotonic()


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = (len(ordered) - 1) * percentile
    low = int(math.floor(idx))
    high = int(math.ceil(idx))
    if low == high:
        return float(ordered[low])
    weight = idx - low
    return float(ordered[low] * (1.0 - weight) + ordered[high] * weight)


def record_request(
    method: str,
    path: str,
    status_code: int,
    *,
    duration_ms: float | None = None,
) -> None:
    """Call from middleware after each request."""
    global _request_totals, _server_error_totals
    # Normalize path: non-alpha segments (IDs, slugs) -> {id} to limit cardinality
    parts = path.strip("/").split("/")
    normalized = [p if p and p.isalpha() else "{id}" for p in parts]
    path_template = "/" + "/".join(normalized) if normalized else "/"
    status_class = f"{status_code // 100}xx"
    key = (method, path_template, status_class)
    _request_counts[key] += 1
    _request_totals += 1
    if status_code >= 500:
        _server_error_totals += 1
    if duration_ms is not None and duration_ms >= 0:
        _request_latencies_ms.append(float(duration_ms))


def get_request_counts() -> dict[tuple[str, str, str], int]:
    return dict(_request_counts)


def get_uptime_seconds() -> float:
    return time.monotonic() - _start_time


def get_sli_snapshot() -> dict[str, Any]:
    availability = 1.0
    if _request_totals > 0:
        availability = max(0.0, 1.0 - (_server_error_totals / float(_request_totals)))
    latencies = list(_request_latencies_ms)
    p95_latency_ms = _percentile(latencies, 0.95) if latencies else 0.0
    return {
        "request_count": int(_request_totals),
        "server_error_count": int(_server_error_totals),
        "api_availability": round(availability, 6),
        "api_p95_latency_ms": round(p95_latency_ms, 3),
    }


def format_prometheus() -> str:
    """Render metrics in Prometheus text exposition format."""
    snapshot = get_sli_snapshot()
    lines = [
        "# HELP http_requests_total Total HTTP requests by method, path, status class.",
        "# TYPE http_requests_total counter",
    ]
    for (method, path, status_class), count in sorted(get_request_counts().items()):
        labels = f'method="{method}",path="{path}",status="{status_class}"'
        lines.append(f"http_requests_total{{{labels}}} {count}")
    lines.append("")
    lines.extend(
        [
            "# HELP process_uptime_seconds Process uptime in seconds.",
            "# TYPE process_uptime_seconds gauge",
            f"process_uptime_seconds {get_uptime_seconds():.2f}",
            "",
            "# HELP secplat_api_availability_ratio API availability ratio based on 5xx responses.",
            "# TYPE secplat_api_availability_ratio gauge",
            f"secplat_api_availability_ratio {snapshot['api_availability']}",
            "",
            "# HELP secplat_api_p95_latency_ms API p95 latency in milliseconds.",
            "# TYPE secplat_api_p95_latency_ms gauge",
            f"secplat_api_p95_latency_ms {snapshot['api_p95_latency_ms']}",
        ]
    )
    return "\n".join(lines) + "\n"
