"""Prometheus-style metrics: in-memory counters updated by middleware."""
from collections import defaultdict
import time

# (method, path_template, status_class) -> count. path_template normalizes path (e.g. /assets/{id} -> /assets/).
_request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
_start_time = time.monotonic()


def record_request(method: str, path: str, status_code: int) -> None:
    """Call from middleware after each request."""
    # Normalize path: non-alpha segments (IDs, slugs) -> {id} to limit cardinality
    parts = path.strip("/").split("/")
    normalized = [p if p and p.isalpha() else "{id}" for p in parts]
    path_template = "/" + "/".join(normalized) if normalized else "/"
    status_class = f"{status_code // 100}xx"
    key = (method, path_template, status_class)
    _request_counts[key] += 1


def get_request_counts() -> dict[tuple[str, str, str], int]:
    return dict(_request_counts)


def get_uptime_seconds() -> float:
    return time.monotonic() - _start_time


def format_prometheus() -> str:
    """Render metrics in Prometheus text exposition format."""
    lines = [
        "# HELP http_requests_total Total HTTP requests by method, path, status class.",
        "# TYPE http_requests_total counter",
    ]
    for (method, path, status_class), count in sorted(get_request_counts().items()):
        labels = f'method="{method}",path="{path}",status="{status_class}"'
        lines.append(f"http_requests_total{{{labels}}} {count}")
    lines.append("")
    lines.extend([
        "# HELP process_uptime_seconds Process uptime in seconds.",
        "# TYPE process_uptime_seconds gauge",
        f"process_uptime_seconds {get_uptime_seconds():.2f}",
    ])
    return "\n".join(lines) + "\n"
