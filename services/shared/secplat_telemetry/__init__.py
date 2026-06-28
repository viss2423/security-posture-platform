"""secplat-telemetry: shared logging, OpenTelemetry, and Prometheus metrics for SecPlat sidecar services."""

from secplat_telemetry.logging_config import (
    _STANDARD_ATTRS,
    JsonFormatter,
    configure_logging,
)
from secplat_telemetry.metrics import SimpleMetrics, start_metrics_server
from secplat_telemetry.otel import (
    _NoopSpan,
    configure_otel,
    inject_context,
    start_span,
)

__all__ = [
    "_STANDARD_ATTRS",
    "JsonFormatter",
    "configure_logging",
    "SimpleMetrics",
    "start_metrics_server",
    "_NoopSpan",
    "configure_otel",
    "inject_context",
    "start_span",
]
