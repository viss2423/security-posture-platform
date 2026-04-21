"""Optional OpenTelemetry helpers with safe no-op fallback."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .settings import settings

logger = logging.getLogger("secplat.otel")

_otel_configured = False
_otel_enabled = False
_tracer: Any = None
_propagator: Any = None


class _NoopSpan:
    def set_attribute(self, _key: str, _value: Any) -> None:
        return None

    def record_exception(self, _exc: Exception) -> None:
        return None

    def set_status(self, _status: Any) -> None:
        return None


def is_enabled() -> bool:
    return bool(_otel_enabled)


def configure_otel(*, service_name: str = "secplat-api") -> bool:
    """Initialize OTEL tracing when enabled and dependencies are available."""
    global _otel_configured, _otel_enabled, _tracer, _propagator
    if _otel_configured:
        return _otel_enabled
    _otel_configured = True
    if not bool(getattr(settings, "OTEL_ENABLED", False)):
        return False
    try:
        from opentelemetry import propagate, trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # pragma: no cover - dependency absent path
        logger.warning("OpenTelemetry disabled: missing dependencies (%s)", exc)
        _otel_enabled = False
        return False

    endpoint = str(getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", "") or "").strip()
    if not endpoint:
        logger.warning("OpenTelemetry disabled: OTEL_EXPORTER_OTLP_ENDPOINT is not configured")
        _otel_enabled = False
        return False
    try:
        resource = Resource.create(
            {
                "service.name": str(
                    getattr(settings, "OTEL_SERVICE_NAME", "") or service_name or "secplat-api"
                ),
                "deployment.environment": str(getattr(settings, "ENV", "dev") or "dev"),
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("secplat")
        _propagator = propagate
        _otel_enabled = True
        logger.info("OpenTelemetry tracing configured endpoint=%s", endpoint)
        return True
    except Exception as exc:  # pragma: no cover - exporter setup failures
        logger.warning("OpenTelemetry disabled: initialization failed (%s)", exc)
        _otel_enabled = False
        _tracer = None
        _propagator = None
        return False


def inject_context(carrier: dict[str, Any]) -> dict[str, Any]:
    if not carrier or not _otel_enabled or _propagator is None:
        return carrier
    try:  # pragma: no cover - exercised when OTEL deps are installed
        _propagator.inject(carrier=carrier)
    except Exception:
        logger.debug("OpenTelemetry context injection failed", exc_info=True)
    return carrier


def _extract_context(context_carrier: dict[str, Any] | None = None) -> Any | None:
    if not context_carrier or not _otel_enabled or _propagator is None:
        return None
    try:  # pragma: no cover - exercised when OTEL deps are installed
        return _propagator.extract(carrier=context_carrier)
    except Exception:
        logger.debug("OpenTelemetry context extraction failed", exc_info=True)
        return None


@contextmanager
def start_span(
    name: str,
    *,
    attributes: dict[str, Any] | None = None,
    context_carrier: dict[str, Any] | None = None,
    kind: Any = None,
) -> Iterator[Any]:
    """Start a span if OTEL is enabled; otherwise return a no-op span."""
    if not _otel_enabled or _tracer is None:
        yield _NoopSpan()
        return
    span_kwargs: dict[str, Any] = {}
    extracted_context = _extract_context(context_carrier)
    if extracted_context is not None:
        span_kwargs["context"] = extracted_context
    if kind is not None:
        span_kwargs["kind"] = kind
    with _tracer.start_as_current_span(name, **span_kwargs) as span:
        for key, value in (attributes or {}).items():
            if value is not None:
                span.set_attribute(str(key), value)
        yield span
