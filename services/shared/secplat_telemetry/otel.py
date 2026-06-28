"""Optional OpenTelemetry helpers for SecPlat sidecar services.

Every sidecar service shares the same OTEL bootstrap pattern:
1. Check OTEL_ENABLED / OTEL_EXPORTER_OTLP_ENDPOINT env vars.
2. Lazily import opentelemetry packages.
3. Create a TracerProvider + BatchSpanProcessor + OTLP exporter.
4. Expose ``start_span`` / ``inject_context`` with safe no-op fallback.

This module eliminates the ~80-line duplication across deriver,
correlator, notifier, and worker-web.
"""

from __future__ import annotations

import logging as _logging
import os as _os
import socket as _socket
from collections.abc import Iterator as _Iterator
from contextlib import contextmanager as _contextmanager
from typing import Any as _Any

__all__ = [
    "_NoopSpan",
    "configure_otel",
    "inject_context",
    "start_span",
]

_logger = _logging.getLogger("secplat.otel")

_otel_configured: bool = False
_otel_enabled: bool = False
_tracer: _Any = None
_propagator: _Any = None


class _NoopSpan:
    """Drop-in replacement for an OpenTelemetry Span when tracing is off."""

    def set_attribute(self, _key: str, _value: _Any) -> None:
        return None

    def record_exception(self, _exc: Exception) -> None:
        return None

    def set_status(self, _status: _Any) -> None:
        return None


def is_enabled() -> bool:
    """Return whether OTEL tracing is active."""
    return bool(_otel_enabled)


def configure_otel(*, service_name: str) -> bool:
    """Initialize OTEL tracing for a sidecar service.

    Reads ``OTEL_ENABLED`` and ``OTEL_EXPORTER_OTLP_ENDPOINT`` from the
    environment. Safe to call multiple times — only the first call
    initializes the global tracer.

    Returns:
        ``True`` if tracing was successfully configured.
    """
    global _otel_configured, _otel_enabled, _tracer, _propagator

    if _otel_configured:
        return _otel_enabled
    _otel_configured = True

    if str(_os.getenv("OTEL_ENABLED", "false")).strip().lower() != "true":
        return False

    endpoint = str(_os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "") or "").strip()
    if not endpoint:
        return False

    try:
        from opentelemetry import propagate, trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception:
        _logger.debug("otel dependencies unavailable for %s", service_name, exc_info=True)
        return False

    try:
        resource = Resource.create(
            {
                "service.name": service_name,
                "service.instance.id": f"{_socket.gethostname()}:{_os.getpid()}",
                "deployment.environment": str(_os.getenv("ENV", "dev") or "dev"),
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        _propagator = propagate
        _otel_enabled = True
        _logger.info(
            "otel tracing configured service=%s endpoint=%s",
            service_name,
            endpoint,
        )
        return True
    except Exception:
        _logger.debug("otel initialization failed for %s", service_name, exc_info=True)
        _tracer = None
        _propagator = None
        _otel_enabled = False
        return False


def inject_context(carrier: dict[str, _Any]) -> dict[str, _Any]:
    """Inject the current OTEL trace context into *carrier* (mutates in place)."""
    if not carrier or not _otel_enabled or _propagator is None:
        return carrier
    try:
        _propagator.inject(carrier=carrier)
    except Exception:
        _logger.debug("otel context injection failed", exc_info=True)
    return carrier


def _extract_context(
    context_carrier: dict[str, _Any] | None = None,
) -> _Any | None:
    if not context_carrier or not _otel_enabled or _propagator is None:
        return None
    try:
        return _propagator.extract(carrier=context_carrier)
    except Exception:
        _logger.debug("otel context extraction failed", exc_info=True)
        return None


@_contextmanager
def start_span(
    name: str,
    *,
    attributes: dict[str, _Any] | None = None,
    context_carrier: dict[str, _Any] | None = None,
    kind: _Any = None,
) -> _Iterator[_Any]:
    """Start a span if OTEL is enabled; otherwise yield a no-op span.

    Usage::

        with start_span("http.client.request", attributes={"url.full": url}):
            response = client.get(url)
    """
    if not _otel_enabled or _tracer is None:
        yield _NoopSpan()
        return

    span_kwargs: dict[str, _Any] = {}
    extracted = _extract_context(context_carrier)
    if extracted is not None:
        span_kwargs["context"] = extracted
    if kind is not None:
        span_kwargs["kind"] = kind

    with _tracer.start_as_current_span(name, **span_kwargs) as span:
        for key, value in (attributes or {}).items():
            if value is not None:
                span.set_attribute(str(key), value)
        yield span
