from __future__ import annotations

from app import otel


def test_otel_noop_span_is_safe_without_configuration():
    with otel.start_span("unit.test", attributes={"k": "v"}) as span:
        span.set_attribute("custom", 1)
        span.record_exception(RuntimeError("x"))


def test_otel_configure_returns_bool():
    enabled = otel.configure_otel(service_name="secplat-api-tests")
    assert isinstance(enabled, bool)
