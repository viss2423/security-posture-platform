"""Queue publisher envelope tests (M0.5)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

_previous_postgres_dsn = os.environ.get("POSTGRES_DSN")
os.environ.setdefault(
    "POSTGRES_DSN",
    "postgresql+psycopg://secplat_runtime:secplat_runtime@localhost:5432/secplat",
)

from app import queue

if _previous_postgres_dsn is None:
    os.environ.pop("POSTGRES_DSN", None)


class _DummyRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def xadd(self, stream: str, msg: dict[str, str], maxlen: int):
        self.calls.append((stream, msg, maxlen))
        return "1-0"


class _CapturedSpan:
    def __init__(self, name: str, attributes: dict[str, object]) -> None:
        self.name = name
        self.attributes = dict(attributes)

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[str(key)] = value


class _CapturedSpanContext:
    def __init__(self, sink: list[_CapturedSpan], name: str, attributes: dict[str, object]) -> None:
        self._sink = sink
        self._span = _CapturedSpan(name, attributes)

    def __enter__(self) -> _CapturedSpan:
        self._sink.append(self._span)
        return self._span

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def _assert_envelope_fields(msg: dict[str, str]) -> None:
    assert msg["event_id"]
    assert msg["event_type"]
    assert msg["ts"]
    assert msg["org_id"]
    assert "request_id" in msg
    assert "payload" in msg


def test_publish_scan_job_writes_envelope_and_legacy_payload(monkeypatch):
    dummy = _DummyRedis()
    monkeypatch.setattr(queue, "_client", lambda: dummy)

    ok = queue.publish_scan_job(
        42,
        "repository_scan",
        None,
        "pytest",
        trace_id="req-scan-42",
    )

    assert ok is True
    assert len(dummy.calls) == 1
    stream, msg, _maxlen = dummy.calls[0]
    assert stream == queue.STREAM_SCAN
    _assert_envelope_fields(msg)
    assert msg["event_type"] == "scan.requested"
    assert msg["request_id"] == "req-scan-42"
    assert msg["job_id"] == "42"
    assert msg["job_type"] == "repository_scan"
    payload = json.loads(msg["payload"])
    assert payload["job_id"] == 42
    assert payload["job_type"] == "repository_scan"


def test_publish_notify_writes_envelope_and_down_assets(monkeypatch):
    dummy = _DummyRedis()
    monkeypatch.setattr(queue, "_client", lambda: dummy)
    monkeypatch.setattr(
        queue,
        "inject_context",
        lambda carrier: carrier.__setitem__("traceparent", "00-abc-123-01") or carrier,
    )

    ok = queue.publish_notify(["asset-a", "asset-b"], trace_id="req-notify-1")

    assert ok is True
    assert len(dummy.calls) == 1
    stream, msg, _maxlen = dummy.calls[0]
    assert stream == queue.STREAM_NOTIFY
    _assert_envelope_fields(msg)
    assert msg["event_type"] == "notify.requested"
    assert msg["type"] == "down_assets"
    assert msg["traceparent"] == "00-abc-123-01"
    assert json.loads(msg["down_assets"]) == ["asset-a", "asset-b"]
    payload = json.loads(msg["payload"])
    assert payload["type"] == "down_assets"
    assert payload["down_assets"] == ["asset-a", "asset-b"]


def test_publish_notify_records_messaging_span(monkeypatch):
    dummy = _DummyRedis()
    spans: list[_CapturedSpan] = []
    monkeypatch.setattr(queue, "_client", lambda: dummy)
    monkeypatch.setattr(
        queue,
        "start_span",
        lambda name, attributes=None: _CapturedSpanContext(
            spans, str(name), dict(attributes or {})
        ),
    )

    ok = queue.publish_notify(["asset-a"], trace_id="trace-otel-1")

    assert ok is True
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "messaging.publish"
    assert span.attributes.get("messaging.system") == "redis"
    assert span.attributes.get("messaging.destination.name") == queue.STREAM_NOTIFY
    assert span.attributes.get("event.name") == "notify.requested"
    assert span.attributes.get("messaging.message.id")
