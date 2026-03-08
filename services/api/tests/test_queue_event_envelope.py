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
os.environ.setdefault("POSTGRES_DSN", "postgresql+psycopg://secplat:secplat@localhost:5432/secplat")

from app import queue

if _previous_postgres_dsn is None:
    os.environ.pop("POSTGRES_DSN", None)


class _DummyRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def xadd(self, stream: str, msg: dict[str, str], maxlen: int):
        self.calls.append((stream, msg, maxlen))
        return "1-0"


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

    ok = queue.publish_notify(["asset-a", "asset-b"], trace_id="req-notify-1")

    assert ok is True
    assert len(dummy.calls) == 1
    stream, msg, _maxlen = dummy.calls[0]
    assert stream == queue.STREAM_NOTIFY
    _assert_envelope_fields(msg)
    assert msg["event_type"] == "notify.requested"
    assert msg["type"] == "down_assets"
    assert json.loads(msg["down_assets"]) == ["asset-a", "asset-b"]
    payload = json.loads(msg["payload"])
    assert payload["type"] == "down_assets"
    assert payload["down_assets"] == ["asset-a", "asset-b"]
