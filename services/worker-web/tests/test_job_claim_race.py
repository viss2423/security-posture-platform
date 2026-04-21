from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = b"{}" if payload is not None else b""

    def json(self) -> dict:
        return dict(self._payload)


def _load_worker_module():
    worker_path = Path(__file__).resolve().parents[1] / "worker.py"
    worker_dir = str(worker_path.parent)
    if worker_dir not in sys.path:
        sys.path.insert(0, worker_dir)
    spec = importlib.util.spec_from_file_location("secplat_worker_web_worker", worker_path)
    assert spec and spec.loader, "Failed to load worker.py module spec"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_worker_control_plane_uses_claim_execute_complete_contract(monkeypatch):
    os.environ.setdefault("API_URL", "http://api:8000")
    os.environ.setdefault("WORKER_API_USERNAME", "scanner-service")
    os.environ.setdefault("WORKER_API_PASSWORD", "scanner-local-strong")
    worker = _load_worker_module()
    calls: list[tuple[str, dict | None, dict | None]] = []

    responses = iter(
        [
            _FakeResponse(200, {"access_token": "token-1"}),
            _FakeResponse(
                200,
                {
                    "claimed": True,
                    "job_id": 42,
                    "job_type": "web_exposure",
                    "status": "running",
                    "claim_token": "claim-42",
                },
            ),
            _FakeResponse(
                200,
                {
                    "ok": True,
                    "job_id": 42,
                    "job_type": "web_exposure",
                    "status": "done",
                },
            ),
            _FakeResponse(
                200,
                {
                    "job_id": 42,
                    "status": "done",
                    "acknowledge": True,
                },
            ),
        ]
    )

    def _fake_post(url, *, data=None, json=None, headers=None, timeout=None):
        calls.append((url, data or json, headers))
        return next(responses)

    monkeypatch.setattr(worker.requests, "post", _fake_post)
    monkeypatch.setattr(
        worker,
        "inject_context",
        lambda carrier: carrier.__setitem__("traceparent", "00-worker-claim-01") or carrier,
    )

    claim = worker.claim_job_by_id(42, "worker-a", trace_id="trace-123")
    assert claim["claimed"] is True
    assert claim["claim_token"] == "claim-42"

    executed = worker._execute_job_via_api(42, "web_exposure", trace_id="trace-123")
    assert executed["status"] == "done"

    completed = worker.complete_job(
        42,
        "claim-42",
        "worker-a",
        log_line="Done",
        trace_id="trace-123",
    )
    assert completed["acknowledge"] is True

    assert calls[0][0].endswith("/auth/login")
    assert calls[1][0].endswith("/internal/jobs/42/claim")
    assert calls[2][0].endswith("/jobs/42/execute")
    assert calls[3][0].endswith("/internal/jobs/42/complete")
    assert calls[1][1] == {"worker_id": "worker-a"}
    assert calls[3][1]["claim_token"] == "claim-42"
    assert calls[2][2]["x-request-id"] == "trace-123"
    assert calls[2][2]["traceparent"] == "00-worker-claim-01"


def test_worker_control_plane_uses_fail_endpoint_for_retryable_errors(monkeypatch):
    os.environ.setdefault("API_URL", "http://api:8000")
    os.environ.setdefault("WORKER_API_USERNAME", "scanner-service")
    os.environ.setdefault("WORKER_API_PASSWORD", "scanner-local-strong")
    worker = _load_worker_module()
    calls: list[tuple[str, dict | None, dict | None]] = []

    responses = iter(
        [
            _FakeResponse(200, {"access_token": "token-2"}),
            _FakeResponse(
                200,
                {
                    "job_id": 52,
                    "status": "queued",
                    "requeued": True,
                    "acknowledge": False,
                    "existing_terminal": False,
                },
            ),
        ]
    )

    def _fake_post(url, *, data=None, json=None, headers=None, timeout=None):
        calls.append((url, data or json, headers))
        return next(responses)

    monkeypatch.setattr(worker.requests, "post", _fake_post)
    monkeypatch.setattr(
        worker,
        "inject_context",
        lambda carrier: carrier.__setitem__("traceparent", "00-worker-fail-01") or carrier,
    )

    failed = worker.fail_job(
        52,
        "claim-52",
        "worker-a",
        error="retryable=true error=upstream timeout",
        retryable=True,
        log_line="Retrying from stream after error",
        trace_id="trace-456",
    )

    assert failed["requeued"] is True
    assert failed["status"] == "queued"
    assert calls[1][0].endswith("/internal/jobs/52/fail")
    assert calls[1][1]["retryable"] is True
    assert calls[1][2]["x-request-id"] == "trace-456"
    assert calls[1][2]["traceparent"] == "00-worker-fail-01"
