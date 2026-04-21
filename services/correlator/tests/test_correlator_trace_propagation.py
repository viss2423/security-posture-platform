from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


class _FakeResponse:
    def __init__(self, payload: dict | None = None, status_code: int = 200):
        self._payload = payload or {}
        self.status_code = status_code

    def json(self) -> dict:
        return dict(self._payload)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http_status_{self.status_code}")


def _load_module():
    module_path = Path(__file__).resolve().parents[1] / "main.py"
    module_dir = str(module_path.parent)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    spec = importlib.util.spec_from_file_location("secplat_correlator_main", module_path)
    assert spec and spec.loader, "Failed to load correlator module spec"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_create_incident_injects_trace_context(monkeypatch):
    os.environ.setdefault("API_URL", "http://api:8000")
    correlator = _load_module()
    correlator._token = "token-1"
    calls: list[tuple[str, dict | None, dict | None]] = []

    def _fake_post(url, *, json=None, headers=None, timeout=None, data=None):
        calls.append((url, json or data, headers))
        return _FakeResponse({"id": 91})

    monkeypatch.setattr(correlator.httpx, "post", _fake_post)
    monkeypatch.setattr(
        correlator,
        "inject_context",
        lambda carrier: carrier.__setitem__("traceparent", "00-correlator-01") or carrier,
    )

    result = correlator.create_incident(
        "Finding: demo on asset-a",
        severity="high",
        asset_keys=["asset-a"],
        incident_key="finding:asset-a:demo",
        trace_id="trace-correlator-1",
    )

    assert result["id"] == 91
    assert calls[0][0].endswith("/incidents")
    assert calls[0][2]["Authorization"] == "Bearer token-1"
    assert calls[0][2]["x-request-id"] == "trace-correlator-1"
    assert calls[0][2]["traceparent"] == "00-correlator-01"
