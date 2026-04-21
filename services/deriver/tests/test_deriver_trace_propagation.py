from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


class _FakeResponse:
    def __init__(self, payload: dict | None = None) -> None:
        self._payload = payload or {"ok": True}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return dict(self._payload)


class _FakeClient:
    def __init__(self, calls: list[tuple[str, dict | None, dict | None]]) -> None:
        self._calls = calls

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def post(self, url, *, json=None, headers=None):
        self._calls.append((url, json, headers))
        return _FakeResponse()


def _load_module():
    module_path = Path(__file__).resolve().parents[1] / "main.py"
    module_dir = str(module_path.parent)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    spec = importlib.util.spec_from_file_location("secplat_deriver_main", module_path)
    assert spec and spec.loader, "Failed to load deriver module spec"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_opensearch_post_injects_trace_context(monkeypatch):
    os.environ.setdefault("OPENSEARCH_URL", "http://opensearch:9200")
    deriver = _load_module()
    calls: list[tuple[str, dict | None, dict | None]] = []

    monkeypatch.setattr(deriver.httpx, "Client", lambda timeout=30.0: _FakeClient(calls))
    monkeypatch.setattr(
        deriver,
        "inject_context",
        lambda carrier: carrier.__setitem__("traceparent", "00-deriver-01") or carrier,
    )

    payload = deriver._post("/secplat-events/_search", json={"size": 1})

    assert payload["ok"] is True
    assert calls[0][0].endswith("/secplat-events/_search")
    assert calls[0][2]["traceparent"] == "00-deriver-01"
