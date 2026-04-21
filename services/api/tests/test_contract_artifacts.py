from __future__ import annotations

import json
from pathlib import Path


def _event_envelope_path() -> Path:
    return Path(__file__).resolve().parents[3] / "docs" / "contracts" / "event-envelope.json"


def test_event_envelope_contract_includes_notify_requested() -> None:
    payload = json.loads(_event_envelope_path().read_text(encoding="utf-8"))
    event_enum = payload.get("properties", {}).get("event_type", {}).get("enum", [])
    assert "notify.requested" in event_enum


def test_event_envelope_contract_required_fields() -> None:
    payload = json.loads(_event_envelope_path().read_text(encoding="utf-8"))
    required = set(payload.get("required") or [])
    assert {"event_id", "event_type", "ts", "org_id"}.issubset(required)
