"""Canonical event envelope schema used for queue-published events."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class EventEnvelope(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str
    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    org_id: str = "default"
    request_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _event_type_non_empty(cls, value: str) -> str:
        normalized = (value or "").strip()
        if not normalized:
            raise ValueError("event_type required")
        return normalized

    @field_validator("org_id")
    @classmethod
    def _org_id_non_empty(cls, value: str) -> str:
        normalized = (value or "").strip()
        if not normalized:
            raise ValueError("org_id required")
        return normalized


def build_event_envelope(
    *,
    event_type: str,
    payload: dict[str, Any] | None = None,
    request_id: str | None = None,
    org_id: str = "default",
) -> EventEnvelope:
    """Construct and validate a canonical event envelope."""
    return EventEnvelope(
        event_type=event_type,
        payload=payload or {},
        request_id=(request_id or "").strip() or None,
        org_id=(org_id or "default").strip() or "default",
    )
