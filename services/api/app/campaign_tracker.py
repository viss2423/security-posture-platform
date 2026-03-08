"""Threat campaign tag normalization helpers."""

from __future__ import annotations

import re
from typing import Any

VALID_CONFIDENCE_LABELS = {"low", "medium", "high"}
_CAMPAIGN_TAG_RE = re.compile(r"[^a-z0-9._-]+")


def normalize_campaign_tag(value: Any) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = _CAMPAIGN_TAG_RE.sub("-", raw).strip("-")
    return normalized or None


def normalize_confidence_label(value: Any, *, default: str = "medium") -> str:
    candidate = str(value or "").strip().lower()
    if candidate in VALID_CONFIDENCE_LABELS:
        return candidate
    return default
