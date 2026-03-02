"""Minimal Redis Streams client for SecPlat. Phase 1."""

from .client import consume, ensure_group, publish

__all__ = ["publish", "consume", "ensure_group"]
