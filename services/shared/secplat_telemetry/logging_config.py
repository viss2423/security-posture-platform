"""Structured JSON logging for SecPlat sidecar services.

Provides a JsonFormatter that emits JSON logs with UTC timestamps,
service identity, and PID. Includes configure_logging() for one-shot
setup of the root logger.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime

# Standard LogRecord attributes that we filter out of the JSON payload
# to avoid noise — the important fields (message, level, logger) are
# captured explicitly in JsonFormatter.format().
_STANDARD_ATTRS: set[str] = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
}


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line with service metadata."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "pid": os.getpid(),
        }

        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in payload:
                continue
            try:
                json.dumps({key: value})
                payload[key] = value
            except Exception:
                payload[key] = str(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True)


def configure_logging(
    *,
    service_name: str,
    log_level: int = logging.INFO,
) -> None:
    """Install JSON log handler on the root logger for a sidecar service.

    Args:
        service_name: Human-readable service identity (e.g. ``secplat-deriver``).
        log_level: Python logging level (default ``INFO``).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service=service_name))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(log_level)
