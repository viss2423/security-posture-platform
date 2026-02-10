"""Structured logging: level from settings, key=value format for request logs."""
import logging
import sys

from app.settings import settings


def configure_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    # Use a structured formatter for our request log: request_id=... method=... path=... status=...
    # (Request handler will log in that format; we just set level and default format.)
    logging.Formatter.converter = lambda *args: __import__("time").gmtime()
