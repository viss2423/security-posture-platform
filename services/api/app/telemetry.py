"""Telemetry ingestion and anomaly job helpers for Suricata, Zeek, auditd, auth log, and Cowrie."""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import math
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from .alerts_v2 import normalize_alert_severity, upsert_security_alert
from .db import SessionLocal
from .queue import publish_scan_job
from .settings import settings

logger = logging.getLogger("secplat.telemetry")

SUPPORTED_TELEMETRY_SOURCES = {"suricata", "zeek", "auditd", "authlog", "cowrie", "custom"}

MITRE_BY_SOURCE_EVENT: dict[tuple[str, str], list[str]] = {
    ("suricata", "alert"): ["TA0001", "TA0002", "TA0011"],
    ("suricata", "dns"): ["TA0011"],
    ("zeek", "dns"): ["TA0011"],
    ("zeek", "conn"): ["TA0008"],
    ("auditd", "execve"): ["TA0004"],
    ("auditd", "user_cmd"): ["TA0004"],
    ("authlog", "ssh_auth_failed"): ["TA0006"],
    ("authlog", "ssh_auth_success"): ["TA0001"],
    ("authlog", "sudo_command"): ["TA0004"],
    ("authlog", "su_session"): ["TA0004"],
    ("authlog", "cron_command"): ["TA0003"],
    ("authlog", "process_event"): ["TA0002"],
    ("cowrie", "cowrie.login.failed"): ["TA0006"],
    ("cowrie", "cowrie.command.input"): ["TA0002", "TA0008"],
}

AUTHLOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
AUTHLOG_SSH_SUCCESS_RE = re.compile(
    r"Accepted\s+\w+\s+for\s+(?P<username>[^\s]+)\s+from\s+(?P<src_ip>[^\s]+)\s+port\s+(?P<src_port>\d+)",
    re.IGNORECASE,
)
AUTHLOG_SSH_FAILED_RE = re.compile(
    r"Failed\s+\w+\s+for(?:\s+invalid user)?\s+(?P<username>[^\s]+)\s+from\s+(?P<src_ip>[^\s]+)\s+port\s+(?P<src_port>\d+)",
    re.IGNORECASE,
)
AUTHLOG_SSH_INVALID_USER_RE = re.compile(
    r"Invalid user\s+(?P<username>[^\s]+)\s+from\s+(?P<src_ip>[^\s]+)",
    re.IGNORECASE,
)
AUTHLOG_SUDO_COMMAND_RE = re.compile(
    r"^(?P<username>[^:]+)\s*:\s+.*COMMAND=(?P<command>.+)$",
    re.IGNORECASE,
)
AUTHLOG_SU_SESSION_RE = re.compile(
    r"session opened for user\s+(?P<target>[^\s]+)\s+by\s+(?P<actor>[^\s(]+)",
    re.IGNORECASE,
)
AUTHLOG_CRON_COMMAND_RE = re.compile(r"CMD\s+\((?P<command>.+)\)", re.IGNORECASE)


def _authlog_timestamp(month: str, day: str, clock: str) -> datetime | None:
    year = datetime.now(UTC).year
    try:
        parsed = datetime.strptime(f"{year} {month} {int(day):02d} {clock}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _classify_authlog_event(process: str, message: str) -> dict[str, Any]:
    process_name = str(process or "").strip()
    message_text = str(message or "").strip()
    process_lower = process_name.lower()

    out: dict[str, Any] = {
        "event_type": "process_event",
        "title": f"{process_name or 'system'} process event",
        "description": message_text or None,
        "severity": "low",
        "protocol": "syslog",
        "src_ip": None,
        "src_port": None,
        "username": None,
        "command": None,
    }

    if "sshd" in process_lower:
        success = AUTHLOG_SSH_SUCCESS_RE.search(message_text)
        if success:
            out.update(
                {
                    "event_type": "ssh_auth_success",
                    "title": "SSH authentication success",
                    "severity": "medium",
                    "protocol": "ssh",
                    "src_ip": success.group("src_ip"),
                    "src_port": success.group("src_port"),
                    "username": success.group("username"),
                }
            )
            return out

        failed = AUTHLOG_SSH_FAILED_RE.search(message_text)
        if failed:
            out.update(
                {
                    "event_type": "ssh_auth_failed",
                    "title": "SSH authentication failed",
                    "severity": "high",
                    "protocol": "ssh",
                    "src_ip": failed.group("src_ip"),
                    "src_port": failed.group("src_port"),
                    "username": failed.group("username"),
                }
            )
            return out

        invalid_user = AUTHLOG_SSH_INVALID_USER_RE.search(message_text)
        if invalid_user:
            out.update(
                {
                    "event_type": "ssh_auth_failed",
                    "title": "SSH invalid user attempt",
                    "severity": "high",
                    "protocol": "ssh",
                    "src_ip": invalid_user.group("src_ip"),
                    "username": invalid_user.group("username"),
                }
            )
            return out

    if process_lower == "sudo":
        sudo_command = AUTHLOG_SUDO_COMMAND_RE.search(message_text)
        out.update(
            {
                "event_type": "sudo_command",
                "title": "Sudo command execution",
                "severity": "high",
                "protocol": "sudo",
            }
        )
        if sudo_command:
            out["username"] = sudo_command.group("username").strip()
            out["command"] = sudo_command.group("command").strip()
        return out

    if process_lower.startswith("su"):
        su_session = AUTHLOG_SU_SESSION_RE.search(message_text)
        out.update(
            {
                "event_type": "su_session",
                "title": "User switch session",
                "severity": "high",
                "protocol": "su",
            }
        )
        if su_session:
            out["username"] = su_session.group("actor").strip()
            out["command"] = f"target_user={su_session.group('target').strip()}"
        return out

    if process_lower in {"cron", "crond"} or "cmd (" in message_text.lower():
        cron_command = AUTHLOG_CRON_COMMAND_RE.search(message_text)
        out.update(
            {
                "event_type": "cron_command",
                "title": "Cron command execution",
                "severity": "medium",
                "protocol": "cron",
            }
        )
        if cron_command:
            out["command"] = cron_command.group("command").strip()
        return out

    if any(word in message_text.lower() for word in ("failed", "error", "denied")):
        out["severity"] = "medium"
    return out


def _parse_authlog_line(line: str) -> dict[str, Any] | None:
    raw_line = str(line or "").strip()
    if not raw_line:
        return None
    match = AUTHLOG_LINE_RE.match(raw_line)
    if not match:
        return None

    month = match.group("month")
    day = match.group("day")
    clock = match.group("clock")
    host = (match.group("host") or "").strip()
    process = (match.group("process") or "").strip()
    pid = match.group("pid")
    message = (match.group("message") or "").strip()
    event_time = _authlog_timestamp(month, day, clock)
    classified = _classify_authlog_event(process, message)

    src_ip = _parse_ip(classified.get("src_ip"))
    src_port = _parse_port(classified.get("src_port"))
    username = str(classified.get("username") or "").strip() or None
    command = str(classified.get("command") or "").strip() or None
    event_type = str(classified.get("event_type") or "process_event").strip().lower()
    description = str(classified.get("description") or message).strip() or None

    dedupe_key = f"{event_type}:{host}:{process}:{src_ip or 'na'}:{username or 'na'}:{command or description or 'na'}"

    return {
        "timestamp": _iso_z(event_time) if event_time else None,
        "event_type": event_type,
        "title": classified.get("title"),
        "description": description,
        "severity": classified.get("severity"),
        "protocol": classified.get("protocol"),
        "src_ip": src_ip,
        "src_port": src_port,
        "host": host or None,
        "process": process or None,
        "pid": int(pid) if pid and pid.isdigit() else None,
        "username": username,
        "command": command,
        "message": message,
        "dedupe_key": dedupe_key,
        "raw_line": raw_line,
    }


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (TypeError, ValueError, OSError):
            return None
    if isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            return None
        try:
            return datetime.fromisoformat(text_value.replace("Z", "+00:00"))
        except ValueError:
            try:
                return datetime.fromtimestamp(float(text_value), tz=UTC)
            except (TypeError, ValueError, OSError):
                return None
    return None


def _safe_json(value: Any, *, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return default
        if isinstance(parsed, type(default)):
            return parsed
    return default


def _iso_z(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _lag_stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {
            "ingest_lag_seconds_avg": None,
            "ingest_lag_seconds_p95": None,
            "ingest_lag_seconds_max": None,
        }
    ordered = sorted(values)
    p95_index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1))
    return {
        "ingest_lag_seconds_avg": round(sum(ordered) / len(ordered), 3),
        "ingest_lag_seconds_p95": round(float(ordered[p95_index]), 3),
        "ingest_lag_seconds_max": round(float(ordered[-1]), 3),
    }


def _parse_ip(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def _parse_port(value: Any) -> int | None:
    if value is None:
        return None
    try:
        numeric = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 0 <= numeric <= 65535:
        return numeric
    return None


def _parse_domain(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip().lower().rstrip(".")
    if not raw:
        return None
    if raw.startswith(("http://", "https://")):
        host = urlparse(raw).hostname
        return host.lower() if host else None
    if " " in raw:
        raw = raw.split(" ")[-1]
    if ":" in raw and raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if "." not in raw:
        return None
    if _parse_ip(raw):
        return None
    return raw


def _resolve_asset(
    db: Session, *, asset_key: str | None, src_ip: str | None, dst_ip: str | None
) -> tuple[int | None, str | None]:
    normalized_key = (asset_key or "").strip()
    if normalized_key:
        row = (
            db.execute(
                text("SELECT asset_id, asset_key FROM assets WHERE asset_key = :asset_key"),
                {"asset_key": normalized_key},
            )
            .mappings()
            .first()
        )
        if row:
            return int(row["asset_id"]), str(row["asset_key"])
        return None, normalized_key

    candidates = [ip for ip in (dst_ip, src_ip) if ip]
    for candidate in candidates:
        row = (
            db.execute(
                text(
                    """
                    SELECT asset_id, asset_key
                    FROM assets
                    WHERE address ILIKE :contains
                    ORDER BY verified DESC, asset_id ASC
                    LIMIT 1
                    """
                ),
                {"contains": f"%{candidate}%"},
            )
            .mappings()
            .first()
        )
        if row:
            return int(row["asset_id"]), str(row["asset_key"])
    return None, None


def _ioc_match(
    db: Session,
    *,
    src_ip: str | None,
    dst_ip: str | None,
    domain: str | None,
    url: str | None,
) -> tuple[bool, str | None]:
    indicators: list[tuple[str, str]] = []
    for ip_value in (src_ip, dst_ip):
        if ip_value:
            indicators.append(("ip", ip_value))
    domain_candidate = domain or _parse_domain(url)
    if domain_candidate:
        indicators.append(("domain", domain_candidate))
    if not indicators:
        return False, None

    clauses: list[str] = []
    params: dict[str, Any] = {}
    for idx, (kind, indicator) in enumerate(indicators):
        clauses.append(f"(indicator_type = :kind{idx} AND indicator = :indicator{idx})")
        params[f"kind{idx}"] = kind
        params[f"indicator{idx}"] = indicator
    sql = f"""
        SELECT source
        FROM threat_iocs
        WHERE is_active = TRUE
          AND ({' OR '.join(clauses)})
        ORDER BY last_seen_at DESC
        LIMIT 1
    """
    row = db.execute(text(sql), params).mappings().first()
    if not row:
        return False, None
    return True, str(row.get("source") or "")


def _normalize_suricata_event(raw: dict[str, Any]) -> dict[str, Any]:
    alert = _safe_json(raw.get("alert"), default={})
    event_type = str(raw.get("event_type") or "event").strip().lower()
    severity = alert.get("severity")
    signature = str(alert.get("signature") or event_type).strip()
    return {
        "event_type": event_type,
        "title": signature or "Suricata event",
        "description": str(alert.get("category") or raw.get("proto") or "").strip() or None,
        "severity_text": normalize_alert_severity(severity),
        "severity_numeric": int(severity) if str(severity or "").isdigit() else None,
        "src_ip": _parse_ip(raw.get("src_ip")),
        "src_port": _parse_port(raw.get("src_port")),
        "dst_ip": _parse_ip(raw.get("dest_ip") or raw.get("dst_ip")),
        "dst_port": _parse_port(raw.get("dest_port") or raw.get("dst_port")),
        "domain": _parse_domain(
            raw.get("dns", {}).get("rrname") if isinstance(raw.get("dns"), dict) else None
        ),
        "url": None,
        "protocol": str(raw.get("proto") or "").strip().lower() or None,
        "event_time": _parse_dt(raw.get("timestamp")),
        "dedupe_key": str(
            raw.get("flow_id")
            or alert.get("signature_id")
            or f"{event_type}:{raw.get('src_ip')}:{raw.get('dest_ip')}:{signature}"
        ),
        "mitre_techniques": MITRE_BY_SOURCE_EVENT.get(("suricata", event_type), ["TA0001"]),
        "raw": raw,
    }


def _normalize_zeek_event(raw: dict[str, Any]) -> dict[str, Any]:
    event_type = str(raw.get("event_type") or raw.get("log_type") or "conn").strip().lower()
    src_ip = _parse_ip(raw.get("id.orig_h") or raw.get("src_ip") or raw.get("orig_h"))
    dst_ip = _parse_ip(raw.get("id.resp_h") or raw.get("dst_ip") or raw.get("resp_h"))
    src_port = _parse_port(raw.get("id.orig_p") or raw.get("src_port") or raw.get("orig_p"))
    dst_port = _parse_port(raw.get("id.resp_p") or raw.get("dst_port") or raw.get("resp_p"))
    query = raw.get("query") or raw.get("qclass_name")
    title = "Zeek network event"
    if event_type == "dns" and query:
        title = f"Zeek DNS query {query}"
    elif event_type == "ssl":
        title = "Zeek SSL/TLS event"
    return {
        "event_type": event_type,
        "title": title,
        "description": str(raw.get("service") or raw.get("note") or "").strip() or None,
        "severity_text": normalize_alert_severity(
            raw.get("severity") or ("low" if event_type == "conn" else "medium")
        ),
        "severity_numeric": None,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "domain": _parse_domain(query),
        "url": str(raw.get("uri") or raw.get("host") or "").strip() or None,
        "protocol": str(raw.get("proto") or raw.get("service") or "").strip().lower() or None,
        "event_time": _parse_dt(raw.get("ts") or raw.get("timestamp")),
        "dedupe_key": str(
            raw.get("uid") or f"{event_type}:{src_ip}:{dst_ip}:{src_port}:{dst_port}:{query}"
        ),
        "mitre_techniques": MITRE_BY_SOURCE_EVENT.get(("zeek", event_type), ["TA0008"]),
        "raw": raw,
    }


def _normalize_auditd_event(raw: dict[str, Any]) -> dict[str, Any]:
    event_type = str(raw.get("type") or raw.get("event_type") or "auditd").strip().lower()
    command = str(raw.get("exe") or raw.get("comm") or raw.get("cmd") or "").strip()
    title = "Auditd privilege activity"
    if command:
        title = f"Auditd {command}"
    severity = "medium"
    if any(word in command.lower() for word in ("sudo", "passwd", "useradd", "usermod", "visudo")):
        severity = "high"
    return {
        "event_type": event_type,
        "title": title,
        "description": str(raw.get("msg") or raw.get("auid") or "").strip() or None,
        "severity_text": severity,
        "severity_numeric": None,
        "src_ip": _parse_ip(raw.get("addr") or raw.get("src_ip")),
        "src_port": _parse_port(raw.get("src_port")),
        "dst_ip": _parse_ip(raw.get("dst_ip")),
        "dst_port": _parse_port(raw.get("dst_port")),
        "domain": _parse_domain(raw.get("hostname")),
        "url": None,
        "protocol": "syscall",
        "event_time": _parse_dt(raw.get("timestamp") or raw.get("@timestamp")),
        "dedupe_key": str(raw.get("serial") or f"{event_type}:{command}:{raw.get('auid')}"),
        "mitre_techniques": MITRE_BY_SOURCE_EVENT.get(("auditd", event_type), ["TA0004"]),
        "raw": raw,
    }


def _normalize_authlog_event(raw: dict[str, Any]) -> dict[str, Any]:
    event_type = str(raw.get("event_type") or "process_event").strip().lower()
    src_ip = _parse_ip(raw.get("src_ip"))
    src_port = _parse_port(raw.get("src_port"))
    process = str(raw.get("process") or "").strip()
    host = str(raw.get("host") or "").strip()
    title = str(raw.get("title") or "").strip() or "Linux auth log event"
    description = str(raw.get("description") or raw.get("message") or "").strip() or None
    severity = normalize_alert_severity(raw.get("severity") or "medium")
    return {
        "event_type": event_type,
        "title": title,
        "description": description,
        "severity_text": severity,
        "severity_numeric": None,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": None,
        "dst_port": None,
        "domain": _parse_domain(host),
        "url": None,
        "protocol": str(raw.get("protocol") or "").strip().lower() or "syslog",
        "event_time": _parse_dt(raw.get("timestamp") or raw.get("@timestamp")),
        "dedupe_key": str(
            raw.get("dedupe_key")
            or f"{event_type}:{host}:{process}:{src_ip}:{src_port}:{raw.get('username')}"
        ),
        "mitre_techniques": MITRE_BY_SOURCE_EVENT.get(("authlog", event_type), ["TA0002"]),
        "raw": raw,
    }


def _normalize_cowrie_event(raw: dict[str, Any]) -> dict[str, Any]:
    event_type = str(raw.get("eventid") or raw.get("event_type") or "cowrie.event").strip().lower()
    src_ip = _parse_ip(raw.get("src_ip"))
    username = str(raw.get("username") or "").strip()
    title = "Cowrie honeypot activity"
    if event_type:
        title = f"Cowrie {event_type}"
    description = str(raw.get("input") or raw.get("message") or "").strip() or None
    severity = "medium"
    if event_type.endswith("login.failed") or event_type.endswith("command.input"):
        severity = "high"
    return {
        "event_type": event_type,
        "title": title,
        "description": description,
        "severity_text": severity,
        "severity_numeric": None,
        "src_ip": src_ip,
        "src_port": _parse_port(raw.get("src_port")),
        "dst_ip": None,
        "dst_port": _parse_port(raw.get("dst_port")),
        "domain": None,
        "url": None,
        "protocol": "ssh",
        "event_time": _parse_dt(raw.get("timestamp")),
        "dedupe_key": str(raw.get("session") or f"{event_type}:{src_ip}:{username}:{description}"),
        "mitre_techniques": MITRE_BY_SOURCE_EVENT.get(("cowrie", event_type), ["TA0006"]),
        "raw": raw,
    }


def normalize_telemetry_event(source: str, raw: dict[str, Any]) -> dict[str, Any]:
    normalized_source = (source or "custom").strip().lower()
    if normalized_source == "suricata":
        return _normalize_suricata_event(raw)
    if normalized_source == "zeek":
        return _normalize_zeek_event(raw)
    if normalized_source == "auditd":
        return _normalize_auditd_event(raw)
    if normalized_source == "authlog":
        return _normalize_authlog_event(raw)
    if normalized_source == "cowrie":
        return _normalize_cowrie_event(raw)
    return {
        "event_type": str(raw.get("event_type") or "event").strip().lower() or "event",
        "title": str(raw.get("title") or "Telemetry event").strip() or "Telemetry event",
        "description": str(raw.get("description") or "").strip() or None,
        "severity_text": normalize_alert_severity(raw.get("severity")),
        "severity_numeric": None,
        "src_ip": _parse_ip(raw.get("src_ip")),
        "src_port": _parse_port(raw.get("src_port")),
        "dst_ip": _parse_ip(raw.get("dst_ip")),
        "dst_port": _parse_port(raw.get("dst_port")),
        "domain": _parse_domain(raw.get("domain")),
        "url": str(raw.get("url") or "").strip() or None,
        "protocol": str(raw.get("protocol") or "").strip().lower() or None,
        "event_time": _parse_dt(raw.get("timestamp") or raw.get("event_time")),
        "dedupe_key": str(raw.get("dedupe_key") or json.dumps(raw, sort_keys=True)),
        "mitre_techniques": _safe_json(raw.get("mitre_techniques"), default=[]),
        "raw": raw,
    }


def _insert_event(
    db: Session,
    *,
    source: str,
    asset_id: int | None,
    asset_key: str | None,
    normalized: dict[str, Any],
    collector: str | None,
    ingest_job_id: int | None,
    raw_offset: int | None,
    raw_path: str | None,
    ingest_lag_seconds: float | None,
    ti_match: bool,
    ti_source: str | None,
) -> int:
    row = (
        db.execute(
            text(
                """
                INSERT INTO security_events(
                  source, event_type, asset_id, asset_key, collector, ingest_job_id, raw_offset, raw_path, severity,
                  src_ip, src_port, dst_ip, dst_port, domain, url, protocol, event_time,
                  ingest_lag_seconds, ti_match, ti_source, mitre_techniques, payload_json
                )
                VALUES (
                  :source, :event_type, :asset_id, :asset_key, :collector, :ingest_job_id, :raw_offset, :raw_path, :severity,
                  :src_ip, :src_port, :dst_ip, :dst_port, :domain, :url, :protocol, :event_time,
                  :ingest_lag_seconds, :ti_match, :ti_source, CAST(:mitre_techniques AS jsonb), CAST(:payload_json AS jsonb)
                )
                RETURNING event_id
                """
            ),
            {
                "source": source,
                "event_type": normalized.get("event_type") or "event",
                "asset_id": asset_id,
                "asset_key": asset_key,
                "collector": collector,
                "ingest_job_id": ingest_job_id,
                "raw_offset": raw_offset,
                "raw_path": raw_path,
                "severity": normalized.get("severity_numeric"),
                "src_ip": normalized.get("src_ip"),
                "src_port": normalized.get("src_port"),
                "dst_ip": normalized.get("dst_ip"),
                "dst_port": normalized.get("dst_port"),
                "domain": normalized.get("domain"),
                "url": normalized.get("url"),
                "protocol": normalized.get("protocol"),
                "event_time": normalized.get("event_time") or datetime.now(UTC),
                "ingest_lag_seconds": ingest_lag_seconds,
                "ti_match": ti_match,
                "ti_source": ti_source,
                "mitre_techniques": json.dumps(normalized.get("mitre_techniques") or []),
                "payload_json": json.dumps(normalized.get("raw") or {}),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("telemetry_event_insert_failed")
    return int(row["event_id"])


def _opensearch_indices_for_source(source: str) -> list[str]:
    prefix = str(settings.TELEMETRY_OPENSEARCH_INDEX_PREFIX or "secplat-telemetry").strip().lower()
    if not prefix:
        prefix = "secplat-telemetry"
    normalized_source = (source or "custom").strip().lower() or "custom"
    return [f"{prefix}-all", f"{prefix}-{normalized_source}"]


def _build_opensearch_doc(
    *,
    event_id: int,
    source: str,
    asset_key: str | None,
    normalized: dict[str, Any],
    collector: str | None,
    ingest_job_id: int | None,
    raw_offset: int | None,
    raw_path: str | None,
    ingest_lag_seconds: float | None,
    ti_match: bool,
    ti_source: str | None,
) -> dict[str, Any]:
    raw = _safe_json(normalized.get("raw"), default={})
    alert = _safe_json(raw.get("alert"), default={})
    event_time = _parse_dt(normalized.get("event_time")) or datetime.now(UTC)
    doc = {
        "@timestamp": _iso_z(event_time),
        "event_id": int(event_id),
        "source": source,
        "event_type": str(normalized.get("event_type") or "event"),
        "asset_key": asset_key,
        "collector": collector,
        "ingest_job_id": ingest_job_id,
        "raw_offset": raw_offset,
        "raw_path": raw_path,
        "title": normalized.get("title"),
        "description": normalized.get("description"),
        "severity_text": normalize_alert_severity(normalized.get("severity_text")),
        "severity_numeric": normalized.get("severity_numeric"),
        "src_ip": normalized.get("src_ip"),
        "src_port": normalized.get("src_port"),
        "dst_ip": normalized.get("dst_ip"),
        "dst_port": normalized.get("dst_port"),
        "domain": normalized.get("domain"),
        "url": normalized.get("url"),
        "protocol": normalized.get("protocol"),
        "dedupe_key": normalized.get("dedupe_key"),
        "mitre_techniques": normalized.get("mitre_techniques") or [],
        "ingest_lag_seconds": ingest_lag_seconds,
        "ti_match": bool(ti_match),
        "ti_source": ti_source,
        "signature": str(alert.get("signature") or "").strip() or None,
        "signature_id": alert.get("signature_id"),
        "payload_json": raw,
    }
    if source == "zeek":
        doc["zeek_query"] = raw.get("query")
        doc["zeek_uid"] = raw.get("uid")
    elif source == "auditd":
        doc["audit_command"] = raw.get("exe") or raw.get("comm") or raw.get("cmd")
        doc["audit_user"] = raw.get("auid")
    elif source == "authlog":
        doc["authlog_host"] = raw.get("host")
        doc["authlog_process"] = raw.get("process")
        doc["authlog_pid"] = raw.get("pid")
        doc["authlog_user"] = raw.get("username")
        doc["authlog_command"] = raw.get("command")
    elif source == "cowrie":
        doc["cowrie_session"] = raw.get("session")
        doc["cowrie_username"] = raw.get("username")
        doc["cowrie_eventid"] = raw.get("eventid")
    return doc


def _mirror_events_to_opensearch(source: str, docs: list[dict[str, Any]]) -> None:
    if not settings.TELEMETRY_MIRROR_TO_OPENSEARCH:
        return
    if not docs:
        return
    base_url = str(settings.OPENSEARCH_URL or "").strip().rstrip("/")
    if not base_url:
        return
    index_names = _opensearch_indices_for_source(source)
    lines: list[str] = []
    for index_name in index_names:
        for doc in docs:
            lines.append(json.dumps({"index": {"_index": index_name}}))
            lines.append(json.dumps(doc, default=str))
    body = "\n".join(lines) + "\n"
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                f"{base_url}/_bulk",
                content=body,
                headers={"Content-Type": "application/x-ndjson"},
            )
            response.raise_for_status()
            payload = response.json()
            if payload.get("errors") is True:
                item_errors = 0
                for item in payload.get("items") or []:
                    action = item.get("index") if isinstance(item, dict) else None
                    if isinstance(action, dict) and action.get("error"):
                        item_errors += 1
                logger.warning(
                    "telemetry_opensearch_mirror_partial_failure source=%s docs=%s item_errors=%s",
                    source,
                    len(docs),
                    item_errors,
                )
    except Exception:
        logger.warning(
            "telemetry_opensearch_mirror_failed source=%s docs=%s",
            source,
            len(docs),
            exc_info=True,
        )


def ingest_telemetry_events(
    db: Session,
    *,
    source: str,
    events: list[dict[str, Any]],
    default_asset_key: str | None = None,
    create_alerts: bool = True,
    collector: str | None = None,
    ingest_job_id: int | None = None,
    raw_path: str | None = None,
) -> dict[str, Any]:
    normalized_source = (source or "custom").strip().lower()
    if normalized_source not in SUPPORTED_TELEMETRY_SOURCES:
        raise ValueError(f"unsupported_telemetry_source:{normalized_source}")
    normalized_collector = (
        str(collector or f"ingest.{normalized_source}").strip() or f"ingest.{normalized_source}"
    )
    normalized_ingest_job_id = _parse_int(ingest_job_id)
    normalized_raw_path = str(raw_path or "").strip() or None
    inserted_events = 0
    created_or_updated_alerts = 0
    ti_matches = 0
    traceable_events = 0
    sources_counter: dict[str, int] = defaultdict(int)
    lag_seconds_values: list[float] = []
    mirror_docs: list[dict[str, Any]] = []
    for idx, raw in enumerate(events[: max(1, int(settings.TELEMETRY_IMPORT_MAX_EVENTS))], start=1):
        if not isinstance(raw, dict):
            continue
        normalized = normalize_telemetry_event(normalized_source, raw)
        event_time = _parse_dt(normalized.get("event_time")) or datetime.now(UTC)
        normalized["event_time"] = event_time
        ingest_lag_seconds = max(0.0, (datetime.now(UTC) - event_time).total_seconds())
        lag_seconds_values.append(ingest_lag_seconds)
        event_collector = (
            str(raw.get("collector") or normalized_collector).strip() or normalized_collector
        )
        event_ingest_job_id = _parse_int(raw.get("ingest_job_id"))
        if event_ingest_job_id is None:
            event_ingest_job_id = normalized_ingest_job_id
        event_raw_offset = _parse_int(raw.get("raw_offset"))
        if event_raw_offset is None:
            event_raw_offset = idx
        event_raw_path = str(raw.get("raw_path") or "").strip() or normalized_raw_path
        resolved_asset_id, resolved_asset_key = _resolve_asset(
            db,
            asset_key=(
                str(raw.get("asset_key") or "").strip() or (default_asset_key or "").strip() or None
            ),
            src_ip=normalized.get("src_ip"),
            dst_ip=normalized.get("dst_ip"),
        )
        ti_match, ti_source = _ioc_match(
            db,
            src_ip=normalized.get("src_ip"),
            dst_ip=normalized.get("dst_ip"),
            domain=normalized.get("domain"),
            url=normalized.get("url"),
        )
        if ti_match:
            ti_matches += 1
            if ti_source:
                sources_counter[ti_source] += 1
        event_id = _insert_event(
            db,
            source=normalized_source,
            asset_id=resolved_asset_id,
            asset_key=resolved_asset_key,
            normalized=normalized,
            collector=event_collector,
            ingest_job_id=event_ingest_job_id,
            raw_offset=event_raw_offset,
            raw_path=event_raw_path,
            ingest_lag_seconds=ingest_lag_seconds,
            ti_match=ti_match,
            ti_source=ti_source,
        )
        mirror_docs.append(
            _build_opensearch_doc(
                event_id=event_id,
                source=normalized_source,
                asset_key=resolved_asset_key,
                normalized=normalized,
                collector=event_collector,
                ingest_job_id=event_ingest_job_id,
                raw_offset=event_raw_offset,
                raw_path=event_raw_path,
                ingest_lag_seconds=ingest_lag_seconds,
                ti_match=ti_match,
                ti_source=ti_source,
            )
        )
        inserted_events += 1
        if event_collector and (
            event_ingest_job_id is not None or event_raw_path or event_raw_offset
        ):
            traceable_events += 1

        severity_text = normalize_alert_severity(normalized.get("severity_text"))
        create_alert = create_alerts and (
            severity_text in {"critical", "high"}
            or bool(ti_match)
            or normalized_source in {"cowrie", "auditd", "authlog"}
        )
        if create_alert:
            dedupe_key = str(normalized.get("dedupe_key") or normalized.get("title"))
            upsert_security_alert(
                db,
                source=normalized_source,
                alert_type=normalized.get("event_type") or "detection",
                title=normalized.get("title") or "Telemetry alert",
                description=normalized.get("description"),
                dedupe_key=dedupe_key,
                severity=severity_text,
                asset_id=resolved_asset_id,
                asset_key=resolved_asset_key,
                event_time=normalized.get("event_time"),
                ti_match=ti_match,
                ti_source=ti_source,
                mitre_techniques=normalized.get("mitre_techniques") or [],
                payload_json=normalized.get("raw") or {},
                context_json={
                    "source": normalized_source,
                    "src_ip": normalized.get("src_ip"),
                    "dst_ip": normalized.get("dst_ip"),
                    "domain": normalized.get("domain"),
                    "url": normalized.get("url"),
                },
            )
            created_or_updated_alerts += 1
    _mirror_events_to_opensearch(normalized_source, mirror_docs)
    lag_summary = _lag_stats(lag_seconds_values)
    traceability_coverage_pct = (
        round((traceable_events / inserted_events) * 100.0, 2) if inserted_events else 0.0
    )
    return {
        "source": normalized_source,
        "collector": normalized_collector,
        "ingest_job_id": normalized_ingest_job_id,
        "raw_path": normalized_raw_path,
        "processed_events": inserted_events,
        "alert_updates": created_or_updated_alerts,
        "ti_matches": ti_matches,
        "ti_sources": dict(sources_counter),
        "traceable_events": traceable_events,
        "traceability_coverage_pct": traceability_coverage_pct,
        **lag_summary,
    }


def _read_events_from_file(path: str) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError("telemetry_file_not_found")
    if not file_path.is_file():
        raise ValueError("telemetry_path_not_file")
    raw_path = str(file_path)
    if file_path.suffix.lower() in {".json", ".jsonl", ".log"}:
        events: list[dict[str, Any]] = []
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_no, line in enumerate(handle, start=1):
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    parsed.setdefault("raw_offset", line_no)
                    parsed.setdefault("raw_path", raw_path)
                    events.append(parsed)
        return events
    if file_path.suffix.lower() in {".csv", ".tsv"}:
        delimiter = "\t" if file_path.suffix.lower() == ".tsv" else ","
        with file_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            events: list[dict[str, Any]] = []
            for row_no, row in enumerate(reader, start=2):
                item = dict(row)
                item.setdefault("raw_offset", row_no)
                item.setdefault("raw_path", raw_path)
                events.append(item)
            return events
    raise ValueError("telemetry_file_unsupported")


def _read_authlog_events_from_file(path: str) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError("telemetry_file_not_found")
    if not file_path.is_file():
        raise ValueError("telemetry_path_not_file")
    raw_path = str(file_path)
    events: list[dict[str, Any]] = []
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            parsed = _parse_authlog_line(raw)
            if parsed:
                parsed.setdefault("raw_offset", line_no)
                parsed.setdefault("raw_path", raw_path)
                events.append(parsed)
    return events


def _append_job_log(db: Session, job_id: int, message: str) -> None:
    line = f"[{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}] {message}"
    db.execute(
        text(
            """
            UPDATE scan_jobs
            SET log_output = COALESCE(log_output, '') || :line || E'\n'
            WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "line": line},
    )
    db.commit()


def _set_job_status(
    db: Session, job_id: int, *, status: str, error: str | None = None, started: bool = False
) -> None:
    if started:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = :status, started_at = NOW(), finished_at = NULL, error = NULL
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id, "status": status},
        )
    else:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = :status, finished_at = NOW(), error = :error
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id, "status": status, "error": error},
        )
    db.commit()


def run_telemetry_import_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        _set_job_status(db, job_id, status="running", started=True)
        row = (
            db.execute(
                text(
                    """
                    SELECT job_id, COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            raise ValueError("telemetry_job_not_found")
        params = _safe_json(row.get("job_params_json"), default={})
        source = str(params.get("source") or "custom").strip().lower()
        path = str(params.get("file_path") or "").strip()
        default_asset_key = str(params.get("asset_key") or "").strip() or None
        create_alerts = bool(params.get("create_alerts", True))
        if not path:
            source_path_map = {
                "suricata": settings.TELEMETRY_SURICATA_LOG_PATH,
                "zeek": settings.TELEMETRY_ZEEK_LOG_PATH,
                "auditd": settings.TELEMETRY_AUDITD_LOG_PATH,
                "authlog": settings.TELEMETRY_AUTH_LOG_PATH,
                "cowrie": settings.TELEMETRY_COWRIE_LOG_PATH,
            }
            path = source_path_map.get(source, "")
        if not path:
            raise ValueError("telemetry_file_path_required")
        _append_job_log(db, job_id, f"Telemetry import started source={source} path={path}")
        if source == "authlog":
            events = _read_authlog_events_from_file(path)
        else:
            events = _read_events_from_file(path)
        _append_job_log(db, job_id, f"Loaded {len(events)} candidate rows from file")
        last_seen_row = (
            db.execute(
                text(
                    """
                    SELECT MAX(event_time) AS last_event_time
                    FROM security_events
                    WHERE source = :source
                    """
                ),
                {"source": source},
            )
            .mappings()
            .first()
        )
        last_event_time = _parse_dt((last_seen_row or {}).get("last_event_time"))
        if last_event_time:
            original_count = len(events)
            filtered: list[dict[str, Any]] = []
            for raw in events:
                if not isinstance(raw, dict):
                    continue
                normalized = normalize_telemetry_event(source, raw)
                event_time = _parse_dt(normalized.get("event_time"))
                if event_time and event_time > last_event_time:
                    filtered.append(raw)
            events = filtered
            _append_job_log(
                db,
                job_id,
                f"Filtered incremental events using last_event_time={_iso_z(last_event_time)} "
                f"(kept={len(events)} dropped={max(0, original_count - len(events))})",
            )
        if not events:
            _append_job_log(db, job_id, "No new telemetry events to ingest")
            _set_job_status(db, job_id, status="done")
            return
        summary = ingest_telemetry_events(
            db,
            source=source,
            events=events,
            default_asset_key=default_asset_key,
            create_alerts=create_alerts,
            collector=f"jobs.telemetry_import.{source}",
            ingest_job_id=job_id,
            raw_path=path,
        )
        _append_job_log(
            db,
            job_id,
            "Telemetry import completed: "
            f"{summary['processed_events']} events, {summary['alert_updates']} alert updates, "
            f"{summary['ti_matches']} IOC matches",
        )
        _set_job_status(db, job_id, status="done")
    except Exception as exc:
        logger.exception("telemetry_import_job_failed job_id=%s", job_id)
        _append_job_log(db, job_id, f"Telemetry import failed: {exc}")
        _set_job_status(db, job_id, status="failed", error=str(exc))
    finally:
        db.close()


def launch_telemetry_import_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text(
                    """
                    SELECT target_asset_id, requested_by
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            logger.warning("telemetry_import_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    published = publish_scan_job(
        int(job_id),
        "telemetry_import",
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    )
    if not published:
        logger.warning("telemetry_import_enqueue_failed job_id=%s", job_id)


def _hour_bucket(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def run_network_anomaly_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        _set_job_status(db, job_id, status="running", started=True)
        row = (
            db.execute(
                text(
                    """
                    SELECT COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            raise ValueError("anomaly_job_not_found")
        params = _safe_json(row.get("job_params_json"), default={})
        lookback_hours = max(
            6, int(params.get("lookback_hours") or settings.TELEMETRY_DEFAULT_LOOKBACK_HOURS)
        )
        threshold = float(params.get("threshold") or settings.NETWORK_ANOMALY_THRESHOLD)
        now = datetime.now(UTC)
        since = now - timedelta(hours=lookback_hours + 1)
        event_rows = (
            db.execute(
                text(
                    """
                    SELECT asset_key, source, event_time
                    FROM security_events
                    WHERE event_time >= :since
                    """
                ),
                {"since": since},
            )
            .mappings()
            .all()
        )
        by_asset_bucket: dict[str, dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
        by_asset_source: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for item in event_rows:
            asset_key = str(item.get("asset_key") or "unassigned")
            event_time = _parse_dt(item.get("event_time")) or now
            bucket = _hour_bucket(event_time)
            by_asset_bucket[asset_key][bucket] += 1
            source = str(item.get("source") or "unknown")
            by_asset_source[asset_key][source] += 1

        current_bucket = _hour_bucket(now)
        inserted_scores = 0
        anomaly_alerts = 0
        for asset_key, hourly_counts in by_asset_bucket.items():
            current_value = float(hourly_counts.get(current_bucket, 0))
            baseline_values = [
                float(value)
                for bucket, value in sorted(hourly_counts.items())
                if bucket < current_bucket
            ]
            if len(baseline_values) < 3:
                continue
            baseline_mean = sum(baseline_values) / len(baseline_values)
            variance = sum((value - baseline_mean) ** 2 for value in baseline_values) / len(
                baseline_values
            )
            baseline_std = math.sqrt(max(variance, 0.0))
            if baseline_std > 0:
                anomaly_score = (current_value - baseline_mean) / baseline_std
            else:
                anomaly_score = (
                    0.0 if current_value <= baseline_mean else current_value - baseline_mean
                )

            db.execute(
                text(
                    """
                    INSERT INTO asset_anomaly_scores(
                      asset_key, computed_at, anomaly_score, baseline_mean,
                      baseline_std, current_value, source_breakdown, context_json
                    )
                    VALUES (
                      :asset_key, :computed_at, :anomaly_score, :baseline_mean,
                      :baseline_std, :current_value, CAST(:source_breakdown AS jsonb),
                      CAST(:context_json AS jsonb)
                    )
                    """
                ),
                {
                    "asset_key": asset_key,
                    "computed_at": now,
                    "anomaly_score": float(anomaly_score),
                    "baseline_mean": float(baseline_mean),
                    "baseline_std": float(baseline_std),
                    "current_value": current_value,
                    "source_breakdown": json.dumps(dict(by_asset_source.get(asset_key) or {})),
                    "context_json": json.dumps(
                        {
                            "lookback_hours": lookback_hours,
                            "current_bucket": current_bucket.isoformat(),
                        }
                    ),
                },
            )
            inserted_scores += 1
            if anomaly_score >= threshold:
                upsert_security_alert(
                    db,
                    source="anomaly",
                    alert_type="network_anomaly",
                    title=f"Network anomaly on {asset_key}",
                    description=(
                        f"Current activity {int(current_value)} vs baseline {baseline_mean:.2f}"
                    ),
                    dedupe_key=f"{asset_key}:{current_bucket.isoformat()}",
                    severity="high" if anomaly_score >= (threshold * 1.8) else "medium",
                    asset_key=None if asset_key == "unassigned" else asset_key,
                    ti_match=False,
                    mitre_techniques=["TA0011"],
                    context_json={
                        "anomaly_score": round(float(anomaly_score), 4),
                        "baseline_mean": round(float(baseline_mean), 4),
                        "baseline_std": round(float(baseline_std), 4),
                        "current_value": int(current_value),
                    },
                )
                anomaly_alerts += 1
        db.commit()
        _append_job_log(
            db,
            job_id,
            f"Anomaly job completed: {inserted_scores} scores written, {anomaly_alerts} alerts generated",
        )
        _set_job_status(db, job_id, status="done")
    except Exception as exc:
        logger.exception("network_anomaly_job_failed job_id=%s", job_id)
        _append_job_log(db, job_id, f"Network anomaly job failed: {exc}")
        _set_job_status(db, job_id, status="failed", error=str(exc))
    finally:
        db.close()


def launch_network_anomaly_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text(
                    """
                    SELECT target_asset_id, requested_by
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            logger.warning("network_anomaly_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    published = publish_scan_job(
        int(job_id),
        "network_anomaly_score",
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    )
    if not published:
        logger.warning("network_anomaly_enqueue_failed job_id=%s", job_id)


def enqueue_network_anomaly_job(
    *,
    requested_by: str = "system",
    lookback_hours: int | None = None,
    threshold: float | None = None,
) -> int:
    db = SessionLocal()
    try:
        params: dict[str, Any] = {}
        if lookback_hours is not None:
            params["lookback_hours"] = int(lookback_hours)
        if threshold is not None:
            params["threshold"] = float(threshold)
        row = (
            db.execute(
                text(
                    """
                    INSERT INTO scan_jobs(job_type, requested_by, status, job_params_json)
                    VALUES (
                      'network_anomaly_score',
                      :requested_by,
                      'queued',
                      CAST(:job_params_json AS jsonb)
                    )
                    RETURNING job_id
                    """
                ),
                {"requested_by": requested_by, "job_params_json": json.dumps(params)},
            )
            .mappings()
            .first()
        )
        db.commit()
        if not row:
            raise ValueError("network_anomaly_enqueue_failed")
        job_id = int(row["job_id"])
        launch_network_anomaly_job(job_id)
        return job_id
    finally:
        db.close()


def enqueue_telemetry_import_job(
    *,
    source: str,
    requested_by: str = "system",
    file_path: str | None = None,
    asset_key: str | None = None,
    create_alerts: bool = True,
    skip_if_running: bool = True,
) -> int | None:
    normalized_source = (source or "").strip().lower()
    if normalized_source not in {"suricata", "zeek", "auditd", "authlog", "cowrie", "custom"}:
        raise ValueError("telemetry_source_invalid")
    resolved_path = str(file_path or "").strip()
    if not resolved_path and normalized_source != "custom":
        source_path_map = {
            "suricata": settings.TELEMETRY_SURICATA_LOG_PATH,
            "zeek": settings.TELEMETRY_ZEEK_LOG_PATH,
            "auditd": settings.TELEMETRY_AUDITD_LOG_PATH,
            "authlog": settings.TELEMETRY_AUTH_LOG_PATH,
            "cowrie": settings.TELEMETRY_COWRIE_LOG_PATH,
        }
        resolved_path = str(source_path_map.get(normalized_source) or "").strip()
    if normalized_source == "custom" and not resolved_path:
        raise ValueError("telemetry_file_path_required")
    if normalized_source != "custom":
        if not resolved_path:
            raise ValueError("telemetry_file_path_required")
        if not Path(resolved_path).exists():
            raise ValueError("telemetry_file_not_found")

    db = SessionLocal()
    try:
        if skip_if_running:
            existing = (
                db.execute(
                    text(
                        """
                        SELECT job_id
                        FROM scan_jobs
                        WHERE job_type = 'telemetry_import'
                          AND status IN ('queued', 'running')
                          AND COALESCE(job_params_json ->> 'source', '') = :source
                          AND (
                            status = 'running'
                            OR created_at >= (NOW() - INTERVAL '15 minutes')
                          )
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {"source": normalized_source},
                )
                .mappings()
                .first()
            )
            if existing:
                return None
        params: dict[str, Any] = {
            "source": normalized_source,
            "create_alerts": bool(create_alerts),
        }
        if resolved_path:
            params["file_path"] = resolved_path
        if asset_key:
            params["asset_key"] = str(asset_key).strip()
        row = (
            db.execute(
                text(
                    """
                    INSERT INTO scan_jobs(job_type, requested_by, status, job_params_json)
                    VALUES (
                      'telemetry_import',
                      :requested_by,
                      'queued',
                      CAST(:job_params_json AS jsonb)
                    )
                    RETURNING job_id
                    """
                ),
                {"requested_by": requested_by, "job_params_json": json.dumps(params)},
            )
            .mappings()
            .first()
        )
        db.commit()
        if not row:
            raise ValueError("telemetry_enqueue_failed")
        job_id = int(row["job_id"])
        launch_telemetry_import_job(job_id)
        return job_id
    finally:
        db.close()


def build_keepalive_events(source: str, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Generate low-volume demo telemetry so dashboards remain populated in lab environments."""
    current = now or datetime.now(UTC)
    timestamp = _iso_z(current) or current.isoformat().replace("+00:00", "Z")
    minute_bucket = current.strftime("%Y%m%d%H%M")
    normalized_source = (source or "").strip().lower()

    if normalized_source == "suricata":
        return [
            {
                "timestamp": timestamp,
                "event_type": "alert",
                "src_ip": "198.51.100.22",
                "src_port": 33445,
                "dest_ip": "172.20.0.16",
                "dest_port": 443,
                "proto": "TCP",
                "flow_id": f"keepalive-suricata-{minute_bucket}",
                "alert": {
                    "signature_id": 2400021,
                    "signature": "ET TROJAN Suspicious outbound TLS SNI",
                    "category": "Potential Malware Command and Control",
                    "severity": 1,
                },
            }
        ]
    if normalized_source == "zeek":
        return [
            {
                "ts": timestamp,
                "event_type": "dns",
                "uid": f"keepalive-zeek-{minute_bucket}",
                "id.orig_h": "172.20.0.15",
                "id.resp_h": "8.8.8.8",
                "id.orig_p": 51515,
                "id.resp_p": 53,
                "proto": "udp",
                "query": "keepalive.secplat-lab.example",
                "qtype_name": "A",
            }
        ]
    if normalized_source == "auditd":
        return [
            {
                "timestamp": timestamp,
                "type": "execve",
                "exe": "/usr/bin/sudo",
                "comm": "sudo",
                "auid": "1001",
                "msg": "keepalive sudo check",
                "serial": f"keepalive-auditd-{minute_bucket}",
            }
        ]
    if normalized_source == "authlog":
        return [
            {
                "timestamp": timestamp,
                "event_type": "ssh_auth_failed",
                "title": "SSH authentication failed",
                "description": "Failed password for root from 203.0.113.75 port 42111 ssh2",
                "severity": "high",
                "protocol": "ssh",
                "src_ip": "203.0.113.75",
                "src_port": 42111,
                "host": "secplat-lab",
                "process": "sshd",
                "username": "root",
                "dedupe_key": f"keepalive-authlog-{minute_bucket}",
            }
        ]
    if normalized_source == "cowrie":
        return [
            {
                "timestamp": timestamp,
                "eventid": "cowrie.login.failed",
                "src_ip": "203.0.113.55",
                "username": "root",
                "session": f"keepalive-cowrie-{minute_bucket}",
                "message": "keepalive failed login",
            },
            {
                "timestamp": timestamp,
                "eventid": "cowrie.command.input",
                "src_ip": "203.0.113.55",
                "session": f"keepalive-cowrie-{minute_bucket}",
                "input": "uname -a",
            },
        ]
    return [
        {
            "timestamp": timestamp,
            "event_type": "event",
            "title": "Telemetry keepalive",
            "description": f"Keepalive event for source {normalized_source or 'custom'}",
        }
    ]


def ensure_recent_telemetry_activity(
    *,
    sources: list[str] | None = None,
    max_silence_minutes: int = 3,
    asset_key: str | None = None,
    create_alerts: bool = False,
) -> dict[str, Any]:
    """Inject keepalive telemetry if configured sources have gone quiet."""
    selected_sources = [
        s
        for s in [(item or "").strip().lower() for item in (sources or [])]
        if s in {"suricata", "zeek", "auditd", "authlog", "cowrie", "custom"}
    ]
    if not selected_sources:
        selected_sources = ["suricata", "zeek", "auditd", "cowrie"]
    # Preserve order while removing duplicates.
    selected_sources = list(dict.fromkeys(selected_sources))

    effective_asset_key = (asset_key or "").strip() or None
    db = SessionLocal()
    try:
        params: dict[str, Any] = {}
        placeholders: list[str] = []
        for idx, source in enumerate(selected_sources):
            key = f"s{idx}"
            params[key] = source
            placeholders.append(f":{key}")
        rows = (
            db.execute(
                text(
                    f"""
                    SELECT source, MAX(event_time) AS last_event_time
                    FROM security_events
                    WHERE source IN ({", ".join(placeholders)})
                    GROUP BY source
                    """
                ),
                params,
            )
            .mappings()
            .all()
        )
        last_seen_by_source: dict[str, datetime | None] = {
            str(row.get("source") or ""): _parse_dt(row.get("last_event_time")) for row in rows
        }
        now = datetime.now(UTC)
        cutoff = now - timedelta(minutes=max(1, int(max_silence_minutes)))
        injected_by_source: dict[str, int] = {}
        for source in selected_sources:
            last_seen = last_seen_by_source.get(source)
            if last_seen and last_seen >= cutoff:
                continue
            events = build_keepalive_events(source, now=now)
            summary = ingest_telemetry_events(
                db,
                source=source,
                events=events,
                default_asset_key=effective_asset_key,
                create_alerts=create_alerts,
                collector=f"keepalive.{source}",
                raw_path=f"keepalive://{source}",
            )
            injected = int(summary.get("processed_events") or 0)
            if injected > 0:
                injected_by_source[source] = injected
        if injected_by_source:
            db.commit()
        return {
            "checked_sources": selected_sources,
            "max_silence_minutes": int(max_silence_minutes),
            "injected_by_source": injected_by_source,
            "injected_events": int(sum(injected_by_source.values())),
            "last_event_time_by_source": {
                source: _iso_z(last_seen_by_source.get(source)) for source in selected_sources
            },
        }
    finally:
        db.close()
