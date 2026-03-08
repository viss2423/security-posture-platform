"""Threat-intelligence feed refresh and asset matching."""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import text

from .campaign_tracker import normalize_campaign_tag, normalize_confidence_label
from .db import SessionLocal
from .intel_confidence_service import (
    blended_confidence,
    confidence_label,
    normalize_confidence_score,
    normalize_source_priority,
)
from .queue import publish_scan_job
from .settings import settings

logger = logging.getLogger("secplat.threat_intel")


def _is_deadlock_retryable(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "deadlock detected" in message
        or "current transaction is aborted" in message
        or "serialization failure" in message
    )


def _run_db_with_retry(
    db,
    operation_name: str,
    fn,
    *,
    retries: int = 4,
    base_delay_seconds: float = 0.1,
):
    for attempt in range(retries + 1):
        try:
            return fn()
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                pass
            if attempt >= retries or not _is_deadlock_retryable(exc):
                raise
            delay = base_delay_seconds * (2**attempt)
            logger.warning(
                "threat_intel_retry operation=%s attempt=%s delay=%.3fs error=%s",
                operation_name,
                attempt + 1,
                delay,
                exc,
            )
            time.sleep(delay)
    raise RuntimeError("threat_intel_retry_exhausted")

DEFAULT_THREAT_INTEL_FEEDS: list[dict[str, Any]] = [
    {
        "source": "abuseipdb-s100-mirror",
        "url": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4",
        "indicator_type": "ip",
        "format": "text",
    },
    {
        "source": "ciarmy-badguys",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "indicator_type": "ip",
        "format": "text",
    },
    {
        "source": "binary-defense-banlist",
        "url": "https://www.binarydefense.com/banlist.txt",
        "indicator_type": "ip",
        "format": "text",
    },
    {
        "source": "openphish-urls",
        "url": "https://openphish.com/feed.txt",
        "indicator_type": "domain",
        "format": "text",
    },
    {
        "source": "crowdsec-community",
        "url": "https://admin.api.crowdsec.net/v1/blocklists/community/download",
        "indicator_type": "ip",
        "format": "text",
        "optional": True,
        "headers_env": {"x-api-key": "THREAT_INTEL_CROWDSEC_API_KEY"},
    },
    {
        "source": "abuseipdb-official",
        "url": "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90",
        "indicator_type": "ip",
        "format": "text",
        "optional": True,
        "headers": {"Accept": "text/plain"},
        "headers_env": {"Key": "THREAT_INTEL_ABUSEIPDB_API_KEY"},
    },
]

SOURCE_CONFIDENCE_PROFILES: dict[str, dict[str, Any]] = {
    "abuseipdb-official": {"priority": 90, "confidence": 0.9},
    "abuseipdb-s100-mirror": {"priority": 80, "confidence": 0.82},
    "crowdsec-community": {"priority": 78, "confidence": 0.8},
    "binary-defense-banlist": {"priority": 74, "confidence": 0.76},
    "ciarmy-badguys": {"priority": 70, "confidence": 0.72},
    "openphish-urls": {"priority": 83, "confidence": 0.86},
    "manual-lab": {"priority": 65, "confidence": 0.7},
}


def _job_log_line(message: str) -> str:
    return f"[{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}] {message}"


def _append_job_log(db, job_id: int, message: str) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET log_output = COALESCE(log_output, '') || :line || E'\n'
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "line": _job_log_line(message)},
    )
    db.commit()


def _set_job_running(db, job_id: int) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET status = 'running',
                   started_at = NOW(),
                   finished_at = NULL,
                   error = NULL
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id},
    )
    db.commit()


def _finish_job(
    db, job_id: int, *, ok: bool, error: str | None = None, message: str | None = None
) -> None:
    if message:
        _append_job_log(db, job_id, message)
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET status = :status,
                   finished_at = NOW(),
                   error = :error
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "status": "done" if ok else "failed", "error": error},
    )
    db.commit()


def _normalize_feed(feed: dict[str, Any]) -> dict[str, Any] | None:
    source = str(feed.get("source") or feed.get("name") or "").strip().lower()
    url = str(feed.get("url") or "").strip()
    indicator_type = str(feed.get("indicator_type") or "").strip().lower()
    fmt = str(feed.get("format") or "text").strip().lower()
    optional = bool(feed.get("optional") is True)
    headers: dict[str, str] = {}
    raw_headers = feed.get("headers") or {}
    if raw_headers is not None and not isinstance(raw_headers, dict):
        raise ValueError(f"feed_headers_invalid:{source or 'unknown'}")
    for header_name, header_value in (raw_headers or {}).items():
        normalized_name = str(header_name or "").strip()
        normalized_value = str(header_value or "").strip()
        if normalized_name and normalized_value:
            headers[normalized_name] = normalized_value
    raw_headers_env = feed.get("headers_env") or {}
    if raw_headers_env is not None and not isinstance(raw_headers_env, dict):
        raise ValueError(f"feed_headers_env_invalid:{source or 'unknown'}")
    missing_env_vars: list[str] = []
    for header_name, setting_name in (raw_headers_env or {}).items():
        normalized_name = str(header_name or "").strip()
        normalized_setting_name = str(setting_name or "").strip()
        if not normalized_name or not normalized_setting_name:
            continue
        setting_value = str(getattr(settings, normalized_setting_name, "") or "").strip()
        if setting_value:
            headers[normalized_name] = setting_value
        else:
            missing_env_vars.append(normalized_setting_name)
    if not source:
        raise ValueError("feed_source_required")
    if not url:
        raise ValueError(f"feed_url_required:{source}")
    if indicator_type not in {"ip", "domain"}:
        raise ValueError(f"feed_indicator_type_invalid:{source}")
    if fmt not in {"text"}:
        raise ValueError(f"feed_format_invalid:{source}")
    if missing_env_vars and optional:
        return None
    if missing_env_vars:
        raise ValueError(f"feed_headers_missing:{source}:{','.join(missing_env_vars)}")

    profile = SOURCE_CONFIDENCE_PROFILES.get(source, {})
    source_priority = normalize_source_priority(
        feed.get("source_priority"),
        default=int(profile.get("priority", 50)),
    )
    base_confidence = normalize_confidence_score(
        feed.get("confidence_score") if "confidence_score" in feed else feed.get("confidence"),
        default=float(profile.get("confidence", 0.6)),
    )
    campaign_tag = normalize_campaign_tag(feed.get("campaign_tag"))
    campaign_title = str(feed.get("campaign_title") or "").strip() or None
    expires_in_days_raw = feed.get("expires_in_days")
    expires_in_days: int | None = None
    if expires_in_days_raw is not None:
        try:
            expires_in_days = max(0, int(expires_in_days_raw))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"feed_expires_invalid:{source}") from exc
    return {
        "source": source,
        "url": url,
        "indicator_type": indicator_type,
        "format": fmt,
        "headers": headers,
        "optional": optional,
        "source_priority": source_priority,
        "confidence_score": base_confidence,
        "campaign_tag": campaign_tag,
        "campaign_title": campaign_title,
        "expires_in_days": expires_in_days,
    }


def _configured_feeds(job_params: dict[str, Any]) -> list[dict[str, Any]]:
    override = job_params.get("feeds")
    raw = override
    if raw is None:
        raw = settings.THREAT_INTEL_FEEDS_JSON.strip()
    if isinstance(raw, str) and raw:
        loaded = json.loads(raw)
    elif isinstance(raw, list):
        loaded = raw
    else:
        loaded = DEFAULT_THREAT_INTEL_FEEDS
    if not isinstance(loaded, list):
        raise ValueError("threat_intel_feeds_invalid")
    normalized: list[dict[str, Any]] = []
    for item in loaded:
        if not isinstance(item, dict):
            continue
        feed = _normalize_feed(item)
        if feed:
            normalized.append(feed)
    return normalized


def _extract_candidate(raw_value: str, *, indicator_type: str) -> str | None:
    normalized = raw_value.strip()
    if not normalized:
        return None
    if normalized.startswith(("http://", "https://")):
        host = urlparse(normalized).hostname or ""
    else:
        if indicator_type == "domain" and " " in normalized:
            host = normalized.split()[-1]
        else:
            host = normalized.split(",")[0].split()[0]
        if "/" in host:
            host = host.split("/", 1)[0]
        if ":" in host and indicator_type == "domain":
            host = host.split(":", 1)[0]
    host = host.strip().strip("[]").lower().rstrip(".")
    if not host:
        return None
    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if host.startswith("*."):
        host = host[2:]
    if not host or " " in host or "." not in host:
        return None
    return host


def _parse_text_feed(content: str, *, indicator_type: str) -> list[str]:
    indicators: list[str] = []
    seen: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "//")):
            continue
        candidate = _extract_candidate(stripped, indicator_type=indicator_type)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        indicators.append(candidate)
    return indicators


def _fetch_feed(feed: dict[str, Any]) -> dict[str, Any]:
    headers = {"User-Agent": "SecPlat Threat Intel/1.0"}
    for key, value in (feed.get("headers") or {}).items():
        normalized_key = str(key or "").strip()
        normalized_value = str(value or "").strip()
        if normalized_key and normalized_value:
            headers[normalized_key] = normalized_value
    with httpx.Client(
        follow_redirects=True,
        timeout=max(int(settings.THREAT_INTEL_HTTP_TIMEOUT_SECONDS), 1),
        headers=headers,
    ) as client:
        response = client.get(feed["url"])
        response.raise_for_status()
    indicators = _parse_text_feed(response.text, indicator_type=feed["indicator_type"])
    expires_at = None
    expires_in_days = feed.get("expires_in_days")
    if isinstance(expires_in_days, int) and expires_in_days > 0:
        expires_at = (datetime.now(UTC) + timedelta(days=expires_in_days)).isoformat()
    return {
        "source": feed["source"],
        "url": feed["url"],
        "indicator_type": feed["indicator_type"],
        "indicators": indicators,
        "source_priority": normalize_source_priority(feed.get("source_priority"), default=50),
        "confidence_score": normalize_confidence_score(feed.get("confidence_score"), default=0.6),
        "campaign_tag": normalize_campaign_tag(feed.get("campaign_tag")),
        "campaign_title": feed.get("campaign_title"),
        "expires_at": expires_at,
    }


def _manual_iocs(job_params: dict[str, Any]) -> list[dict[str, Any]]:
    raw = job_params.get("manual_iocs") or []
    if isinstance(raw, str) and raw.strip():
        loaded = json.loads(raw)
    else:
        loaded = raw
    if not isinstance(loaded, list):
        return []
    grouped: dict[tuple[str, str, int, float, str | None], list[str]] = {}
    for item in loaded:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "manual-lab").strip().lower()
        indicator_type = str(item.get("indicator_type") or "").strip().lower()
        indicator = _extract_candidate(
            str(item.get("indicator") or ""),
            indicator_type=indicator_type,
        )
        if indicator_type not in {"ip", "domain"} or not indicator:
            continue
        source_profile = SOURCE_CONFIDENCE_PROFILES.get(source, {})
        source_priority = normalize_source_priority(
            item.get("source_priority"),
            default=int(source_profile.get("priority", 65)),
        )
        confidence_score = normalize_confidence_score(
            item.get("confidence_score") if "confidence_score" in item else item.get("confidence"),
            default=float(source_profile.get("confidence", 0.7)),
        )
        campaign_tag = normalize_campaign_tag(item.get("campaign_tag"))
        key = (source, indicator_type, source_priority, confidence_score, campaign_tag)
        grouped.setdefault(key, [])
        if indicator not in grouped[key]:
            grouped[key].append(indicator)
    return [
        {
            "source": source,
            "url": None,
            "indicator_type": indicator_type,
            "indicators": indicators,
            "source_priority": source_priority,
            "confidence_score": confidence_score,
            "campaign_tag": campaign_tag,
            "campaign_title": str(campaign_tag or "").replace("-", " ").title() or None,
            "expires_at": None,
        }
        for (source, indicator_type, source_priority, confidence_score, campaign_tag), indicators in grouped.items()
    ]


def _upsert_iocs(db, feed_results: list[dict[str, Any]]) -> tuple[int, int]:
    total = 0
    by_source: dict[str, list[dict[str, Any]]] = {}
    for result in feed_results:
        source = str(result.get("source") or "").strip()
        if not source:
            continue
        by_source.setdefault(source, []).append(result)

    campaign_rows = (
        db.execute(
            text(
                """
                SELECT campaign_tag, confidence_weight, source_priority, confidence_label
                FROM threat_ioc_campaigns
                WHERE is_active = TRUE
                """
            )
        )
        .mappings()
        .all()
    )
    campaign_profiles: dict[str, dict[str, Any]] = {}
    for row in campaign_rows:
        tag = normalize_campaign_tag(row.get("campaign_tag"))
        if not tag:
            continue
        campaign_profiles[tag] = {
            "confidence_weight": row.get("confidence_weight"),
            "source_priority": row.get("source_priority"),
            "confidence_label": row.get("confidence_label"),
        }

    refreshed_sources: set[str] = set(by_source.keys())
    for source, source_results in by_source.items():
        current_keys: set[tuple[str, str]] = set()
        for result in source_results:
            indicator_type = str(result.get("indicator_type") or "").strip().lower()
            for indicator in result.get("indicators") or []:
                normalized = str(indicator or "").strip().lower()
                if indicator_type in {"ip", "domain"} and normalized:
                    current_keys.add((indicator_type, normalized))

        existing_rows = (
            db.execute(
                text(
                    """
                    SELECT id, indicator, indicator_type
                    FROM threat_iocs
                    WHERE source = :source
                    """
                ),
                {"source": source},
            )
            .mappings()
            .all()
        )
        for row in existing_rows:
            key = (
                str(row.get("indicator_type") or "").strip().lower(),
                str(row.get("indicator") or "").strip().lower(),
            )
            if key not in current_keys:
                db.execute(
                    text(
                        """
                        UPDATE threat_iocs
                           SET is_active = FALSE,
                               updated_at = NOW()
                         WHERE id = :id
                        """
                    ),
                    {"id": int(row["id"])},
                )
        for result in source_results:
            indicator_type = str(result.get("indicator_type") or "").strip().lower()
            feed_url = result.get("url")
            source_priority = normalize_source_priority(result.get("source_priority"), default=50)
            base_confidence = normalize_confidence_score(
                result.get("confidence_score"),
                default=0.6,
            )
            campaign_tag = normalize_campaign_tag(result.get("campaign_tag"))
            campaign_title = str(result.get("campaign_title") or "").strip() or None
            campaign_profile = campaign_profiles.get(campaign_tag or "")
            effective_priority = source_priority
            if campaign_profile:
                effective_priority = normalize_source_priority(
                    campaign_profile.get("source_priority"),
                    default=source_priority,
                )
            effective_confidence = blended_confidence(
                base_score=base_confidence,
                source_priority=effective_priority,
                campaign_weight=(campaign_profile or {}).get("confidence_weight", 1.0),
            )
            confidence_lbl = normalize_confidence_label(
                (campaign_profile or {}).get("confidence_label"),
                default=confidence_label(effective_confidence),
            )
            expires_at = result.get("expires_at")
            if campaign_tag:
                db.execute(
                    text(
                        """
                        INSERT INTO threat_ioc_campaigns(
                          campaign_tag, title, description, confidence_weight, source_priority,
                          confidence_label, is_active, created_by, created_at, updated_at
                        )
                        VALUES (
                          :campaign_tag, :title, :description, 1.0, :source_priority,
                          :confidence_label, TRUE, 'system-threat-intel', NOW(), NOW()
                        )
                        ON CONFLICT (campaign_tag) DO UPDATE
                        SET updated_at = NOW()
                        """
                    ),
                    {
                        "campaign_tag": campaign_tag,
                        "title": campaign_title or campaign_tag.replace("-", " ").title(),
                        "description": f"Auto-created from feed source {source}",
                        "source_priority": effective_priority,
                        "confidence_label": confidence_lbl,
                    },
                )
            for indicator in result.get("indicators") or []:
                normalized = str(indicator or "").strip().lower()
                if indicator_type not in {"ip", "domain"} or not normalized:
                    continue
                metadata = {
                    "feed_url": feed_url,
                    "source": source,
                    "indicator_type": indicator_type,
                    "source_priority": effective_priority,
                    "confidence_score": effective_confidence,
                    "confidence_label": confidence_lbl,
                    "campaign_tag": campaign_tag,
                }
                db.execute(
                    text(
                        """
                        INSERT INTO threat_iocs(
                          source, indicator, indicator_type, feed_url, first_seen_at, last_seen_at,
                          is_active, metadata, confidence_score, confidence_label, source_priority,
                          campaign_tag, expires_at, created_at, updated_at
                        )
                        VALUES (
                          :source, :indicator, :indicator_type, :feed_url, NOW(), NOW(),
                          TRUE, CAST(:metadata AS jsonb), :confidence_score, :confidence_label,
                          :source_priority, :campaign_tag, :expires_at, NOW(), NOW()
                        )
                        ON CONFLICT (source, indicator_type, indicator) DO UPDATE
                        SET feed_url = EXCLUDED.feed_url,
                            last_seen_at = NOW(),
                            is_active = TRUE,
                            confidence_score = EXCLUDED.confidence_score,
                            confidence_label = EXCLUDED.confidence_label,
                            source_priority = EXCLUDED.source_priority,
                            campaign_tag = EXCLUDED.campaign_tag,
                            expires_at = EXCLUDED.expires_at,
                            metadata = EXCLUDED.metadata,
                            updated_at = NOW()
                        """
                    ),
                    {
                        "source": source,
                        "indicator": normalized,
                        "indicator_type": indicator_type,
                        "feed_url": feed_url,
                        "confidence_score": effective_confidence,
                        "confidence_label": confidence_lbl,
                        "source_priority": effective_priority,
                        "campaign_tag": campaign_tag,
                        "expires_at": expires_at,
                        "metadata": json.dumps(metadata),
                    },
                )
                total += 1
    db.commit()
    return total, len(refreshed_sources)


def _domain_candidate(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    candidate = _extract_candidate(str(raw_value), indicator_type="domain")
    if candidate and "." in candidate:
        return candidate
    return None


def _ip_candidate(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    return _extract_candidate(str(raw_value), indicator_type="ip")


def _rebuild_asset_matches(db) -> int:
    rows = (
        db.execute(
            text(
                """
                SELECT asset_id, asset_key, name, address
                FROM assets
                WHERE COALESCE(is_active, TRUE) = TRUE
                """
            )
        )
        .mappings()
        .all()
    )
    asset_lookup: dict[str, dict[str, list[dict[str, Any]]]] = {"domain": {}, "ip": {}}
    for row in rows:
        asset_id = int(row["asset_id"])
        asset_key = str(row.get("asset_key") or "")
        name = str(row.get("name") or "")
        address = row.get("address")
        for field, value in (
            ("address", address),
            ("name", name),
            ("asset_key", asset_key),
        ):
            domain = _domain_candidate(value)
            if domain:
                asset_lookup["domain"].setdefault(domain, []).append(
                    {
                        "asset_id": asset_id,
                        "asset_key": asset_key,
                        "match_field": field,
                        "matched_value": domain,
                    }
                )
            ip_value = _ip_candidate(value)
            if ip_value:
                asset_lookup["ip"].setdefault(ip_value, []).append(
                    {
                        "asset_id": asset_id,
                        "asset_key": asset_key,
                        "match_field": field,
                        "matched_value": ip_value,
                    }
                )
    active_iocs = (
        db.execute(
            text(
                """
                SELECT id, source, indicator, indicator_type, campaign_tag, confidence_label, confidence_score
                FROM threat_iocs
                WHERE is_active = TRUE
                """
            )
        )
        .mappings()
        .all()
    )
    db.execute(text("DELETE FROM threat_ioc_asset_matches"))
    db.execute(text("UPDATE threat_iocs SET last_match_count = 0 WHERE is_active = TRUE"))
    match_counts: dict[int, int] = {}
    inserted = 0
    for ioc in active_iocs:
        threat_ioc_id = int(ioc["id"])
        indicator = str(ioc.get("indicator") or "").strip().lower()
        indicator_type = str(ioc.get("indicator_type") or "").strip().lower()
        matches = asset_lookup.get(indicator_type, {}).get(indicator, [])
        unique_matches: list[dict[str, Any]] = []
        seen_keys: set[tuple[int, str, str]] = set()
        for match in matches:
            match_key = (
                int(match["asset_id"]),
                str(match["match_field"]),
                str(match["matched_value"]),
            )
            if match_key in seen_keys:
                continue
            seen_keys.add(match_key)
            unique_matches.append(match)
        match_counts[threat_ioc_id] = len(unique_matches)
        for match in unique_matches:
            db.execute(
                text(
                    """
                    INSERT INTO threat_ioc_asset_matches(
                      threat_ioc_id, asset_id, asset_key, match_field, matched_value,
                      first_seen_at, last_seen_at, metadata
                    )
                    VALUES (
                      :threat_ioc_id, :asset_id, :asset_key, :match_field, :matched_value,
                      NOW(), NOW(), CAST(:metadata AS jsonb)
                    )
                    ON CONFLICT (threat_ioc_id, asset_id, match_field, matched_value)
                    DO UPDATE SET
                      asset_key = EXCLUDED.asset_key,
                      last_seen_at = EXCLUDED.last_seen_at,
                      metadata = EXCLUDED.metadata
                    """
                ),
                {
                    "threat_ioc_id": threat_ioc_id,
                    "asset_id": int(match["asset_id"]),
                    "asset_key": match["asset_key"],
                    "match_field": match["match_field"],
                    "matched_value": match["matched_value"],
                    "metadata": json.dumps({"source": ioc.get("source")}),
                },
            )
            db.execute(
                text(
                    """
                    INSERT INTO threat_ioc_sightings(
                      threat_ioc_id, asset_id, asset_key, match_field, matched_value,
                      source_event_id, source_event_ref, source_tool, sighted_at, context_json
                    )
                    VALUES (
                      :threat_ioc_id, :asset_id, :asset_key, :match_field, :matched_value,
                      NULL, :source_event_ref, 'threat_intel_refresh', NOW(), CAST(:context_json AS jsonb)
                    )
                    """
                ),
                {
                    "threat_ioc_id": threat_ioc_id,
                    "asset_id": int(match["asset_id"]),
                    "asset_key": match["asset_key"],
                    "match_field": match["match_field"],
                    "matched_value": match["matched_value"],
                    "source_event_ref": (
                        f"ioc:{threat_ioc_id}:{match['asset_key']}:"
                        f"{match['match_field']}:{match['matched_value']}"
                    ),
                    "context_json": json.dumps(
                        {
                            "source": ioc.get("source"),
                            "campaign_tag": ioc.get("campaign_tag"),
                            "confidence_label": ioc.get("confidence_label"),
                            "confidence_score": ioc.get("confidence_score"),
                        }
                    ),
                },
            )
            inserted += 1
    for threat_ioc_id, count in match_counts.items():
        db.execute(
            text(
                """
                UPDATE threat_iocs
                   SET last_match_count = :match_count,
                       updated_at = NOW()
                 WHERE id = :threat_ioc_id
                """
            ),
            {"threat_ioc_id": threat_ioc_id, "match_count": int(count)},
        )
    db.commit()
    return inserted


def run_threat_intel_refresh_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        _set_job_running(db, job_id)
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
            raise ValueError("threat_intel_job_not_found")
        params = row.get("job_params_json") or {}
        if isinstance(params, str):
            params = json.loads(params)
        feeds = _configured_feeds(params)
        manual = _manual_iocs(params)
        if not feeds and not manual:
            raise ValueError("threat_intel_no_feeds_configured")
        _append_job_log(db, job_id, "Threat-intel refresh started")
        results: list[dict[str, Any]] = []
        for feed in feeds:
            try:
                result = _fetch_feed(feed)
                results.append(result)
                _append_job_log(
                    db,
                    job_id,
                    f"Fetched {len(result['indicators'])} indicators from {feed['source']}",
                )
            except Exception as exc:
                logger.warning("threat_intel_feed_failed source=%s error=%s", feed["source"], exc)
                _append_job_log(
                    db,
                    job_id,
                    f"Feed failed for {feed['source']}: {exc}",
                )
        for result in manual:
            results.append(result)
            _append_job_log(
                db,
                job_id,
                f"Loaded {len(result['indicators'])} manual indicators for {result['source']}",
            )
        if not results:
            raise ValueError("threat_intel_feed_refresh_failed")
        total_iocs, refreshed_sources = _run_db_with_retry(
            db,
            "upsert_iocs",
            lambda: _upsert_iocs(db, results),
        )
        match_count = _run_db_with_retry(
            db,
            "rebuild_asset_matches",
            lambda: _rebuild_asset_matches(db),
        )
        _finish_job(
            db,
            job_id,
            ok=True,
            message=(
                f"Threat-intel refresh completed: {total_iocs} indicators across "
                f"{refreshed_sources} sources, {match_count} asset matches"
            ),
        )
    except Exception as exc:
        logger.exception("threat_intel_refresh_failed job_id=%s", job_id)
        try:
            db.rollback()
        except Exception:
            pass
        try:
            _finish_job(
                db,
                job_id,
                ok=False,
                error=str(exc),
                message=f"Threat-intel refresh failed: {exc}",
            )
        except Exception:
            logger.exception("threat_intel_refresh_finish_failed job_id=%s", job_id)
    finally:
        db.close()


def launch_threat_intel_refresh_job(job_id: int) -> None:
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
            logger.warning("threat_intel_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    published = publish_scan_job(
        int(job_id),
        "threat_intel_refresh",
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    )
    if not published:
        logger.warning("threat_intel_enqueue_failed job_id=%s", job_id)
