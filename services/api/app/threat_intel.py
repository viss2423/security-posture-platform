"""Threat-intelligence feed refresh and asset matching."""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import text

from .db import SessionLocal
from .settings import settings

logger = logging.getLogger("secplat.threat_intel")

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
    return {
        "source": source,
        "url": url,
        "indicator_type": indicator_type,
        "format": fmt,
        "headers": headers,
        "optional": optional,
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
    return {
        "source": feed["source"],
        "url": feed["url"],
        "indicator_type": feed["indicator_type"],
        "indicators": indicators,
    }


def _manual_iocs(job_params: dict[str, Any]) -> list[dict[str, Any]]:
    raw = job_params.get("manual_iocs") or []
    if isinstance(raw, str) and raw.strip():
        loaded = json.loads(raw)
    else:
        loaded = raw
    if not isinstance(loaded, list):
        return []
    grouped: dict[tuple[str, str], list[str]] = {}
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
        key = (source, indicator_type)
        grouped.setdefault(key, [])
        if indicator not in grouped[key]:
            grouped[key].append(indicator)
    return [
        {
            "source": source,
            "url": None,
            "indicator_type": indicator_type,
            "indicators": indicators,
        }
        for (source, indicator_type), indicators in grouped.items()
    ]


def _upsert_iocs(db, feed_results: list[dict[str, Any]]) -> tuple[int, int]:
    total = 0
    by_source: dict[str, list[dict[str, Any]]] = {}
    for result in feed_results:
        source = str(result.get("source") or "").strip()
        if not source:
            continue
        by_source.setdefault(source, []).append(result)

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
            for indicator in result.get("indicators") or []:
                normalized = str(indicator or "").strip().lower()
                if indicator_type not in {"ip", "domain"} or not normalized:
                    continue
                metadata = {
                    "feed_url": feed_url,
                    "source": source,
                    "indicator_type": indicator_type,
                }
                db.execute(
                    text(
                        """
                        INSERT INTO threat_iocs(
                          source, indicator, indicator_type, feed_url, first_seen_at, last_seen_at,
                          is_active, metadata, created_at, updated_at
                        )
                        VALUES (
                          :source, :indicator, :indicator_type, :feed_url, NOW(), NOW(),
                          TRUE, CAST(:metadata AS jsonb), NOW(), NOW()
                        )
                        ON CONFLICT (source, indicator_type, indicator) DO UPDATE
                        SET feed_url = EXCLUDED.feed_url,
                            last_seen_at = NOW(),
                            is_active = TRUE,
                            metadata = EXCLUDED.metadata,
                            updated_at = NOW()
                        """
                    ),
                    {
                        "source": source,
                        "indicator": normalized,
                        "indicator_type": indicator_type,
                        "feed_url": feed_url,
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
        domain_candidates = []
        ip_candidates = []
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
                domain_candidates.append(domain)
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
                ip_candidates.append(ip_value)
    active_iocs = (
        db.execute(
            text(
                """
                SELECT id, source, indicator, indicator_type
                FROM threat_iocs
                WHERE is_active = TRUE
                """
            )
        )
        .mappings()
        .all()
    )
    db.execute(text("DELETE FROM threat_ioc_asset_matches"))
    inserted = 0
    for ioc in active_iocs:
        indicator = str(ioc.get("indicator") or "").strip().lower()
        indicator_type = str(ioc.get("indicator_type") or "").strip().lower()
        matches = asset_lookup.get(indicator_type, {}).get(indicator, [])
        for match in matches:
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
                    """
                ),
                {
                    "threat_ioc_id": int(ioc["id"]),
                    "asset_id": int(match["asset_id"]),
                    "asset_key": match["asset_key"],
                    "match_field": match["match_field"],
                    "matched_value": match["matched_value"],
                    "metadata": json.dumps({"source": ioc.get("source")}),
                },
            )
            inserted += 1
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
        total_iocs, refreshed_sources = _upsert_iocs(db, results)
        match_count = _rebuild_asset_matches(db)
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
        _finish_job(
            db, job_id, ok=False, error=str(exc), message=f"Threat-intel refresh failed: {exc}"
        )
    finally:
        db.close()


def launch_threat_intel_refresh_job(job_id: int) -> None:
    thread = threading.Thread(
        target=run_threat_intel_refresh_job,
        args=(job_id,),
        name=f"threat-intel-job-{job_id}",
        daemon=True,
    )
    thread.start()
