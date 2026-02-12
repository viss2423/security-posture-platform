"""
SecPlat scanner: TLS + security headers. Supports two scopes:
- internal_only: scan only INTERNAL_TARGETS (or VERIFY_WEB_URL, JUICE_URL, API_URL).
- internal_and_verified: internal targets + assets from API with verified=true (external_web).
"""
import logging
import sys
import time

import httpx

from config import (
    API_URL,
    INTERNAL_TARGETS,
    MAX_TARGETS,
    SCOPE,
    SCAN_INTERVAL_SECONDS,
)
from scans import run_scans

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scanner")


def get_verified_targets() -> list[tuple[str, str]]:
    """Fetch assets with verified=true; return (url, asset_key). URL from address or https://asset_key."""
    targets = []
    try:
        r = httpx.get(f"{API_URL}/assets/", timeout=15.0)
        r.raise_for_status()
        assets = r.json()
    except Exception as e:
        logger.warning("Failed to fetch assets for verified targets: %s", e)
        return targets
    for a in assets[:MAX_TARGETS]:
        if not a.get("verified"):
            continue
        if a.get("type") != "external_web":
            continue
        address = (a.get("address") or "").strip()
        asset_key = (a.get("asset_key") or "").strip()
        if not asset_key:
            continue
        url = address if address else f"https://{asset_key}"
        if not url.startswith("http"):
            url = "https://" + url
        targets.append((url, asset_key))
    return targets


def get_all_targets() -> list[tuple[str, str]]:
    """Internal + (if scope internal_and_verified) verified external."""
    seen_urls = set()
    out = []
    for url, key in INTERNAL_TARGETS:
        if url not in seen_urls:
            seen_urls.add(url)
            out.append((url, key))
    if SCOPE == "internal_and_verified":
        for url, key in get_verified_targets():
            if url not in seen_urls and len(out) < MAX_TARGETS:
                seen_urls.add(url)
                out.append((url, key))
    return out


def submit_finding(finding: dict, asset_key: str) -> bool:
    """POST one finding to API. Returns True on success."""
    payload = {
        "finding_key": finding["finding_key"],
        "asset_key": asset_key,
        "category": finding.get("category"),
        "title": finding["title"],
        "severity": finding.get("severity", "medium"),
        "confidence": finding.get("confidence", "high"),
        "evidence": finding.get("evidence"),
        "remediation": finding.get("remediation"),
        "source": finding.get("source"),
    }
    try:
        r = httpx.post(f"{API_URL}/findings/", json=payload, timeout=10.0)
        r.raise_for_status()
        return True
    except Exception as e:
        logger.warning("Submit finding %s: %s", finding.get("finding_key"), e)
        return False


def run_once() -> None:
    targets = get_all_targets()
    logger.info("Scope=%s, targets=%d", SCOPE, len(targets))
    submitted = 0
    for url, asset_key in targets:
        try:
            findings = run_scans(url, asset_key)
            for f in findings:
                if submit_finding(f, asset_key):
                    submitted += 1
        except Exception as e:
            logger.warning("Scan %s (%s): %s", url, asset_key, e)
    logger.info("Submitted %d findings", submitted)


def main() -> None:
    if SCOPE not in ("internal_only", "internal_and_verified"):
        logger.error("Invalid SCANNER_SCOPE=%s; use internal_only or internal_and_verified", SCOPE)
        sys.exit(1)
    logger.info("Scanner started; scope=%s, interval=%ds", SCOPE, SCAN_INTERVAL_SECONDS)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.exception("Run failed: %s", e)
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
