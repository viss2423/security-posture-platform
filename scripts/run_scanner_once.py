#!/usr/bin/env python3
"""Run scanner once and submit findings to API. Usage: python scripts/run_scanner_once.py"""
import hashlib
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    print("httpx not installed. Run: pip install httpx")
    sys.exit(1)

API_URL = "http://localhost:8000"  # Change if needed

TARGETS = [
    ("http://localhost:8081", "verify-web"),      # verify-web (nginx)
    ("http://localhost:3000", "juice-shop"),      # Juice Shop
    ("http://localhost:8000", "secplat-api"),     # API
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "high", "Add Strict-Transport-Security header."),
    ("Content-Security-Policy", "CSP", "medium", "Add Content-Security-Policy header."),
    ("X-Frame-Options", "X-Frame-Options", "medium", "Add X-Frame-Options header."),
    ("X-Content-Type-Options", "X-Content-Type-Options", "low", "Add X-Content-Type-Options: nosniff."),
]


def finding_key(asset_key: str, category: str, title: str) -> str:
    raw = f"{asset_key}:{category}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def scan_headers(url: str, asset_key: str) -> list[dict]:
    findings = []
    try:
        r = httpx.get(url, follow_redirects=True, timeout=10.0)
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
    except httpx.HTTPError as e:
        findings.append({
            "finding_key": finding_key(asset_key, "headers", "HTTP request failed"),
            "asset_key": asset_key,
            "category": "security_headers",
            "title": "HTTP request failed",
            "severity": "medium",
            "confidence": "high",
            "evidence": str(e)[:300],
            "remediation": "Ensure the URL is reachable.",
            "source": "header_scan",
        })
        return findings

    for header_name, short_name, severity, remediation in SECURITY_HEADERS:
        if header_name.lower() not in headers_lower:
            findings.append({
                "finding_key": finding_key(asset_key, "headers", f"Missing {short_name}"),
                "asset_key": asset_key,
                "category": "security_headers",
                "title": f"Missing {short_name}",
                "severity": severity,
                "confidence": "high",
                "evidence": f"Header {header_name} not present in response",
                "remediation": remediation,
                "source": "header_scan",
            })
    return findings


def scan_tls(url: str, asset_key: str) -> list[dict]:
    p = urlparse(url)
    scheme = p.scheme or "http"
    if scheme != "https":
        return [{
            "finding_key": finding_key(asset_key, "tls", "No HTTPS"),
            "asset_key": asset_key,
            "category": "tls",
            "title": "No HTTPS",
            "severity": "high",
            "confidence": "high",
            "evidence": f"URL uses {scheme}",
            "remediation": "Serve over HTTPS.",
            "source": "tls_scan",
        }]
    # If HTTPS, check cert (not applicable for local HTTP targets)
    return []


def submit(finding: dict) -> bool:
    try:
        r = httpx.post(f"{API_URL}/findings/", json=finding, timeout=10.0)
        r.raise_for_status()
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False


def main():
    print(f"Scanner: running against {len(TARGETS)} targets...")
    total = 0
    for url, asset_key in TARGETS:
        print(f"\n[{asset_key}] {url}")
        findings = []
        findings.extend(scan_tls(url, asset_key))
        findings.extend(scan_headers(url, asset_key))
        for f in findings:
            ok = submit(f)
            status = "OK" if ok else "FAIL"
            print(f"  {status}: {f['title']} ({f['severity']})")
            if ok:
                total += 1
    print(f"\nDone. Submitted {total} findings. Visit http://localhost:3002/findings (or your frontend URL).")


if __name__ == "__main__":
    main()
