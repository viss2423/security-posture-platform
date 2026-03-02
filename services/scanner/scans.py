"""TLS and security-headers checks. Returns list of finding dicts (category, title, severity, evidence, remediation, finding_key)."""
import hashlib
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from config import REQUEST_TIMEOUT

# Headers we care about (presence = good; absence = finding)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "high", "Add Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains)."),
    ("Content-Security-Policy", "CSP", "medium", "Add Content-Security-Policy to reduce XSS risk."),
    ("X-Frame-Options", "X-Frame-Options", "medium", "Add X-Frame-Options (e.g. DENY or SAMEORIGIN)."),
    ("X-Content-Type-Options", "X-Content-Type-Options", "low", "Add X-Content-Type-Options: nosniff."),
]


def _finding_key(asset_key: str, category: str, title: str, extra: str = "") -> str:
    raw = f"{asset_key}:{category}:{title}:{extra}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _parse_url(url: str) -> tuple[str, str, int, bool]:
    p = urlparse(url)
    scheme = p.scheme or "http"
    host = p.hostname or p.path or "localhost"
    port = p.port or (443 if scheme == "https" else 80)
    return host, scheme, port, scheme == "https"


def scan_tls(url: str, asset_key: str) -> list[dict]:
    """TLS posture: cert expiry days, issuer, protocol. Returns finding dicts."""
    host, scheme, port, is_https = _parse_url(url)
    if not is_https:
        return [
            {
                "finding_key": _finding_key(asset_key, "tls", "No HTTPS"),
                "category": "tls",
                "title": "No HTTPS",
                "severity": "high",
                "confidence": "high",
                "evidence": f"URL uses {scheme}",
                "remediation": "Serve over HTTPS.",
                "source": "tls_scan",
            }
        ]
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_cn = issuer.get("commonName", "—")
                protocol = ssock.version()
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "finding_key": _finding_key(asset_key, "tls", "Certificate verification failed"),
            "category": "tls",
            "title": "Certificate verification failed",
            "severity": "high",
            "confidence": "high",
            "evidence": str(e)[:500],
            "remediation": "Fix certificate chain or hostname mismatch.",
            "source": "tls_scan",
        })
        return findings
    except (socket.timeout, OSError, ssl.SSLError) as e:
        findings.append({
            "finding_key": _finding_key(asset_key, "tls", "TLS connection failed"),
            "category": "tls",
            "title": "TLS connection failed",
            "severity": "medium",
            "confidence": "high",
            "evidence": str(e)[:500],
            "remediation": "Ensure TLS is enabled and reachable.",
            "source": "tls_scan",
        })
        return findings

    if days_left <= 0:
        findings.append({
            "finding_key": _finding_key(asset_key, "tls", "Certificate expired"),
            "category": "tls",
            "title": "Certificate expired",
            "severity": "critical",
            "confidence": "high",
            "evidence": f"Expired {exp.isoformat()}",
            "remediation": "Renew the certificate.",
            "source": "tls_scan",
        })
    elif days_left <= 14:
        findings.append({
            "finding_key": _finding_key(asset_key, "tls", "Certificate expiring within 14 days"),
            "category": "tls",
            "title": f"Certificate expiring in {days_left} days",
            "severity": "high",
            "confidence": "high",
            "evidence": f"Expires {exp.isoformat()}, issuer {issuer_cn}",
            "remediation": "Renew the certificate before expiry.",
            "source": "tls_scan",
        })
    # Optional: low-severity metadata finding for visibility (cert OK)
    # findings.append({ "title": "TLS OK", "severity": "info", ... })  # skip to avoid noise
    return findings


def scan_headers(url: str, asset_key: str) -> list[dict]:
    """Security headers: presence of HSTS, CSP, X-Frame-Options, X-Content-Type-Options."""
    findings = []
    try:
        r = httpx.get(url, follow_redirects=True, timeout=REQUEST_TIMEOUT)
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
    except httpx.HTTPError as e:
        findings.append({
            "finding_key": _finding_key(asset_key, "headers", "HTTP request failed"),
            "category": "security_headers",
            "title": "HTTP request failed",
            "severity": "medium",
            "confidence": "high",
            "evidence": str(e)[:500],
            "remediation": "Ensure the URL is reachable.",
            "source": "header_scan",
        })
        return findings

    for header_name, short_name, severity, remediation in SECURITY_HEADERS:
        if header_name.lower() not in headers_lower:
            findings.append({
                "finding_key": _finding_key(asset_key, "headers", f"Missing {short_name}"),
                "category": "security_headers",
                "title": f"Missing {short_name}",
                "severity": severity,
                "confidence": "high",
                "evidence": f"Header {header_name} not present",
                "remediation": remediation,
                "source": "header_scan",
            })
    return findings


def run_scans(url: str, asset_key: str) -> list[dict]:
    """Run TLS + headers scans for one URL. Returns combined finding dicts."""
    out = []
    out.extend(scan_tls(url, asset_key))
    out.extend(scan_headers(url, asset_key))
    return out
