"""
SecPlat scanner: TLS + security headers, plus optional repository scans. Supports two scopes:
- internal_only: scan only INTERNAL_TARGETS (or VERIFY_WEB_URL, JUICE_URL, API_URL).
- internal_and_verified: internal targets + assets from API with verified=true (external_web).
"""

import base64
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from urllib.parse import quote, urlencode

import httpx
from config import (
    API_URL,
    DEPENDENCY_SCAN_ASSET_KEY,
    DEPENDENCY_SCAN_ASSET_NAME,
    DEPENDENCY_SCAN_CRITICALITY,
    DEPENDENCY_SCAN_ENABLED,
    DEPENDENCY_SCAN_ENVIRONMENT,
    DEPENDENCY_SCAN_PATH,
    INTERNAL_TARGETS,
    MAX_TARGETS,
    OSV_SCANNER_BIN,
    OSV_SCANNER_TIMEOUT_SECONDS,
    SCAN_INTERVAL_SECONDS,
    SCOPE,
    TRIVY_BIN,
    TRIVY_SCAN_ASSET_KEY,
    TRIVY_SCAN_ASSET_NAME,
    TRIVY_SCAN_CRITICALITY,
    TRIVY_SCAN_ENABLED,
    TRIVY_SCAN_ENVIRONMENT,
    TRIVY_SCAN_PATH,
    TRIVY_SCANNERS,
    TRIVY_TIMEOUT_SECONDS,
)
from dependency_scan import OSV_SOURCE, run_osv_scan
from scans import run_scans
from trivy_scan import TRIVY_SOURCE, run_trivy_scan

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
MAX_HTTP_ATTEMPTS = int(os.getenv("SCANNER_HTTP_MAX_ATTEMPTS", "3"))
API_AUTH_USERNAME = os.getenv("SCANNER_API_USERNAME", os.getenv("ADMIN_USERNAME", "")).strip()
API_AUTH_PASSWORD = os.getenv("SCANNER_API_PASSWORD", os.getenv("ADMIN_PASSWORD", "")).strip()
TOKEN_REFRESH_SKEW_SECONDS = int(os.getenv("SCANNER_TOKEN_REFRESH_SKEW_SECONDS", "30"))

_api_access_token: str | None = None
_api_access_token_expiry: float = 0.0

_STANDARD_ATTRS = {
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
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload = {
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


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service="secplat-scanner"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


configure_logging()
logger = logging.getLogger("scanner")


def _parse_api_retryable(response: httpx.Response) -> bool:
    if response.status_code in RETRYABLE_STATUS:
        return True
    try:
        body = response.json()
    except Exception:
        return False
    error_obj = body.get("error") if isinstance(body, dict) else None
    if isinstance(error_obj, dict) and isinstance(error_obj.get("retryable"), bool):
        return bool(error_obj["retryable"])
    return False


def _parse_error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict) and isinstance(err.get("message"), str):
                return err["message"]
            detail = body.get("detail")
            if isinstance(detail, str):
                return detail
    except Exception:
        pass
    return (response.text or response.reason_phrase or "request failed").strip()


def _is_retryable_transport_error(exc: Exception) -> bool:
    return isinstance(
        exc,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.PoolTimeout,
            httpx.RemoteProtocolError,
        ),
    )


def _decode_jwt_exp(token: str) -> float:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return 0.0
        segment = parts[1]
        pad = "=" * ((4 - len(segment) % 4) % 4)
        raw = json.loads(base64.urlsafe_b64decode((segment + pad).encode()).decode())
        exp = raw.get("exp")
        return float(exp) if isinstance(exp, (int, float)) else 0.0
    except Exception:
        return 0.0


def _login_access_token() -> str | None:
    global _api_access_token, _api_access_token_expiry
    if not API_AUTH_USERNAME or not API_AUTH_PASSWORD:
        return None
    try:
        r = httpx.post(
            f"{API_URL}/auth/login",
            data={"username": API_AUTH_USERNAME, "password": API_AUTH_PASSWORD},
            timeout=10.0,
        )
        if r.status_code >= 400:
            logger.warning(
                "scanner_login_failed",
                extra={
                    "action": "scanner_login",
                    "status": r.status_code,
                    "retryable": _parse_api_retryable(r),
                    "error": _parse_error_message(r),
                },
            )
            return None
        token = (r.json() or {}).get("access_token")
        if not token:
            logger.warning(
                "scanner_login_missing_token",
                extra={
                    "action": "scanner_login",
                    "status": "error",
                    "retryable": False,
                },
            )
            return None
        _api_access_token = token
        exp = _decode_jwt_exp(token)
        _api_access_token_expiry = exp if exp > 0 else (time.time() + 300)
        return _api_access_token
    except Exception as e:
        logger.warning(
            "scanner_login_error",
            extra={
                "action": "scanner_login",
                "status": "error",
                "retryable": True,
                "error": str(e),
            },
        )
        return None


def _get_auth_headers(force_refresh: bool = False) -> dict[str, str]:
    global _api_access_token
    should_refresh = force_refresh or not _api_access_token
    if _api_access_token and time.time() >= (_api_access_token_expiry - TOKEN_REFRESH_SKEW_SECONDS):
        should_refresh = True
    if should_refresh:
        _login_access_token()
    if not _api_access_token:
        return {}
    return {"Authorization": f"Bearer {_api_access_token}"}


def _api_request_raw(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    timeout: float = 10.0,
    expected_statuses: set[int] | None = None,
) -> httpx.Response | None:
    accepted_statuses = set(expected_statuses or set())
    for attempt in range(1, MAX_HTTP_ATTEMPTS + 1):
        headers = _get_auth_headers()
        try:
            r = httpx.request(
                method,
                f"{API_URL}{path}",
                json=json_body,
                headers=headers or None,
                timeout=timeout,
            )
            if r.status_code < 400 or r.status_code in accepted_statuses:
                return r
            if r.status_code in (401, 403) and API_AUTH_USERNAME and API_AUTH_PASSWORD:
                # Token may have expired or been rotated; refresh once per attempt.
                _get_auth_headers(force_refresh=True)
                if attempt < MAX_HTTP_ATTEMPTS:
                    time.sleep(0.2)
                    continue
            retryable = _parse_api_retryable(r)
            logger.warning(
                "api_request_failed",
                extra={
                    "action": "api_request",
                    "status": r.status_code,
                    "retryable": retryable,
                    "attempt": attempt,
                    "method": method,
                    "path": path,
                    "error": _parse_error_message(r),
                },
            )
            if not retryable:
                return r
        except Exception as e:
            retryable = _is_retryable_transport_error(e)
            logger.warning(
                "api_request_error",
                extra={
                    "action": "api_request",
                    "status": "error",
                    "retryable": retryable,
                    "attempt": attempt,
                    "method": method,
                    "path": path,
                    "error": str(e),
                },
            )
            if not retryable:
                return None
        if attempt < MAX_HTTP_ATTEMPTS:
            time.sleep(2 ** (attempt - 1))
    return None


def _api_request(
    method: str, path: str, *, json_body: dict | None = None, timeout: float = 10.0
) -> httpx.Response | None:
    response = _api_request_raw(method, path, json_body=json_body, timeout=timeout)
    if response is None or response.status_code >= 400:
        return None
    return response


def get_verified_targets() -> list[tuple[str, str]]:
    """Fetch assets with verified=true; return (url, asset_key). URL from address or https://asset_key."""
    targets = []
    r = _api_request("GET", "/assets/", timeout=15.0)
    if not r:
        return targets
    try:
        assets = r.json()
    except Exception:
        logger.warning(
            "verified_targets_invalid_response",
            extra={
                "action": "fetch_verified_targets",
                "status": "error",
                "retryable": False,
                "error": "assets response is not valid JSON",
            },
        )
        return targets
    if not isinstance(assets, list):
        logger.warning(
            "verified_targets_invalid_shape",
            extra={
                "action": "fetch_verified_targets",
                "status": "error",
                "retryable": False,
                "error": "assets response is not a list",
            },
        )
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
    for key in (
        "vulnerability_id",
        "package_ecosystem",
        "package_name",
        "package_version",
        "fixed_version",
        "scanner_metadata_json",
    ):
        if key in finding and finding.get(key) is not None:
            payload[key] = finding.get(key)
    r = _api_request("POST", "/findings/", json_body=payload, timeout=10.0)
    return r is not None


def _empty_scan_stats(enabled: bool) -> dict[str, int | bool]:
    return {
        "enabled": enabled,
        "detected": 0,
        "submitted": 0,
        "resolved": 0,
    }


def _ensure_repository_asset(
    *,
    asset_key: str,
    asset_name: str,
    scan_path: str,
    environment: str,
    criticality: str,
    scanner_source: str,
    extra_tags: list[str] | None = None,
) -> bool:
    if not asset_key:
        logger.warning(
            "repository_scan_asset_missing",
            extra={
                "action": "repository_scan_asset",
                "status": "failed",
                "retryable": False,
                "error": "repository asset key is empty",
                "scanner_source": scanner_source,
            },
        )
        return False
    path = f"/assets/by-key/{quote(asset_key, safe='')}"
    existing = _api_request_raw("GET", path, timeout=10.0, expected_statuses={404})
    if existing is not None and existing.status_code == 200:
        return True
    if existing is None or existing.status_code != 404:
        return False
    created = _api_request(
        "POST",
        "/assets/",
        json_body={
            "asset_key": asset_key,
            "type": "app",
            "name": asset_name,
            "asset_type": "repository",
            "environment": environment,
            "criticality": criticality,
            "tags": list(dict.fromkeys(["repository", *(extra_tags or [])])),
            "metadata": {
                "scanner_source": scanner_source,
                "scan_path": scan_path,
            },
        },
        timeout=10.0,
    )
    return created is not None


def _list_findings_for_source(asset_key: str, source: str, *, limit: int = 500) -> list[dict]:
    query = urlencode(
        {
            "asset_key": asset_key,
            "source": source,
            "limit": min(max(limit, 1), 500),
        }
    )
    response = _api_request_raw("GET", f"/findings/?{query}", timeout=15.0)
    if response is None or response.status_code >= 400:
        return []
    try:
        payload = response.json()
    except Exception:
        return []
    return payload if isinstance(payload, list) else []


def _update_finding_status(finding_id: int, status: str) -> bool:
    response = _api_request(
        "PATCH",
        f"/findings/{finding_id}/status",
        json_body={"status": status},
        timeout=10.0,
    )
    return response is not None


def _reconcile_findings_for_source(asset_key: str, source: str, current_keys: set[str]) -> int:
    resolved = 0
    existing_findings = _list_findings_for_source(asset_key, source)
    for finding in existing_findings:
        finding_key = str(finding.get("finding_key") or "").strip()
        if not finding_key or finding_key in current_keys:
            continue
        if str(finding.get("status") or "open").strip().lower() == "remediated":
            continue
        finding_id = finding.get("finding_id")
        if isinstance(finding_id, int) and _update_finding_status(finding_id, "remediated"):
            resolved += 1
    return resolved


def _run_dependency_scan() -> dict[str, int | bool]:
    stats = _empty_scan_stats(DEPENDENCY_SCAN_ENABLED)
    if not DEPENDENCY_SCAN_ENABLED:
        return stats
    if not _ensure_repository_asset(
        asset_key=DEPENDENCY_SCAN_ASSET_KEY,
        asset_name=DEPENDENCY_SCAN_ASSET_NAME,
        scan_path=DEPENDENCY_SCAN_PATH,
        environment=DEPENDENCY_SCAN_ENVIRONMENT,
        criticality=DEPENDENCY_SCAN_CRITICALITY,
        scanner_source=OSV_SOURCE,
        extra_tags=["dependency-scan"],
    ):
        logger.warning(
            "dependency_scan_asset_unavailable",
            extra={
                "action": "dependency_scan",
                "status": "failed",
                "retryable": True,
                "asset_key": DEPENDENCY_SCAN_ASSET_KEY,
            },
        )
        return stats
    try:
        result = run_osv_scan(
            DEPENDENCY_SCAN_PATH,
            asset_key=DEPENDENCY_SCAN_ASSET_KEY,
            osv_scanner_bin=OSV_SCANNER_BIN,
            timeout_seconds=OSV_SCANNER_TIMEOUT_SECONDS,
        )
    except Exception as e:
        logger.warning(
            "dependency_scan_failed",
            extra={
                "action": "dependency_scan",
                "status": "failed",
                "retryable": True,
                "asset_key": DEPENDENCY_SCAN_ASSET_KEY,
                "scan_path": DEPENDENCY_SCAN_PATH,
                "error": str(e),
            },
        )
        return stats

    current_keys: set[str] = set()
    findings = result.get("findings") or []
    stats["detected"] = len(findings)
    for finding in findings:
        finding_key = str(finding.get("finding_key") or "").strip()
        if finding_key:
            current_keys.add(finding_key)
        if submit_finding(finding, DEPENDENCY_SCAN_ASSET_KEY):
            stats["submitted"] = int(stats["submitted"]) + 1
    stats["resolved"] = _reconcile_findings_for_source(
        DEPENDENCY_SCAN_ASSET_KEY,
        OSV_SOURCE,
        current_keys,
    )
    logger.info(
        "dependency_scan_finished",
        extra={
            "action": "dependency_scan",
            "status": "done",
            "asset_key": DEPENDENCY_SCAN_ASSET_KEY,
            "scan_path": DEPENDENCY_SCAN_PATH,
            "detected": stats["detected"],
            "submitted": stats["submitted"],
            "resolved": stats["resolved"],
            "tool_exit_code": result.get("exit_code"),
            "tool_stderr": (result.get("stderr") or "")[:300],
        },
    )
    return stats


def _run_trivy_scan() -> dict[str, int | bool]:
    stats = _empty_scan_stats(TRIVY_SCAN_ENABLED)
    if not TRIVY_SCAN_ENABLED:
        return stats
    if not _ensure_repository_asset(
        asset_key=TRIVY_SCAN_ASSET_KEY,
        asset_name=TRIVY_SCAN_ASSET_NAME,
        scan_path=TRIVY_SCAN_PATH,
        environment=TRIVY_SCAN_ENVIRONMENT,
        criticality=TRIVY_SCAN_CRITICALITY,
        scanner_source=TRIVY_SOURCE,
        extra_tags=["trivy-scan"],
    ):
        logger.warning(
            "trivy_scan_asset_unavailable",
            extra={
                "action": "trivy_scan",
                "status": "failed",
                "retryable": True,
                "asset_key": TRIVY_SCAN_ASSET_KEY,
            },
        )
        return stats
    try:
        result = run_trivy_scan(
            TRIVY_SCAN_PATH,
            asset_key=TRIVY_SCAN_ASSET_KEY,
            trivy_bin=TRIVY_BIN,
            scanners=TRIVY_SCANNERS,
            timeout_seconds=TRIVY_TIMEOUT_SECONDS,
        )
    except Exception as e:
        logger.warning(
            "trivy_scan_failed",
            extra={
                "action": "trivy_scan",
                "status": "failed",
                "retryable": True,
                "asset_key": TRIVY_SCAN_ASSET_KEY,
                "scan_path": TRIVY_SCAN_PATH,
                "error": str(e),
            },
        )
        return stats

    current_keys: set[str] = set()
    findings = result.get("findings") or []
    stats["detected"] = len(findings)
    for finding in findings:
        finding_key = str(finding.get("finding_key") or "").strip()
        if finding_key:
            current_keys.add(finding_key)
        if submit_finding(finding, TRIVY_SCAN_ASSET_KEY):
            stats["submitted"] = int(stats["submitted"]) + 1
    stats["resolved"] = _reconcile_findings_for_source(
        TRIVY_SCAN_ASSET_KEY,
        TRIVY_SOURCE,
        current_keys,
    )
    logger.info(
        "trivy_scan_finished",
        extra={
            "action": "trivy_scan",
            "status": "done",
            "asset_key": TRIVY_SCAN_ASSET_KEY,
            "scan_path": TRIVY_SCAN_PATH,
            "scanners": TRIVY_SCANNERS,
            "detected": stats["detected"],
            "submitted": stats["submitted"],
            "resolved": stats["resolved"],
            "tool_exit_code": result.get("exit_code"),
            "tool_stderr": (result.get("stderr") or "")[:300],
        },
    )
    return stats


def run_once() -> None:
    targets = get_all_targets()
    logger.info(
        "scanner_run_started",
        extra={
            "action": "scanner_run",
            "scope": SCOPE,
            "targets": len(targets),
            "status": "started",
        },
    )
    submitted = 0
    dependency_stats = _empty_scan_stats(DEPENDENCY_SCAN_ENABLED)
    trivy_stats = _empty_scan_stats(TRIVY_SCAN_ENABLED)
    for url, asset_key in targets:
        try:
            findings = run_scans(url, asset_key)
            for f in findings:
                if submit_finding(f, asset_key):
                    submitted += 1
        except Exception as e:
            logger.warning(
                "scan_target_failed",
                extra={
                    "action": "scan_target",
                    "status": "failed",
                    "retryable": False,
                    "asset_key": asset_key,
                    "target_url": url,
                    "error": str(e),
                },
            )
    dependency_stats = _run_dependency_scan()
    trivy_stats = _run_trivy_scan()
    logger.info(
        "scanner_run_finished",
        extra={
            "action": "scanner_run",
            "scope": SCOPE,
            "status": "done",
            "submitted_findings": submitted,
            "dependency_scan_enabled": dependency_stats["enabled"],
            "dependency_findings_detected": dependency_stats["detected"],
            "dependency_findings_submitted": dependency_stats["submitted"],
            "dependency_findings_resolved": dependency_stats["resolved"],
            "trivy_scan_enabled": trivy_stats["enabled"],
            "trivy_findings_detected": trivy_stats["detected"],
            "trivy_findings_submitted": trivy_stats["submitted"],
            "trivy_findings_resolved": trivy_stats["resolved"],
        },
    )


def main() -> None:
    if SCOPE not in ("internal_only", "internal_and_verified"):
        logger.error(
            "invalid_scope",
            extra={
                "action": "scanner_start",
                "status": "failed",
                "retryable": False,
                "scope": SCOPE,
                "error": "Invalid SCANNER_SCOPE",
            },
        )
        sys.exit(1)
    if not API_AUTH_USERNAME or not API_AUTH_PASSWORD:
        logger.warning(
            "scanner_api_auth_not_configured",
            extra={
                "action": "scanner_start",
                "status": "warning",
                "retryable": False,
                "message": "SCANNER_API_USERNAME/SCANNER_API_PASSWORD not set; protected API endpoints may return 401",
            },
        )
    else:
        _login_access_token()
    logger.info(
        "scanner_started",
        extra={
            "action": "scanner_start",
            "status": "ok",
            "scope": SCOPE,
            "interval_seconds": SCAN_INTERVAL_SECONDS,
            "dependency_scan_enabled": DEPENDENCY_SCAN_ENABLED,
            "dependency_scan_path": DEPENDENCY_SCAN_PATH,
            "trivy_scan_enabled": TRIVY_SCAN_ENABLED,
            "trivy_scan_path": TRIVY_SCAN_PATH,
            "trivy_scanners": TRIVY_SCANNERS,
        },
    )
    while True:
        try:
            run_once()
        except Exception as e:
            logger.exception(
                "scanner_run_failed",
                extra={
                    "action": "scanner_run",
                    "status": "failed",
                    "retryable": True,
                    "error": str(e),
                },
            )
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
