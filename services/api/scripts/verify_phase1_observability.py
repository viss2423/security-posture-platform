"""Phase 1 observability validation for the live compose stack."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime

    UTC = UTC
from pathlib import Path
from typing import Any
from uuid import uuid4


def _json_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    form_body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> Any:
    req_headers = dict(headers or {})
    data: bytes | None = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    request = urllib.request.Request(url, method=method.upper(), data=data, headers=req_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
        if not payload:
            return None
        return json.loads(payload.decode("utf-8"))


def _wait_for_json(
    url: str,
    *,
    timeout_seconds: int = 120,
    predicate=None,
    headers: dict[str, str] | None = None,
) -> Any:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            payload = _json_request("GET", url, headers=headers)
            if predicate is None or predicate(payload):
                return payload
        except Exception as exc:  # pragma: no cover - exercised in live validation only
            last_error = exc
        time.sleep(2)
    if last_error:
        raise last_error
    raise TimeoutError(f"Timed out waiting for {url}")


def _flatten_trace(trace_payload: dict[str, Any]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for batch in trace_payload.get("batches", []):
        resource_attrs = {
            item.get("key"): next(iter((item.get("value") or {}).values()), None)
            for item in ((batch.get("resource") or {}).get("attributes") or [])
        }
        service_name = str(resource_attrs.get("service.name") or "")
        for scope in batch.get("scopeSpans", []) or []:
            for span in scope.get("spans", []) or []:
                attrs = {
                    item.get("key"): next(iter((item.get("value") or {}).values()), None)
                    for item in span.get("attributes") or []
                }
                flattened.append(
                    {
                        "service_name": service_name,
                        "name": span.get("name"),
                        "attributes": attrs,
                    }
                )
    return flattened


def _trace_matches(trace_payload: dict[str, Any], *, request_id: str) -> bool:
    spans = _flatten_trace(trace_payload)
    required = {
        "api_findings": False,
        "api_publish": False,
        "correlator_process": False,
        "correlator_incidents": False,
        "api_incidents": False,
    }
    for span in spans:
        attrs = span["attributes"]
        service_name = span["service_name"]
        name = str(span["name"] or "")
        if (
            service_name == "secplat-api"
            and name == "http.server.request"
            and attrs.get("url.path") == "/findings/"
            and attrs.get("secplat.request_id") == request_id
        ):
            required["api_findings"] = True
        if (
            service_name == "secplat-api"
            and name == "messaging.publish"
            and attrs.get("messaging.destination.name") == "secplat.events.correlation"
        ):
            required["api_publish"] = True
        if (
            service_name == "secplat-correlator"
            and name == "messaging.process"
            and attrs.get("secplat.request_id") == request_id
            and attrs.get("messaging.destination.name") == "secplat.events.correlation"
        ):
            required["correlator_process"] = True
        if (
            service_name == "secplat-correlator"
            and name == "http.client.request"
            and attrs.get("url.full") == "http://api:8000/incidents"
            and attrs.get("secplat.request_id") == request_id
        ):
            required["correlator_incidents"] = True
        if (
            service_name == "secplat-api"
            and name == "http.server.request"
            and attrs.get("url.path") == "/incidents"
            and attrs.get("secplat.request_id") == request_id
        ):
            required["api_incidents"] = True
    return all(required.values())


def _tempo_search(
    *,
    tempo_base_url: str,
    query: str,
    limit: int = 20,
) -> dict[str, Any]:
    encoded = urllib.parse.urlencode({"q": query, "limit": str(limit)})
    return _json_request("GET", f"{tempo_base_url.rstrip('/')}/api/search?{encoded}")


def _assert_stack_ready(
    prometheus_base_url: str, grafana_base_url: str, tempo_base_url: str
) -> None:
    prometheus_ready = urllib.request.urlopen(
        f"{prometheus_base_url.rstrip('/')}/-/ready", timeout=20
    ).read()
    if b"Ready" not in prometheus_ready:
        raise RuntimeError("prometheus_not_ready")
    grafana_health = _json_request("GET", f"{grafana_base_url.rstrip('/')}/api/health")
    if str(grafana_health.get("database")) != "ok":
        raise RuntimeError("grafana_not_ready")
    tempo_ready = urllib.request.urlopen(f"{tempo_base_url.rstrip('/')}/ready", timeout=20).read()
    if b"ready" not in tempo_ready.lower():
        raise RuntimeError("tempo_not_ready")


def _assert_prometheus_targets(prometheus_base_url: str) -> None:
    payload = _wait_for_json(
        f"{prometheus_base_url.rstrip('/')}/api/v1/targets",
        predicate=lambda body: all(
            item.get("health") == "up"
            for item in ((body.get("data") or {}).get("activeTargets") or [])
        ),
    )
    targets = (payload.get("data") or {}).get("activeTargets") or []
    expected_jobs = {
        "secplat-api",
        "secplat-worker-web",
        "secplat-correlator",
        "secplat-notifier",
        "secplat-deriver",
        "secplat-otel-collector",
    }
    observed_jobs = {str(item.get("labels", {}).get("job") or "") for item in targets}
    if expected_jobs - observed_jobs:
        raise RuntimeError(f"missing_prometheus_targets:{sorted(expected_jobs - observed_jobs)}")


def _assert_prometheus_rules(prometheus_base_url: str) -> None:
    payload = _json_request("GET", f"{prometheus_base_url.rstrip('/')}/api/v1/rules")
    rules = []
    for group in (payload.get("data") or {}).get("groups") or []:
        rules.extend(group.get("rules") or [])
    expected = {
        "SecPlatApiAvailabilityBurn",
        "SecPlatApiLatencyP95High",
        "SecPlatWorkerLoopErrors",
        "SecPlatBackgroundServiceMissing",
    }
    by_name = {str(rule.get("name") or ""): rule for rule in rules}
    missing = expected - set(by_name)
    if missing:
        raise RuntimeError(f"missing_prometheus_rules:{sorted(missing)}")
    unhealthy = sorted(name for name, rule in by_name.items() if rule.get("health") != "ok")
    if unhealthy:
        raise RuntimeError(f"unhealthy_prometheus_rules:{unhealthy}")


def _login(api_base_url: str, username: str, password: str) -> str:
    payload = _json_request(
        "POST",
        f"{api_base_url.rstrip('/')}/auth/login",
        form_body={"username": username, "password": password},
    )
    token = str((payload or {}).get("access_token") or "").strip()
    if not token:
        raise RuntimeError("login_missing_access_token")
    return token


def _ensure_asset(api_base_url: str, token: str, *, asset_key: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        _json_request(
            "GET", f"{api_base_url.rstrip('/')}/assets/by-key/{asset_key}", headers=headers
        )
        return
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _json_request(
        "POST",
        f"{api_base_url.rstrip('/')}/assets/",
        headers=headers,
        json_body={
            "asset_key": asset_key,
            "type": "host",
            "name": "Phase1 Observability Asset",
            "owner": "phase1-observability",
            "environment": "dev",
            "criticality": "medium",
        },
    )


def _write_custom_telemetry_file(file_path: Path, *, asset_key: str) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    event = {
        "timestamp": timestamp,
        "event_type": "credential_attack",
        "title": "Phase1 Telemetry Alert",
        "description": "Telemetry import for Phase 1 observability validation",
        "severity": "high",
        "src_ip": "203.0.113.10",
        "dst_ip": "10.10.10.10",
        "protocol": "tcp",
        "asset_key": asset_key,
        "dedupe_key": f"phase1-observability-{uuid4()}",
    }
    file_path.write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")


def _poll_job(
    api_base_url: str, token: str, *, job_id: int, timeout_seconds: int = 120
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    return _wait_for_json(
        f"{api_base_url.rstrip('/')}/jobs/{job_id}",
        timeout_seconds=timeout_seconds,
        headers=headers,
        predicate=lambda body: str((body or {}).get("status") or "") in {"done", "failed"},
    )


def _poll_incident(
    api_base_url: str, token: str, *, incident_key: str, timeout_seconds: int = 120
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        payload = _json_request(
            "GET",
            f"{api_base_url.rstrip('/')}/incidents?limit=100",
            headers=headers,
        )
        for item in payload.get("items") or []:
            if str(item.get("incident_key") or "") == incident_key:
                return item
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for incident {incident_key}")


def _poll_trace(
    tempo_base_url: str, *, request_id: str, timeout_seconds: int = 120
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    query = f'{{.secplat.request_id="{request_id}"}}'
    while time.time() < deadline:
        search = _tempo_search(tempo_base_url=tempo_base_url, query=query, limit=20)
        for trace in search.get("traces", []):
            trace_id = str(trace.get("traceID") or "").strip()
            if not trace_id:
                continue
            payload = _json_request("GET", f"{tempo_base_url.rstrip('/')}/api/traces/{trace_id}")
            if _trace_matches(payload, request_id=request_id):
                return {"trace_id": trace_id, "payload": payload}
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for Tempo trace for request_id={request_id}")


def _warm_api(api_base_url: str, *, count: int = 120) -> None:
    for _ in range(max(1, int(count))):
        _json_request("GET", f"{api_base_url.rstrip('/')}/health", timeout=15.0)


def _poll_release_gate(api_base_url: str, *, timeout_seconds: int = 120) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_payload: dict[str, Any] | None = None
    while time.time() < deadline:
        payload = _json_request(
            "GET",
            f"{api_base_url.rstrip('/')}/platform/release-gate/current?strict_missing=true",
        )
        last_payload = payload
        results = {item.get("name"): item for item in payload.get("results", [])}
        required = (
            "api_availability",
            "api_p95_latency_ms",
            "ingestion_visibility_seconds",
            "alert_creation_seconds",
            "background_job_freshness_minutes",
        )
        sample = payload.get("sample") or {}
        sample_source = str(sample.get("source") or "")
        if (
            all(results.get(name, {}).get("status") != "missing" for name in required)
            and sample_source.startswith("platform_")
            and not sample_source.endswith("_override")
            and bool(payload.get("gate_passed"))
        ):
            return payload
        time.sleep(5)
    raise RuntimeError(
        "release_gate_missing_measurements:"
        + json.dumps(last_payload or {}, sort_keys=True, separators=(",", ":"))
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--prometheus-base-url", default="http://127.0.0.1:9091")
    parser.add_argument("--grafana-base-url", default="http://127.0.0.1:3001")
    parser.add_argument("--tempo-base-url", default="http://127.0.0.1:3200")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument(
        "--telemetry-file",
        default=str(Path("lab-data") / "phase1" / "custom-telemetry.jsonl"),
    )
    args = parser.parse_args(argv)

    _assert_stack_ready(
        args.prometheus_base_url,
        args.grafana_base_url,
        args.tempo_base_url,
    )
    _assert_prometheus_targets(args.prometheus_base_url)
    _assert_prometheus_rules(args.prometheus_base_url)

    token = _login(args.api_base_url, args.username, args.password)
    asset_key = f"phase1-observability-{uuid4().hex[:12]}"
    request_id = f"phase1-trace-{uuid4().hex}"
    finding_key = f"phase1-finding-{uuid4().hex[:12]}"
    incident_key = f"finding:{asset_key}:{finding_key}"
    _warm_api(args.api_base_url, count=160)
    _ensure_asset(args.api_base_url, token, asset_key=asset_key)

    telemetry_host_path = Path(args.telemetry_file)
    _write_custom_telemetry_file(telemetry_host_path, asset_key=asset_key)
    telemetry_container_path = f"/workspace/{telemetry_host_path.as_posix()}"
    headers = {"Authorization": f"Bearer {token}", "x-request-id": request_id}

    telemetry_job = _json_request(
        "POST",
        f"{args.api_base_url.rstrip('/')}/jobs",
        headers=headers,
        json_body={
            "job_type": "telemetry_import",
            "requested_by": "phase1-observability",
            "job_params_json": {
                "source": "custom",
                "file_path": telemetry_container_path,
                "asset_key": asset_key,
                "create_alerts": True,
            },
        },
    )
    telemetry_job_state = _poll_job(
        args.api_base_url,
        token,
        job_id=int(telemetry_job["job_id"]),
    )
    if str(telemetry_job_state.get("status") or "") != "done":
        raise RuntimeError(f"telemetry_job_failed:{telemetry_job_state}")

    _json_request(
        "POST",
        f"{args.api_base_url.rstrip('/')}/findings/",
        headers=headers,
        json_body={
            "finding_key": finding_key,
            "asset_key": asset_key,
            "title": "Phase1 Trace Finding",
            "severity": "medium",
            "confidence": "high",
            "source": "phase1-smoke",
            "category": "test",
            "evidence": "trace smoke",
            "remediation": "none",
        },
    )

    _poll_incident(args.api_base_url, token, incident_key=incident_key)
    trace = _poll_trace(args.tempo_base_url, request_id=request_id)
    _warm_api(args.api_base_url, count=220)
    release_gate = _poll_release_gate(args.api_base_url)

    summary = {
        "stack": {
            "prometheus": "ready",
            "grafana": "ready",
            "tempo": "ready",
        },
        "trace_id": trace["trace_id"],
        "request_id": request_id,
        "asset_key": asset_key,
        "finding_key": finding_key,
        "incident_key": incident_key,
        "telemetry_job_id": telemetry_job["job_id"],
        "release_gate": {
            "gate_passed": bool(release_gate.get("gate_passed")),
            "results": release_gate.get("results"),
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
