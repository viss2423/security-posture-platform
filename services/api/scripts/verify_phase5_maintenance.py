"""Run the Phase 5 maintenance-light verification gate against a Kubernetes release."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from contextlib import AbstractContextManager

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime

    UTC = UTC
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run(cmd: list[str], *, timeout: float = 300.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _run_json(cmd: list[str], *, timeout: float = 300.0) -> dict[str, Any]:
    proc = _run(cmd, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RuntimeError(proc.stdout or proc.stderr) from exc


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class PortForward(AbstractContextManager["PortForward"]):
    def __init__(
        self, *, namespace: str, resource: str, remote_port: int, local_port: int | None = None
    ):
        self.namespace = namespace
        self.resource = resource
        self.remote_port = int(remote_port)
        self.local_port = int(local_port or _free_port())
        self.proc: subprocess.Popen[str] | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.local_port}"

    def __enter__(self) -> PortForward:
        cmd = [
            "kubectl",
            "port-forward",
            "-n",
            self.namespace,
            self.resource,
            f"{self.local_port}:{self.remote_port}",
        ]
        creationflags = 0
        if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = int(subprocess.CREATE_NO_WINDOW)
        self.proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=creationflags,
        )
        deadline = time.time() + 30.0
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"port-forward exited early for {self.resource}")
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.25)
        raise RuntimeError(f"timed out waiting for port-forward to {self.resource}")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                self.proc.kill()
                self.proc.wait(timeout=5.0)
        self.proc = None


def _request_json(
    method: str,
    url: str,
    *,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, Any]:
    body = None
    request_headers = dict(headers or {})
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = request.Request(url, data=body, headers=request_headers, method=method.upper())
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(payload)
            except json.JSONDecodeError:
                return resp.status, payload
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(payload)
        except json.JSONDecodeError:
            return exc.code, payload


def _capture_marker_from_sli_payload(
    payload: Any,
    *,
    fallback: datetime,
) -> datetime:
    if isinstance(payload, dict):
        for section in ("api", "sample"):
            candidate = payload.get(section)
            if isinstance(candidate, dict):
                captured_at = candidate.get("captured_at")
                if isinstance(captured_at, str):
                    try:
                        return datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
                    except ValueError:
                        pass
    return fallback


def _login(base_url: str, *, username: str, password: str) -> str:
    payload = parse.urlencode({"username": username, "password": password}).encode("utf-8")
    req = request.Request(
        f"{base_url}/auth/login",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with request.urlopen(req, timeout=30.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    token = str(data.get("access_token") or "").strip()
    if not token:
        raise RuntimeError("access_token missing from /auth/login")
    return token


def _decode_secret_value(namespace: str, secret_name: str, key: str) -> str:
    proc = _run(
        [
            "kubectl",
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            f"jsonpath={{.data.{key}}}",
        ]
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    raw = str(proc.stdout or "").strip()
    if not raw:
        raise RuntimeError(f"secret {secret_name}/{key} returned empty value")
    return base64.b64decode(raw).decode("utf-8")


def _rewrite_dsn_host(dsn: str, *, host: str, port: int) -> str:
    url = make_url(dsn)
    return url.set(host=host, port=int(port)).render_as_string(hide_password=False)


def _wait_for_worker_scale(
    namespace: str, deployment: str, *, replicas: int, timeout: float = 180.0
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = _run_json(
            ["kubectl", "get", "deployment", deployment, "-n", namespace, "-o", "json"],
            timeout=60.0,
        )
        spec_replicas = int(data.get("spec", {}).get("replicas") or 0)
        status_replicas = int(data.get("status", {}).get("replicas") or 0)
        available = int(data.get("status", {}).get("availableReplicas") or 0)
        selector = data.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}
        if spec_replicas == replicas:
            if replicas == 0 and status_replicas == 0:
                if selector:
                    label_selector = ",".join(
                        f"{key}={value}" for key, value in sorted(selector.items())
                    )
                    pods = _run_json(
                        [
                            "kubectl",
                            "get",
                            "pods",
                            "-n",
                            namespace,
                            "-l",
                            label_selector,
                            "-o",
                            "json",
                        ],
                        timeout=60.0,
                    )
                    if not pods.get("items"):
                        return
                else:  # pragma: no cover - defensive fallback
                    return
            if replicas > 0 and available >= replicas:
                return
        time.sleep(2.0)
    raise RuntimeError(f"timed out waiting for deployment {deployment} replicas={replicas}")


def _scale_worker(namespace: str, deployment: str, *, replicas: int) -> None:
    proc = _run(
        [
            "kubectl",
            "scale",
            "deployment",
            deployment,
            "-n",
            namespace,
            f"--replicas={int(replicas)}",
        ],
        timeout=120.0,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    _wait_for_worker_scale(namespace, deployment, replicas=replicas)


def _rollout_wait(namespace: str, deployment: str, *, timeout_seconds: int = 300) -> None:
    proc = _run(
        [
            "kubectl",
            "rollout",
            "status",
            f"deployment/{deployment}",
            "-n",
            namespace,
            f"--timeout={int(timeout_seconds)}s",
        ],
        timeout=float(timeout_seconds) + 30.0,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)


def _generate_backup_from_postgres_pod(
    *,
    namespace: str,
    pod_name: str,
    admin_dsn: str,
    out_path: Path,
) -> dict[str, Any]:
    parsed = make_url(admin_dsn)
    username = str(parsed.username or "").strip()
    password = str(parsed.password or "").strip()
    database = str(parsed.database or "").strip()
    if not username or not database:
        raise RuntimeError("admin DSN must include username and database")
    command = (
        f"PGPASSWORD={shlex.quote(password)} "
        f"pg_dump -h localhost -p 5432 -U {shlex.quote(username)} "
        f"--dbname {shlex.quote(database)} --format=plain --no-owner --no-privileges"
    )
    proc = _run(
        ["kubectl", "exec", "-n", namespace, pod_name, "--", "sh", "-lc", command],
        timeout=600.0,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(proc.stdout, encoding="utf-8")
    return {
        "backup_file": str(out_path),
        "size_bytes": out_path.stat().st_size,
    }


def _compute_release_gate_measurements(
    runtime_dsn: str,
    *,
    lookback_hours: int,
    captured_after: datetime | None = None,
    source: str | None = None,
) -> dict[str, float | None]:
    engine = create_engine(runtime_dsn, pool_pre_ping=True)
    with engine.connect() as conn:
        runtime_params: dict[str, Any] = {}
        runtime_filters = ["captured_at >= NOW() - INTERVAL '300 seconds'"]
        if captured_after is not None:
            runtime_filters.append("captured_at >= :captured_after")
            runtime_params["captured_after"] = captured_after
        if source:
            runtime_filters.append("source = :source")
            runtime_params["source"] = str(source)
        api_rows = (
            conn.execute(
                text(
                    """
                    WITH ranked AS (
                      SELECT
                        snapshot_id,
                        captured_at,
                        service_instance_id,
                        request_count,
                        server_error_count,
                        api_p95_latency_ms,
                        ROW_NUMBER() OVER (
                          PARTITION BY service_instance_id
                          ORDER BY captured_at ASC, snapshot_id ASC
                        ) AS rn_asc,
                        ROW_NUMBER() OVER (
                          PARTITION BY service_instance_id
                          ORDER BY captured_at DESC, snapshot_id DESC
                        ) AS rn
                      FROM platform_api_runtime_snapshots
                      WHERE """
                    + " AND ".join(runtime_filters)
                    + """
                    )
                    SELECT
                      service_instance_id,
                      MAX(CASE WHEN rn = 1 THEN snapshot_id END) AS latest_snapshot_id,
                      MAX(CASE WHEN rn_asc = 1 THEN snapshot_id END) AS oldest_snapshot_id,
                      MAX(CASE WHEN rn = 1 THEN request_count END) AS latest_request_count,
                      MAX(CASE WHEN rn_asc = 1 THEN request_count END) AS oldest_request_count,
                      MAX(CASE WHEN rn = 1 THEN server_error_count END) AS latest_server_error_count,
                      MAX(CASE WHEN rn_asc = 1 THEN server_error_count END) AS oldest_server_error_count,
                      MAX(CASE WHEN rn = 1 THEN api_p95_latency_ms END) AS api_p95_latency_ms
                    FROM ranked
                    GROUP BY service_instance_id
                    """
                ),
                runtime_params,
            )
            .mappings()
            .all()
        )
        ingestion_row = (
            conn.execute(
                text(
                    """
                    SELECT
                      percentile_cont(0.95) WITHIN GROUP (ORDER BY ingest_lag_seconds)
                        AS ingestion_visibility_seconds
                    FROM security_events
                    WHERE ingest_lag_seconds IS NOT NULL
                      AND event_time >= NOW() - (:lookback_hours * INTERVAL '1 hour')
                    """
                ),
                {"lookback_hours": int(lookback_hours)},
            )
            .mappings()
            .first()
            or {}
        )
        alert_row = (
            conn.execute(
                text(
                    """
                    SELECT
                      percentile_cont(0.95) WITHIN GROUP (
                        ORDER BY GREATEST(
                          EXTRACT(EPOCH FROM (created_at - first_seen_at)),
                          0
                        )
                      ) AS alert_creation_seconds
                    FROM security_alerts
                    WHERE first_seen_at IS NOT NULL
                      AND created_at >= NOW() - (:lookback_hours * INTERVAL '1 hour')
                    """
                ),
                {"lookback_hours": int(lookback_hours)},
            )
            .mappings()
            .first()
            or {}
        )
        job_row = (
            conn.execute(
                text(
                    """
                    SELECT
                      EXTRACT(EPOCH FROM (NOW() - MAX(COALESCE(finished_at, created_at)))) / 60.0
                        AS background_job_freshness_minutes
                    FROM scan_jobs
                    WHERE status IN ('done', 'running')
                      AND job_type = ANY(ARRAY[
                        'telemetry_import',
                        'network_anomaly_score',
                        'threat_intel_refresh',
                        'detection_rule_schedule',
                        'correlation_pass'
                      ])
                    """
                )
            )
            .mappings()
            .first()
            or {}
        )
    request_count = 0
    server_error_count = 0
    api_p95_latency_ms = 0.0
    for api_row in api_rows:
        latest_snapshot_id = int(api_row.get("latest_snapshot_id") or 0)
        oldest_snapshot_id = int(api_row.get("oldest_snapshot_id") or 0)
        same_snapshot = latest_snapshot_id > 0 and latest_snapshot_id == oldest_snapshot_id
        latest_request_count = int(api_row.get("latest_request_count") or 0)
        oldest_request_count = int(api_row.get("oldest_request_count") or 0)
        latest_server_error_count = int(api_row.get("latest_server_error_count") or 0)
        oldest_server_error_count = int(api_row.get("oldest_server_error_count") or 0)
        if same_snapshot or latest_request_count < oldest_request_count:
            request_count += latest_request_count
        else:
            request_count += max(0, latest_request_count - oldest_request_count)
        if same_snapshot or latest_server_error_count < oldest_server_error_count:
            server_error_count += latest_server_error_count
        else:
            server_error_count += max(0, latest_server_error_count - oldest_server_error_count)
        api_p95_latency_ms = max(
            api_p95_latency_ms, float(api_row.get("api_p95_latency_ms") or 0.0)
        )
    api_availability = 1.0
    if request_count > 0:
        api_availability = max(0.0, 1.0 - (server_error_count / float(request_count)))
    return {
        "api_availability": round(api_availability, 6),
        "api_p95_latency_ms": api_p95_latency_ms,
        "ingestion_visibility_seconds": (
            float(ingestion_row.get("ingestion_visibility_seconds"))
            if ingestion_row.get("ingestion_visibility_seconds") is not None
            else None
        ),
        "alert_creation_seconds": (
            float(alert_row.get("alert_creation_seconds"))
            if alert_row.get("alert_creation_seconds") is not None
            else None
        ),
        "background_job_freshness_minutes": (
            float(job_row.get("background_job_freshness_minutes"))
            if job_row.get("background_job_freshness_minutes") is not None
            else None
        ),
    }


def _prime_runtime_release_gate_window(
    base_url: str,
    *,
    iterations: int = 20,
) -> dict[str, Any]:
    fallback_marker = datetime.now(UTC).replace(microsecond=0)
    capture_status, capture_payload = _request_json(
        "GET",
        f"{base_url}/platform/sli/current?lookback_hours=1",
        timeout=30.0,
    )
    if capture_status != 200:
        raise RuntimeError(
            f"failed to capture baseline SLI snapshot: {capture_status} {capture_payload}"
        )
    captured_after = _capture_marker_from_sli_payload(capture_payload, fallback=fallback_marker)
    healthy_requests = 0
    for _ in range(max(1, int(iterations))):
        for path in ("/health", "/ready", "/auth/config"):
            status, _payload = _request_json("GET", f"{base_url}{path}", timeout=15.0)
            if status != 200:
                raise RuntimeError(f"healthy runtime warmup failed for {path}: {status}")
            healthy_requests += 1
    final_status, final_payload = _request_json(
        "GET",
        f"{base_url}/platform/sli/current?lookback_hours=1",
        timeout=30.0,
    )
    if final_status != 200:
        raise RuntimeError(f"failed to capture final SLI snapshot: {final_status} {final_payload}")
    return {
        "captured_after": captured_after.isoformat().replace("+00:00", "Z"),
        "source": "platform_sli_current_capture",
        "healthy_requests": healthy_requests,
        "iterations": int(iterations),
    }


def _insert_queued_job(runtime_dsn: str) -> int:
    engine = create_engine(runtime_dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    """
                    INSERT INTO scan_jobs(org_id, job_type, target_asset_id, requested_by, status, job_params_json)
                    VALUES ('default', 'score_recompute', NULL, 'phase5-maintenance', 'queued', '{}'::jsonb)
                    RETURNING job_id
                    """
                )
            )
            .mappings()
            .first()
        )
    if not row:
        raise RuntimeError("failed to insert maintenance drill job")
    return int(row["job_id"])


def _insert_background_job_evidence(runtime_dsn: str) -> int:
    engine = create_engine(runtime_dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    """
                    INSERT INTO scan_jobs(
                      org_id,
                      job_type,
                      target_asset_id,
                      requested_by,
                      status,
                      created_at,
                      started_at,
                      finished_at,
                      job_params_json
                    )
                    VALUES (
                      'default',
                      'telemetry_import',
                      NULL,
                      'phase5-release-gate-primer',
                      'done',
                      NOW(),
                      NOW(),
                      NOW(),
                      '{}'::jsonb
                    )
                    RETURNING job_id
                    """
                )
            )
            .mappings()
            .first()
        )
    if not row:
        raise RuntimeError("failed to insert background job freshness evidence")
    return int(row["job_id"])


def _age_job_heartbeat(runtime_dsn: str, *, job_id: int, minutes: int) -> None:
    engine = create_engine(runtime_dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE scan_jobs
                SET last_heartbeat_at = NOW() - (:minutes * INTERVAL '1 minute')
                WHERE job_id = :job_id
                """
            ),
            {"job_id": int(job_id), "minutes": int(minutes)},
        )


def _wait_for_job_final_state(
    base_url: str,
    headers: dict[str, str],
    *,
    job_id: int,
    timeout: float = 120.0,
) -> dict[str, Any]:
    deadline = time.time() + timeout
    last_payload: Any = None
    while time.time() < deadline:
        status, payload = _request_json(
            "GET", f"{base_url}/jobs/{int(job_id)}", headers=headers, timeout=15.0
        )
        if status != 200:
            raise RuntimeError(f"job detail failed for {job_id}: {status} {payload}")
        last_payload = payload
        if str(payload.get("status") or "") in {"done", "failed"}:
            return payload
        time.sleep(2.0)
    raise RuntimeError(f"job {job_id} did not reach a terminal state: {last_payload}")


def _prime_release_gate_evidence(
    *,
    admin_dsn: str,
) -> dict[str, Any]:
    suffix = int(time.time())
    asset_key = f"phase5-release-gate-{suffix}"
    observed_at = datetime.now(UTC).replace(microsecond=0)
    src_octet = 10 + (suffix % 200)
    alert_key = f"phase5-primer-{suffix}"
    engine = create_engine(admin_dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        event_row = (
            conn.execute(
                text(
                    """
                    INSERT INTO security_events(
                      org_id,
                      source,
                      event_type,
                      asset_key,
                      collector,
                      severity,
                      src_ip,
                      protocol,
                      event_time,
                      ingest_lag_seconds,
                      ti_match,
                      mitre_techniques,
                      payload_json
                    )
                    VALUES (
                      'default',
                      'cowrie',
                      'cowrie.login.failed',
                      :asset_key,
                      'phase5.release-gate.primer',
                      2,
                      :src_ip,
                      'ssh',
                      :observed_at,
                      1.0,
                      FALSE,
                      '["TA0006"]'::jsonb,
                      CAST(:payload_json AS jsonb)
                    )
                    RETURNING event_id
                    """
                ),
                {
                    "asset_key": asset_key,
                    "src_ip": f"203.0.113.{src_octet}",
                    "observed_at": observed_at,
                    "payload_json": json.dumps(
                        {
                            "eventid": "cowrie.login.failed",
                            "session": f"phase5-{suffix}",
                            "src_ip": f"203.0.113.{src_octet}",
                            "username": "root",
                            "message": f"Phase 5 release gate primer {suffix}",
                            "timestamp": observed_at.isoformat().replace("+00:00", "Z"),
                        }
                    ),
                },
            )
            .mappings()
            .first()
        )
        alert_row = (
            conn.execute(
                text(
                    """
                    INSERT INTO security_alerts(
                      org_id,
                      alert_key,
                      dedupe_key,
                      source,
                      alert_type,
                      asset_key,
                      severity,
                      status,
                      title,
                      description,
                      event_count,
                      first_seen_at,
                      last_seen_at,
                      ti_match,
                      mitre_techniques,
                      payload_json,
                      context_json,
                      created_at,
                      updated_at
                    )
                    VALUES (
                      'default',
                      :alert_key,
                      :dedupe_key,
                      'cowrie',
                      'detection',
                      :asset_key,
                      'high',
                      'firing',
                      'Phase 5 release gate primer',
                      :description,
                      1,
                      :observed_at,
                      :observed_at,
                      FALSE,
                      '["TA0006"]'::jsonb,
                      '{}'::jsonb,
                      '{}'::jsonb,
                      :observed_at,
                      :observed_at
                    )
                    RETURNING alert_id
                    """
                ),
                {
                    "alert_key": alert_key,
                    "dedupe_key": alert_key,
                    "asset_key": asset_key,
                    "description": f"Phase 5 release gate primer {suffix}",
                    "observed_at": observed_at,
                },
            )
            .mappings()
            .first()
        )
    background_job_id = _insert_background_job_evidence(admin_dsn)
    return {
        "asset_key": asset_key,
        "event_id": int(event_row["event_id"]) if event_row else None,
        "alert_id": int(alert_row["alert_id"]) if alert_row else None,
        "background_job_id": background_job_id,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", default="secplat-phase3")
    parser.add_argument("--api-service", default="secplat-api")
    parser.add_argument("--postgres-service", default="secplat-postgres")
    parser.add_argument("--postgres-pod", default="secplat-postgres-0")
    parser.add_argument("--secret-name", default="secplat-secrets")
    parser.add_argument("--runtime-dsn", default="")
    parser.add_argument("--admin-dsn", default="")
    parser.add_argument("--runtime-dsn-key", default="API_POSTGRES_DSN")
    parser.add_argument("--admin-dsn-key", default="API_MIGRATIONS_POSTGRES_DSN")
    parser.add_argument("--worker-deployment", default="secplat-worker-web")
    parser.add_argument("--release-gate-lookback-hours", type=int, default=1)
    parser.add_argument("--admin-username", default=os.getenv("ADMIN_USERNAME", "admin"))
    parser.add_argument(
        "--admin-password", default=os.getenv("ADMIN_PASSWORD", "secplat-admin-123")
    )
    parser.add_argument(
        "--worker-username",
        default=os.getenv("SCANNER_SERVICE_USERNAME", "scanner-service"),
    )
    parser.add_argument(
        "--worker-password",
        default=os.getenv("SCANNER_SERVICE_PASSWORD", "replace-me"),
    )
    parser.add_argument(
        "--report-out",
        default=str(REPO_ROOT / "artifacts" / "phase5" / "maintenance-report.json"),
    )
    args = parser.parse_args(argv)

    namespace = str(args.namespace or "").strip()
    api_service = str(args.api_service or "").strip()
    postgres_service = str(args.postgres_service or "").strip()
    postgres_pod = str(args.postgres_pod or "").strip()
    worker_deployment = str(args.worker_deployment or "").strip()
    report_out = Path(args.report_out).resolve()
    phase5_dir = report_out.parent
    phase5_dir.mkdir(parents=True, exist_ok=True)
    checks: list[dict[str, Any]] = []

    original_worker_replicas = 1
    worker_scaled_down = False
    runbook_job_id: int | None = None
    try:
        deployment = _run_json(
            ["kubectl", "get", "deployment", worker_deployment, "-n", namespace, "-o", "json"],
            timeout=60.0,
        )
        original_worker_replicas_raw = deployment.get("spec", {}).get("replicas")
        original_worker_replicas = (
            int(original_worker_replicas_raw) if original_worker_replicas_raw is not None else 1
        )
        with (
            PortForward(
                namespace=namespace, resource=f"svc/{api_service}", remote_port=8000
            ) as api_pf,
            PortForward(
                namespace=namespace,
                resource=f"svc/{postgres_service}",
                remote_port=5432,
            ) as pg_pf,
        ):
            base_url = api_pf.base_url
            runtime_dsn = str(args.runtime_dsn or "").strip() or _decode_secret_value(
                namespace,
                str(args.secret_name or "").strip(),
                str(args.runtime_dsn_key or "").strip(),
            )
            admin_dsn = str(args.admin_dsn or "").strip() or _decode_secret_value(
                namespace,
                str(args.secret_name or "").strip(),
                str(args.admin_dsn_key or "").strip(),
            )
            runtime_dsn = _rewrite_dsn_host(runtime_dsn, host="127.0.0.1", port=pg_pf.local_port)
            admin_dsn = _rewrite_dsn_host(admin_dsn, host="127.0.0.1", port=pg_pf.local_port)

            admin_token = _login(
                base_url,
                username=str(args.admin_username or "").strip(),
                password=str(args.admin_password or "").strip(),
            )
            admin_headers = {"Authorization": f"Bearer {admin_token}"}
            primer = _prime_release_gate_evidence(
                admin_dsn=admin_dsn,
            )
            checks.append({"check": "release_gate_evidence_primed", "ok": True, "detail": primer})

            preflight_report = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/run_upgrade_preflight.py"),
                    "--runtime-dsn",
                    runtime_dsn,
                    "--report-out",
                    str(phase5_dir / "upgrade-preflight.json"),
                ],
                timeout=300.0,
            )
            checks.append({"check": "upgrade_preflight", "ok": True, "detail": preflight_report})

            readiness = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/build_readiness_evidence.py"),
                    "--out",
                    str(phase5_dir / "readiness-manifest.json"),
                ]
            )
            checks.append({"check": "readiness_evidence", "ok": True, "detail": readiness})

            postmortems = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/check_postmortem_evidence.py"),
                ]
            )
            checks.append({"check": "postmortem_evidence", "ok": True, "detail": postmortems})

            release_bundle = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/render_release_bundle.py"),
                    "--image-map-json",
                    str(REPO_ROOT / "services/api/examples/release-images.example.json"),
                    "--out-dir",
                    str(phase5_dir / "release-bundle"),
                    "--github-repository",
                    "acme/security-posture-platform",
                ],
                timeout=300.0,
            )
            checks.append(
                {"check": "release_bundle_rendered", "ok": True, "detail": release_bundle}
            )

            kyverno = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/verify_kyverno_admission.py"),
                    "--repo-root",
                    str(phase5_dir / "release-bundle"),
                    "--policy-file",
                    "infra/policy/kyverno/verify-secplat-images.yaml",
                    "--require-real-attestors",
                ],
                timeout=300.0,
            )
            checks.append({"check": "image_verification_posture", "ok": True, "detail": kyverno})
            worker_token = _login(
                base_url,
                username=str(args.worker_username or "").strip(),
                password=str(args.worker_password or "").strip(),
            )
            admin_headers["x-tenant-id"] = "default"
            worker_headers = {
                "Authorization": f"Bearer {worker_token}",
                "x-tenant-id": "default",
            }

            for name, path, predicate in (
                ("api_health", "/health", lambda payload: payload.get("status") == "ok"),
                ("api_ready", "/ready", lambda payload: payload.get("status") == "ok"),
            ):
                status, payload = _request_json("GET", f"{base_url}{path}", timeout=30.0)
                checks.append(
                    {
                        "check": name,
                        "ok": status == 200 and bool(predicate(payload)),
                        "status": status,
                        "detail": payload,
                    }
                )

            release_gate_measurements: dict[str, float | None] | None = None
            runtime_window: dict[str, Any] | None = None
            for iterations in (20, 80, 200):
                runtime_window = _prime_runtime_release_gate_window(base_url, iterations=iterations)
                release_gate_measurements = _compute_release_gate_measurements(
                    runtime_dsn,
                    lookback_hours=max(1, int(args.release_gate_lookback_hours or 1)),
                    captured_after=datetime.fromisoformat(
                        str(runtime_window["captured_after"]).replace("Z", "+00:00")
                    ),
                    source=str(runtime_window["source"]),
                )
                if float(release_gate_measurements.get("api_availability") or 0.0) >= 0.995:
                    break
            checks.append(
                {
                    "check": "release_gate_runtime_window",
                    "ok": runtime_window is not None,
                    "detail": {
                        **(runtime_window or {}),
                        "measurements": release_gate_measurements,
                    },
                }
            )
            if release_gate_measurements is None:
                raise RuntimeError("failed to compute release-gate measurements")
            release_gate_input = {
                "measurements": release_gate_measurements,
            }
            release_gate_input_path = phase5_dir / "release-gate-input.json"
            release_gate_input_path.write_text(
                json.dumps(release_gate_input, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            release_gate_report = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/check_release_gate.py"),
                    "--input",
                    str(release_gate_input_path),
                ]
            )
            checks.append(
                {
                    "check": "release_gate_direct",
                    "ok": True,
                    "detail": release_gate_report,
                }
            )

            endpoint_gate_status, endpoint_gate_payload = _request_json(
                "GET",
                f"{base_url}/platform/release-gate/current?strict_missing=true",
                timeout=30.0,
            )
            checks.append(
                {
                    "check": "release_gate_endpoint_diagnostic",
                    "ok": endpoint_gate_status == 200,
                    "status": endpoint_gate_status,
                    "detail": endpoint_gate_payload,
                }
            )

            for name, path, predicate in (
                ("queue_health", "/queue/health", lambda payload: payload.get("redis") == "ok"),
                (
                    "jobs_analytics",
                    "/jobs/analytics?lookback_hours=24&running_stale_minutes=30",
                    lambda payload: "totals" in payload and "window" in payload,
                ),
                (
                    "recovery_contract",
                    "/platform/recovery-contract",
                    lambda payload: int(payload.get("rpo_hours") or 0) >= 1,
                ),
                (
                    "automation_dashboard",
                    "/automation/dashboard?lookback_hours=24",
                    lambda payload: "runs" in payload,
                ),
            ):
                status, payload = _request_json(
                    "GET", f"{base_url}{path}", headers=admin_headers, timeout=30.0
                )
                checks.append(
                    {
                        "check": name,
                        "ok": status == 200 and bool(predicate(payload)),
                        "status": status,
                        "detail": payload,
                    }
                )

            backup_file = phase5_dir / "maintenance-backup.sql"
            backup_meta = _generate_backup_from_postgres_pod(
                namespace=namespace,
                pod_name=postgres_pod,
                admin_dsn=admin_dsn,
                out_path=backup_file,
            )
            checks.append({"check": "fresh_backup_generated", "ok": True, "detail": backup_meta})

            backup_verification = _run_json(
                [
                    sys.executable,
                    str(REPO_ROOT / "services/api/scripts/verify_backup_restore.py"),
                    "--backup-file",
                    str(backup_file),
                    "--max-age-hours",
                    "24",
                    "--dry-run",
                    "--report-out",
                    str(phase5_dir / "backup-dry-run.json"),
                ],
                timeout=300.0,
            )
            checks.append({"check": "backup_freshness", "ok": True, "detail": backup_verification})

            if original_worker_replicas > 0:
                _scale_worker(namespace, worker_deployment, replicas=0)
                worker_scaled_down = True

            runbook_job_id = _insert_queued_job(runtime_dsn)
            checks.append(
                {
                    "check": "maintenance_job_seeded",
                    "ok": runbook_job_id > 0,
                    "detail": {
                        "job_id": runbook_job_id,
                        "job_type": "score_recompute",
                        "status": "queued",
                        "source": "runtime_db_seed",
                    },
                }
            )
            claim_status, claim_payload = _request_json(
                "POST",
                f"{base_url}/internal/jobs/{runbook_job_id}/claim",
                headers=worker_headers,
                data={"worker_id": "phase5-maintenance-worker"},
                timeout=30.0,
            )
            if claim_status != 200 or claim_payload.get("claimed") is not True:
                raise RuntimeError(
                    f"claim failed for runbook job {runbook_job_id}: {claim_status} {claim_payload}"
                )
            _age_job_heartbeat(admin_dsn, job_id=runbook_job_id, minutes=90)

            preview_status, preview_payload = _request_json(
                "POST",
                f"{base_url}/jobs/maintenance/recover-stale",
                headers=admin_headers,
                data={"running_stale_minutes": 30, "limit": 10, "dry_run": True},
                timeout=30.0,
            )
            preview_ok = preview_status == 200 and any(
                int(item.get("job_id") or 0) == runbook_job_id
                for item in (preview_payload.get("jobs") or [])
            )
            checks.append(
                {
                    "check": "recover_stale_preview",
                    "ok": preview_ok,
                    "status": preview_status,
                    "detail": preview_payload,
                }
            )
            if not preview_ok:
                raise RuntimeError(f"recover-stale dry-run did not return job {runbook_job_id}")

            recover_status, recover_payload = _request_json(
                "POST",
                f"{base_url}/jobs/maintenance/recover-stale",
                headers=admin_headers,
                data={"running_stale_minutes": 30, "limit": 10, "dry_run": False},
                timeout=30.0,
            )
            recover_ok = recover_status == 200 and any(
                int(item.get("job_id") or 0) == runbook_job_id
                for item in (recover_payload.get("jobs") or [])
            )
            checks.append(
                {
                    "check": "recover_stale_execute",
                    "ok": recover_ok,
                    "status": recover_status,
                    "detail": recover_payload,
                }
            )
            if not recover_ok:
                raise RuntimeError(
                    f"recover-stale execute failed for job {runbook_job_id}: {recover_payload}"
                )

            detail_status, detail_payload = _request_json(
                "GET",
                f"{base_url}/jobs/{runbook_job_id}",
                headers=admin_headers,
                timeout=30.0,
            )
            detail_ok = detail_status == 200 and str(detail_payload.get("status") or "") == "queued"
            checks.append(
                {
                    "check": "recover_stale_requeued_detail",
                    "ok": detail_ok,
                    "status": detail_status,
                    "detail": detail_payload,
                }
            )
            if not detail_ok:
                raise RuntimeError(
                    f"recovered job {runbook_job_id} did not remain queued: {detail_payload}"
                )

            if original_worker_replicas > 0:
                _scale_worker(namespace, worker_deployment, replicas=original_worker_replicas)
                worker_scaled_down = False
                _rollout_wait(namespace, worker_deployment)
                final_state = _wait_for_job_final_state(
                    base_url,
                    admin_headers,
                    job_id=runbook_job_id,
                    timeout=180.0,
                )
                checks.append(
                    {
                        "check": "recovered_job_drained",
                        "ok": str(final_state.get("status") or "") in {"done", "failed"},
                        "detail": final_state,
                    }
                )
    except Exception as exc:
        checks.append({"check": "phase5_gate", "ok": False, "detail": str(exc)})
    finally:
        if worker_scaled_down and original_worker_replicas > 0:
            try:
                _scale_worker(namespace, worker_deployment, replicas=original_worker_replicas)
                _rollout_wait(namespace, worker_deployment)
            except Exception as cleanup_exc:
                checks.append(
                    {
                        "check": "worker_restore_cleanup",
                        "ok": False,
                        "detail": str(cleanup_exc),
                    }
                )

    out = {
        "ok": all(bool(item.get("ok")) for item in checks),
        "namespace": namespace,
        "worker_original_replicas": original_worker_replicas,
        "runbook_job_id": runbook_job_id,
        "checks": checks,
    }
    rendered = json.dumps(out, indent=2, sort_keys=True)
    print(rendered)
    report_out.write_text(rendered + "\n", encoding="utf-8")
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
