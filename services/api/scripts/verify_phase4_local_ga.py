"""Run the local Phase 4 GA verification gate against a Kubernetes release."""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, parse, request

REPO_ROOT = Path(__file__).resolve().parents[3]


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    rank = max(0.0, min(100.0, float(pct))) / 100.0 * (len(values) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(values[lower])
    lower_value = float(values[lower])
    upper_value = float(values[upper])
    return lower_value + (upper_value - lower_value) * (rank - lower)


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
    started = time.perf_counter()
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            try:
                return resp.status, {"json": json.loads(payload), "latency_ms": elapsed_ms}
            except json.JSONDecodeError:
                return resp.status, {"body": payload, "latency_ms": elapsed_ms}
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = payload
        return exc.code, {"json": parsed, "latency_ms": elapsed_ms}


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


def _wait_for_http(
    url: str,
    *,
    expect_status: int,
    condition: callable[[Any], bool] | None = None,
    timeout: float = 180.0,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    deadline = time.time() + timeout
    last_payload: Any = None
    last_status: int | None = None
    while time.time() < deadline:
        status, payload = _request_json("GET", url, headers=headers, timeout=10.0)
        last_status = status
        last_payload = payload.get("json") if isinstance(payload, dict) else payload
        if status == expect_status and (condition is None or condition(last_payload)):
            return {
                "ok": True,
                "status": status,
                "payload": last_payload,
            }
        time.sleep(1.0)
    return {
        "ok": False,
        "status": last_status,
        "payload": last_payload,
    }


def _current_pod_name(namespace: str, selector: str) -> str:
    data = _run_json(
        ["kubectl", "get", "pods", "-n", namespace, "-l", selector, "-o", "json"],
        timeout=120.0,
    )
    items = data.get("items") or []
    if not items:
        raise RuntimeError(f"no pods found for selector {selector!r}")
    items.sort(key=lambda item: str(item.get("metadata", {}).get("name", "")))
    return str(items[0]["metadata"]["name"])


def _wait_for_pod_ready(namespace: str, pod_name: str, *, timeout: float = 600.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = _run_json(
            ["kubectl", "get", "pod", "-n", namespace, pod_name, "-o", "json"],
            timeout=120.0,
        )
        conditions = data.get("status", {}).get("conditions") or []
        ready = next((c for c in conditions if c.get("type") == "Ready"), None)
        phase = str(data.get("status", {}).get("phase") or "")
        if phase == "Running" and ready and str(ready.get("status")) == "True":
            return
        time.sleep(2.0)
    raise RuntimeError(f"timed out waiting for pod {pod_name} to become ready")


def _delete_pod(namespace: str, pod_name: str) -> None:
    proc = _run(["kubectl", "delete", "pod", "-n", namespace, pod_name], timeout=120.0)
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)


@dataclass
class LoadResult:
    endpoint: str
    total_requests: int
    success_count: int
    failure_count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "total_requests": self.total_requests,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
            "max_ms": round(self.max_ms, 3),
        }


def _exercise_endpoint(url: str, *, iterations: int) -> LoadResult:
    latencies: list[float] = []
    failures = 0
    for _ in range(iterations):
        status, payload = _request_json("GET", url, timeout=20.0)
        if status >= 400:
            failures += 1
            continue
        latencies.append(float(payload["latency_ms"]))
    success_count = len(latencies)
    values = sorted(latencies)
    return LoadResult(
        endpoint=url,
        total_requests=iterations,
        success_count=success_count,
        failure_count=failures,
        p50_ms=_percentile(values, 50.0),
        p95_ms=_percentile(values, 95.0),
        p99_ms=_percentile(values, 99.0),
        max_ms=max(values) if values else 0.0,
    )


def _restart_and_verify(
    *,
    namespace: str,
    selector: str,
    outage_probe_url: str,
    outage_status: int,
    recovery_probe_url: str,
    recovery_status: int,
    outage_condition: callable[[Any], bool] | None = None,
    recovery_condition: callable[[Any], bool] | None = None,
    label: str,
) -> dict[str, Any]:
    pod_name = _current_pod_name(namespace, selector)
    _delete_pod(namespace, pod_name)
    outage = _wait_for_http(
        outage_probe_url,
        expect_status=outage_status,
        condition=outage_condition,
        timeout=240.0,
    )
    replacement = _current_pod_name(namespace, selector)
    _wait_for_pod_ready(namespace, replacement, timeout=600.0)
    recovery = _wait_for_http(
        recovery_probe_url,
        expect_status=recovery_status,
        condition=recovery_condition,
        timeout=300.0,
    )
    ok = bool(outage.get("ok")) and bool(recovery.get("ok"))
    return {
        "check": label,
        "ok": ok,
        "deleted_pod": pod_name,
        "replacement_pod": replacement,
        "outage": outage,
        "recovery": recovery,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", default="secplat-phase3")
    parser.add_argument("--api-service", default="secplat-api")
    parser.add_argument("--api-port", type=int, default=8000)
    parser.add_argument("--admin-username", default=os.getenv("ADMIN_USERNAME", "admin"))
    parser.add_argument(
        "--admin-password", default=os.getenv("ADMIN_PASSWORD", "secplat-admin-123")
    )
    parser.add_argument("--load-iterations", type=int, default=60)
    parser.add_argument("--api-p95-threshold-ms", type=float, default=500.0)
    parser.add_argument("--report-out", default="artifacts/phase4/ga-local-report.json")
    parser.add_argument(
        "--skip-postgres-restart",
        action="store_true",
        help="Skip the Postgres restart/recovery check.",
    )
    args = parser.parse_args(argv)

    if not shutil.which("kubectl"):
        print(json.dumps({"ok": False, "errors": ["kubectl not found in PATH"]}, indent=2))
        return 2

    report_path = Path(args.report_out)
    if not report_path.is_absolute():
        report_path = REPO_ROOT / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)

    checks: list[dict[str, Any]] = []
    ok = True
    try:
        with PortForward(
            namespace=str(args.namespace),
            resource=f"svc/{args.api_service}",
            remote_port=int(args.api_port),
        ) as pf:
            base_url = pf.base_url
            baseline_health = _wait_for_http(f"{base_url}/health", expect_status=200, timeout=60.0)
            baseline_ready = _wait_for_http(
                f"{base_url}/ready",
                expect_status=200,
                timeout=120.0,
                condition=lambda payload: bool(
                    payload and payload.get("checks", {}).get("postgres") == "ok"
                ),
            )
            baseline_queue = _wait_for_http(
                f"{base_url}/queue/health",
                expect_status=200,
                timeout=120.0,
                condition=lambda payload: bool(payload and payload.get("redis") == "ok"),
            )
            checks.append({"check": "baseline_health", **baseline_health})
            checks.append({"check": "baseline_ready", **baseline_ready})
            checks.append({"check": "baseline_queue_health", **baseline_queue})
            if not all(item.get("ok") for item in checks[-3:]):
                ok = False

            load_checks = [
                _exercise_endpoint(f"{base_url}/health", iterations=int(args.load_iterations)),
                _exercise_endpoint(f"{base_url}/ready", iterations=int(args.load_iterations)),
                _exercise_endpoint(f"{base_url}/auth/config", iterations=int(args.load_iterations)),
            ]
            load_ok = True
            load_details = []
            for result in load_checks:
                detail = result.as_dict()
                detail["threshold_ms"] = float(args.api_p95_threshold_ms)
                detail["ok"] = detail["failure_count"] == 0 and detail["p95_ms"] <= float(
                    args.api_p95_threshold_ms
                )
                load_ok = load_ok and bool(detail["ok"])
                load_details.append(detail)
            checks.append({"check": "api_load_smoke", "ok": load_ok, "detail": load_details})
            ok = ok and load_ok

            checks.append(
                _restart_and_verify(
                    namespace=str(args.namespace),
                    selector="app.kubernetes.io/name=opensearch,app.kubernetes.io/instance=secplat",
                    outage_probe_url=f"{base_url}/ready",
                    outage_status=503,
                    recovery_probe_url=f"{base_url}/ready",
                    recovery_status=200,
                    outage_condition=lambda payload: bool(
                        payload and str(payload.get("checks", {}).get("opensearch") or "") != "ok"
                    ),
                    recovery_condition=lambda payload: bool(
                        payload and payload.get("checks", {}).get("opensearch") == "ok"
                    ),
                    label="opensearch_restart_recovery",
                )
            )
            ok = ok and bool(checks[-1].get("ok"))

            checks.append(
                _restart_and_verify(
                    namespace=str(args.namespace),
                    selector="app.kubernetes.io/name=redis,app.kubernetes.io/instance=secplat",
                    outage_probe_url=f"{base_url}/queue/health",
                    outage_status=503,
                    recovery_probe_url=f"{base_url}/queue/health",
                    recovery_status=200,
                    outage_condition=lambda payload: bool(
                        payload and payload.get("redis") == "error"
                    ),
                    recovery_condition=lambda payload: bool(
                        payload and payload.get("redis") == "ok"
                    ),
                    label="redis_restart_recovery",
                )
            )
            ok = ok and bool(checks[-1].get("ok"))

            if not bool(args.skip_postgres_restart):
                checks.append(
                    _restart_and_verify(
                        namespace=str(args.namespace),
                        selector="app.kubernetes.io/name=postgres,app.kubernetes.io/instance=secplat",
                        outage_probe_url=f"{base_url}/ready",
                        outage_status=503,
                        recovery_probe_url=f"{base_url}/ready",
                        recovery_status=200,
                        outage_condition=lambda payload: bool(
                            payload and str(payload.get("checks", {}).get("postgres") or "") != "ok"
                        ),
                        recovery_condition=lambda payload: bool(
                            payload and payload.get("checks", {}).get("postgres") == "ok"
                        ),
                        label="postgres_restart_recovery",
                    )
                )
                ok = ok and bool(checks[-1].get("ok"))

            final_login_status = None
            try:
                final_token = _login(
                    base_url,
                    username=str(args.admin_username),
                    password=str(args.admin_password),
                )
                status, payload = _request_json(
                    "GET",
                    f"{base_url}/platform/demo/status",
                    headers={"Authorization": f"Bearer {final_token}"},
                    timeout=30.0,
                )
                final_login_status = {
                    "ok": status == 200,
                    "status": status,
                    "payload": payload.get("json"),
                }
            except Exception as exc:
                final_login_status = {"ok": False, "detail": str(exc)}
            checks.append({"check": "post_recovery_api_smoke", **final_login_status})
            ok = ok and bool(checks[-1].get("ok"))
    except Exception as exc:
        ok = False
        checks.append({"check": "phase4_gate", "ok": False, "detail": str(exc)})

    out = {
        "ok": ok,
        "namespace": str(args.namespace),
        "api_service": str(args.api_service),
        "load_iterations": int(args.load_iterations),
        "checks": checks,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    report_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(run())
