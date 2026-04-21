from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "verify_phase5_maintenance.py"


def _load_module():
    script_path = _script_path()
    spec = importlib.util.spec_from_file_location("verify_phase5_maintenance", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rewrite_dsn_host_updates_target_host_and_port():
    mod = _load_module()
    rendered = mod._rewrite_dsn_host(  # noqa: SLF001
        "postgresql+psycopg://user:pass@secplat-postgres:5432/secplat",
        host="127.0.0.1",
        port=15432,
    )
    assert rendered == "postgresql+psycopg://user:pass@127.0.0.1:15432/secplat"


def test_capture_marker_from_sli_payload_prefers_persisted_api_snapshot():
    mod = _load_module()
    fallback = mod.datetime(2026, 4, 4, 13, 15, 0, tzinfo=mod.UTC)  # noqa: SLF001

    marker = mod._capture_marker_from_sli_payload(  # noqa: SLF001
        {
            "api": {"captured_at": "2026-04-04T13:14:40.123456+00:00"},
            "sample": {"captured_at": "2026-04-04T13:14:41.654321+00:00"},
        },
        fallback=fallback,
    )

    assert marker == mod.datetime(2026, 4, 4, 13, 14, 40, 123456, tzinfo=mod.UTC)  # noqa: SLF001


def test_wait_for_worker_scale_zero_waits_for_worker_pods_to_disappear(monkeypatch):
    mod = _load_module()
    deployment_checks = 0
    pod_checks = 0

    def fake_run_json(cmd: list[str], *, timeout: float = 300.0):
        nonlocal deployment_checks, pod_checks
        if cmd[:4] == ["kubectl", "get", "deployment", "secplat-worker-web"]:
            deployment_checks += 1
            return {
                "spec": {
                    "replicas": 0,
                    "selector": {"matchLabels": {"app.kubernetes.io/name": "secplat-worker-web"}},
                },
                "status": {"replicas": 0, "availableReplicas": 0},
            }
        if cmd[:3] == ["kubectl", "get", "pods"]:
            pod_checks += 1
            return (
                {"items": [{"metadata": {"name": "worker-pod"}}]}
                if pod_checks == 1
                else {"items": []}
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(mod, "_run_json", fake_run_json)
    monkeypatch.setattr(mod.time, "sleep", lambda _seconds: None)

    mod._wait_for_worker_scale("test-ns", "secplat-worker-web", replicas=0, timeout=1.0)

    assert deployment_checks >= 2
    assert pod_checks == 2


def test_phase5_run_seeds_job_directly_and_skips_jobs_creation_route(monkeypatch, tmp_path):
    mod = _load_module()

    class FakePortForward:
        def __init__(self, *args, **kwargs):
            self.base_url = "http://127.0.0.1:18080"
            self.local_port = 15432

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    def fake_run_json(cmd: list[str], *, timeout: float = 300.0):
        if cmd[:4] == ["kubectl", "get", "deployment", "secplat-worker-web"]:
            return {"spec": {"replicas": 0}, "status": {"replicas": 0, "availableReplicas": 0}}
        script_name = Path(cmd[1]).name if len(cmd) > 1 else ""
        if script_name == "run_upgrade_preflight.py":
            return {"ok": True}
        if script_name == "build_readiness_evidence.py":
            return {"ok": True}
        if script_name == "check_postmortem_evidence.py":
            return {"ok": True}
        if script_name == "render_release_bundle.py":
            return {"ok": True}
        if script_name == "verify_kyverno_admission.py":
            return {"ok": True}
        if script_name == "verify_backup_restore.py":
            return {"ok": True}
        if script_name == "check_release_gate.py":
            return {"gate_passed": True}
        raise AssertionError(f"unexpected command: {cmd}")

    def fake_request_json(
        method: str,
        url: str,
        *,
        data: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ):
        del headers, timeout
        if method == "POST" and url.endswith("/jobs"):
            raise AssertionError("phase5 verifier should seed the maintenance job directly")
        if method == "GET" and url.endswith("/queue/health"):
            return 200, {"redis": "ok"}
        if method == "GET" and url.endswith("/health"):
            return 200, {"status": "ok"}
        if method == "GET" and url.endswith("/ready"):
            return 200, {"status": "ok"}
        if method == "GET" and "release-gate/current" in url:
            return 200, {"gate_passed": True}
        if method == "GET" and "/jobs/analytics" in url:
            return 200, {"totals": {}, "window": {}}
        if method == "GET" and url.endswith("/platform/recovery-contract"):
            return 200, {"rpo_hours": 24}
        if method == "GET" and "/automation/dashboard" in url:
            return 200, {"runs": {}}
        if method == "POST" and url.endswith("/internal/jobs/77/claim"):
            return 200, {"claimed": True, "job_id": 77}
        if method == "POST" and url.endswith("/jobs/maintenance/recover-stale"):
            if data and data.get("dry_run"):
                return 200, {"jobs": [{"job_id": 77}], "recovered_count": 0}
            return 200, {"jobs": [{"job_id": 77, "status": "queued"}], "recovered_count": 1}
        if method == "GET" and url.endswith("/jobs/77"):
            return 200, {"status": "queued"}
        raise AssertionError(f"unexpected request: {method} {url}")

    seeded_dsns: list[str] = []

    monkeypatch.setattr(mod, "PortForward", FakePortForward)
    monkeypatch.setattr(mod, "_run_json", fake_run_json)
    monkeypatch.setattr(
        mod,
        "_decode_secret_value",
        lambda namespace,
        secret_name,
        key: "postgresql+psycopg://user:pass@secplat-postgres:5432/secplat",
    )
    monkeypatch.setattr(mod, "_rewrite_dsn_host", lambda dsn, *, host, port: dsn)
    monkeypatch.setattr(
        mod, "_login", lambda base_url, *, username, password: f"token-for-{username}"
    )
    monkeypatch.setattr(mod, "_prime_release_gate_evidence", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(
        mod,
        "_prime_runtime_release_gate_window",
        lambda *args, **kwargs: {
            "captured_after": "2026-04-04T13:08:40Z",
            "source": "platform_sli_current_capture",
            "healthy_requests": 60,
            "iterations": 20,
        },
    )
    monkeypatch.setattr(
        mod,
        "_compute_release_gate_measurements",
        lambda *args, **kwargs: {
            "api_availability": 1.0,
            "api_p95_latency_ms": 100.0,
            "ingestion_visibility_seconds": 1.0,
            "alert_creation_seconds": 1.0,
            "background_job_freshness_minutes": 1.0,
        },
    )
    monkeypatch.setattr(mod, "_request_json", fake_request_json)
    monkeypatch.setattr(
        mod,
        "_generate_backup_from_postgres_pod",
        lambda **kwargs: {"backup_file": str(tmp_path / "backup.sql"), "size_bytes": 128},
    )
    monkeypatch.setattr(mod, "_scale_worker", lambda *args, **kwargs: None)
    monkeypatch.setattr(mod, "_rollout_wait", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        mod, "_wait_for_job_final_state", lambda *args, **kwargs: {"status": "done"}
    )
    monkeypatch.setattr(
        mod,
        "_insert_queued_job",
        lambda dsn: seeded_dsns.append(dsn) or 77,
    )
    monkeypatch.setattr(mod, "_age_job_heartbeat", lambda *args, **kwargs: None)

    report_out = tmp_path / "maintenance-report.json"
    exit_code = mod.run(
        [
            "--namespace",
            "test-ns",
            "--report-out",
            str(report_out),
        ]
    )

    assert exit_code == 0
    assert seeded_dsns == ["postgresql+psycopg://user:pass@secplat-postgres:5432/secplat"]
    report = json.loads(report_out.read_text(encoding="utf-8"))
    assert report["ok"] is True
    assert any(
        item["check"] == "maintenance_job_seeded" and item["ok"] for item in report["checks"]
    )
