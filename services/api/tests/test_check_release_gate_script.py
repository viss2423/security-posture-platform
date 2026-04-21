from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_release_gate.py"


def test_check_release_gate_script_passes_for_healthy_inputs(tmp_path):
    payload = {
        "measurements": {
            "api_availability": 0.997,
            "api_p95_latency_ms": 350,
            "ingestion_visibility_seconds": 90,
            "alert_creation_seconds": 100,
            "background_job_freshness_minutes": 12,
        }
    }
    in_file = tmp_path / "sli.json"
    in_file.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--input", str(in_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"gate_passed": true' in proc.stdout


def test_check_release_gate_script_fails_for_budget_exhaustion(tmp_path):
    payload = {
        "measurements": {
            "api_availability": 0.990,
            "api_p95_latency_ms": 350,
            "ingestion_visibility_seconds": 90,
            "alert_creation_seconds": 100,
            "background_job_freshness_minutes": 12,
        }
    }
    in_file = tmp_path / "sli.json"
    in_file.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--input", str(in_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert '"gate_passed": false' in proc.stdout


def test_check_release_gate_script_uses_env_path_input(tmp_path):
    payload = {
        "measurements": {
            "api_availability": 0.998,
            "api_p95_latency_ms": 320,
            "ingestion_visibility_seconds": 60,
            "alert_creation_seconds": 90,
            "background_job_freshness_minutes": 10,
        }
    }
    in_file = tmp_path / "env-sli.json"
    in_file.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
        env={
            **dict(os.environ),
            "SECPLAT_SLI_REPORT_PATH": str(in_file),
            "SECPLAT_SLI_REPORT_JSON": "",
        },
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"input_source": "env:SECPLAT_SLI_REPORT_PATH:file:' in proc.stdout


def test_check_release_gate_script_uses_env_inline_json():
    payload = {
        "measurements": {
            "api_availability": 0.998,
            "api_p95_latency_ms": 350,
            "ingestion_visibility_seconds": 90,
            "alert_creation_seconds": 120,
            "background_job_freshness_minutes": 20,
        }
    }
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
        env={
            **dict(os.environ),
            "SECPLAT_SLI_REPORT_JSON": json.dumps(payload),
            "SECPLAT_SLI_REPORT_PATH": "",
        },
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"input_source": "env:SECPLAT_SLI_REPORT_JSON:inline_json"' in proc.stdout
