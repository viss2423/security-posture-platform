from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "build_readiness_evidence.py"


def test_readiness_contract_endpoint_contains_support_sla():
    c = TestClient(app)
    r = c.get("/platform/readiness-contract")
    assert r.status_code == 200
    body = r.json()
    assert body["contract_version"]
    assert body["support_sla"]["sev1"]["initial_response_minutes"] == 30


def test_build_readiness_evidence_script_passes():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
