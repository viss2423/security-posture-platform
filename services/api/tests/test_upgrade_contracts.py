from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_upgrade_contract.py"


def test_upgrade_policy_endpoint_exposes_contract():
    c = TestClient(app)
    r = c.get("/platform/upgrade-policy")
    assert r.status_code == 200
    body = r.json()
    assert body["contract_version"]
    assert body["versioning"]["api"] == "semantic-versioning"
    assert len(body["upgrade_order"]) >= 4


def test_upgrade_contract_script_passes_for_repo_state():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
