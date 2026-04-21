from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "run_upgrade_preflight.py"


def test_upgrade_preflight_script_passes_static_repo_checks():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout


def test_upgrade_preflight_script_requires_live_inputs_when_requested():
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--require-live"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "api_base_url required" in proc.stdout
