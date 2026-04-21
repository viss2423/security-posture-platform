from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_contract_parity.py"


def test_check_contract_parity_script_passes_for_repo_state():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
