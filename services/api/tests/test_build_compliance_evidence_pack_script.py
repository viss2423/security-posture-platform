from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "build_compliance_evidence_pack.py"


def test_build_compliance_evidence_pack_script_passes():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
