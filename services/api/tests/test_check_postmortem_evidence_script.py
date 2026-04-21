from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_postmortem_evidence.py"


def test_postmortem_evidence_script_passes_for_repo_state():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout


def test_postmortem_evidence_script_fails_for_invalid_file(tmp_path):
    postmortems = tmp_path / "postmortems"
    postmortems.mkdir(parents=True, exist_ok=True)
    (postmortems / "README.md").write_text(
        "# Incident Postmortem Evidence\nsev1 and sev2 are required\n",
        encoding="utf-8",
    )
    (postmortems / "template.md").write_text(
        "\n".join(
            [
                "# template",
                "## Summary",
                "## Impact",
                "## Timeline",
                "## Root Cause",
                "## Corrective Actions",
                "## Prevention Actions",
                "## Owner",
            ]
        ),
        encoding="utf-8",
    )
    (postmortems / "2026-03-09-sev1-bad.md").write_text(
        "\n".join(
            [
                "# 2026-03-09-sev1-bad",
                "## Summary",
                "x",
                "## Impact",
                "x",
                "## Timeline",
                "x",
                "## Root Cause",
                "x",
                "## Corrective Actions",
                "x",
                "## Prevention Actions",
                "no bullet",
                "## Owner",
                "x",
            ]
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--postmortems-dir", str(postmortems)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "Prevention Actions must include at least one bullet" in proc.stdout
