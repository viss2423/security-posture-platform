from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_upgrade_compatibility.py"


def test_upgrade_compatibility_script_passes_for_repo_state():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout


def test_upgrade_compatibility_script_fails_for_drop_table(tmp_path):
    migrations = tmp_path / "migrations"
    migrations.mkdir(parents=True, exist_ok=True)
    (migrations / "001_safe.sql").write_text("CREATE TABLE demo(id INTEGER);", encoding="utf-8")
    (migrations / "002_breaking.sql").write_text(
        "DROP TABLE demo;",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--migrations-dir", str(migrations)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert '"ok": false' in proc.stdout
    assert "drop_table" in proc.stdout


def test_upgrade_compatibility_script_allows_marked_breaking_change(tmp_path):
    migrations = tmp_path / "migrations"
    migrations.mkdir(parents=True, exist_ok=True)
    (migrations / "001_breaking.sql").write_text(
        "-- secplat: allow-breaking-change\nDROP TABLE demo;",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--migrations-dir", str(migrations)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
