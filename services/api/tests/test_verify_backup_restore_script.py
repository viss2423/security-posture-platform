from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "verify_backup_restore.py"


def _load_script_module():
    script_path = _script_path()
    spec = importlib.util.spec_from_file_location("verify_backup_restore", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_backup_restore_script_passes_for_valid_backup(tmp_path):
    backup_file = tmp_path / "backup.dump"
    backup_file.write_bytes(b"backup-data")
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--backup-file",
            str(backup_file),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout


def test_verify_backup_restore_script_fails_for_empty_backup(tmp_path):
    backup_file = tmp_path / "empty.dump"
    backup_file.write_bytes(b"")
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--backup-file",
            str(backup_file),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert '"ok": false' in proc.stdout


def test_verify_backup_restore_script_non_dry_run_requires_target_dsn(tmp_path):
    backup_file = tmp_path / "backup.sql"
    backup_file.write_text("CREATE TABLE test_table(id INTEGER);", encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--backup-file",
            str(backup_file),
            "--no-dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "restore_target_dsn required for non-dry-run mode" in proc.stdout


def test_verify_backup_restore_script_non_dry_run_sqlite_restore(tmp_path):
    backup_file = tmp_path / "backup.sql"
    backup_file.write_text(
        "CREATE TABLE restore_probe(id INTEGER PRIMARY KEY);"
        "INSERT INTO restore_probe(id) VALUES (1);",
        encoding="utf-8",
    )
    sqlite_db = tmp_path / "restore-target.db"
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--backup-file",
            str(backup_file),
            "--no-dry-run",
            "--restore-target-dsn",
            f"sqlite+pysqlite:///{sqlite_db}",
            "--expect-table",
            "restore_probe",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"restore_expected_tables"' in proc.stdout
    assert '"ok": true' in proc.stdout


def test_split_sql_statements_handles_pg_dump_comments_and_dollar_quoted_bodies():
    mod = _load_script_module()
    blob = """
--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: secplat
--
CREATE FUNCTION public.set_updated_at() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TABLE restore_probe(id INTEGER PRIMARY KEY);
"""
    statements = mod._split_sql_statements(blob)
    assert any("CREATE FUNCTION public.set_updated_at()" in stmt for stmt in statements)
    assert any("CREATE TABLE restore_probe" in stmt for stmt in statements)
