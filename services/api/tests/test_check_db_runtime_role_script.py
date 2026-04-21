from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_db_runtime_role.py"


def _load_script_module():
    script_path = _script_path()
    spec = importlib.util.spec_from_file_location("check_db_runtime_role", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_evaluate_role_posture_rejects_superuser():
    mod = _load_script_module()
    out = mod.evaluate_role_posture(
        {
            "current_user": "secplat",
            "is_superuser": True,
            "bypass_rls": False,
        }
    )
    assert out["ok"] is False
    assert any("superuser" in msg for msg in out["errors"])


def test_evaluate_role_posture_rejects_bypass_rls():
    mod = _load_script_module()
    out = mod.evaluate_role_posture(
        {
            "current_user": "secplat",
            "is_superuser": False,
            "bypass_rls": True,
        }
    )
    assert out["ok"] is False
    assert any("BYPASSRLS" in msg for msg in out["errors"])


def test_evaluate_role_posture_accepts_non_privileged_role():
    mod = _load_script_module()
    out = mod.evaluate_role_posture(
        {
            "current_user": "secplat_app",
            "is_superuser": False,
            "bypass_rls": False,
        }
    )
    assert out["ok"] is True
    assert out["errors"] == []


def test_check_db_runtime_role_script_skips_when_dsn_missing():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
        env={**dict(os.environ), "SECPLAT_RUNTIME_DB_DSN": "", "POSTGRES_DSN": ""},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"skipped": true' in proc.stdout


def test_check_db_runtime_role_script_fails_when_dsn_required_and_missing():
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--require-dsn"],
        capture_output=True,
        text=True,
        check=False,
        env={**dict(os.environ), "SECPLAT_RUNTIME_DB_DSN": "", "POSTGRES_DSN": ""},
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "missing database DSN" in proc.stdout
