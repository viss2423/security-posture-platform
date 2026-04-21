from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "provision_runtime_db_role.py"


def _load_script_module():
    script_path = _script_path()
    spec = importlib.util.spec_from_file_location("provision_runtime_db_role", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_identifier_accepts_safe_identifiers():
    mod = _load_script_module()
    assert mod._validate_identifier("secplat_runtime", label="runtime-user") == "secplat_runtime"
    assert mod._validate_identifier("secplat1", label="runtime-user") == "secplat1"


def test_validate_identifier_rejects_unsafe_identifiers():
    mod = _load_script_module()
    with pytest.raises(ValueError):
        mod._validate_identifier("secplat-runtime", label="runtime-user")
    with pytest.raises(ValueError):
        mod._validate_identifier("secplat runtime", label="runtime-user")
    with pytest.raises(ValueError):
        mod._validate_identifier("123runtime", label="runtime-user")


def test_runtime_dsn_uses_runtime_credentials():
    mod = _load_script_module()
    dsn = mod._runtime_dsn(
        "postgresql+psycopg://admin:admin@localhost:5433/secplat",
        "secplat_runtime",
        "runtime_pw",
    )
    assert "secplat_runtime:runtime_pw@" in dsn


def test_quote_sql_literal_escapes_single_quote():
    mod = _load_script_module()
    quoted = mod._quote_sql_literal("pw'withquote")
    assert quoted == "'pw''withquote'"
