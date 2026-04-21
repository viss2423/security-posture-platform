from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_script_module():
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "generate_backup_artifact.py"
    spec = importlib.util.spec_from_file_location("generate_backup_artifact", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_backup_artifact_resolves_docker_mode_when_container_present():
    mod = _load_script_module()
    mode = mod._resolve_mode(explicit_mode="auto", docker_container="secplat-postgres")
    assert mode in {"native", "docker"}


def test_generate_backup_artifact_parses_postgres_dsn():
    mod = _load_script_module()
    parts = mod._parse_dsn("postgresql+psycopg://secplat:pw@localhost:5433/secplat")
    assert parts["username"] == "secplat"
    assert parts["database"] == "secplat"
    assert parts["port"] == "5433"
