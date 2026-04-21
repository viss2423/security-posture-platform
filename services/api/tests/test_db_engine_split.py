from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _api_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _run_probe(*, postgres_dsn: str, migrations_dsn: str) -> tuple[int, str]:
    code = (
        "from app.db import engine, migration_engine\n"
        "print(engine.url.render_as_string(hide_password=False))\n"
        "print(migration_engine.url.render_as_string(hide_password=False))\n"
    )
    env = {
        **dict(os.environ),
        "POSTGRES_DSN": postgres_dsn,
        "MIGRATIONS_POSTGRES_DSN": migrations_dsn,
        "PYTHONPATH": str(_api_root()),
    }
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_migration_engine_defaults_to_runtime_dsn_when_override_missing():
    runtime = "postgresql+psycopg://runtime:pw@localhost:5432/secplat"
    rc, out = _run_probe(postgres_dsn=runtime, migrations_dsn="")
    assert rc == 0, out
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0] == runtime
    assert lines[1] == runtime


def test_migration_engine_uses_override_dsn_when_provided():
    runtime = "postgresql+psycopg://runtime:pw@localhost:5432/secplat"
    migrations = "postgresql+psycopg://admin:pw@localhost:5432/secplat"
    rc, out = _run_probe(postgres_dsn=runtime, migrations_dsn=migrations)
    assert rc == 0, out
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0] == runtime
    assert lines[1] == migrations
