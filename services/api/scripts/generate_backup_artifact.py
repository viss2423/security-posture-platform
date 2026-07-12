"""Generate a fresh PostgreSQL backup artifact for recovery drills."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime

    UTC = UTC
from pathlib import Path
from typing import Any

from sqlalchemy.engine import make_url


def _resolve_mode(*, explicit_mode: str, docker_container: str) -> str:
    mode = str(explicit_mode or "").strip().lower()
    if mode in {"native", "docker"}:
        return mode
    if shutil.which("pg_dump"):
        return "native"
    if docker_container:
        return "docker"
    raise ValueError("pg_dump is unavailable; pass --docker-container or install pg_dump")


def _parse_dsn(dsn: str) -> dict[str, str]:
    url = make_url(str(dsn or "").strip())
    if (url.get_backend_name() or "").strip() != "postgresql":
        raise ValueError("backup generation only supports PostgreSQL DSNs")
    return {
        "host": str(url.host or "localhost"),
        "port": str(url.port or 5432),
        "username": str(url.username or ""),
        "password": str(url.password or ""),
        "database": str(url.database or ""),
    }


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def _generate_native(*, dsn: str, out_path: Path) -> dict[str, Any]:
    proc = _run(
        [
            "pg_dump",
            "--dbname",
            dsn,
            "--format=plain",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(out_path),
        ]
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "pg_dump failed").strip())
    return {"mode": "native", "stdout_tail": (proc.stdout or "")[-500:]}


def _generate_docker(*, dsn: str, docker_container: str, out_path: Path) -> dict[str, Any]:
    parsed = _parse_dsn(dsn)
    if not parsed["username"] or not parsed["database"]:
        raise ValueError("DSN must include username and database for docker backup mode")
    host = parsed["host"].lower()
    port = parsed["port"]
    if host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        host = "localhost"
        port = "5432"
    container_tmp = f"/tmp/secplat_backup_{secrets.token_hex(8)}.sql"
    password = shlex.quote(parsed["password"])
    command = (
        f"PGPASSWORD={password} "
        "pg_dump "
        f"-h {shlex.quote(host)} -p {shlex.quote(port)} "
        f"-U {shlex.quote(parsed['username'])} "
        f"--dbname {shlex.quote(parsed['database'])} "
        "--format=plain --no-owner --no-privileges "
        f"--file {shlex.quote(container_tmp)}"
    )
    proc = _run(["docker", "exec", docker_container, "sh", "-lc", command])
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "docker pg_dump failed").strip())
    copy = _run(["docker", "cp", f"{docker_container}:{container_tmp}", str(out_path)])
    cleanup = _run(["docker", "exec", docker_container, "rm", "-f", container_tmp])
    if copy.returncode != 0:
        raise RuntimeError((copy.stderr or copy.stdout or "docker cp failed").strip())
    return {
        "mode": "docker",
        "docker_container": docker_container,
        "cleanup_ok": cleanup.returncode == 0,
        "stdout_tail": (proc.stdout or "")[-500:],
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dsn", default=os.getenv("MIGRATIONS_POSTGRES_DSN") or os.getenv("POSTGRES_DSN", "")
    )
    parser.add_argument("--out", required=True, help="Output path for the SQL backup artifact.")
    parser.add_argument("--mode", default="auto", help="Backup mode: auto, native, or docker.")
    parser.add_argument(
        "--docker-container",
        default=os.getenv("SECPLAT_POSTGRES_CONTAINER", ""),
        help="Docker container name used when mode resolves to docker.",
    )
    parser.add_argument("--report-out", default="", help="Optional JSON report output path.")
    args = parser.parse_args(argv)

    dsn = str(args.dsn or "").strip()
    if not dsn:
        out = {"ok": False, "errors": ["missing PostgreSQL DSN"], "mode": "missing"}
        rendered = json.dumps(out, indent=2, sort_keys=True)
        print(rendered)
        if args.report_out:
            Path(args.report_out).write_text(rendered + "\n", encoding="utf-8")
        return 2

    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = _resolve_mode(
            explicit_mode=str(args.mode or "").strip(),
            docker_container=str(args.docker_container or "").strip(),
        )
        if mode == "native":
            meta = _generate_native(dsn=dsn, out_path=out_path)
        else:
            meta = _generate_docker(
                dsn=dsn,
                docker_container=str(args.docker_container or "").strip(),
                out_path=out_path,
            )
        report = {
            "ok": True,
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "mode": mode,
            "backup_file": str(out_path),
            "size_bytes": out_path.stat().st_size,
            **meta,
        }
    except Exception as exc:
        report = {"ok": False, "errors": [str(exc)]}

    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.report_out:
        Path(args.report_out).write_text(rendered + "\n", encoding="utf-8")
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    sys.exit(run())
