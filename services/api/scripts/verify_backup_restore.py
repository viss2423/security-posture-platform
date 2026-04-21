"""Backup/restore verification helper (dry-run capable)."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time

try:
    from datetime import UTC, datetime, timedelta
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime, timedelta

    UTC = UTC
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


def _backup_status(backup_file: Path | None, *, max_age_hours: int) -> tuple[bool, dict[str, Any]]:
    if backup_file is None:
        return (
            False,
            {
                "check": "backup_file_present",
                "ok": False,
                "detail": "No backup file provided",
            },
        )
    if not backup_file.exists():
        return (
            False,
            {"check": "backup_file_exists", "ok": False, "detail": f"Missing: {backup_file}"},
        )
    size = backup_file.stat().st_size
    if size <= 0:
        return (
            False,
            {"check": "backup_file_non_empty", "ok": False, "detail": "Backup file is empty"},
        )
    mtime = datetime.fromtimestamp(backup_file.stat().st_mtime, tz=UTC)
    max_age = timedelta(hours=max(1, int(max_age_hours)))
    age_ok = datetime.now(UTC) - mtime <= max_age
    return (
        age_ok,
        {
            "check": "backup_file_freshness",
            "ok": age_ok,
            "detail": {
                "path": str(backup_file),
                "size_bytes": size,
                "modified_at": mtime.isoformat().replace("+00:00", "Z"),
                "max_age_hours": int(max_age_hours),
            },
        },
    )


def _is_archive_backup(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered.endswith((".dump", ".backup", ".tar"))


def _run_archive_restore_check(
    backup_file: Path,
    *,
    restore_target_dsn: str,
    restore_cmd: str,
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    started = time.monotonic()
    list_cmd = [restore_cmd, "--list", str(backup_file)]
    listed = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
    list_ok = listed.returncode == 0
    checks.append(
        {
            "check": "restore_archive_readable",
            "ok": list_ok,
            "detail": {
                "command": list_cmd,
                "returncode": listed.returncode,
                "stdout_tail": (listed.stdout or "")[-500:],
                "stderr_tail": (listed.stderr or "")[-500:],
            },
        }
    )
    if not list_ok:
        return False, {"restore_duration_seconds": round(time.monotonic() - started, 3)}, checks

    apply_cmd = [
        restore_cmd,
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        "--dbname",
        restore_target_dsn,
        str(backup_file),
    ]
    applied = subprocess.run(apply_cmd, capture_output=True, text=True, check=False)
    apply_ok = applied.returncode == 0
    checks.append(
        {
            "check": "restore_execution",
            "ok": apply_ok,
            "detail": {
                "command": apply_cmd,
                "returncode": applied.returncode,
                "stdout_tail": (applied.stdout or "")[-500:],
                "stderr_tail": (applied.stderr or "")[-500:],
            },
        }
    )
    return apply_ok, {"restore_duration_seconds": round(time.monotonic() - started, 3)}, checks


def _restore_sql_backup_via_psql(
    backup_file: Path,
    *,
    restore_target_dsn: str,
    restore_sql_cmd: str,
    restore_sql_mode: str,
    docker_psql_container: str,
) -> tuple[bool, dict[str, Any]]:
    mode = str(restore_sql_mode or "auto").strip().lower()
    if mode not in {"auto", "native", "docker", "python"}:
        raise ValueError("restore_sql_mode must be one of: auto, native, docker, python")
    if mode == "python":
        raise ValueError("python mode is not valid for PostgreSQL SQL dumps")

    if mode == "auto":
        if shutil.which(restore_sql_cmd):
            mode = "native"
        elif docker_psql_container:
            mode = "docker"
        else:
            raise ValueError("psql is unavailable; pass --docker-psql-container or install psql")

    if mode == "native":
        proc = subprocess.run(
            [
                restore_sql_cmd,
                "--dbname",
                restore_target_dsn,
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                str(backup_file),
            ],
            capture_output=True,
            text=True,
            check=False,
            env=dict(os.environ),
        )
        return (
            proc.returncode == 0,
            {
                "mode": "native",
                "returncode": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-500:],
                "stderr_tail": (proc.stderr or "")[-500:],
            },
        )

    parsed = make_url(restore_target_dsn)
    host = str(parsed.host or "localhost").lower()
    port = str(parsed.port or 5432)
    if host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        host = "localhost"
        port = "5432"
    username = str(parsed.username or "").strip()
    password = str(parsed.password or "").strip().replace("'", "'\"'\"'")
    database = str(parsed.database or "").strip()
    if not username or not database:
        raise ValueError(
            "restore target dsn must include username and database for docker psql mode"
        )

    container_tmp = f"/tmp/secplat_restore_{secrets.token_hex(8)}.sql"
    copy = subprocess.run(
        ["docker", "cp", str(backup_file), f"{docker_psql_container}:{container_tmp}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if copy.returncode != 0:
        return (
            False,
            {
                "mode": "docker",
                "returncode": copy.returncode,
                "stdout_tail": (copy.stdout or "")[-500:],
                "stderr_tail": (copy.stderr or "")[-500:],
            },
        )
    command = (
        f"PGPASSWORD='{password}' "
        f"{restore_sql_cmd} "
        f"-h '{host}' -p {port} -U '{username}' -d '{database}' "
        "-v ON_ERROR_STOP=1 "
        f"-f '{container_tmp}'"
    )
    proc = subprocess.run(
        ["docker", "exec", docker_psql_container, "sh", "-lc", command],
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(
        ["docker", "exec", docker_psql_container, "rm", "-f", container_tmp],
        capture_output=True,
        text=True,
        check=False,
    )
    return (
        proc.returncode == 0,
        {
            "mode": "docker",
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-500:],
            "stderr_tail": (proc.stderr or "")[-500:],
        },
    )


def _split_sql_statements(blob: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    in_line_comment = False
    in_block_comment = False
    dollar_tag: str | None = None
    line_start = True
    idx = 0
    length = len(blob)

    while idx < length:
        ch = blob[idx]
        nxt = blob[idx + 1] if idx + 1 < length else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                line_start = True
            idx += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                idx += 2
            else:
                idx += 1
            continue

        if dollar_tag is not None:
            current.append(ch)
            if blob.startswith(dollar_tag, idx):
                if len(dollar_tag) > 1:
                    current.extend(list(dollar_tag[1:]))
                idx += len(dollar_tag)
                dollar_tag = None
            else:
                idx += 1
            line_start = ch == "\n"
            continue

        if line_start and ch in {" ", "\t", "\r"}:
            current.append(ch)
            idx += 1
            continue

        if line_start and ch == "\\":
            while idx < length and blob[idx] != "\n":
                idx += 1
            continue

        if not in_single and not in_double:
            if ch == "-" and nxt == "-":
                in_line_comment = True
                idx += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                idx += 2
                continue
            if ch == "$":
                end = idx + 1
                while end < length and (blob[end].isalnum() or blob[end] == "_"):
                    end += 1
                if end < length and blob[end] == "$":
                    dollar_tag = blob[idx : end + 1]
                    current.append(dollar_tag)
                    idx = end + 1
                    line_start = False
                    continue

        if ch == "'" and not in_double:
            current.append(ch)
            if in_single and nxt == "'":
                current.append(nxt)
                idx += 2
                continue
            in_single = not in_single
            idx += 1
            line_start = False
            continue

        if ch == '"' and not in_single:
            current.append(ch)
            in_double = not in_double
            idx += 1
            line_start = False
            continue

        if ch == ";" and not in_single and not in_double:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            idx += 1
            line_start = True
            continue

        current.append(ch)
        line_start = ch == "\n"
        idx += 1

    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def _restore_sql_backup(
    backup_file: Path,
    *,
    restore_target_dsn: str,
    expect_tables: list[str],
    restore_sql_cmd: str,
    restore_sql_mode: str,
    docker_psql_container: str,
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    started = time.monotonic()
    checks: list[dict[str, Any]] = []
    backend = (make_url(restore_target_dsn).get_backend_name() or "").strip().lower()
    if backend == "postgresql":
        restore_ok, restore_detail = _restore_sql_backup_via_psql(
            backup_file,
            restore_target_dsn=restore_target_dsn,
            restore_sql_cmd=restore_sql_cmd,
            restore_sql_mode=restore_sql_mode,
            docker_psql_container=docker_psql_container,
        )
        checks.append(
            {
                "check": "restore_execution",
                "ok": restore_ok,
                "detail": restore_detail,
            }
        )
        if not restore_ok:
            return False, {"restore_duration_seconds": round(time.monotonic() - started, 3)}, checks
    else:
        sql_blob = backup_file.read_text(encoding="utf-8")
        statements = _split_sql_statements(sql_blob)
        if not statements:
            checks.append(
                {
                    "check": "restore_sql_statements_present",
                    "ok": False,
                    "detail": "No executable SQL statements found in backup file",
                }
            )
            return False, {"restore_duration_seconds": round(time.monotonic() - started, 3)}, checks
        engine = create_engine(restore_target_dsn, pool_pre_ping=True)
        executed_count = 0
        try:
            with engine.begin() as conn:
                for stmt in statements:
                    conn.execute(text(stmt))
                    executed_count += 1
        except Exception as exc:
            checks.append(
                {
                    "check": "restore_execution",
                    "ok": False,
                    "detail": {
                        "error": str(exc),
                        "executed_statements": executed_count,
                    },
                }
            )
            return False, {"restore_duration_seconds": round(time.monotonic() - started, 3)}, checks

        checks.append(
            {
                "check": "restore_execution",
                "ok": True,
                "detail": {"executed_statements": executed_count},
            }
        )
    engine = create_engine(restore_target_dsn, pool_pre_ping=True)
    if expect_tables:
        inspector = inspect(engine)
        existing = set(inspector.get_table_names())
        missing = sorted(set(expect_tables) - existing)
        checks.append(
            {
                "check": "restore_expected_tables",
                "ok": len(missing) == 0,
                "detail": {
                    "expected_tables": expect_tables,
                    "missing_tables": missing,
                },
            }
        )
    return (
        all(bool(item.get("ok")) for item in checks),
        {"restore_duration_seconds": round(time.monotonic() - started, 3)},
        checks,
    )


def _run_restore_validation(
    backup_file: Path,
    *,
    restore_target_dsn: str,
    restore_cmd: str,
    expect_tables: list[str],
    restore_sql_cmd: str,
    restore_sql_mode: str,
    docker_psql_container: str,
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    if _is_archive_backup(backup_file):
        return _run_archive_restore_check(
            backup_file,
            restore_target_dsn=restore_target_dsn,
            restore_cmd=restore_cmd,
        )
    return _restore_sql_backup(
        backup_file,
        restore_target_dsn=restore_target_dsn,
        expect_tables=expect_tables,
        restore_sql_cmd=restore_sql_cmd,
        restore_sql_mode=restore_sql_mode,
        docker_psql_container=docker_psql_container,
    )


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-file", default="", help="Path to backup artifact to validate")
    parser.add_argument(
        "--max-age-hours",
        type=int,
        default=24,
        help="Maximum allowed backup age in hours",
    )
    parser.add_argument(
        "--report-out",
        default="",
        help="Optional path to write JSON verification report",
    )
    parser.add_argument(
        "--restore-target-dsn",
        default="",
        help="Target database DSN for non-dry-run restore verification.",
    )
    parser.add_argument(
        "--restore-cmd",
        default="pg_restore",
        help="Restore command used for archive backups (.dump/.backup/.tar).",
    )
    parser.add_argument(
        "--restore-sql-cmd",
        default="psql",
        help="Restore command used for plain SQL backups when target is PostgreSQL.",
    )
    parser.add_argument(
        "--restore-sql-mode",
        default="auto",
        help="Restore mode for plain SQL backups: auto, native, docker, or python.",
    )
    parser.add_argument(
        "--docker-psql-container",
        default=os.getenv("SECPLAT_POSTGRES_CONTAINER", ""),
        help="Docker container name used when restore_sql_mode resolves to docker.",
    )
    parser.add_argument(
        "--expect-table",
        action="append",
        default=[],
        help="Table expected to exist after restore (repeatable).",
    )
    parser.add_argument(
        "--dry-run",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep true for CI/local checks that do not execute restore operations.",
    )
    args = parser.parse_args(argv)
    backup_file = Path(args.backup_file) if args.backup_file else None
    backup_ok, backup_check = _backup_status(backup_file, max_age_hours=args.max_age_hours)
    checks = [backup_check]
    if args.dry_run:
        checks.append(
            {
                "check": "restore_execution",
                "ok": True,
                "detail": "Dry-run mode: restore command execution skipped",
            }
        )
    else:
        if backup_file is None:
            checks.append(
                {
                    "check": "restore_execution",
                    "ok": False,
                    "detail": "backup_file is required for non-dry-run mode",
                }
            )
        elif not str(args.restore_target_dsn or "").strip():
            checks.append(
                {
                    "check": "restore_execution",
                    "ok": False,
                    "detail": "restore_target_dsn required for non-dry-run mode",
                }
            )
        elif backup_ok:
            restore_ok, restore_meta, restore_checks = _run_restore_validation(
                backup_file,
                restore_target_dsn=str(args.restore_target_dsn).strip(),
                restore_cmd=str(args.restore_cmd).strip() or "pg_restore",
                expect_tables=[
                    str(item).strip() for item in (args.expect_table or []) if str(item).strip()
                ],
                restore_sql_cmd=str(args.restore_sql_cmd).strip() or "psql",
                restore_sql_mode=str(args.restore_sql_mode).strip() or "auto",
                docker_psql_container=str(args.docker_psql_container).strip(),
            )
            checks.extend(restore_checks)
            checks.append(
                {
                    "check": "restore_duration_seconds",
                    "ok": restore_ok,
                    "detail": restore_meta.get("restore_duration_seconds"),
                }
            )
    report = {
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "dry_run": bool(args.dry_run),
        "ok": all(bool(item.get("ok")) for item in checks),
        "checks": checks,
    }
    if args.report_out:
        Path(args.report_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
