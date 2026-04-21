"""Run the Phase 2 runtime hardening and recovery validation gate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime

    UTC = UTC
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.settings import settings

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run_json(cmd: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    return json.loads(proc.stdout)


def _maintenance_dsn(admin_dsn: str) -> str:
    url = make_url(admin_dsn)
    database = str(url.database or "").strip()
    replacement = "postgres" if database.lower() != "postgres" else database
    return url.set(database=replacement or "postgres").render_as_string(hide_password=False)


def _drop_and_create_database(*, admin_dsn: str, database_name: str) -> None:
    engine = create_engine(
        _maintenance_dsn(admin_dsn), isolation_level="AUTOCOMMIT", pool_pre_ping=True
    )
    with engine.connect() as conn:
        conn.execute(
            text(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = :database_name AND pid <> pg_backend_pid()
                """
            ),
            {"database_name": database_name},
        )
        conn.execute(text(f"DROP DATABASE IF EXISTS {database_name}"))
        conn.execute(text(f"CREATE DATABASE {database_name}"))


def _runtime_user_parts(runtime_dsn: str) -> tuple[str, str]:
    url = make_url(runtime_dsn)
    return str(url.username or "").strip(), str(url.password or "").strip()


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime-dsn",
        default=os.getenv("SECPLAT_RUNTIME_DB_DSN") or os.getenv("POSTGRES_DSN", ""),
    )
    parser.add_argument(
        "--admin-dsn",
        default=os.getenv("SECPLAT_ADMIN_DB_DSN")
        or os.getenv("MIGRATIONS_POSTGRES_DSN")
        or "postgresql+psycopg://secplat:secplat@localhost:5433/secplat",
    )
    parser.add_argument(
        "--docker-postgres-container",
        default=os.getenv("SECPLAT_POSTGRES_CONTAINER", "secplat-postgres"),
    )
    parser.add_argument(
        "--image-map-json",
        default="services/api/examples/release-images.example.json",
    )
    parser.add_argument(
        "--release-out-dir",
        default="artifacts/phase2/release-bundle",
    )
    parser.add_argument(
        "--github-repository",
        default="acme/security-posture-platform",
    )
    parser.add_argument(
        "--restore-database",
        default="secplat_restore_phase2",
    )
    parser.add_argument(
        "--backup-out",
        default="artifacts/phase2/secplat-recovery-backup.sql",
    )
    parser.add_argument(
        "--security-contact-email",
        default=os.getenv("SECURITY_CONTACT_EMAIL") or settings.SECURITY_CONTACT_EMAIL,
    )
    parser.add_argument(
        "--security-policy-url",
        default=os.getenv("SECURITY_POLICY_URL") or settings.SECURITY_POLICY_URL,
    )
    parser.add_argument(
        "--security-contact-url",
        default=os.getenv("SECURITY_CONTACT_URL")
        or str(getattr(settings, "SECURITY_CONTACT_URL", "") or ""),
    )
    args = parser.parse_args(argv)

    runtime_dsn = str(args.runtime_dsn or "").strip()
    admin_dsn = str(args.admin_dsn or "").strip()
    if not runtime_dsn or not admin_dsn:
        print(
            json.dumps(
                {"ok": False, "errors": ["missing runtime/admin dsn"]}, indent=2, sort_keys=True
            )
        )
        return 2

    repo_root = REPO_ROOT
    release_out_dir = repo_root / str(args.release_out_dir)
    backup_out = repo_root / str(args.backup_out)
    image_map_json = repo_root / str(args.image_map_json)
    security_env = {
        **os.environ,
        "SECURITY_CONTACT_EMAIL": str(args.security_contact_email or "").strip(),
        "SECURITY_POLICY_URL": str(args.security_policy_url or "").strip(),
        "SECURITY_CONTACT_URL": str(args.security_contact_url or "").strip(),
    }
    checks: list[dict[str, Any]] = []
    restore_report: dict[str, Any] | None = None
    try:
        rendered = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/render_release_bundle.py"),
                "--repo-root",
                str(repo_root),
                "--image-map-json",
                str(image_map_json),
                "--out-dir",
                str(release_out_dir),
                "--github-repository",
                str(args.github_repository),
            ]
        )
        checks.append(
            {"check": "release_bundle_rendered", "ok": True, "detail": rendered["out_dir"]}
        )

        pinning = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/check_k8s_image_pinning.py"),
                "--repo-root",
                str(release_out_dir),
                "--k8s-dir",
                "infra/k8s",
                "--policy-file",
                "infra/policy/kyverno/verify-secplat-images.yaml",
                "--require-real-digests",
            ]
        )
        checks.append({"check": "release_bundle_pinning", "ok": True, "detail": pinning})

        kyverno = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/verify_kyverno_admission.py"),
                "--repo-root",
                str(release_out_dir),
                "--policy-file",
                "infra/policy/kyverno/verify-secplat-images.yaml",
                "--require-real-attestors",
            ]
        )
        checks.append({"check": "kyverno_admission_controls", "ok": True, "detail": kyverno})

        disclosure = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/check_security_disclosure_config.py"),
                "--require-real",
            ],
            env=security_env,
        )
        checks.append({"check": "security_disclosure_config", "ok": True, "detail": disclosure})

        source_role = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/check_db_runtime_role.py"),
                "--dsn",
                runtime_dsn,
                "--require-dsn",
            ]
        )
        checks.append({"check": "source_runtime_role", "ok": True, "detail": source_role})

        backup = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/generate_backup_artifact.py"),
                "--dsn",
                admin_dsn,
                "--out",
                str(backup_out),
                "--docker-container",
                str(args.docker_postgres_container),
            ]
        )
        checks.append({"check": "fresh_backup_artifact", "ok": True, "detail": backup})

        restore_db = str(args.restore_database or "").strip()
        _drop_and_create_database(admin_dsn=admin_dsn, database_name=restore_db)
        runtime_user, runtime_password = _runtime_user_parts(runtime_dsn)
        _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/provision_runtime_db_role.py"),
                "--admin-dsn",
                admin_dsn,
                "--runtime-user",
                runtime_user,
                "--runtime-password",
                runtime_password,
                "--database",
                restore_db,
            ]
        )
        restore_url = (
            make_url(runtime_dsn).set(database=restore_db).render_as_string(hide_password=False)
        )
        restore_admin_url = (
            make_url(admin_dsn).set(database=restore_db).render_as_string(hide_password=False)
        )
        restore_role = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/check_db_runtime_role.py"),
                "--dsn",
                restore_url,
                "--require-dsn",
            ]
        )
        checks.append({"check": "restore_runtime_role", "ok": True, "detail": restore_role})

        report_path = repo_root / "artifacts/phase2/recovery-restore-report.json"
        restore_report = _run_json(
            [
                sys.executable,
                str(repo_root / "services/api/scripts/verify_backup_restore.py"),
                "--backup-file",
                str(backup_out),
                "--no-dry-run",
                "--restore-target-dsn",
                restore_admin_url,
                "--docker-psql-container",
                str(args.docker_postgres_container),
                "--expect-table",
                "assets",
                "--expect-table",
                "findings",
                "--expect-table",
                "users",
                "--expect-table",
                "scan_jobs",
                "--report-out",
                str(report_path),
            ]
        )
        checks.append({"check": "restore_drill", "ok": True, "detail": restore_report})
    except Exception as exc:
        checks.append({"check": "phase2_gate", "ok": False, "detail": str(exc)})

    ok = all(bool(item.get("ok")) for item in checks)
    achieved_rpo_hours = None
    achieved_rto_seconds = None
    if ok and backup_out.exists():
        achieved_rpo_hours = round(
            (
                datetime.now(UTC) - datetime.fromtimestamp(backup_out.stat().st_mtime, tz=UTC)
            ).total_seconds()
            / 3600.0,
            4,
        )
    if ok and restore_report:
        for item in restore_report.get("checks", []):
            if item.get("check") == "restore_duration_seconds":
                achieved_rto_seconds = item.get("detail")
                break

    out = {
        "ok": ok,
        "checks": checks,
        "backup_file": str(backup_out),
        "achieved_rpo_hours": achieved_rpo_hours,
        "achieved_rto_seconds": achieved_rto_seconds,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(run())
