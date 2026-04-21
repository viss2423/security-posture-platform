"""Validate database runtime role posture for tenant-isolated deployments.

Checks that the active DB role is not superuser and does not bypass row-level security.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from sqlalchemy import create_engine, text


def evaluate_role_posture(row: dict[str, Any]) -> dict[str, Any]:
    current_user = str(row.get("current_user") or "").strip()
    is_superuser = bool(row.get("is_superuser"))
    bypass_rls = bool(row.get("bypass_rls"))
    checks = [
        {
            "check": "db_role_resolved",
            "ok": bool(current_user),
            "detail": current_user or "missing current_user",
        },
        {
            "check": "db_role_not_superuser",
            "ok": not is_superuser,
            "detail": "superuser disabled" if not is_superuser else "runtime role is superuser",
        },
        {
            "check": "db_role_no_bypass_rls",
            "ok": not bypass_rls,
            "detail": "BYPASSRLS disabled" if not bypass_rls else "runtime role has BYPASSRLS",
        },
    ]
    errors = [item["detail"] for item in checks if not item["ok"]]
    return {
        "ok": len(errors) == 0,
        "current_user": current_user,
        "is_superuser": is_superuser,
        "bypass_rls": bypass_rls,
        "checks": checks,
        "errors": errors,
    }


def _resolve_dsn(*, explicit_dsn: str, dsn_env: str) -> tuple[str, str]:
    dsn = str(explicit_dsn or "").strip()
    if dsn:
        return dsn, "arg:--dsn"

    env_name = str(dsn_env or "").strip() or "SECPLAT_RUNTIME_DB_DSN"
    env_dsn = str(os.getenv(env_name, "") or "").strip()
    if env_dsn:
        return env_dsn, f"env:{env_name}"

    default_env_dsn = str(os.getenv("POSTGRES_DSN", "") or "").strip()
    if default_env_dsn:
        return default_env_dsn, "env:POSTGRES_DSN"

    return "", "missing"


def _fetch_role_row(dsn: str, *, connect_timeout_seconds: int) -> dict[str, Any]:
    engine = create_engine(
        dsn,
        pool_pre_ping=True,
        connect_args={"connect_timeout": int(connect_timeout_seconds)},
    )
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    """
                    SELECT
                      current_user AS current_user,
                      r.rolsuper AS is_superuser,
                      r.rolbypassrls AS bypass_rls
                    FROM pg_roles r
                    WHERE r.rolname = current_user
                    """
                )
            )
            .mappings()
            .first()
        )
    if row is None:
        raise RuntimeError("Unable to resolve runtime role from pg_roles")
    return dict(row)


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default="", help="Database DSN to evaluate.")
    parser.add_argument(
        "--dsn-env",
        default="SECPLAT_RUNTIME_DB_DSN",
        help="Environment variable to read DSN from when --dsn is not set.",
    )
    parser.add_argument(
        "--require-dsn",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail when DSN is not provided via arg/env.",
    )
    parser.add_argument(
        "--connect-timeout-seconds",
        type=int,
        default=5,
        help="Connection timeout used for role posture query.",
    )
    parser.add_argument(
        "--report-out",
        default="",
        help="Optional output path for JSON report.",
    )
    args = parser.parse_args(argv)

    dsn, dsn_source = _resolve_dsn(explicit_dsn=args.dsn, dsn_env=args.dsn_env)
    if not dsn:
        out = {
            "ok": not bool(args.require_dsn),
            "skipped": True,
            "dsn_source": dsn_source,
            "errors": [] if not bool(args.require_dsn) else ["missing database DSN"],
        }
        rendered = json.dumps(out, indent=2, sort_keys=True)
        print(rendered)
        if args.report_out:
            with open(args.report_out, "w", encoding="utf-8") as f:
                f.write(rendered + "\n")
        return 0 if out["ok"] else 2

    try:
        row = _fetch_role_row(dsn, connect_timeout_seconds=int(args.connect_timeout_seconds))
        posture = evaluate_role_posture(row)
        out = {
            **posture,
            "skipped": False,
            "dsn_source": dsn_source,
        }
    except Exception as exc:
        out = {
            "ok": False,
            "skipped": False,
            "dsn_source": dsn_source,
            "errors": [str(exc)],
        }

    rendered = json.dumps(out, indent=2, sort_keys=True)
    print(rendered)
    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    sys.exit(run())
