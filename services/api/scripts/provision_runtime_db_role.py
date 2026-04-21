"""Provision a least-privilege PostgreSQL runtime role for SecPlat."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _validate_identifier(value: str, *, label: str) -> str:
    candidate = str(value or "").strip()
    if not IDENTIFIER_RE.match(candidate):
        raise ValueError(f"invalid {label}: {value!r}")
    return candidate


def _resolve_admin_dsn(explicit: str) -> str:
    if explicit.strip():
        return explicit.strip()
    from_env = str(os.getenv("POSTGRES_DSN", "") or "").strip()
    if from_env:
        return from_env
    raise ValueError("missing admin DSN; pass --admin-dsn or set POSTGRES_DSN")


def _runtime_dsn(admin_dsn: str, runtime_user: str, runtime_password: str) -> str:
    url = make_url(admin_dsn)
    runtime_url = url.set(username=runtime_user, password=runtime_password)
    return runtime_url.render_as_string(hide_password=False)


def _database_name(admin_dsn: str, override: str) -> str:
    if override.strip():
        return override.strip()
    url = make_url(admin_dsn)
    name = (url.database or "").strip()
    if not name:
        raise ValueError("could not resolve database name from DSN; pass --database")
    return name


def _quote_sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--admin-dsn",
        default="",
        help="Admin/superuser DSN used to create and grant runtime role.",
    )
    parser.add_argument(
        "--runtime-user",
        default="secplat_runtime",
        help="Runtime application role to create/update.",
    )
    parser.add_argument(
        "--runtime-password",
        default="secplat_runtime",
        help="Password for runtime role.",
    )
    parser.add_argument(
        "--database",
        default="",
        help="Database name to grant connect privileges on (default: resolve from admin DSN).",
    )
    parser.add_argument(
        "--connect-timeout-seconds",
        type=int,
        default=5,
        help="Connection timeout for admin DSN.",
    )
    args = parser.parse_args(argv)

    try:
        admin_dsn = _resolve_admin_dsn(args.admin_dsn)
        runtime_user = _validate_identifier(args.runtime_user, label="runtime-user")
        database_name = _validate_identifier(
            _database_name(admin_dsn, args.database), label="database"
        )
        runtime_password = str(args.runtime_password or "").strip()
        if not runtime_password:
            raise ValueError("runtime-password cannot be empty")
        escaped_password = _quote_sql_literal(runtime_password)

        engine = create_engine(
            admin_dsn,
            pool_pre_ping=True,
            connect_args={"connect_timeout": int(args.connect_timeout_seconds)},
        )
        with engine.begin() as conn:
            exists = bool(
                conn.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :role_name"),
                    {"role_name": runtime_user},
                )
                .mappings()
                .first()
            )
            if exists:
                conn.execute(
                    text(
                        f"ALTER ROLE {runtime_user} "
                        f"LOGIN PASSWORD {escaped_password} NOSUPERUSER NOBYPASSRLS "
                        "NOCREATEDB NOCREATEROLE NOREPLICATION"
                    )
                )
            else:
                conn.execute(
                    text(
                        f"CREATE ROLE {runtime_user} "
                        f"LOGIN PASSWORD {escaped_password} NOSUPERUSER NOBYPASSRLS "
                        "NOCREATEDB NOCREATEROLE NOREPLICATION"
                    )
                )
            conn.execute(text(f"GRANT CONNECT ON DATABASE {database_name} TO {runtime_user}"))
            conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {runtime_user}"))
            conn.execute(
                text(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {runtime_user}"
                )
            )
            conn.execute(
                text(
                    f"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {runtime_user}"
                )
            )
            conn.execute(
                text(
                    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {runtime_user}"
                )
            )
            conn.execute(
                text(
                    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                    f"GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {runtime_user}"
                )
            )

        out: dict[str, Any] = {
            "ok": True,
            "runtime_user": runtime_user,
            "database": database_name,
            "runtime_dsn": _runtime_dsn(admin_dsn, runtime_user, runtime_password),
        }
    except Exception as exc:
        out = {"ok": False, "errors": [str(exc)]}

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    sys.exit(run())
