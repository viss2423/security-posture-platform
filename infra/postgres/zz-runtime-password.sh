#!/bin/bash
# Runs after init.sql on first DB init (alphabetical order: init.sql < zz-...).
#
# init.sql creates the least-privilege `secplat_runtime` role with a hardcoded
# default password. In production POSTGRES_RUNTIME_PASSWORD is a strong secret,
# so without this sync the API/ingestion connect with the strong password while
# the role still has the default — causing "password authentication failed" and
# a crash-loop. This aligns the role's password with POSTGRES_RUNTIME_PASSWORD.
set -euo pipefail

if [ -n "${POSTGRES_RUNTIME_PASSWORD:-}" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    ALTER ROLE secplat_runtime WITH PASSWORD '${POSTGRES_RUNTIME_PASSWORD}';
SQL
  echo "[init] secplat_runtime password synced from POSTGRES_RUNTIME_PASSWORD"
fi
