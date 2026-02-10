#!/usr/bin/env bash
# Dump Postgres DB for SecPlat. Load .env or set POSTGRES_DB, POSTGRES_USER, POSTGRES_PORT.
set -e
cd "$(dirname "$0")/.."
if [ -f .env ]; then set -a; source .env; set +a; fi
: "${POSTGRES_DB:=secplat}"
: "${POSTGRES_USER:=secplat}"
: "${POSTGRES_PORT:=5432}"
out="secplat_$(date +%Y%m%d_%H%M).dump"
pg_dump -h "${POSTGRES_HOST:-localhost}" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -F c -f "$out" "$POSTGRES_DB"
echo "Wrote $out"
