#!/bin/bash
# Creates multiple Postgres databases from the POSTGRES_MULTIPLE_DATABASES env var.
# Usage: POSTGRES_MULTIPLE_DATABASES=supertokens,keycloak
set -e

if [ -n "$POSTGRES_MULTIPLE_DATABASES" ]; then
  for db in $(echo "$POSTGRES_MULTIPLE_DATABASES" | tr ',' ' '); do
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
      CREATE DATABASE "$db";
      GRANT ALL PRIVILEGES ON DATABASE "$db" TO "$POSTGRES_USER";
SQL
    echo "Created database: $db"
  done
fi
