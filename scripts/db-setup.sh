#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${ROOT_DIR}/.env" ]]; then
 set -a
 # shellcheck disable=SC1091
 source "${ROOT_DIR}/.env"
 set +a
fi

PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
PGDATABASE="${PGDATABASE:-coivitas_dev}"
PGUSER="${PGUSER:-coivitas}"
PGPASSWORD="${PGPASSWORD:-coivitas}"
PGBOOTSTRAP_DB="${PGBOOTSTRAP_DB:-postgres}"

export PGPASSWORD

psql -v ON_ERROR_STOP=1 \
 --host "${PGHOST}" \
 --port "${PGPORT}" \
 --username "${PGUSER}" \
 --dbname "${PGBOOTSTRAP_DB}" <<SQL
SELECT 'CREATE DATABASE "${PGDATABASE}"'
WHERE NOT EXISTS (
 SELECT 1 FROM pg_database WHERE datname = '${PGDATABASE}'
)\gexec
SQL

psql -v ON_ERROR_STOP=1 \
 --host "${PGHOST}" \
 --port "${PGPORT}" \
 --username "${PGUSER}" \
 --dbname "${PGDATABASE}" <<'SQL'
CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS policy;
SQL

echo "Database schemas are ready in ${PGDATABASE}."
