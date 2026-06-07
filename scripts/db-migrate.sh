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

export PGPASSWORD

# Compatible with macOS default Bash 3: do not use mapfile.
# NUL-separated to avoid word-splitting failures when a path contains whitespace.
MIGRATIONS=()
while IFS= read -r -d '' migration; do
 MIGRATIONS+=("${migration}")
done < <(find "${ROOT_DIR}/packages" -type f -path '*/sql/*.sql' -print0 | sort -z)

if [[ "${#MIGRATIONS[@]}" -eq 0 ]]; then
 echo "No SQL migrations found under packages/*/sql."
 exit 0
fi

for migration in "${MIGRATIONS[@]}"; do
 echo "Applying migration: ${migration}"
 psql -v ON_ERROR_STOP=1 \
 --host "${PGHOST}" \
 --port "${PGPORT}" \
 --username "${PGUSER}" \
 --dbname "${PGDATABASE}" \
 --file "${migration}"
done

echo "Applied ${#MIGRATIONS[@]} migration(s)."
