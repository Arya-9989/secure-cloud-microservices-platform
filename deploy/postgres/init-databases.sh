#!/bin/sh
# Runs once, on first start of an empty data volume (docker-entrypoint-initdb.d).
# Creates one database and one login role per service. Each role owns only its
# own database and cannot connect to the other one.
set -eu

: "${AUTH_DB_PASSWORD:?AUTH_DB_PASSWORD is required}"
: "${ORDERS_DB_PASSWORD:?ORDERS_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v auth_password="$AUTH_DB_PASSWORD" \
  -v orders_password="$ORDERS_DB_PASSWORD" <<'SQL'
REVOKE ALL ON DATABASE postgres FROM PUBLIC;

CREATE ROLE auth LOGIN PASSWORD :'auth_password';
CREATE DATABASE auth OWNER auth;
REVOKE ALL ON DATABASE auth FROM PUBLIC;

CREATE ROLE orders LOGIN PASSWORD :'orders_password';
CREATE DATABASE orders OWNER orders;
REVOKE ALL ON DATABASE orders FROM PUBLIC;
SQL
