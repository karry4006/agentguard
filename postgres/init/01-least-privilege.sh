#!/bin/sh
set -eu

# The official image runs init scripts as the bootstrap superuser. Provision
# separate migration and runtime identities before the first migration runs.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v dbname="$POSTGRES_DB" \
  -v bootstrap_user="$POSTGRES_USER" \
  -v runtime_user="$AGENTGUARD_RUNTIME_USER" \
  -v runtime_password="$AGENTGUARD_RUNTIME_PASSWORD" \
  -v migration_user="$AGENTGUARD_MIGRATION_USER" \
  -v migration_password="$AGENTGUARD_MIGRATION_PASSWORD" \
  -v retention_user="$AGENTGUARD_RETENTION_USER" \
  -v retention_password="$AGENTGUARD_RETENTION_PASSWORD" \
  -v compactor_user="${AGENTGUARD_LEDGER_COMPACTOR_USER:-agentguard_ledger_compactor}" \
  -v compactor_password="${AGENTGUARD_LEDGER_COMPACTOR_PASSWORD}" \
  -v integrity_compactor_user="${AGENTGUARD_INTEGRITY_COMPACTOR_USER:-agentguard_integrity_compactor}" \
  -v integrity_compactor_password="${AGENTGUARD_INTEGRITY_COMPACTOR_PASSWORD:-}" \
  -v replication_user="${AGENTGUARD_ARCHIVE_REPLICATION_USER:-agentguard_replication_worker}" \
  -v replication_password="${AGENTGUARD_ARCHIVE_REPLICATION_PASSWORD:-}" <<'SQL'
CREATE ROLE agentguard_breakglass NOLOGIN SUPERUSER;
CREATE ROLE :"migration_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'migration_password';
CREATE ROLE :"runtime_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'runtime_password';
CREATE ROLE :"retention_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'retention_password';
CREATE ROLE :"compactor_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'compactor_password';
CREATE ROLE :"integrity_compactor_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'integrity_compactor_password';
CREATE ROLE :"replication_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'replication_password';
GRANT CONNECT ON DATABASE :"dbname" TO :"migration_user", :"runtime_user";GRANT CREATE ON DATABASE :"dbname" TO :"migration_user";
GRANT CONNECT ON DATABASE :"dbname" TO :"retention_user";
GRANT CONNECT ON DATABASE :"dbname" TO :"compactor_user";
GRANT CONNECT ON DATABASE :"dbname" TO :"integrity_compactor_user";
GRANT CONNECT ON DATABASE :"dbname" TO :"replication_user";
REVOKE CREATE, TEMPORARY ON DATABASE :"dbname" FROM PUBLIC;
REVOKE CREATE, TEMPORARY ON DATABASE :"dbname" FROM :"runtime_user";
REVOKE CREATE, TEMPORARY ON DATABASE :"dbname" FROM :"compactor_user";
REVOKE CREATE, TEMPORARY ON DATABASE :"dbname" FROM :"integrity_compactor_user";
REVOKE CREATE, TEMPORARY ON DATABASE :"dbname" FROM :"replication_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"migration_user";
GRANT USAGE ON SCHEMA public TO :"runtime_user";
GRANT USAGE ON SCHEMA public TO :"retention_user";
GRANT USAGE ON SCHEMA public TO :"compactor_user";
GRANT USAGE ON SCHEMA public TO :"integrity_compactor_user";
GRANT USAGE ON SCHEMA public TO :"replication_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_user" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"runtime_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_user" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"runtime_user";
ALTER ROLE :"bootstrap_user" NOLOGIN NOINHERIT;
SQL
