-- Enable pg_stat_statements for query-level performance diagnosis.
-- Requires shared_preload_libraries to include "pg_stat_statements"
-- (configured in nix/modules/nameserver-control.nix), which takes effect
-- on PostgreSQL restart. Apply this migration *after* the deploy that
-- restarts PG with the library loaded; otherwise CREATE EXTENSION fails.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
