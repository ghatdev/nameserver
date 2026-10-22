-- atlas:txmode none
--
-- Add the missing secondary index on domain_ips(ip).
--
-- The PK (domain, ip) does not serve `WHERE ip = $1` queries (ip is
-- the trailing column), so the `INSERT INTO ips … (SELECT COUNT(DISTINCT
-- domain) FROM domain_ips WHERE ip = $1)` lookup in flow processing
-- falls back to parallel seq scans. With ~900k domain_ips rows at the
-- time of writing, this pegs 3-4 postgres workers at near-full CPU
-- during any burst of flow ingestion (hence the ~90% CPU after the
-- 2026-04-23 injector backlog drain).
--
-- CONCURRENTLY avoids blocking inserts; because of that it can't run
-- inside a transaction, which is why the txmode directive is set to
-- none at the top of this file.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_domain_ips_ip
    ON domain_ips (ip);
