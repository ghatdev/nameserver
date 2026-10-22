-- Expression index for similarity tier-1 queries that filter by the first
-- domain label (split_part(domain, '.', 1)).  Without this, PostgreSQL must
-- seq-scan the 17M+ row indicator_domains table on every call.
CREATE INDEX IF NOT EXISTS idx_ind_domains_label
    ON indicator_domains ((split_part(domain, '.', 1)));

-- Grant access so the application role can use the new index.
GRANT ALL ON indicator_domains TO nameserver;
