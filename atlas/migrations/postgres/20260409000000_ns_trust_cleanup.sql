-- Phase 1: Reset polluted ns_domains (contained root/TLD servers, not authoritative NS).
-- New code stores only authoritative delegation NS; existing data must be cleared so
-- IS DISTINCT FROM comparisons (Phase 2) start from a clean baseline.
UPDATE domain_reputation SET ns_domains = '[]'::jsonb WHERE ns_domains <> '[]'::jsonb;
UPDATE domain_label_embeddings SET ns_domains = '[]'::jsonb WHERE ns_domains <> '[]'::jsonb;

-- Phase 2 prep: track when NS set last changed for continuity-based stability.
ALTER TABLE domain_reputation ADD COLUMN IF NOT EXISTS last_ns_change_at TIMESTAMPTZ;

-- Grant access to the application role.
GRANT ALL ON domain_reputation TO nameserver;
GRANT ALL ON domain_label_embeddings TO nameserver;
