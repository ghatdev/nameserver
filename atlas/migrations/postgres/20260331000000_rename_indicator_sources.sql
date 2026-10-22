-- Rename indicator_sources → sources.
-- FK constraints track by OID, so child tables (indicator_domains, indicator_ips,
-- indicator_asns, filters, enrichment_bindings) continue to work without changes.
ALTER TABLE indicator_sources RENAME TO sources;

-- Rename indexes for hygiene.
ALTER INDEX indicator_sources_pkey RENAME TO sources_pkey;
ALTER INDEX indicator_sources_slug_key RENAME TO sources_slug_key;

-- Grant permissions to nameserver role (matches existing grant pattern).
GRANT SELECT, INSERT, UPDATE, DELETE ON sources TO nameserver;
