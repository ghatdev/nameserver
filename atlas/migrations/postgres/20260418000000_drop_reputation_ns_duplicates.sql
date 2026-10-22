-- Drop legacy duplicate NS columns from domain_reputation.
-- Canonical NS list lives in domain_ns_map. Change detection is now computed
-- in Rust (see reputation::detect_ns_change) with provider-level coalescing.

ALTER TABLE domain_reputation DROP COLUMN IF EXISTS ns_domains;
ALTER TABLE domain_reputation DROP COLUMN IF EXISTS delegation_ns;

-- Reset last_ns_change_at for rows where the value was set by the buggy
-- strict-equality JSONB comparator during the 2026-04-09 → 2026-04-12 window
-- when the auth-NS extractor was being fixed. These are demonstrably spurious
-- (the extractor changed what was stored, not what the delegation actually was).
UPDATE domain_reputation
   SET last_ns_change_at = NULL
 WHERE last_ns_change_at >= '2026-04-09'::timestamptz
   AND last_ns_change_at <  '2026-04-13'::timestamptz;
