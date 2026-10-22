-- Drop the legacy pg_trgm + levenshtein tier-2 similarity stack.
--
-- The Rust binary deployed in commit 38ffc24 no longer issues
-- levenshtein() or `%` queries — `similarity::search_edit_distance`
-- was deleted and the scoring chain's tier-2 fallback path was
-- removed. Both the GIN trigram index and the two extensions are
-- therefore unused; this migration removes them so the desired
-- schema in atlas/schema/postgres.sql converges with reality.
--
-- Production validation (300-label sample, 2026-04-25):
--   * lev returned >=1 neighbor for 15.7% of queries
--   * ANN  returned >=1 neighbor for 100.0% of queries
--   * for the 47 lev-nonempty cases, ANN top-5 overlapped lev top-5
--     with mean 0.612 and median 0.600 (44.7% had full overlap)
--   * 84.3% of queries surface neighbors only ANN can find
--
-- See project_cnn_stage2c_scaffolding.md for full context.

DROP INDEX IF EXISTS idx_dle_label_trgm;

-- pg_trgm and fuzzystrmatch had exactly one consumer each
-- (`search_edit_distance`'s `%` and `levenshtein()` calls). Nothing
-- else in the schema or the codebase depends on them.
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS fuzzystrmatch;
