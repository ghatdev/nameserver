-- atlas:txmode none
--
-- Fix the per-flow levenshtein scan in scoring_chain's tier-2 similarity
-- search. `similarity::search_edit_distance` was doing a parallel seq
-- scan over all ~294k rows of domain_label_embeddings at ~127 ms/call
-- because the `levenshtein()` predicate has no index support. With the
-- Stage 2c contrastive embedder not yet built (see
-- project_cnn_stage2a_done.md), levenshtein is still the right
-- semantics — we just need it to be cheap. pg_trgm's `%` operator
-- gives us an index-backed prefilter: the GIN trigram index narrows
-- the candidate set to domains that share 3-grams with the query,
-- then levenshtein runs only over those. Exact edit-distance semantics
-- are preserved because `%` is additive to the existing levenshtein
-- WHERE clause, not a replacement.
--
-- CREATE INDEX CONCURRENTLY is required because domain_label_embeddings
-- is written to inline by ml_worker::process_flow — any write-blocking
-- DDL would starve the detector pipeline during build. That's why this
-- migration runs with txmode=none.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dle_label_trgm
    ON domain_label_embeddings USING GIN (label gin_trgm_ops);
