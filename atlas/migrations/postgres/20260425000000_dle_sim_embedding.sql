-- Stage 2c: contrastive label embedder integration.
--
-- Adds the 64-dim `sim_embedding` column + HNSW cosine index to
-- `domain_label_embeddings`. The new column is nullable so existing
-- rows can be backfilled incrementally; the live query path will
-- skip rows where `sim_embedding IS NULL`.
--
-- See:
--   * project_cnn_stage2c_scaffolding.md — the trained model
--     (`ml/models/detector_cnn_sim_v1/cnn_sim_embedding.onnx`,
--     slice-3 R@5 = 1.000 at epoch 6).
--   * crates/nameserver-control/src/similarity.rs — `search_edit_distance`
--     rewrite that consumes the new column.
--   * The existing 32-dim `embedding` column is retained — it feeds
--     LightGBM as a lexical feature and is not redundant with
--     `sim_embedding` (different geometry, different consumer).

ALTER TABLE domain_label_embeddings
    ADD COLUMN IF NOT EXISTS sim_embedding vector(64);

CREATE INDEX IF NOT EXISTS idx_dle_sim_embedding
    ON domain_label_embeddings USING hnsw (sim_embedding vector_cosine_ops);
