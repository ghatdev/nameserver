-- Add rank column to well_known_domains for ML feature (well_known_rank_norm)
ALTER TABLE well_known_domains ADD COLUMN IF NOT EXISTS rank INTEGER;
