-- Add retry tracking to rdap_cache for backoff logic
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS last_error TEXT;
