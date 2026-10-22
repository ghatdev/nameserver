-- Add 'suffix' to the indicator_type enum.
ALTER TYPE indicator_type ADD VALUE IF NOT EXISTS 'suffix';

-- Indicator data: public suffixes (PSL + custom).
CREATE TABLE IF NOT EXISTS indicator_suffixes (
    source    UUID NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    suffix    TEXT NOT NULL,
    rule_type TEXT NOT NULL DEFAULT 'exact',
    added_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source, suffix, rule_type)
);
CREATE INDEX IF NOT EXISTS idx_ind_suffixes_suffix ON indicator_suffixes (suffix);

-- Grant DML access to application user.
GRANT SELECT, INSERT, UPDATE, DELETE ON indicator_suffixes TO nameserver;
