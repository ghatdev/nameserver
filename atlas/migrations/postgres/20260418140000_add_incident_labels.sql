-- incident_labels: external IOCs (URLhaus, ThreatFox, manual review) used as
-- ground truth / weak labels for detector evaluation. See
-- docs/zero-second-detection-eval.md.

CREATE TABLE IF NOT EXISTS incident_labels (
    domain        TEXT NOT NULL,
    source        TEXT NOT NULL,
    labeled_at    TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ,
    verdict       TEXT NOT NULL,
    confidence    REAL,
    threat_type   TEXT,
    extra         JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (domain, source)
);

CREATE INDEX IF NOT EXISTS idx_incident_labels_labeled_at ON incident_labels (labeled_at);
CREATE INDEX IF NOT EXISTS idx_incident_labels_verdict    ON incident_labels (verdict);
CREATE INDEX IF NOT EXISTS idx_incident_labels_first_seen ON incident_labels (first_seen_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_labels TO nameserver;
