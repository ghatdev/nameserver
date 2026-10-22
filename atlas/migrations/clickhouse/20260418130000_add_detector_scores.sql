-- detector_scores: one row per (flow_id, detector_name, detector_version).
-- Multiple detectors score the same flow in parallel — rows coexist and are
-- comparable via flow_id join. Used to evaluate detectors against each
-- other and against labels (Pillar 4) before a promotion decision.
--
-- Carries: detector identity + score (0-1) + optional label + scored_at.
-- A features_fingerprint (hash of inputs) lets us reproduce scores if the
-- same detector version is re-run on archived feature sets.

CREATE TABLE nameserver.detector_scores (
    flow_id              UUID,
    started_at           DateTime64(3),
    detector_name        LowCardinality(String),
    detector_version     String,
    score                Float32,
    verdict              LowCardinality(String) DEFAULT '',
    features_fingerprint String DEFAULT '',
    scored_at            DateTime64(3),
    notes                String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (detector_name, detector_version, started_at, flow_id)
TTL toDateTime(started_at) + INTERVAL 90 DAY;
