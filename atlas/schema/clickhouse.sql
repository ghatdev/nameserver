CREATE TABLE nameserver.flows (
    profile_id        String DEFAULT '',
    geo_country       LowCardinality(String) DEFAULT '',
    geo_asn           UInt32 DEFAULT 0,
    flow_id           UUID,
    started_at        DateTime64(3),
    completed_at      DateTime64(3),
    total_ms          UInt32,
    domain            String,
    qtype             LowCardinality(String),
    list_action       LowCardinality(String),
    list_filter       String DEFAULT '',
    rcode             LowCardinality(String),
    response_ips      Array(String),
    response_ttl      UInt32,
    response_auth_ttl UInt32 DEFAULT 0,
    dnssec_status     LowCardinality(String),
    dnssec_algorithm  String,
    dnssec_ds_present UInt8,
    dnssec_rrsig_expiry Int64,
    dnssec_failure_reason String,
    servfail_reason   LowCardinality(String) DEFAULT '',
    cname_chain       Array(String),
    resolution_path   Nested(
        step           UInt8,
        asked          String,
        server         String,
        server_name    String,
        response_type  LowCardinality(String),
        ms             UInt16,
        error          LowCardinality(String)
    ),
    all_records_json  String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (domain, started_at)
TTL toDateTime(started_at) + INTERVAL 90 DAY;

-- Per-flow novelty features. Sibling table to flows joined by flow_id.
-- Written by the PG processing path AFTER the domains upsert, because
-- is_first_contact requires the PG row state. Decoupled from `flows` so the
-- experimental novelty schema can iterate without disturbing the stable flow
-- ingest table.
CREATE TABLE nameserver.flow_novelty (
    flow_id               UUID,
    started_at            DateTime64(3),
    domain                String,
    registrable           String,
    profile_id            String DEFAULT '',
    geo_asn               UInt32 DEFAULT 0,
    is_first_contact      UInt8,
    first_seen_in_network DateTime64(3),
    age_minutes_at_flow   UInt32
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (registrable, started_at)
TTL toDateTime(started_at) + INTERVAL 90 DAY;

-- Per-domain velocity aggregated in 5-minute windows. Source = flow_novelty
-- (carries the precomputed registrable). AggregatingMergeTree so uniq() is
-- mergeable; query with countMerge / uniqMerge.
CREATE TABLE nameserver.domain_velocity_5m (
    window_start            DateTime64(3),
    registrable             String,
    query_count_state       AggregateFunction(count, UInt8),
    distinct_profiles_state AggregateFunction(uniq, String),
    distinct_asns_state     AggregateFunction(uniq, UInt32)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (registrable, window_start)
TTL toDateTime(window_start) + INTERVAL 30 DAY;

CREATE MATERIALIZED VIEW nameserver.domain_velocity_5m_mv
TO nameserver.domain_velocity_5m AS
SELECT
    toStartOfFiveMinute(started_at) AS window_start,
    registrable,
    countState()                    AS query_count_state,
    uniqState(profile_id)           AS distinct_profiles_state,
    uniqState(geo_asn)              AS distinct_asns_state
FROM nameserver.flow_novelty
GROUP BY window_start, registrable;

-- ML-based detector scores — one row per scored flow. Schema inherited
-- from the legacy `ml_predictions` table. Renamed to `detector_scores`
-- as part of the unification (see PR#5 / migration
-- 20260426_rename_ml_predictions_to_detector_scores.sql); the prior
-- multi-detector `detector_scores` table (generic name/version/score
-- shape) was dropped in the same migration along with that framework.
CREATE TABLE nameserver.detector_scores (
    predicted_at      DateTime64(3),
    domain            String,
    ml_probability    Float32,
    final_probability Float32,
    ml_class          LowCardinality(String),
    divergent         UInt8,
    override_rule     String DEFAULT '',
    ns_trust          LowCardinality(String) DEFAULT '',
    dnssec_adj        Float32 DEFAULT 0,
    ns_adj            Float32 DEFAULT 0,
    similarity_adj    Float32 DEFAULT 0,
    hosting_adj       Float32 DEFAULT 0,
    nrd_adj           Float32 DEFAULT 0,
    temporal_adj      Float32 DEFAULT 0
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(predicted_at)
ORDER BY (domain, predicted_at)
TTL toDateTime(predicted_at) + INTERVAL 90 DAY;
