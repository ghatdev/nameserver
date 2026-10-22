-- flow_novelty: per-flow novelty features sibling to `flows`. Joined by
-- flow_id. Carries is_first_contact (PG-derived) + precomputed registrable
-- so downstream MVs don't need a UDF.

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

-- domain_velocity_5m: AggregatingMergeTree of per-(registrable, window_start)
-- counters. Mergeable across partitions/parts; query via countMerge /
-- uniqMerge.
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
