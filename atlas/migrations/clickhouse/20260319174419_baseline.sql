-- Create "flows" table
CREATE TABLE `nameserver`.`flows` (
    `profile_id`        String DEFAULT '',
    `geo_country`       LowCardinality(String) DEFAULT '',
    `geo_asn`           UInt32 DEFAULT 0,
    `flow_id`           UUID,
    `started_at`        DateTime64(3),
    `completed_at`      DateTime64(3),
    `total_ms`          UInt32,
    `domain`            String,
    `qtype`             LowCardinality(String),
    `list_action`       LowCardinality(String),
    `list_filter`       String DEFAULT '',
    `rcode`             LowCardinality(String),
    `response_ips`      Array(String),
    `response_ttl`      UInt32,
    `response_auth_ttl` UInt32 DEFAULT 0,
    `dnssec_status`     LowCardinality(String),
    `dnssec_algorithm`  String,
    `dnssec_ds_present` UInt8,
    `dnssec_rrsig_expiry` Int64,
    `dnssec_failure_reason` String,
    `cname_chain`       Array(String),
    `resolution_path` Nested(
        `step`           UInt8,
        `asked`          String,
        `server`         String,
        `server_name`    String,
        `response_type`  LowCardinality(String),
        `ms`             UInt16
    ),
    `all_records_json`  String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (domain, started_at)
TTL toDateTime(started_at) + INTERVAL 90 DAY;

-- Create "ml_predictions" table
CREATE TABLE `nameserver`.`ml_predictions` (
    `predicted_at`      DateTime64(3),
    `domain`            String,
    `ml_probability`    Float32,
    `final_probability` Float32,
    `ml_class`          LowCardinality(String),
    `divergent`         UInt8,
    `override_rule`     String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(predicted_at)
ORDER BY (domain, predicted_at)
TTL toDateTime(predicted_at) + INTERVAL 90 DAY;
