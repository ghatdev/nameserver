use clickhouse::Row;
use nameserver_common::messages::flow::DnsFlow;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Flattened representation of [`DnsFlow`] for ClickHouse columnar storage.
///
/// Resolution path uses ClickHouse Nested parallel arrays.
/// `all_records` is stored as a JSON string (complex nested, rarely queried per-column).
#[derive(Row, Serialize, Deserialize, Debug)]
pub struct FlowRow {
    pub profile_id: String,
    pub geo_country: String,
    pub geo_asn: u32,
    #[serde(with = "clickhouse::serde::uuid")]
    pub flow_id: Uuid,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub started_at: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub completed_at: OffsetDateTime,
    pub total_ms: u32,
    pub domain: String,
    pub qtype: String,
    pub list_action: String,
    pub list_filter: String,
    pub rcode: String,
    pub response_ips: Vec<String>,
    pub response_ttl: u32,
    pub response_auth_ttl: u32,
    pub dnssec_status: String,
    pub dnssec_algorithm: String,
    pub dnssec_ds_present: u8,
    pub dnssec_rrsig_expiry: i64,
    pub dnssec_failure_reason: String,
    pub servfail_reason: String,
    pub cname_chain: Vec<String>,
    // Resolution path as Nested parallel arrays.
    #[serde(rename = "resolution_path.step")]
    pub rp_step: Vec<u8>,
    #[serde(rename = "resolution_path.asked")]
    pub rp_asked: Vec<String>,
    #[serde(rename = "resolution_path.server")]
    pub rp_server: Vec<String>,
    #[serde(rename = "resolution_path.server_name")]
    pub rp_server_name: Vec<String>,
    #[serde(rename = "resolution_path.response_type")]
    pub rp_response_type: Vec<String>,
    #[serde(rename = "resolution_path.ms")]
    pub rp_ms: Vec<u16>,
    /// Categorized transport error when response_type = "error" — one of
    /// timeout, connection_refused, truncated, id_mismatch, question_mismatch,
    /// invalid_response, network_error. Empty for non-error steps. Lets us
    /// distinguish send failures from upstream SERVFAIL without parsing
    /// all_records_json.
    #[serde(rename = "resolution_path.error")]
    pub rp_error: Vec<String>,
    pub all_records_json: String,
}

impl From<DnsFlow> for FlowRow {
    fn from(f: DnsFlow) -> Self {
        let started_at =
            OffsetDateTime::from_unix_timestamp_nanos(f.started_at as i128 * 1_000_000)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let completed_at =
            OffsetDateTime::from_unix_timestamp_nanos(f.completed_at as i128 * 1_000_000)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);

        let qtype = serde_json::to_value(&f.query.qtype)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", f.query.qtype));
        let list_action = serde_json::to_value(&f.list_action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", f.list_action));
        let rcode = serde_json::to_value(&f.response.rcode)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", f.response.rcode));
        let dnssec_status = serde_json::to_value(&f.dnssec.status)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", f.dnssec.status));

        let mut rp_step = Vec::with_capacity(f.resolution_path.len());
        let mut rp_asked = Vec::with_capacity(f.resolution_path.len());
        let mut rp_server = Vec::with_capacity(f.resolution_path.len());
        let mut rp_server_name = Vec::with_capacity(f.resolution_path.len());
        let mut rp_response_type = Vec::with_capacity(f.resolution_path.len());
        let mut rp_ms = Vec::with_capacity(f.resolution_path.len());
        let mut rp_error = Vec::with_capacity(f.resolution_path.len());

        for step in &f.resolution_path {
            rp_step.push(step.step);
            rp_asked.push(step.asked.clone());
            rp_server.push(step.server.clone());
            rp_server_name.push(step.server_name.clone().unwrap_or_default());
            let rt = serde_json::to_value(&step.response_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", step.response_type));
            rp_response_type.push(rt);
            rp_ms.push(step.ms);
            rp_error.push(step.got.error.clone().unwrap_or_default());
        }

        let all_records_json = serde_json::to_string(&f.response.all_records).unwrap_or_default();

        FlowRow {
            profile_id: f.profile_id.unwrap_or_default(),
            geo_country: f.geo_country.unwrap_or_default(),
            geo_asn: f.geo_asn,
            flow_id: f.flow_id,
            started_at,
            completed_at,
            total_ms: f.total_ms,
            domain: f.query.domain,
            qtype,
            list_action,
            list_filter: f.list_filter.unwrap_or_default(),
            rcode,
            response_ips: f.response.ips,
            response_ttl: f.response.min_ttl,
            response_auth_ttl: f.response.auth_ttl,
            dnssec_status,
            dnssec_algorithm: f.dnssec.algorithm.unwrap_or_default(),
            dnssec_ds_present: u8::from(f.dnssec.ds_present),
            dnssec_rrsig_expiry: f.dnssec.rrsig_expiry.unwrap_or(0),
            dnssec_failure_reason: f.dnssec.failure_reason.unwrap_or_default(),
            servfail_reason: f.servfail_reason.map(|r| r.to_string()).unwrap_or_default(),
            cname_chain: f.cname_chain.unwrap_or_default(),
            rp_step,
            rp_asked,
            rp_server,
            rp_server_name,
            rp_response_type,
            rp_ms,
            rp_error,
            all_records_json,
        }
    }
}

/// Per-flow novelty features. Written by the PG processing path after the
/// domains upsert, so `is_first_contact` reflects PG-side truth. Joined back
/// to `flows` by `flow_id`.
#[derive(Row, Serialize, Deserialize, Debug, Clone)]
pub struct FlowNoveltyRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub flow_id: Uuid,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub started_at: OffsetDateTime,
    pub domain: String,
    pub registrable: String,
    pub profile_id: String,
    pub geo_asn: u32,
    pub is_first_contact: u8,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub first_seen_in_network: OffsetDateTime,
    pub age_minutes_at_flow: u32,
}

/// ClickHouse `detector_scores` row — one per scored flow. Schema
/// inherited from the legacy `ml_predictions` table; the rename happened
/// in migration `20260426_rename_ml_predictions_to_detector_scores.sql`.
#[derive(Row, Serialize, Deserialize, Debug)]
pub struct DetectorScoreRow {
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub predicted_at: OffsetDateTime,
    pub domain: String,
    pub ml_probability: f32,
    pub final_probability: f32,
    pub ml_class: String,
    pub divergent: u8,
    pub override_rule: String,
    pub ns_trust: String,
    pub dnssec_adj: f32,
    pub ns_adj: f32,
    pub similarity_adj: f32,
    pub hosting_adj: f32,
    pub nrd_adj: f32,
    pub temporal_adj: f32,
}

impl From<nameserver_common::messages::DetectorScore> for DetectorScoreRow {
    fn from(p: nameserver_common::messages::DetectorScore) -> Self {
        let predicted_at =
            OffsetDateTime::from_unix_timestamp(p.timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        DetectorScoreRow {
            predicted_at,
            domain: p.domain,
            ml_probability: p.ml_probability,
            final_probability: p.final_probability,
            ml_class: p.classification,
            divergent: u8::from(p.divergent),
            override_rule: p.override_rule.unwrap_or_default(),
            ns_trust: p.ns_trust,
            dnssec_adj: p.dnssec_adj,
            ns_adj: p.ns_adj,
            similarity_adj: p.similarity_adj,
            hosting_adj: p.hosting_adj,
            nrd_adj: p.nrd_adj,
            temporal_adj: p.temporal_adj,
        }
    }
}
