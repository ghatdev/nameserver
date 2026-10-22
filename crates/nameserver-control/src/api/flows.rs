use std::collections::{HashMap, HashSet};
use std::convert::Infallible;

use super::AppState;
use crate::clickhouse::FlowRow;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt;
use nameserver_common::messages::flow::DnsFlow;
use nameserver_common::nats_subjects::{STREAM_FLOWS, SUBJECT_FLOW};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct FlowQuery {
    /// Filter by domain name.
    domain: Option<String>,
    /// Filter by query type (A, AAAA, CNAME, etc.).
    r#type: Option<String>,
    /// Number of recent flows to return (default 20).
    recent: Option<u32>,
    /// Return top N domains by query count instead of individual flows.
    top: Option<u32>,
    /// Filter to NXDOMAIN responses only.
    nxdomain: Option<bool>,
    /// Filter by list action (BLOCK, ALLOW, PASS).
    action: Option<String>,
    /// Filter by profile ID.
    profile: Option<String>,
    /// Return per-profile aggregation instead of individual flows.
    by_profile: Option<bool>,
}

#[derive(clickhouse::Row, serde::Deserialize, serde::Serialize)]
struct TopDomainRow {
    domain: String,
    count: u64,
}

#[derive(clickhouse::Row, serde::Deserialize, serde::Serialize)]
struct ProfileAggRow {
    profile_id: String,
    total_queries: u64,
    blocked: u64,
    nxdomain: u64,
}

use nameserver_common::filter::normalize_domain;

pub async fn get_flows(
    State(state): State<AppState>,
    Query(params): Query<FlowQuery>,
) -> impl IntoResponse {
    let db_name = &state.ch_config.database;
    let limit = params.recent.unwrap_or(20);

    // Build WHERE clause with ? placeholders for bind parameters.
    let mut conditions = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ref domain) = params.domain {
        conditions.push("domain = ?");
        bind_values.push(normalize_domain(domain));
    }
    if let Some(ref qtype) = params.r#type {
        conditions.push("qtype = ?");
        bind_values.push(qtype.clone());
    }
    if params.nxdomain.unwrap_or(false) {
        conditions.push("rcode = 'NXDOMAIN'");
    }
    if let Some(ref action) = params.action {
        conditions.push("list_action = ?");
        bind_values.push(action.clone());
    }
    if let Some(ref profile) = params.profile {
        conditions.push("profile_id = ?");
        bind_values.push(profile.clone());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    // By-profile aggregation mode.
    if params.by_profile.unwrap_or(false) {
        let sql = format!(
            "SELECT profile_id, count() as total_queries, \
             countIf(list_action = 'BLOCK') as blocked, \
             countIf(rcode = 'NXDOMAIN') as nxdomain \
             FROM {db}.flows {wc} GROUP BY profile_id ORDER BY total_queries DESC",
            db = db_name,
            wc = where_clause,
        );
        let mut query = state.ch.query(&sql);
        for val in &bind_values {
            query = query.bind(val.as_str());
        }
        let result: Result<Vec<ProfileAggRow>, clickhouse::error::Error> = async {
            let mut cursor = query.fetch::<ProfileAggRow>()?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().await? {
                rows.push(row);
            }
            Ok(rows)
        }
        .await;
        return match result {
            Ok(rows) => {
                let profile_ids: Vec<&str> = rows.iter().map(|r| r.profile_id.as_str()).collect();
                let profile_names = lookup_profile_names(&state, &profile_ids).await;
                let json_rows: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|r| {
                        let name = profile_names
                            .get(r.profile_id.as_str())
                            .cloned()
                            .unwrap_or_default();
                        serde_json::json!({
                            "profile_id": r.profile_id,
                            "profile_name": name,
                            "total_queries": r.total_queries,
                            "blocked": r.blocked,
                            "nxdomain": r.nxdomain,
                        })
                    })
                    .collect();
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "by_profile": json_rows })),
                )
                    .into_response()
            }
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
    }

    // Top domains mode.
    if let Some(top_n) = params.top {
        let sql = format!(
            "SELECT domain, count() as count FROM {db}.flows {wc} GROUP BY domain ORDER BY count DESC LIMIT {n}",
            db = db_name,
            wc = where_clause,
            n = top_n,
        );
        let mut query = state.ch.query(&sql);
        for val in &bind_values {
            query = query.bind(val.as_str());
        }
        let result: Result<Vec<TopDomainRow>, clickhouse::error::Error> = async {
            let mut cursor = query.fetch::<TopDomainRow>()?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().await? {
                rows.push(row);
            }
            Ok(rows)
        }
        .await;
        match result {
            Ok(rows) => (
                StatusCode::OK,
                Json(serde_json::json!({ "top_domains": rows })),
            )
                .into_response(),
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    } else {
        let sql = format!(
            "SELECT * FROM {db}.flows {wc} ORDER BY started_at DESC LIMIT {n}",
            db = db_name,
            wc = where_clause,
            n = limit,
        );
        let mut query = state.ch.query(&sql);
        for val in &bind_values {
            query = query.bind(val.as_str());
        }
        let result: Result<Vec<FlowRow>, clickhouse::error::Error> = async {
            let mut cursor = query.fetch::<FlowRow>()?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().await? {
                rows.push(row);
            }
            Ok(rows)
        }
        .await;
        match result {
            Ok(rows) => {
                let mut json_rows: Vec<serde_json::Value> =
                    rows.iter().map(flow_row_to_json).collect();
                enrich_flows(&state, &mut json_rows).await;
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "flows": json_rows })),
                )
                    .into_response()
            }
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    }
}

fn flow_row_to_json(row: &FlowRow) -> serde_json::Value {
    serde_json::json!({
        "flow_id": row.flow_id.to_string(),
        "started_at": row.started_at.unix_timestamp(),
        "completed_at": row.completed_at.unix_timestamp(),
        "total_ms": row.total_ms,
        "domain": row.domain,
        "qtype": row.qtype,
        "list_action": row.list_action,
        "list_filter": row.list_filter,
        "profile_id": row.profile_id,
        "geo_country": row.geo_country,
        "geo_asn": row.geo_asn,
        "rcode": row.rcode,
        "response_ips": row.response_ips,
        "response_ttl": row.response_ttl,
        "dnssec_status": row.dnssec_status,
        "dnssec_algorithm": row.dnssec_algorithm,
        "dnssec_ds_present": row.dnssec_ds_present != 0,
        "dnssec_rrsig_expiry": row.dnssec_rrsig_expiry,
        "dnssec_failure_reason": row.dnssec_failure_reason,
        "servfail_reason": row.servfail_reason,
        "all_records_json": row.all_records_json,
        "cname_chain": row.cname_chain,
        "resolution_path": {
            "steps": row.rp_step,
            "asked": row.rp_asked,
            "servers": row.rp_server,
            "server_names": row.rp_server_name,
            "response_types": row.rp_response_type,
            "ms": row.rp_ms,
        },
    })
}

/// Enrich flow JSON objects with ASN org names and profile display names from PostgreSQL.
async fn enrich_flows(state: &AppState, flows: &mut [serde_json::Value]) {
    if flows.is_empty() {
        return;
    }

    // Collect unique ASNs and profile IDs.
    let mut asns = HashSet::new();
    let mut profile_ids = Vec::new();
    for flow in flows.iter() {
        if let Some(asn) = flow["geo_asn"].as_u64()
            && asn > 0
        {
            asns.insert(asn as u32);
        }
        if let Some(pid) = flow["profile_id"].as_str()
            && !pid.is_empty()
        {
            profile_ids.push(pid);
        }
    }

    let asn_orgs = lookup_asn_orgs(state, &asns).await;
    let profile_names = lookup_profile_names(state, &profile_ids).await;

    for flow in flows.iter_mut() {
        let obj = match flow.as_object_mut() {
            Some(o) => o,
            None => continue,
        };

        let asn = obj.get("geo_asn").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let org = asn_orgs.get(&asn).cloned().unwrap_or_default();
        obj.insert("geo_asn_org".to_string(), serde_json::Value::String(org));

        let pid = obj
            .get("profile_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = profile_names.get(pid.as_str()).cloned().unwrap_or_default();
        obj.insert("profile_name".to_string(), serde_json::Value::String(name));
    }
}

/// Batch-lookup ASN organization names from PostgreSQL `geo_entries`.
async fn lookup_asn_orgs(state: &AppState, asns: &HashSet<u32>) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if asns.is_empty() {
        return map;
    }

    let asn_vec: Vec<i32> = asns.iter().map(|&a| a as i32).collect();

    let rows = sqlx::query!(
        "SELECT DISTINCT asn, asn_desc FROM geo_entries \
         WHERE asn = ANY($1) AND asn_desc IS NOT NULL AND asn_desc != ''",
        &asn_vec,
    )
    .fetch_all(&state.db.pool)
    .await;

    let Ok(rows) = rows else {
        return map;
    };

    for row in &rows {
        if let Some(ref desc) = row.asn_desc {
            map.entry(row.asn as u32).or_insert_with(|| desc.clone());
        }
    }

    map
}

/// Batch-lookup profile display names from PostgreSQL `profiles`.
async fn lookup_profile_names(state: &AppState, ids: &[&str]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if ids.is_empty() {
        return map;
    }

    let id_vec: Vec<&str> = ids.to_vec();

    let rows = sqlx::query!(
        "SELECT id, display_name FROM profiles WHERE id = ANY($1)",
        &id_vec as &[&str],
    )
    .fetch_all(&state.db.pool)
    .await;

    let Ok(rows) = rows else {
        return map;
    };

    for row in &rows {
        map.insert(row.id.clone(), row.display_name.clone());
    }

    map
}

fn error_response(status: StatusCode, message: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// SSE endpoint: `GET /api/flows/live`
///
/// Creates an ephemeral NATS push consumer (DeliverPolicy::New) and streams
/// each flow as a JSON SSE event. Connection-scoped: consumer is cleaned up
/// when the client disconnects.
pub async fn live_flows(
    State(state): State<AppState>,
) -> Result<
    Sse<impl futures::Stream<Item = Result<Event, Infallible>>>,
    (StatusCode, Json<serde_json::Value>),
> {
    let stream_obj = state.js.get_stream(STREAM_FLOWS).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "live subscription unavailable"})),
        )
    })?;

    let consumer = stream_obj
        .create_consumer(async_nats::jetstream::consumer::push::Config {
            deliver_subject: format!("_INBOX.live.{}", uuid::Uuid::now_v7()),
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
            filter_subject: SUBJECT_FLOW.to_string(),
            inactive_threshold: std::time::Duration::from_secs(30),
            ..Default::default()
        })
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "live subscription unavailable"})),
            )
        })?;

    let messages = consumer.messages().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "live subscription unavailable"})),
        )
    })?;

    let stream = messages.filter_map(|msg| async {
        let msg = msg.ok()?;
        let flow: DnsFlow = rmp_serde::from_slice(&msg.payload).ok()?;
        let json = serde_json::to_string(&flow).ok()?;
        Some(Ok(Event::default().data(json)))
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
