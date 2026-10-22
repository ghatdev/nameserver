use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use super::AppState;

use nameserver_common::filter::normalize_domain;

#[derive(Deserialize)]
pub struct ListDomainsQuery {
    /// Maximum number of results (default 100).
    limit: Option<i64>,
}

pub async fn get_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let fqdn = normalize_domain(&domain);
    let pool = &state.db.pool;

    // Fetch domain record.
    let domain_row = sqlx::query!(
        "SELECT domain, first_seen, last_seen, query_count
         FROM domains WHERE domain = $1",
        fqdn,
    )
    .fetch_optional(pool)
    .await;

    let domain_info = match domain_row {
        Ok(Some(row)) => {
            serde_json::json!({
                "domain": row.domain,
                "first_seen": row.first_seen.unix_timestamp(),
                "last_seen": row.last_seen.unix_timestamp(),
                "query_count": row.query_count,
            })
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("domain '{fqdn}' not found") })),
            )
                .into_response();
        }
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    // Fetch resolution history.
    let resolution_history = match sqlx::query!(
        "SELECT resolved_at, ips, ttl, cname_chain, ns_servers, dnssec_status, resolve_ms
         FROM resolution_history WHERE domain = $1
         ORDER BY resolved_at DESC LIMIT 20",
        fqdn,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "timestamp": row.resolved_at.unix_timestamp(),
                    "ips": row.ips,
                    "ttl": row.ttl,
                    "cname_chain": row.cname_chain,
                    "ns_servers": row.ns_servers,
                    "dnssec_status": row.dnssec_status,
                    "resolve_ms": row.resolve_ms,
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    // Fetch associated IPs — no ::text cast, fetch IpNetwork directly.
    let associated_ips = match sqlx::query!(
        "SELECT di.ip, i.geo_country, i.asn_org, i.domain_count, i.is_cdn
         FROM domain_ips di LEFT JOIN ips i ON di.ip = i.ip
         WHERE di.domain = $1
         ORDER BY di.last_seen DESC LIMIT 50",
        fqdn,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "ip": row.ip.to_string(),
                    "geo_country": row.geo_country,
                    "asn_org": row.asn_org,
                    "domain_count": row.domain_count,
                    "is_cdn": row.is_cdn,
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    // Fetch reputation data.
    let ss = state.suffix_set.load();
    let registrable = crate::scoring_chain::extract_registrable(fqdn.trim_end_matches('.'), &ss);
    let reputation = sqlx::query!(
        "SELECT dr.ns_trust, dr.cname_targets, \
                dr.tld, dr.tld_type, dr.is_well_known, dr.is_nrd, dr.nrd_source, dr.is_trusted, dr.trust_source, \
                dr.total_flow_count, dr.ns_observation_count, \
                dr.avg_auth_ttl, dr.min_auth_ttl, dr.avg_resolve_ms, dr.avg_chain_depth, \
                dr.has_dnssec, dr.has_cname, dr.has_mx, dr.is_cdn, \
                dr.unique_ip_count, dr.a_record_count, dr.primary_asn, dr.primary_country, \
                COALESCE( \
                    (SELECT jsonb_agg(m.ns_domain ORDER BY m.ns_domain) \
                     FROM domain_ns_map m \
                     WHERE m.registrable_domain = dr.registrable_domain), \
                    '[]'::jsonb \
                ) AS \"ns_domains!\" \
         FROM domain_reputation dr \
         WHERE dr.registrable_domain = $1",
        registrable,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| {
        serde_json::json!({
            "registrable_domain": registrable,
            "ns_trust": r.ns_trust,
            "ns_domains": r.ns_domains,
            "cname_targets": r.cname_targets,
            "tld": r.tld,
            "tld_type": r.tld_type,
            "is_well_known": r.is_well_known,
            "is_nrd": r.is_nrd,
            "nrd_source": r.nrd_source,
            "is_trusted": r.is_trusted,
            "trust_source": r.trust_source,
            "total_flow_count": r.total_flow_count,
            "ns_observation_count": r.ns_observation_count,
            "avg_auth_ttl": r.avg_auth_ttl,
            "min_auth_ttl": r.min_auth_ttl,
            "avg_resolve_ms": r.avg_resolve_ms,
            "avg_chain_depth": r.avg_chain_depth,
            "has_dnssec": r.has_dnssec,
            "has_cname": r.has_cname,
            "has_mx": r.has_mx,
            "is_cdn": r.is_cdn,
            "unique_ip_count": r.unique_ip_count,
            "a_record_count": r.a_record_count,
            "primary_asn": r.primary_asn,
            "primary_country": r.primary_country,
        })
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "domain": domain_info,
            "reputation": reputation,
            "resolution_history": resolution_history,
            "associated_ips": associated_ips,
        })),
    )
        .into_response()
}

pub async fn list_domains(
    State(state): State<AppState>,
    Query(params): Query<ListDomainsQuery>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let limit = params.limit.unwrap_or(100).min(10_000);

    let result = sqlx::query!(
        "SELECT domain, first_seen, last_seen, query_count
         FROM domains ORDER BY last_seen DESC LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await;

    match result {
        Ok(rows) => {
            let domains: Vec<_> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "domain": row.domain,
                        "first_seen": row.first_seen.unix_timestamp(),
                        "last_seen": row.last_seen.unix_timestamp(),
                        "query_count": row.query_count,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "domains": domains })),
            )
                .into_response()
        }
        Err(e) => super::internal_error(e).into_response(),
    }
}
