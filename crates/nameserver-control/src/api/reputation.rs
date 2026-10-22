use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use nameserver_common::filter::normalize_domain;

use super::AppState;
use crate::scoring_chain::extract_registrable;

/// GET /api/reputation/{domain}
pub async fn get_reputation(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let fqdn = normalize_domain(&domain);
    let ss = state.suffix_set.load();
    let registrable = extract_registrable(fqdn.trim_end_matches('.'), &ss);
    let pool = &state.db.pool;

    let row = sqlx::query!(
        "SELECT dr.registrable_domain, dr.total_flow_count, dr.first_seen, dr.last_seen,
                dr.tld, dr.tld_type, dr.ns_trust, dr.ns_observation_count,
                dr.avg_auth_ttl, dr.min_auth_ttl, dr.avg_resolve_ms, dr.avg_chain_depth,
                dr.has_cname, dr.cname_targets,
                dr.has_dnssec, dr.has_mx, dr.unique_ip_count, dr.a_record_count,
                dr.primary_asn, dr.primary_country, dr.is_cdn,
                dr.is_nrd, dr.nrd_source, dr.is_well_known,
                dr.is_trusted, dr.trusted_at, dr.trust_source,
                dr.updated_at,
                COALESCE(
                    (SELECT jsonb_agg(m.ns_domain ORDER BY m.ns_domain)
                     FROM domain_ns_map m
                     WHERE m.registrable_domain = dr.registrable_domain),
                    '[]'::jsonb
                ) AS \"ns_domains!\"
         FROM domain_reputation dr
         WHERE dr.registrable_domain = $1",
        registrable,
    )
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some(r)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "registrable_domain": r.registrable_domain,
                "total_flow_count": r.total_flow_count,
                "first_seen": r.first_seen.unix_timestamp(),
                "last_seen": r.last_seen.unix_timestamp(),
                "tld": r.tld,
                "tld_type": r.tld_type,
                "ns_trust": r.ns_trust,
                "ns_domains": r.ns_domains,
                "ns_observation_count": r.ns_observation_count,
                "avg_auth_ttl": r.avg_auth_ttl,
                "min_auth_ttl": r.min_auth_ttl,
                "avg_resolve_ms": r.avg_resolve_ms,
                "avg_chain_depth": r.avg_chain_depth,
                "has_cname": r.has_cname,
                "cname_targets": r.cname_targets,
                "has_dnssec": r.has_dnssec,
                "has_mx": r.has_mx,
                "unique_ip_count": r.unique_ip_count,
                "a_record_count": r.a_record_count,
                "primary_asn": r.primary_asn,
                "primary_country": r.primary_country,
                "is_cdn": r.is_cdn,
                "is_nrd": r.is_nrd,
                "nrd_source": r.nrd_source,
                "is_well_known": r.is_well_known,
                "is_trusted": r.is_trusted,
                "trusted_at": r.trusted_at.map(|t| t.unix_timestamp()),
                "trust_source": r.trust_source,
                "updated_at": r.updated_at.unix_timestamp(),
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no reputation for '{registrable}'")
            })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}
