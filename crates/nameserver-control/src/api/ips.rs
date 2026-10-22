use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ipnetwork::IpNetwork;

use super::AppState;

pub async fn get_ip(State(state): State<AppState>, Path(ip): Path<String>) -> impl IntoResponse {
    let pool = &state.db.pool;

    let ip_net: IpNetwork = match ip.parse() {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid IP: '{ip}'") })),
            )
                .into_response();
        }
    };

    // Fetch IP record with proper Rust types — no SQL casts needed.
    let ip_row = sqlx::query!(
        "SELECT ip, first_seen, last_seen,
                geo_country, geo_city,
                asn_number, asn_org, is_cdn, is_bulletproof,
                ptr_record, ptr_matches, domain_count, malicious_count,
                blocklist_json
         FROM ips WHERE ip = $1",
        ip_net,
    )
    .fetch_optional(pool)
    .await;

    let row = match ip_row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("IP '{ip}' not found") })),
            )
                .into_response();
        }
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let ip_info = serde_json::json!({
        "ip": row.ip.to_string(),
        "first_seen": row.first_seen.unix_timestamp(),
        "last_seen": row.last_seen.unix_timestamp(),
        "geo_country": row.geo_country,
        "geo_city": row.geo_city,
        "asn_number": row.asn_number,
        "asn_org": row.asn_org,
        "is_cdn": row.is_cdn,
        "is_bulletproof": row.is_bulletproof,
        "ptr_record": row.ptr_record,
        "ptr_matches": row.ptr_matches,
        "domain_count": row.domain_count,
        "malicious_count": row.malicious_count,
        "blocklist_json": row.blocklist_json,
    });

    // Fetch associated domains.
    let associated_domains = match sqlx::query_scalar!(
        "SELECT di.domain FROM domain_ips di WHERE di.ip = $1 ORDER BY di.last_seen DESC LIMIT 50",
        ip_net
    )
    .fetch_all(pool)
    .await
    {
        Ok(domains) => domains
            .into_iter()
            .map(|d| serde_json::json!({ "domain": d }))
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ip": ip_info,
            "associated_domains": associated_domains,
        })),
    )
        .into_response()
}
