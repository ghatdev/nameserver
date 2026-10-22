use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use time::OffsetDateTime;

use super::AppState;

/// POST /api/ns-map/import
///
/// Import NS mapping data to bootstrap the domain_ns_map table.
/// Body: newline-delimited TSV, each line: `registrable_domain\tns1,ns2,...`
///
/// Bootstrap entries get backdated first_seen (90 days ago) and high
/// observation_count (100) so they immediately qualify as Stable trust
/// in the scoring chain. Existing organic entries are not overwritten.
pub async fn import_ns_map(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let text = match String::from_utf8(body.to_vec()) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid UTF-8: {e}") })),
            )
                .into_response();
        }
    };

    let pool = &state.db.pool;
    let now = OffsetDateTime::now_utc();
    let bootstrap_first_seen = now - time::Duration::days(90);

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let mut imported = 0u64;
    let mut skipped = 0u64;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((domain, ns_csv)) = line.split_once('\t') else {
            skipped += 1;
            continue;
        };

        let domain = domain.trim().trim_end_matches('.');
        if domain.is_empty() || !domain.contains('.') {
            skipped += 1;
            continue;
        }

        for ns in ns_csv.split(',') {
            let ns = ns.trim().trim_end_matches('.');
            if ns.is_empty() {
                continue;
            }
            match sqlx::query!(
                "INSERT INTO domain_ns_map \
                 (registrable_domain, ns_domain, first_seen, last_seen, observation_count) \
                 VALUES ($1, $2, $3, $4, 100) \
                 ON CONFLICT DO NOTHING",
                domain,
                ns,
                bootstrap_first_seen,
                now,
            )
            .execute(&mut *tx)
            .await
            {
                Ok(_) => imported += 1,
                Err(_) => skipped += 1,
            }
        }
    }

    if let Err(e) = tx.commit().await {
        return super::internal_error(e).into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "imported",
            "imported": imported,
            "skipped": skipped,
        })),
    )
        .into_response()
}

/// GET /api/ns-map/status
///
/// Return statistics about the domain_ns_map table.
pub async fn ns_map_status(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Single query with conditional aggregation instead of 4 separate COUNT queries.
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "total!",
                  COUNT(DISTINCT registrable_domain) AS "unique_domains!",
                  COUNT(*) FILTER (WHERE observation_count >= 10) AS "stable!",
                  COUNT(*) FILTER (WHERE observation_count = 100) AS "bootstrap!"
           FROM domain_ns_map"#,
    )
    .fetch_one(pool)
    .await;

    let (total, unique_domains, stable, bootstrap) = match row {
        Ok(r) => (r.total, r.unique_domains, r.stable, r.bootstrap),
        Err(_) => (0, 0, 0, 0),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "total_entries": total,
            "unique_domains": unique_domains,
            "stable_entries": stable,
            "bootstrap_entries": bootstrap,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct WellKnownQuery {
    /// Filter by source (e.g., "tranco-100k", "majestic-1m")
    pub source: Option<String>,
}

/// GET /api/well-known/domains
///
/// Export well-known domains as newline-delimited text.
/// Used by NS resolution scripts and ML training pipeline.
pub async fn well_known_domains(
    State(state): State<AppState>,
    Query(params): Query<WellKnownQuery>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    let domains: Vec<String> = if let Some(source) = &params.source {
        sqlx::query_scalar!(
            "SELECT d.domain FROM indicator_domains d \
             JOIN sources s ON d.source = s.id \
             JOIN enrichment_bindings eb ON eb.source_id = s.id \
             WHERE eb.enrichment_type = 'well_known' AND s.slug = $1 \
             ORDER BY d.domain",
            source,
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_scalar!(
            "SELECT d.domain FROM indicator_domains d \
             JOIN enrichment_bindings eb ON eb.source_id = d.source \
             WHERE eb.enrichment_type = 'well_known' \
             ORDER BY d.domain",
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    };

    let body = domains.join("\n");
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// GET /api/nrd/check/{domain}
///
/// Check if a domain is in any NRD (Newly Registered Domains) source.
/// Returns the youngest matching window as `nrd_age_days`.
pub async fn nrd_check(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let domain = domain.trim_end_matches('.').to_lowercase();

    let ss = state.suffix_set.load();
    let registrable = crate::scoring_chain::extract_registrable(&domain, &ss);

    // Find all NRD sources containing this domain
    let rows = sqlx::query!(
        r#"SELECT s.slug FROM indicator_domains d
           JOIN sources s ON d.source = s.id
           JOIN enrichment_bindings eb ON eb.source_id = s.id
           WHERE eb.enrichment_type = 'nrd' AND d.domain = $1"#,
        &registrable,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let sources: Vec<&str> = rows.iter().map(|r| r.slug.as_str()).collect();
    let nrd_age_days = sources
        .iter()
        .filter_map(|s| crate::scoring_chain::nrd_max_age_days(s))
        .min();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "domain": domain,
            "registrable": registrable,
            "is_nrd": !sources.is_empty(),
            "nrd_age_days": nrd_age_days,
            "nrd_sources": sources,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ThreatQuery {
    pub source: Option<String>,
}

/// GET /api/malicious/domains
///
/// Export malicious domains as newline-delimited text.
pub async fn threat_feed_domains(
    State(state): State<AppState>,
    Query(params): Query<ThreatQuery>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    let domains: Vec<String> = if let Some(source) = &params.source {
        sqlx::query_scalar!(
            "SELECT d.domain FROM indicator_domains d \
             JOIN sources s ON d.source = s.id \
             JOIN filters f ON f.source_id = s.id \
             WHERE f.filter_type = 'block' AND s.slug = $1 \
             ORDER BY d.domain",
            source,
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_scalar!(
            "SELECT DISTINCT d.domain FROM indicator_domains d \
             JOIN filters f ON f.source_id = d.source \
             WHERE f.filter_type = 'block' \
             ORDER BY d.domain",
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    };

    let body = domains.join("\n");
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// GET /api/malicious/ips
///
/// Export malicious IPs as newline-delimited text.
pub async fn threat_feed_ips(
    State(state): State<AppState>,
    Query(params): Query<ThreatQuery>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    let ips: Vec<String> = if let Some(source) = &params.source {
        sqlx::query_scalar!(
            r#"SELECT ip AS "ip!" FROM indicator_ips d
               JOIN sources s ON d.source = s.id
               WHERE s.slug = $1 ORDER BY d.ip"#,
            source,
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|ip: IpNetwork| ip.to_string())
        .collect()
    } else {
        sqlx::query_scalar!(r#"SELECT DISTINCT ip AS "ip!" FROM indicator_ips ORDER BY ip"#,)
            .fetch_all(pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|ip: IpNetwork| ip.to_string())
            .collect()
    };

    let body = ips.join("\n");
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// GET /api/malicious/check/{domain}
///
/// Check if a domain appears in any block-type filter's source.
pub async fn threat_feed_check(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let domain = domain.trim_end_matches('.').to_lowercase();

    let rows = sqlx::query!(
        "SELECT s.slug AS source FROM indicator_domains d \
         JOIN sources s ON d.source = s.id \
         JOIN filters f ON f.source_id = s.id \
         WHERE f.filter_type = 'block' AND d.domain = $1",
        &domain,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let sources: Vec<String> = rows.iter().map(|row| row.source.clone()).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "domain": domain,
            "in_threat_feed": !sources.is_empty(),
            "sources": sources,
        })),
    )
        .into_response()
}
