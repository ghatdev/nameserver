use std::collections::HashSet;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::analysis::registration::{self, RdapBootstrap, RegistrationData};
use crate::db::Database;

use super::AppState;

/// Rate limit between RDAP requests (milliseconds).
const RDAP_RATE_LIMIT_MS: u64 = 500;

/// TLDs/suffixes that will never have RDAP/WHOIS records.
const NON_REGISTRABLE_SUFFIXES: &[&str] = &[
    ".local",
    ".localhost",
    ".internal",
    ".invalid",
    ".test",
    ".example",
    ".arpa",
];

/// Check if a domain should be skipped for RDAP/WHOIS lookup.
pub(crate) fn should_skip_rdap(domain: &str) -> bool {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    NON_REGISTRABLE_SUFFIXES
        .iter()
        .any(|suffix| domain.ends_with(suffix) || domain == &suffix[1..])
}

/// Extract the registrable domain from an FQDN.
///
/// Delegates to `nameserver_common::suffix::extract_registrable` with the
/// provided SuffixSet.
pub(crate) fn extract_registrable_domain(
    fqdn: &str,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> String {
    nameserver_common::suffix::extract_registrable(fqdn, suffix_set).to_string()
}

#[derive(Deserialize)]
pub struct PullQuery {
    limit: Option<u32>,
    domain: Option<String>,
    /// Reset backoff and retry all failed entries.
    retry_failed: Option<bool>,
}

/// POST /api/rdap/pull — batch pull RDAP data for uncached domains.
pub async fn pull_rdap(
    State(state): State<AppState>,
    Query(params): Query<PullQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(1000) as i64;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build HTTP client");

    // Fetch IANA bootstrap once for the batch.
    let bootstrap = match registration::fetch_bootstrap(&http).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("RDAP bootstrap failed: {e}") })),
            )
                .into_response();
        }
    };

    // If a specific domain was requested, just fetch that one.
    if let Some(domain) = &params.domain {
        let ss = state.suffix_set.load();
        let registrable = extract_registrable_domain(domain, &ss);
        let result = pull_single_domain(&state.db, &http, &bootstrap, &registrable).await;
        return (StatusCode::OK, Json(result)).into_response();
    }

    // Retry failed: reset backoff and find failed entries.
    let retry_failed = params.retry_failed.unwrap_or(false);
    if retry_failed {
        let _ = sqlx::query!(
            "UPDATE rdap_cache SET fetched_at = '1970-01-01T00:00:00Z', retry_count = 0 \
             WHERE lookup_method NOT IN ('rdap', 'whois')",
        )
        .execute(&state.db.pool)
        .await;
    }

    // Find uncached/stale registrable domains from the domains table.
    let ss = state.suffix_set.load();
    let domains_to_fetch = match find_uncached_domains(&state.db, limit, &ss).await {
        Ok(d) => d,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    if domains_to_fetch.is_empty() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "fetched": 0, "failed": 0, "skipped": 0, "message": "all domains cached" })),
        )
            .into_response();
    }

    let total = domains_to_fetch.len();
    let mut fetched = 0u32;
    let mut failed = 0u32;
    let skipped = 0u32;

    for (i, domain) in domains_to_fetch.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(RDAP_RATE_LIMIT_MS)).await;
        }

        // Try RDAP first, then WHOIS fallback.
        let mut data = if bootstrap.find_service(domain).is_some() {
            registration::fetch_rdap(domain, &http, &bootstrap).await
        } else {
            // No RDAP service for this TLD — go straight to WHOIS
            RegistrationData {
                creation_date: None,
                expiration_date: None,
                registrar: None,
                status: vec![],
                nameservers: vec![],
                privacy_protected: false,
                lookup_method: "failed".into(),
                fetched_at: OffsetDateTime::now_utc().unix_timestamp(),
            }
        };

        if data.lookup_method == "failed" {
            let whois = registration::fetch_whois(domain).await;
            if whois.creation_date.is_some() {
                data = whois;
            } else {
                data.lookup_method = format!("failed+{}", whois.lookup_method);
            }
        }

        if data.lookup_method == "rdap" || data.lookup_method == "whois" {
            fetched += 1;
        } else {
            failed += 1;
        }

        // Store in cache regardless (failed lookups are cached too).
        let now = OffsetDateTime::now_utc();
        if let Err(e) = upsert_rdap_cache(&state.db, domain, &data, now).await {
            warn!(error = %e, "failed to store RDAP cache");
        }
    }

    info!(total, fetched, failed, skipped, "RDAP pull complete");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "fetched": fetched,
            "failed": failed,
            "skipped": skipped,
            "total_candidates": total,
        })),
    )
        .into_response()
}

/// Pull registration data for a single domain (RDAP + WHOIS fallback).
async fn pull_single_domain(
    db: &Database,
    http: &reqwest::Client,
    bootstrap: &RdapBootstrap,
    registrable: &str,
) -> serde_json::Value {
    let mut data = registration::fetch_rdap(registrable, http, bootstrap).await;

    // WHOIS fallback if RDAP failed
    if data.lookup_method == "failed" {
        let whois = registration::fetch_whois(registrable).await;
        if whois.creation_date.is_some() {
            data = whois;
        } else {
            data.lookup_method = format!("failed+{}", whois.lookup_method);
        }
    }

    let now = OffsetDateTime::now_utc();
    let method = data.lookup_method.clone();

    if let Err(e) = upsert_rdap_cache(db, registrable, &data, now).await {
        return serde_json::json!({
            "error": format!("failed to store cache: {e}"),
            "domain": registrable,
        });
    }

    let fetched = if method == "rdap" || method == "whois" {
        1
    } else {
        0
    };
    let failed = if method == "rdap" || method == "whois" {
        0
    } else {
        1
    };

    serde_json::json!({
        "fetched": fetched,
        "failed": failed,
        "skipped": 0,
        "domain": registrable,
        "lookup_method": method,
    })
}

/// GET /api/rdap/status — RDAP cache coverage stats.
pub async fn rdap_status(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    let total_registrable: i64 =
        sqlx::query_scalar!(r#"SELECT COUNT(DISTINCT domain) as "count!" FROM domains"#,)
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    let cached: i64 = sqlx::query_scalar!(r#"SELECT COUNT(*) as "count!" FROM rdap_cache"#,)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let stale_threshold = OffsetDateTime::now_utc() - time::Duration::hours(24);
    let stale: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM rdap_cache WHERE fetched_at < $1"#,
        stale_threshold,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let failed: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM rdap_cache WHERE lookup_method = 'failed'"#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let stats = serde_json::json!({
        "total_domains": total_registrable,
        "cached": cached,
        "stale": stale,
        "failed": failed,
        "fresh": cached - stale,
    });

    (StatusCode::OK, Json(stats)).into_response()
}

/// GET /api/rdap/lookup/{domain} — show cached RDAP entry.
pub async fn rdap_lookup(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let ss = state.suffix_set.load();
    let registrable = extract_registrable_domain(&domain, &ss);
    let pool = &state.db.pool;

    let result = sqlx::query!(
        r#"SELECT registrable_domain, creation_date, expiration_date, registrar,
                status_json, nameservers_json, privacy_protected, lookup_method,
                fetched_at, updated_at
         FROM rdap_cache WHERE registrable_domain = $1"#,
        registrable,
    )
    .fetch_optional(pool)
    .await;

    match result {
        Ok(Some(row)) => {
            let data = serde_json::json!({
                "registrable_domain": row.registrable_domain,
                "creation_date": row.creation_date,
                "expiration_date": row.expiration_date,
                "registrar": row.registrar,
                "status": row.status_json.unwrap_or(serde_json::json!([])),
                "nameservers": row.nameservers_json.unwrap_or(serde_json::json!([])),
                "privacy_protected": row.privacy_protected,
                "lookup_method": row.lookup_method,
                "fetched_at": row.fetched_at.unix_timestamp(),
                "updated_at": row.updated_at.unix_timestamp(),
            });
            (StatusCode::OK, Json(data)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not found",
                "registrable_domain": registrable,
            })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// Find registrable domains from the `domains` table that are not freshly cached in `rdap_cache`.
async fn find_uncached_domains(
    db: &Database,
    limit: i64,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> anyhow::Result<Vec<String>> {
    let pool = &db.pool;
    let stale_threshold = OffsetDateTime::now_utc() - time::Duration::hours(24);

    // Get all domains, extract registrable domain, find those missing or stale in cache.
    let all_domains: Vec<String> =
        sqlx::query_scalar!("SELECT domain FROM domains ORDER BY last_seen DESC",)
            .fetch_all(pool)
            .await?;

    // Extract unique registrable domains, skipping non-registrable TLDs.
    let mut seen = HashSet::new();
    let mut registrable_domains: Vec<String> = Vec::new();
    for fqdn in &all_domains {
        if should_skip_rdap(fqdn) {
            continue;
        }
        let reg = extract_registrable_domain(fqdn, suffix_set);
        if seen.insert(reg.clone()) {
            registrable_domains.push(reg);
        }
    }

    if registrable_domains.is_empty() {
        return Ok(Vec::new());
    }

    // Single query: find which registrable domains are already freshly cached.
    let freshly_cached: HashSet<String> = sqlx::query_scalar!(
        "SELECT registrable_domain FROM rdap_cache WHERE fetched_at >= $1",
        stale_threshold,
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    // Filter out cached, take up to limit.
    let uncached: Vec<String> = registrable_domains
        .into_iter()
        .filter(|r| !freshly_cached.contains(r))
        .take(limit as usize)
        .collect();

    Ok(uncached)
}

/// Upsert RDAP data into the cache table.
pub(crate) async fn upsert_rdap_cache(
    db: &Database,
    registrable_domain: &str,
    data: &RegistrationData,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    let status_json = serde_json::to_value(&data.status)?;
    let nameservers_json = serde_json::to_value(&data.nameservers)?;

    sqlx::query!(
        "INSERT INTO rdap_cache
         (registrable_domain, creation_date, expiration_date, registrar,
          status_json, nameservers_json, privacy_protected, lookup_method,
          fetched_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
         ON CONFLICT(registrable_domain) DO UPDATE SET
             creation_date = excluded.creation_date,
             expiration_date = excluded.expiration_date,
             registrar = excluded.registrar,
             status_json = excluded.status_json,
             nameservers_json = excluded.nameservers_json,
             privacy_protected = excluded.privacy_protected,
             lookup_method = excluded.lookup_method,
             fetched_at = excluded.fetched_at,
             updated_at = excluded.updated_at",
        registrable_domain,
        data.creation_date.as_deref(),
        data.expiration_date.as_deref(),
        data.registrar.as_deref(),
        status_json,
        nameservers_json,
        data.privacy_protected,
        &data.lookup_method,
        now,
    )
    .execute(&db.pool)
    .await?;

    Ok(())
}

/// Backoff intervals by retry count: 24h, 48h, 7d, 30d.
const BACKOFF_HOURS: &[i64] = &[24, 48, 168, 720];

/// Spawn background registration data worker (RDAP + WHOIS fallback).
///
/// Pipeline per domain:
///   1. Try RDAP (structured JSON, fast)
///   2. If RDAP fails → try WHOIS (TCP port 43, text parsing)
///   3. If both fail → cache failure with backoff (24h → 48h → 7d → 30d)
pub fn spawn_rdap_worker(db: Database, mut rx: mpsc::Receiver<String>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("RDAP worker HTTP client");

        let mut bootstrap: Option<RdapBootstrap> = None;
        let mut seen: HashSet<String> = HashSet::new();

        info!("RDAP worker started");

        while let Some(registrable_domain) = rx.recv().await {
            // Skip if already fetched this session.
            if seen.contains(&registrable_domain) {
                continue;
            }

            // Skip if cached and not due for retry (success: 24h, failure: backoff).
            // Uses updated_at (always set correctly) instead of fetched_at
            // (epoch 0 for legacy rows).
            let should_skip = {
                let row = sqlx::query!(
                    r#"SELECT lookup_method, retry_count,
                            updated_at AS "fetched_at!"
                     FROM rdap_cache WHERE registrable_domain = $1"#,
                    registrable_domain,
                )
                .fetch_optional(&db.pool)
                .await
                .ok()
                .flatten();

                if let Some(row) = row {
                    let method = &row.lookup_method;
                    let retry_count = row.retry_count;
                    let last_attempt = row.fetched_at;
                    let now = OffsetDateTime::now_utc();

                    if method == "rdap" || method == "whois" {
                        // Success: refresh after 24h
                        (now - last_attempt).whole_hours() < 24
                    } else {
                        // Failure: backoff based on retry count
                        let backoff_idx = (retry_count as usize).min(BACKOFF_HOURS.len() - 1);
                        let backoff_h = BACKOFF_HOURS[backoff_idx];
                        (now - last_attempt).whole_hours() < backoff_h
                    }
                } else {
                    false // Not cached → fetch
                }
            };
            if should_skip {
                seen.insert(registrable_domain);
                continue;
            }

            // Refresh bootstrap if needed.
            let now_epoch = OffsetDateTime::now_utc().unix_timestamp();
            let needs_refresh = bootstrap
                .as_ref()
                .map(|b| now_epoch - b.fetched_at > 86400)
                .unwrap_or(true);
            if needs_refresh {
                match registration::fetch_bootstrap(&http).await {
                    Ok(b) => {
                        info!(services = b.services.len(), "RDAP bootstrap loaded");
                        bootstrap = Some(b);
                    }
                    Err(e) => {
                        warn!(error = %e, "RDAP bootstrap fetch failed");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }
            }

            let Some(ref bs) = bootstrap else { continue };

            // Step 1: Try RDAP.
            let mut reg = registration::fetch_rdap(&registrable_domain, &http, bs).await;

            // Step 2: If RDAP failed, try WHOIS fallback.
            if reg.lookup_method == "failed" {
                let whois_result = registration::fetch_whois(&registrable_domain).await;
                if whois_result.creation_date.is_some() {
                    // WHOIS succeeded — use it
                    reg = whois_result;
                } else {
                    // Both failed — keep RDAP error but note WHOIS was tried
                    reg.lookup_method = format!("failed+{}", whois_result.lookup_method);
                }
            }

            // Step 3: Store in rdap_cache with retry tracking.
            let now = OffsetDateTime::now_utc();
            let is_success = reg.lookup_method == "rdap" || reg.lookup_method == "whois";
            let status_json = serde_json::to_value(&reg.status).unwrap_or(serde_json::json!([]));
            let ns_json = serde_json::to_value(&reg.nameservers).unwrap_or(serde_json::json!([]));
            let last_error = if is_success {
                None
            } else {
                Some(reg.lookup_method.clone())
            };

            let _ = sqlx::query!(
                "INSERT INTO rdap_cache \
                   (registrable_domain, creation_date, expiration_date, registrar, \
                    status_json, nameservers_json, privacy_protected, \
                    lookup_method, retry_count, last_error, fetched_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                         CASE WHEN $9 THEN 0 ELSE 1 END, $10, $11, $11) \
                 ON CONFLICT(registrable_domain) DO UPDATE SET \
                   creation_date = COALESCE(excluded.creation_date, rdap_cache.creation_date), \
                   expiration_date = COALESCE(excluded.expiration_date, rdap_cache.expiration_date), \
                   registrar = COALESCE(excluded.registrar, rdap_cache.registrar), \
                   status_json = excluded.status_json, \
                   nameservers_json = excluded.nameservers_json, \
                   privacy_protected = excluded.privacy_protected, \
                   lookup_method = excluded.lookup_method, \
                   retry_count = CASE WHEN $9 THEN 0 ELSE rdap_cache.retry_count + 1 END, \
                   last_error = excluded.last_error, \
                   fetched_at = excluded.fetched_at, \
                   updated_at = excluded.updated_at",
                registrable_domain,        // $1
                reg.creation_date.as_deref(),       // $2
                reg.expiration_date.as_deref(),     // $3
                reg.registrar.as_deref(),           // $4
                status_json,               // $5
                ns_json,                   // $6
                reg.privacy_protected,     // $7
                &reg.lookup_method,        // $8
                is_success,                // $9
                last_error.as_deref(),     // $10
                now,                       // $11
            )
            .execute(&db.pool)
            .await;

            seen.insert(registrable_domain.clone());
            // Rate limit: 500ms between requests (covers both RDAP and WHOIS).
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("RDAP worker stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_registrable_simple() {
        // Default SuffixSet: implicit TLD rule handles single-part TLDs.
        let ss = nameserver_common::suffix::SuffixSet::default();
        assert_eq!(
            extract_registrable_domain("example.com", &ss),
            "example.com"
        );
        assert_eq!(
            extract_registrable_domain("sub.example.com", &ss),
            "example.com"
        );
        assert_eq!(
            extract_registrable_domain("a.b.c.example.com", &ss),
            "example.com"
        );
    }

    #[test]
    fn test_extract_registrable_with_suffix_set() {
        use nameserver_common::suffix::{SuffixSet, extract_registrable};
        let set = SuffixSet::from_psl_text("com\nco.kr\nco.uk\n");
        assert_eq!(extract_registrable("ibk.co.kr", &set), "ibk.co.kr");
        assert_eq!(extract_registrable("www.ibk.co.kr", &set), "ibk.co.kr");
        assert_eq!(extract_registrable("example.co.uk", &set), "example.co.uk");
        assert_eq!(
            extract_registrable("deep.sub.example.co.uk", &set),
            "example.co.uk"
        );
    }

    #[test]
    fn test_extract_registrable_trailing_dot() {
        let ss = nameserver_common::suffix::SuffixSet::default();
        assert_eq!(
            extract_registrable_domain("example.com.", &ss),
            "example.com"
        );
    }

    #[test]
    fn test_extract_registrable_single_label() {
        let ss = nameserver_common::suffix::SuffixSet::default();
        assert_eq!(extract_registrable_domain("localhost", &ss), "localhost");
    }

    #[test]
    fn test_should_skip_rdap() {
        assert!(should_skip_rdap("uuid-1234.local"));
        assert!(should_skip_rdap("10.in-addr.arpa"));
        assert!(should_skip_rdap("192.in-addr.arpa"));
        assert!(should_skip_rdap("test-domain.invalid"));
        assert!(should_skip_rdap("resolver.arpa"));
        assert!(should_skip_rdap("my.test"));
        assert!(should_skip_rdap("host.localhost"));
        assert!(should_skip_rdap("foo.internal"));
        // Trailing dot
        assert!(should_skip_rdap("host.local."));

        assert!(!should_skip_rdap("example.com"));
        assert!(!should_skip_rdap("example.kr"));
        assert!(!should_skip_rdap("sub.cloudfront.net"));
    }
}
