use std::time::Duration;

use async_nats::jetstream;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use nameserver_common::parse_config::{
    FetchConfig, ParseConfig, ValidateConfig, build_extra, parse_rows, primary_column_index,
};
use nameserver_common::types::enums::{EnrichmentType, IndicatorType};

use crate::api::geoip;
use crate::compiler;
use crate::db::Database;

/// How often to check for due source pulls (seconds).
const CHECK_INTERVAL_SECS: u64 = 60;

/// Spawn the auto-pull background task.
pub fn spawn_autopull(
    db: Database,
    nats_client: async_nats::Client,
    js: jetstream::Context,
    suffix_set: std::sync::Arc<arc_swap::ArcSwap<nameserver_common::suffix::SuffixSet>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!("auto-pull task started (check interval: {CHECK_INTERVAL_SECS}s)");

        loop {
            if let Err(e) = run_autopull_cycle(&db, &nats_client, &js, &suffix_set).await {
                warn!(error = %e, "auto-pull cycle error");
            }
            tokio::time::sleep(Duration::from_secs(CHECK_INTERVAL_SECS)).await;
        }
    })
}

async fn run_autopull_cycle(
    db: &Database,
    nats_client: &async_nats::Client,
    js: &jetstream::Context,
    suffix_set: &std::sync::Arc<arc_swap::ArcSwap<nameserver_common::suffix::SuffixSet>>,
) -> anyhow::Result<()> {
    let due_sources = find_due_sources(db).await?;

    if due_sources.is_empty() {
        return Ok(());
    }

    info!(
        count = due_sources.len(),
        "found due indicator sources for auto-pull"
    );

    let mut filters_to_recompile = Vec::new();
    let mut enrichments_to_run = Vec::new();
    let mut geo_changed = false;
    let mut suffix_changed = false;

    for source_id in &due_sources {
        match pull_source(&db.pool, source_id).await {
            Ok(result) => {
                if !result.changed {
                    continue;
                }
                info!(slug = %result.slug, count = result.entry_count, "auto-pull: source updated");

                match result.indicator_type {
                    IndicatorType::Geo => {
                        geo_changed = true;
                    }
                    IndicatorType::Suffix => {
                        suffix_changed = true;
                    }
                    _ => {
                        // Check if this source feeds any filter
                        if let Ok(filter_ids) = find_affected_filters(&db.pool, source_id).await {
                            filters_to_recompile.extend(filter_ids);
                        }
                        // Check if this source has enrichment bindings
                        if let Ok(types) = find_enrichment_bindings(&db.pool, source_id).await {
                            enrichments_to_run.extend(types);
                        }
                    }
                }
            }
            Err(e) => {
                warn!(source = %source_id, error = %e, "auto-pull: failed to pull source");
            }
        }
    }

    // Run enrichment for any changed enrichment sources.
    enrichments_to_run.sort();
    enrichments_to_run.dedup();
    for enrichment_type in &enrichments_to_run {
        enrich_reputation(&db.pool, enrichment_type).await;
    }

    // Recompile affected filters.
    filters_to_recompile.sort();
    filters_to_recompile.dedup();
    if !filters_to_recompile.is_empty() {
        info!(
            count = filters_to_recompile.len(),
            "auto-pull: recompiling affected filters"
        );
        let result = compiler::compile_from_db(db).await?;
        let profile_result = compiler::compile_profile_map(db).await.ok();
        let source_checksums = compiler::read_source_checksums(db).await;
        let published = compiler::publish_filters(nats_client, js, &result).await?;
        info!(published = ?published, "auto-pull: filters compiled and published");

        if let Err(e) = compiler::publish_filter_manifest(js, &result, &source_checksums).await {
            warn!(error = %e, "auto-pull: failed to publish filter manifest");
        }
        if let Some((map, custom)) = profile_result {
            let _ = compiler::publish_profile_configs(nats_client, js, &map, &custom).await;
            info!("auto-pull: profile configs published to KV");
        }
    }

    // Compile and publish GeoIP if geo sources changed.
    if geo_changed {
        info!("auto-pull: refreshing GeoIP table");
        if let Err(e) = geoip::compile_and_publish_geoip(&db.pool, js).await {
            warn!(error = %e, "auto-pull: failed to compile/publish geoip");
        } else {
            compiler::send_reload(nats_client, nameserver_common::admin::ReloadSignal::Geoip).await;
            info!("auto-pull: GeoIP table compiled and published");
        }
    }

    // Compile and publish suffix set if suffix sources changed.
    if suffix_changed {
        info!("auto-pull: refreshing suffix set");
        match compiler::compile_and_publish_suffix_set(&db.pool, nats_client, js).await {
            Ok(new_set) => {
                // Update the in-memory suffix set for the control plane.
                suffix_set.store(std::sync::Arc::new(new_set));
                info!("auto-pull: suffix set compiled, published, and in-memory state updated");
            }
            Err(e) => {
                warn!(error = %e, "auto-pull: failed to compile/publish suffix set");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Source pulling
/// Public entry point for manual pull via API.
pub async fn pull_source_by_id(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
) -> anyhow::Result<serde_json::Value> {
    let result = pull_source(pool, source_id).await?;
    Ok(serde_json::json!({
        "slug": result.slug,
        "changed": result.changed,
        "entry_count": result.entry_count,
    }))
}

// ---------------------------------------------------------------------------

struct PullResult {
    slug: String,
    changed: bool,
    entry_count: u64,
    indicator_type: IndicatorType,
}

/// Pull a single indicator source: fetch → parse → validate → store.
async fn pull_source(pool: &PgPool, source_id: &sqlx::types::Uuid) -> anyhow::Result<PullResult> {
    // Read source metadata + configs.
    let row = sqlx::query!(
        r#"SELECT slug, url, indicator_type as "indicator_type: IndicatorType", fetch_config, parse_config, validate_config, last_checksum
         FROM sources WHERE id = $1 AND enabled = true"#,
        source_id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("source {source_id} not found or disabled"))?;

    let slug = row.slug;
    let url = row.url;
    let indicator_type = row.indicator_type;
    let fetch_config: FetchConfig = match &row.fetch_config {
        v if v.is_null() => FetchConfig::default(),
        v => serde_json::from_value(v.clone())?,
    };
    let parse_config: ParseConfig = match &row.parse_config {
        v if v.is_null() => ParseConfig::default(),
        v => serde_json::from_value(v.clone())?,
    };
    let validate_config: ValidateConfig = match &row.validate_config {
        v if v.is_null() => ValidateConfig::default(),
        v => serde_json::from_value(v.clone())?,
    };
    let prev_checksum: Option<String> = row.last_checksum;

    // Fetch content.
    let body = fetch_content(&url, &fetch_config).await?;
    let checksum = hex::encode(Sha256::digest(body.as_bytes()));

    // Skip if content unchanged.
    if prev_checksum.as_deref() == Some(checksum.as_str()) {
        let now = OffsetDateTime::now_utc();
        sqlx::query!(
            "UPDATE sources SET last_pull_at = $1, updated_at = $1 WHERE id = $2",
            now,
            source_id,
        )
        .execute(pool)
        .await?;
        return Ok(PullResult {
            slug,
            changed: false,
            entry_count: 0,
            indicator_type,
        });
    }

    // Parse all columns from content.
    let rows = parse_rows(&body, &parse_config);

    // Validate.
    if let Some(min) = validate_config.min_entries
        && (rows.len() as u32) < min
    {
        anyhow::bail!(
            "{slug}: parsed {} rows, expected at least {min}",
            rows.len()
        );
    }

    // Store indicators by type. For Domain sources we also receive the
    // list of newly-added domains so we can enqueue them for the
    // resolution injector.
    let mut new_domains_for_injection: Vec<String> = Vec::new();
    let count = match indicator_type {
        IndicatorType::Domain => {
            let ingest = store_domains(pool, source_id, &rows, &parse_config).await?;
            new_domains_for_injection = ingest.new_domains;
            ingest.count
        }
        IndicatorType::Ip => store_ips(pool, source_id, &rows, &parse_config).await?,
        IndicatorType::Asn => store_asns(pool, source_id, &rows, &parse_config).await?,
        IndicatorType::Geo => store_geo(pool, &rows, &slug).await?,
        IndicatorType::Suffix => store_suffixes(pool, source_id, &rows).await?,
        _ => 0,
    };

    // Resolution-injector diff hook: for sources whose new entries we
    // want to acquire labeled per-flow data for, enqueue each new domain.
    // See memory project_resolution_injector.md — this replaces the prior
    // bulk-resolution approach that contaminated detector training.
    if let Some(verdict) = slug_to_injection_verdict(&slug)
        && !new_domains_for_injection.is_empty()
    {
        let scheduled_for = OffsetDateTime::now_utc();
        let priority = slug_to_priority(&slug);
        let mut enqueued = 0u64;
        for domain in &new_domains_for_injection {
            match crate::injector::enqueue(pool, domain, &slug, verdict, priority, scheduled_for)
                .await
            {
                Ok(true) => enqueued += 1,
                Ok(false) => {} // row already active for this (domain, source)
                Err(e) => tracing::warn!(
                    error = %e,
                    slug = %slug,
                    "autopull: failed to enqueue for injection",
                ),
            }
        }
        tracing::info!(
            slug = %slug,
            new = new_domains_for_injection.len(),
            enqueued,
            "autopull: enqueued new domains for injection",
        );
    }

    // Update source pull state.
    let now = OffsetDateTime::now_utc();
    let entry_count_i32 = count as i32;
    sqlx::query!(
        "UPDATE sources SET last_pull_at = $1, last_checksum = $2, last_entry_count = $3, updated_at = $1 WHERE id = $4",
        now,
        checksum,
        entry_count_i32,
        source_id,
    )
    .execute(pool)
    .await?;

    Ok(PullResult {
        slug,
        changed: true,
        entry_count: count,
        indicator_type,
    })
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

async fn fetch_content(url: &str, config: &FetchConfig) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(
            "nameserver-control/0.1 (DNS threat intel; +https://github.com/seoulvalley/nameserver)",
        )
        .build()?;

    let mut req = client.get(url);
    if let Some(ref headers) = config.headers {
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        // Try fallback URLs if primary fails.
        if let Some(ref fallbacks) = config.fallback_urls {
            for fallback_url in fallbacks {
                let fallback_resp = client.get(fallback_url).send().await?;
                if fallback_resp.status().is_success() {
                    return extract_body(fallback_resp, config).await;
                }
            }
        }
        anyhow::bail!("HTTP {}", resp.status());
    }

    extract_body(resp, config).await
}

async fn extract_body(resp: reqwest::Response, config: &FetchConfig) -> anyhow::Result<String> {
    match config.archive.as_deref() {
        Some("zip") => {
            let bytes = resp.bytes().await?;
            extract_csv_from_zip(&bytes)
        }
        Some("gzip") => {
            let bytes = resp.bytes().await?;
            let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
            let mut s = String::new();
            std::io::Read::read_to_string(&mut decoder, &mut s)?;
            Ok(s)
        }
        _ => Ok(resp.text().await?),
    }
}

fn extract_csv_from_zip(zip_bytes: &[u8]) -> anyhow::Result<String> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let mut file = archive.by_index(0)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// ---------------------------------------------------------------------------
// Store indicators by type
// ---------------------------------------------------------------------------

/// Normalize a domain: lowercase, strip trailing dot.
fn normalize_domain(raw: &str) -> String {
    raw.trim().to_lowercase().trim_end_matches('.').to_string()
}

/// Result of a domain-list ingest. `count` is the number of rows we
/// attempted to upsert; `new_domains` lists domains that were inserted
/// for the first time on this pull (for downstream diff consumers like
/// the resolution injector).
pub(crate) struct DomainIngestResult {
    pub count: u64,
    pub new_domains: Vec<String>,
}

/// Sources whose newly-added entries should be enqueued for the
/// resolution injector. Returning Some means "acquire fresh per-flow
/// resolution data with this label verdict"; None means "skip"
/// (benign popularity lists default to skip — enqueuing the whole diff
/// of tranco/majestic would be too much synthetic traffic, and NRD
/// lists are weak signals we don't want as labels).
fn slug_to_injection_verdict(slug: &str) -> Option<crate::injector::LabelVerdict> {
    use crate::injector::LabelVerdict;
    // Scope for malicious injection is intentionally narrow:
    //   - hagezi-pro excluded: an ad/tracker list whose "malicious"
    //     bucket is dominated by trackers and CDN edges, not C2 /
    //     phishing behavior.
    //   - Among Hagezi's DGA windows (7d / 14d / 30d), only the 7-day
    //     window is injected. 14d and 30d are mostly supersets of 7d
    //     and resolving them triples the volume without adding fresh
    //     signal — we want active DGA, not the long tail.
    match slug {
        "hagezi-tif" | "hagezi-dga-7d" => Some(LabelVerdict::Malicious),
        _ => None,
    }
}

/// Per-source drain priority. Kept next to `slug_to_injection_verdict`
/// so the same place decides "do we inject this?" and "in what order?".
/// Values mirror the `injector::priority` constants and the backfill
/// in migration `20260423000000_iq_priority.sql`.
fn slug_to_priority(slug: &str) -> i32 {
    use crate::injector::priority;
    match slug {
        "hagezi-tif" | "hagezi-dga-7d" => priority::MALICIOUS_HIGH,
        _ => priority::DEFAULT,
    }
}

async fn store_domains(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
    rows: &[Vec<String>],
    config: &ParseConfig,
) -> anyhow::Result<DomainIngestResult> {
    // UPSERT-keep-added_at + delete-removed pattern.
    //
    // The naive DELETE+INSERT pattern collapses every entry's added_at to
    // the latest pull time, destroying first-seen history. Instead we
    // INSERT new entries with now(), refresh `extra` for re-occurring
    // entries WITHOUT touching added_at, and explicitly DELETE entries
    // that fell off the upstream feed. Net effect: added_at converges to
    // "the first time we observed this domain on this source," which is
    // what label-time analyses (incident_labels.first_seen_at) need.
    //
    // We also capture the set of domains that are NEW (not previously
    // known for this source) by reading the existing set before insertion
    // and diffing against the incoming list. Callers use this for diff-
    // driven work like resolution injection.
    let now = OffsetDateTime::now_utc();
    let col = primary_column_index(config);
    let mut tx = pool.begin().await?;

    // Existing set for this source, read inside the transaction so it's
    // consistent with the upserts that follow. Typical sizes are 100K-2M
    // string entries; memory impact is bounded by the source size.
    // Using non-macro form because the PG tunnel isn't always up for
    // compile-time sqlx prepare.
    let existing_domains: std::collections::HashSet<String> =
        sqlx::query_scalar::<_, String>("SELECT domain FROM indicator_domains WHERE source = $1")
            .bind(source_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();

    let mut current_domains: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(rows.len());
    let mut new_domains: Vec<String> = Vec::new();

    let mut count = 0u64;
    for row in rows {
        let Some(raw) = row.get(col) else { continue };
        let domain = normalize_domain(raw);
        if domain.is_empty() || !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok()
        {
            continue;
        }
        let extra = build_extra(row, config);
        sqlx::query!(
            "INSERT INTO indicator_domains (source, domain, added_at, extra) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (source, domain) DO UPDATE SET extra = EXCLUDED.extra",
            source_id,
            domain,
            now,
            extra,
        )
        .execute(&mut *tx)
        .await?;
        if !existing_domains.contains(&domain) && !current_domains.contains(&domain) {
            new_domains.push(domain.clone());
        }
        current_domains.insert(domain);
        count += 1;
    }

    // Drop entries that are no longer in the upstream feed.
    let kept: Vec<String> = current_domains.into_iter().collect();
    sqlx::query!(
        "DELETE FROM indicator_domains WHERE source = $1 AND domain <> ALL($2)",
        source_id,
        &kept,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(DomainIngestResult { count, new_domains })
}

async fn store_ips(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
    rows: &[Vec<String>],
    config: &ParseConfig,
) -> anyhow::Result<u64> {
    let now = OffsetDateTime::now_utc();
    let col = primary_column_index(config);
    let mut tx = pool.begin().await?;

    sqlx::query!("DELETE FROM indicator_ips WHERE source = $1", source_id)
        .execute(&mut *tx)
        .await?;

    let mut count = 0u64;
    for row in rows {
        let Some(raw) = row.get(col) else { continue };
        let Ok(net) = raw.parse::<ipnetwork::IpNetwork>() else {
            continue;
        };
        let extra = build_extra(row, config);
        sqlx::query!(
            "INSERT INTO indicator_ips (source, ip, added_at, extra) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            source_id,
            net,
            now,
            extra,
        )
        .execute(&mut *tx)
        .await?;
        count += 1;
    }

    tx.commit().await?;
    Ok(count)
}

async fn store_asns(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
    rows: &[Vec<String>],
    config: &ParseConfig,
) -> anyhow::Result<u64> {
    let now = OffsetDateTime::now_utc();
    let col = primary_column_index(config);
    let mut tx = pool.begin().await?;

    sqlx::query!("DELETE FROM indicator_asns WHERE source = $1", source_id)
        .execute(&mut *tx)
        .await?;

    let mut count = 0u64;
    for row in rows {
        let Some(raw) = row.get(col) else { continue };
        let Ok(asn) = raw.parse::<i32>() else {
            continue;
        };
        let extra = build_extra(row, config);
        sqlx::query!(
            "INSERT INTO indicator_asns (source, asn, added_at, extra) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            source_id,
            asn,
            now,
            extra,
        )
        .execute(&mut *tx)
        .await?;
        count += 1;
    }

    tx.commit().await?;
    Ok(count)
}

async fn store_suffixes(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
    rows: &[Vec<String>],
) -> anyhow::Result<u64> {
    let now = OffsetDateTime::now_utc();
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM indicator_suffixes WHERE source = $1")
        .bind(source_id)
        .execute(&mut *tx)
        .await?;

    let mut count = 0u64;
    for row in rows {
        let Some(raw) = row.first() else { continue };
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        // Classify rule type and normalize.
        let (rule_type, suffix) = if let Some(rest) = raw.strip_prefix("*.") {
            (
                "wildcard",
                rest.to_ascii_lowercase().trim_end_matches('.').to_string(),
            )
        } else if let Some(rest) = raw.strip_prefix('!') {
            (
                "exception",
                rest.to_ascii_lowercase().trim_end_matches('.').to_string(),
            )
        } else {
            (
                "exact",
                raw.to_ascii_lowercase().trim_end_matches('.').to_string(),
            )
        };

        if suffix.is_empty() {
            continue;
        }

        sqlx::query(
            "INSERT INTO indicator_suffixes (source, suffix, rule_type, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(source_id)
        .bind(&suffix)
        .bind(rule_type)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        count += 1;
    }

    tx.commit().await?;
    Ok(count)
}

async fn store_geo(pool: &PgPool, rows: &[Vec<String>], slug: &str) -> anyhow::Result<u64> {
    use ipnetwork::IpNetwork;
    use std::net::IpAddr;

    // Determine ip_version from source slug.
    let ip_version: i16 = if slug.ends_with("-v6") { 6 } else { 4 };

    let mut tx = pool.begin().await?;

    sqlx::query!(
        "DELETE FROM geo_entries WHERE rir = 'iptoasn' AND ip_version = $1",
        ip_version,
    )
    .execute(&mut *tx)
    .await?;

    let mut count = 0u64;
    for row in rows {
        if row.len() < 5 {
            continue;
        }
        let Ok(start_ip) = row[0].parse::<IpAddr>() else {
            continue;
        };
        let Ok(end_ip) = row[1].parse::<IpAddr>() else {
            continue;
        };
        let asn: i32 = row[2].parse::<u32>().unwrap_or(0) as i32;
        let country = &row[3];
        let description = &row[4];

        if asn == 0 {
            continue;
        }
        if country.len() != 2 || country == "None" {
            continue;
        }

        let start_net = IpNetwork::from(start_ip);
        let end_net = IpNetwork::from(end_ip);

        sqlx::query!(
            "INSERT INTO geo_entries (start_ip, end_ip, country, ip_version, rir, asn, asn_desc)
             VALUES ($1, $2, $3, $4, 'iptoasn', $5, $6)
             ON CONFLICT (start_ip, ip_version) DO UPDATE SET
                end_ip = excluded.end_ip, country = excluded.country,
                rir = excluded.rir, asn = excluded.asn, asn_desc = excluded.asn_desc",
            start_net,
            end_net,
            country,
            ip_version,
            asn,
            description,
        )
        .execute(&mut *tx)
        .await?;
        count += 1;
    }

    tx.commit().await?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Post-pull: find what needs recompilation / enrichment
// ---------------------------------------------------------------------------

async fn find_affected_filters(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
) -> anyhow::Result<Vec<sqlx::types::Uuid>> {
    let rows = sqlx::query_scalar!("SELECT id FROM filters WHERE source_id = $1", source_id,)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

async fn find_enrichment_bindings(
    pool: &PgPool,
    source_id: &sqlx::types::Uuid,
) -> anyhow::Result<Vec<EnrichmentType>> {
    let rows = sqlx::query_scalar!(
        r#"SELECT enrichment_type as "enrichment_type: EnrichmentType" FROM enrichment_bindings WHERE source_id = $1"#,
        source_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

/// Batch-update domain_reputation flags from indicator sources with enrichment bindings.
async fn enrich_reputation(pool: &PgPool, enrichment_type: &EnrichmentType) {
    match enrichment_type {
        EnrichmentType::Nrd => enrich_nrd(pool).await,
        EnrichmentType::WellKnown => enrich_well_known(pool).await,
        EnrichmentType::Bulletproof => {} // future
        EnrichmentType::Unknown => {}
    }
}

async fn enrich_nrd(pool: &PgPool) {
    // Set/refresh NRD flag and source for all matching domains (combines mark-new + refresh-source
    // into a single pass over the indicator_domains NRD subset).
    let result = sqlx::query!(
        "UPDATE domain_reputation dr SET is_nrd = TRUE, nrd_source = youngest.slug \
         FROM ( \
             SELECT DISTINCT ON (d.domain) d.domain, s.slug \
             FROM indicator_domains d \
             JOIN sources s ON d.source = s.id \
             JOIN enrichment_bindings eb ON eb.source_id = s.id \
             WHERE eb.enrichment_type = 'nrd' \
             ORDER BY d.domain, s.slug ASC \
         ) youngest \
         WHERE youngest.domain = dr.registrable_domain \
           AND (dr.is_nrd = FALSE OR dr.nrd_source IS DISTINCT FROM youngest.slug)",
    )
    .execute(pool)
    .await;
    if let Ok(r) = result
        && r.rows_affected() > 0
    {
        info!(
            rows = r.rows_affected(),
            "enriched domain_reputation with NRD flags"
        );
    }

    // Clear NRD flag for domains no longer in any NRD source.
    // Uses NOT EXISTS (not NOT IN) to allow hash anti-join on the 12M+ row subquery.
    let _ = sqlx::query!(
        "UPDATE domain_reputation SET is_nrd = FALSE, nrd_source = NULL \
         WHERE is_nrd = TRUE \
           AND NOT EXISTS ( \
               SELECT 1 FROM indicator_domains d \
               JOIN enrichment_bindings eb ON eb.source_id = d.source \
               WHERE eb.enrichment_type = 'nrd' \
                 AND d.domain = domain_reputation.registrable_domain \
           )",
    )
    .execute(pool)
    .await;
}

async fn enrich_well_known(pool: &PgPool) {
    let result = sqlx::query!(
        "UPDATE domain_reputation dr SET is_well_known = TRUE \
         FROM indicator_domains d \
         JOIN enrichment_bindings eb ON eb.source_id = d.source \
         WHERE eb.enrichment_type = 'well_known' \
           AND d.domain = dr.registrable_domain \
           AND dr.is_well_known = FALSE",
    )
    .execute(pool)
    .await;
    if let Ok(r) = result
        && r.rows_affected() > 0
    {
        info!(
            rows = r.rows_affected(),
            "enriched domain_reputation with well-known flags"
        );
    }
}

// ---------------------------------------------------------------------------
// Find due sources
// ---------------------------------------------------------------------------

async fn find_due_sources(db: &Database) -> anyhow::Result<Vec<sqlx::types::Uuid>> {
    let now = OffsetDateTime::now_utc();
    let rows = sqlx::query_scalar!(
        "SELECT id FROM sources
         WHERE enabled = true
           AND url != ''
           AND (last_pull_at IS NULL OR last_pull_at + make_interval(secs => refresh_interval_secs) <= $1)
         ORDER BY slug",
        now,
    )
    .fetch_all(&db.pool)
    .await?;
    Ok(rows)
}
