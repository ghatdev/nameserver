//! Unified cluster state model for reconciliation.
//!
//! Both "actual" (NATS) and "desired" (PostgreSQL) produce the same [`ClusterState`],
//! enabling a pure [`diff()`] and targeted [`apply_diff()`].

use std::collections::{BTreeMap, HashSet};

use futures::StreamExt;
use nameserver_common::admin::{FilterManifest, ReloadSignal};
use nameserver_common::filter::{FilterId, FilterKind};
use nameserver_common::nats_subjects::{
    BUCKET_CONFIG, BUCKET_FILTERS, KV_FILTER_MANIFEST, KV_GEOIP_META, KV_PROFILE_PREFIX,
};
use nameserver_common::types::enums::{BlockMode, OutputFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::compiler;
use crate::db::Database;

// ---------------------------------------------------------------------------
// ClusterState — the canonical state struct
// ---------------------------------------------------------------------------

/// Unified cluster state that both "actual" (NATS) and "desired" (DB) produce.
/// Used by tests and the aggregate diff() function.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ClusterState {
    pub filters: BTreeMap<String, FilterState>,
    pub profiles: BTreeMap<String, ProfileState>,
    pub geoip: Option<GeoipState>,
}

// ---------------------------------------------------------------------------
// Per-resource state readers
// ---------------------------------------------------------------------------

/// Read the actual deployed filter state from NATS (manifest + Object Store).
pub async fn read_actual_filters(
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<BTreeMap<String, FilterState>> {
    let kv = js.get_key_value(BUCKET_CONFIG).await?;
    let mut filters = BTreeMap::new();
    let manifest: FilterManifest = match kv.get(KV_FILTER_MANIFEST).await? {
        Some(bytes) => rmp_serde::from_slice(&bytes).unwrap_or_default(),
        None => FilterManifest::default(),
    };
    let bucket = js.get_object_store(BUCKET_FILTERS).await?;
    for desc in &manifest.filters {
        let obj_key = format!("{}.{}", desc.id, desc.kind.ext());
        let object_exists = bucket.info(&obj_key).await.is_ok();
        filters.insert(
            desc.name.clone(),
            FilterState {
                id: desc.id,
                name: desc.name.clone(),
                kind: desc.kind,
                source_checksum: desc.source_checksum.clone(),
                entry_count: desc.entry_count,
                object_exists,
            },
        );
    }
    Ok(filters)
}

/// Read the actual deployed profile state from NATS KV.
/// Decodes ProfileKvConfig and resolves filter UUIDs to names via the manifest.
pub async fn read_actual_profiles(
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<BTreeMap<String, ProfileState>> {
    let kv = js.get_key_value(BUCKET_CONFIG).await?;

    // Build UUID → name mapping from the filter manifest.
    let manifest: FilterManifest = match kv.get(KV_FILTER_MANIFEST).await? {
        Some(bytes) => rmp_serde::from_slice(&bytes).unwrap_or_default(),
        None => FilterManifest::default(),
    };
    let uuid_to_name: std::collections::HashMap<FilterId, String> = manifest
        .filters
        .iter()
        .map(|f| (f.id, f.name.clone()))
        .collect();

    let mut profiles = BTreeMap::new();
    let mut keys = kv.keys().await?;
    while let Some(key) = keys.next().await {
        if let Ok(k) = key
            && let Some(pid) = k.strip_prefix(KV_PROFILE_PREFIX)
            && let Some(bytes) = kv.get(&k).await?
        {
            let hash = hex::encode(Sha256::digest(&bytes));

            // Decode ProfileKvConfig for detail.
            let detail = rmp_serde::from_slice::<nameserver_common::admin::ProfileKvConfig>(&bytes)
                .ok()
                .map(|cfg| {
                    let mut filter_names: Vec<String> = Vec::new();
                    for r in &cfg.dn_blocklists {
                        let name = uuid_to_name
                            .get(&r.id())
                            .cloned()
                            .unwrap_or_else(|| r.id().to_string());
                        filter_names.push(name);
                    }
                    for r in &cfg.dn_allowlists {
                        let name = uuid_to_name
                            .get(&r.id())
                            .cloned()
                            .unwrap_or_else(|| r.id().to_string());
                        filter_names.push(name);
                    }
                    for r in &cfg.ip_blocklists {
                        let name = uuid_to_name
                            .get(&r.id())
                            .cloned()
                            .unwrap_or_else(|| r.id().to_string());
                        filter_names.push(name);
                    }
                    filter_names.sort();

                    ProfileDetail {
                        display_name: String::new(), // not stored in KV
                        block_mode: cfg.block_mode.clone(),
                        filter_names,
                        has_custom_blocklist: cfg.has_custom_blocklist,
                        has_custom_allowlist: cfg.has_custom_allowlist,
                    }
                });

            profiles.insert(
                pid.to_string(),
                ProfileState {
                    id: pid.to_string(),
                    config_hash: hash,
                    detail,
                },
            );
        }
    }
    Ok(profiles)
}

/// Read the actual deployed geoip state from NATS KV.
pub async fn read_actual_geoip(js: &async_nats::jetstream::Context) -> Option<GeoipState> {
    let kv = js.get_key_value(BUCKET_CONFIG).await.ok()?;
    match kv.get(KV_GEOIP_META).await.ok()? {
        Some(bytes) => {
            let meta: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let checksum = meta["checksum"].as_str().unwrap_or("").to_string();
            let entry_count = meta["entries"].as_u64().unwrap_or(0);
            if checksum.is_empty() {
                None
            } else {
                Some(GeoipState {
                    checksum,
                    entry_count,
                })
            }
        }
        None => None,
    }
}

/// Read desired filter state from PostgreSQL.
pub async fn read_desired_filters(db: &Database) -> anyhow::Result<BTreeMap<String, FilterState>> {
    let mut filters = BTreeMap::new();

    // Read all filters with their source checksums.
    let rows = sqlx::query!(
        r#"SELECT f.id, f.slug,
                f.output_format as "output_format: OutputFormat",
                s.last_checksum, s.last_entry_count
         FROM filters f
         JOIN sources s ON f.source_id = s.id
         ORDER BY f.slug"#,
    )
    .fetch_all(&db.pool)
    .await?;

    for row in &rows {
        let filter_id = FilterId::from_uuid(row.id);
        let slug = &row.slug;
        let checksum = row.last_checksum.clone();
        let count = row.last_entry_count;

        let entry_count = count.unwrap_or(0) as usize;
        if entry_count == 0 {
            continue;
        }

        let kind = match row.output_format {
            OutputFormat::Fst => FilterKind::DnAllowlist,
            OutputFormat::Xor => FilterKind::DnBlocklist,
            OutputFormat::Ipf => FilterKind::IpBlocklist,
        };

        filters.insert(
            slug.clone(),
            FilterState {
                id: filter_id,
                name: slug.clone(),
                kind,
                source_checksum: checksum.unwrap_or_default(),
                entry_count,
                object_exists: true,
            },
        );
    }

    Ok(filters)
}

/// Read desired profile state from PostgreSQL.
pub async fn read_desired_profiles(
    db: &Database,
) -> anyhow::Result<BTreeMap<String, ProfileState>> {
    // Read profile metadata from DB for detail.
    let profile_meta: std::collections::HashMap<String, (String, String)> = sqlx::query!(
        r#"SELECT id, display_name, block_mode as "block_mode: BlockMode" FROM profiles WHERE enabled = true"#,
    )
    .fetch_all(&db.pool)
    .await?
    .iter()
    .map(|row| {
        let id = row.id.clone();
        let name = row.display_name.clone();
        let mode = row.block_mode.as_str().to_string();
        (id, (name, mode))
    })
    .collect();

    // Read filter name mappings (uuid → slug).
    let name_by_uuid: std::collections::HashMap<FilterId, String> =
        sqlx::query!("SELECT id, slug FROM filters",)
            .fetch_all(&db.pool)
            .await?
            .iter()
            .map(|row| {
                let id = FilterId::from_uuid(row.id);
                let slug = row.slug.clone();
                (id, slug)
            })
            .collect();

    let mut profiles = BTreeMap::new();
    if let Ok((configs, _custom)) = compiler::compile_profile_map(db).await {
        for (id, config) in &configs {
            let bytes = rmp_serde::to_vec_named(config).unwrap_or_default();
            let hash = hex::encode(Sha256::digest(&bytes));

            let (display_name, block_mode) = profile_meta.get(id).cloned().unwrap_or_default();

            let mut filter_names: Vec<String> = Vec::new();
            for r in &config.dn_blocklists {
                let name = name_by_uuid
                    .get(&r.id())
                    .cloned()
                    .unwrap_or_else(|| r.id().to_string());
                filter_names.push(name);
            }
            for r in &config.dn_allowlists {
                let name = name_by_uuid
                    .get(&r.id())
                    .cloned()
                    .unwrap_or_else(|| r.id().to_string());
                filter_names.push(name);
            }
            for r in &config.ip_blocklists {
                let name = name_by_uuid
                    .get(&r.id())
                    .cloned()
                    .unwrap_or_else(|| r.id().to_string());
                filter_names.push(name);
            }
            filter_names.sort();

            profiles.insert(
                id.clone(),
                ProfileState {
                    id: id.clone(),
                    config_hash: hash,
                    detail: Some(ProfileDetail {
                        display_name,
                        block_mode,
                        filter_names,
                        has_custom_blocklist: config.has_custom_blocklist,
                        has_custom_allowlist: config.has_custom_allowlist,
                    }),
                },
            );
        }
    }
    Ok(profiles)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterState {
    pub id: FilterId,
    pub name: String,
    pub kind: FilterKind,
    pub source_checksum: String,
    pub entry_count: usize,
    /// Whether the compiled object exists in Object Store.
    /// Desired state: always true. Actual state: probed from Object Store.
    pub object_exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileState {
    pub id: String,
    /// SHA-256 of the serialized ProfileKvConfig bytes (msgpack).
    pub config_hash: String,
    /// Human-readable summary for diff display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ProfileDetail>,
}

/// Human-readable profile summary for diffs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileDetail {
    pub display_name: String,
    pub block_mode: String,
    pub filter_names: Vec<String>,
    pub has_custom_blocklist: bool,
    pub has_custom_allowlist: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoipState {
    pub checksum: String,
    pub entry_count: u64,
}

// ---------------------------------------------------------------------------
// Read actual state from NATS
// ---------------------------------------------------------------------------

impl ClusterState {
    /// Read the actual deployed state from NATS KV + Object Store metadata.
    /// Delegates to per-resource readers.
    #[allow(dead_code)]
    pub async fn read_actual(js: &async_nats::jetstream::Context) -> anyhow::Result<Self> {
        let filters = read_actual_filters(js).await?;
        let profiles = read_actual_profiles(js).await?;
        let geoip = read_actual_geoip(js).await;
        Ok(ClusterState {
            filters,
            profiles,
            geoip,
        })
    }

    /// Read the desired state from the database (what should be deployed).
    /// Delegates to per-resource readers.
    #[allow(dead_code)]
    pub async fn read_desired(db: &Database) -> anyhow::Result<Self> {
        let filters = read_desired_filters(db).await?;
        let profiles = read_desired_profiles(db).await?;
        let geoip = read_geoip_state(&db.pool).await;
        Ok(ClusterState {
            filters,
            profiles,
            geoip,
        })
    }
}

/// Compute geoip state from geo_entries aggregate counts.
pub async fn read_geoip_state(pool: &PgPool) -> Option<GeoipState> {
    let rows = sqlx::query!(
        r#"SELECT rir, ip_version, COUNT(*) as "cnt!" FROM geo_entries
         GROUP BY rir, ip_version ORDER BY rir, ip_version"#,
    )
    .fetch_all(pool)
    .await
    .ok()?;

    if rows.is_empty() {
        return None;
    }

    let mut total = 0u64;
    let mut hasher = Sha256::new();
    for row in &rows {
        let count = row.cnt;
        total += count as u64;
        hasher.update(format!("{}:{}:{count}\n", row.rir, row.ip_version).as_bytes());
    }

    Some(GeoipState {
        checksum: hex::encode(hasher.finalize()),
        entry_count: total,
    })
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// Diff result comparing actual vs desired cluster state.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct StateDiff {
    pub filters: ResourceDiff<FilterDiffEntry>,
    pub profiles: ResourceDiff<ProfileDiffEntry>,
    pub geoip: GeoipDiffResult,
    pub has_changes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceDiff<T> {
    pub added: Vec<T>,
    pub changed: Vec<T>,
    pub removed: Vec<T>,
    pub unchanged: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilterDiffEntry {
    pub name: String,
    pub kind: String,
    pub object_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_entries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_entries: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileDiffEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired: Option<ProfileDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<ProfileDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoipDiffResult {
    pub status: GeoipDiffStatus,
    pub desired_entries: u64,
    pub desired_checksum: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GeoipDiffStatus {
    Unchanged,
    Changed,
    NotPublished,
    NoData,
}

/// Pure comparison of actual vs desired state. No I/O.
#[allow(dead_code)]
pub fn diff(actual: &ClusterState, desired: &ClusterState) -> StateDiff {
    let filters = diff_filters(&actual.filters, &desired.filters);
    let profiles = diff_profiles(&actual.profiles, &desired.profiles);
    let geoip = diff_geoip(&actual.geoip, &desired.geoip);

    let has_changes = !filters.added.is_empty()
        || !filters.changed.is_empty()
        || !filters.removed.is_empty()
        || !profiles.added.is_empty()
        || !profiles.changed.is_empty()
        || !profiles.removed.is_empty()
        || geoip.status == GeoipDiffStatus::Changed
        || geoip.status == GeoipDiffStatus::NotPublished;

    StateDiff {
        filters,
        profiles,
        geoip,
        has_changes,
    }
}

pub fn diff_filters(
    actual: &BTreeMap<String, FilterState>,
    desired: &BTreeMap<String, FilterState>,
) -> ResourceDiff<FilterDiffEntry> {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();

    for (name, des) in desired {
        let obj_key = format!("{}.{}", des.id, des.kind.ext());
        let entry = FilterDiffEntry {
            name: name.clone(),
            kind: format!("{:?}", des.kind),
            object_key: obj_key,
            desired_entries: Some(des.entry_count),
            actual_entries: actual.get(name).map(|a| a.entry_count),
        };

        match actual.get(name) {
            None => added.push(entry),
            Some(act) => {
                // Compare by source_checksum + object existence only.
                // Entry counts differ between raw (desired) and compiled (actual)
                // due to dedup, so they're not reliable for comparison.
                if !act.object_exists || act.source_checksum != des.source_checksum {
                    changed.push(entry);
                } else {
                    unchanged.push(entry);
                }
            }
        }
    }

    for (name, act) in actual {
        if !desired.contains_key(name) {
            let obj_key = format!("{}.{}", act.id, act.kind.ext());
            removed.push(FilterDiffEntry {
                name: name.clone(),
                kind: format!("{:?}", act.kind),
                object_key: obj_key,
                desired_entries: None,
                actual_entries: Some(act.entry_count),
            });
        }
    }

    ResourceDiff {
        added,
        changed,
        removed,
        unchanged,
    }
}

pub fn diff_profiles(
    actual: &BTreeMap<String, ProfileState>,
    desired: &BTreeMap<String, ProfileState>,
) -> ResourceDiff<ProfileDiffEntry> {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();

    for (id, des) in desired {
        match actual.get(id) {
            None => added.push(ProfileDiffEntry {
                id: id.clone(),
                desired: des.detail.clone(),
                actual: None,
            }),
            Some(act) => {
                if act.config_hash != des.config_hash {
                    changed.push(ProfileDiffEntry {
                        id: id.clone(),
                        desired: des.detail.clone(),
                        actual: act.detail.clone(),
                    });
                } else {
                    unchanged.push(ProfileDiffEntry {
                        id: id.clone(),
                        desired: None,
                        actual: None,
                    });
                }
            }
        }
    }

    for (id, act) in actual {
        if !desired.contains_key(id) {
            removed.push(ProfileDiffEntry {
                id: id.clone(),
                desired: None,
                actual: act.detail.clone(),
            });
        }
    }

    ResourceDiff {
        added,
        changed,
        removed,
        unchanged,
    }
}

pub fn diff_geoip(actual: &Option<GeoipState>, desired: &Option<GeoipState>) -> GeoipDiffResult {
    match (desired, actual) {
        (Some(des), Some(act)) => {
            if des.checksum == act.checksum {
                GeoipDiffResult {
                    status: GeoipDiffStatus::Unchanged,
                    desired_entries: des.entry_count,
                    desired_checksum: des.checksum.clone(),
                }
            } else {
                GeoipDiffResult {
                    status: GeoipDiffStatus::Changed,
                    desired_entries: des.entry_count,
                    desired_checksum: des.checksum.clone(),
                }
            }
        }
        (Some(des), None) => GeoipDiffResult {
            status: GeoipDiffStatus::NotPublished,
            desired_entries: des.entry_count,
            desired_checksum: des.checksum.clone(),
        },
        _ => GeoipDiffResult {
            status: GeoipDiffStatus::NoData,
            desired_entries: 0,
            desired_checksum: String::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Per-resource apply functions
// ---------------------------------------------------------------------------

/// Apply only filter changes (compile + publish changed, remove orphans).
pub async fn apply_filter_diff(
    diff: &ResourceDiff<FilterDiffEntry>,
    db: &Database,
    nats_client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<serde_json::Value> {
    let mut response = serde_json::json!({});

    let filter_names_to_publish: HashSet<String> = diff
        .added
        .iter()
        .chain(diff.changed.iter())
        .map(|e| e.name.clone())
        .collect();

    if !filter_names_to_publish.is_empty() {
        let result = compiler::compile_from_db(db).await?;
        let published =
            compiler::publish_filters_selective(nats_client, js, &result, &filter_names_to_publish)
                .await?;
        response["published"] = serde_json::json!(published);

        let source_checksums = compiler::read_source_checksums(db).await;
        compiler::publish_filter_manifest(js, &result, &source_checksums).await?;
    }

    if !diff.removed.is_empty() {
        let mut removed_keys = Vec::new();
        if let Ok(bucket) = js.get_object_store(BUCKET_FILTERS).await {
            for entry in &diff.removed {
                let _ = bucket.delete(&entry.object_key).await;
                removed_keys.push(entry.object_key.clone());
            }
        }
        if filter_names_to_publish.is_empty() {
            let result = compiler::compile_from_db(db).await?;
            let source_checksums = compiler::read_source_checksums(db).await;
            compiler::publish_filter_manifest(js, &result, &source_checksums).await?;
        }
        response["removed"] = serde_json::json!(removed_keys);
    }

    let has_changes = !filter_names_to_publish.is_empty() || !diff.removed.is_empty();
    if !has_changes {
        return Ok(serde_json::json!({ "status": "no_changes" }));
    }

    info!(
        published = filter_names_to_publish.len(),
        removed = diff.removed.len(),
        "filter apply completed"
    );

    Ok(response)
}

/// Apply only profile changes (publish changed profile configs, remove deleted).
pub async fn apply_profile_diff(
    diff: &ResourceDiff<ProfileDiffEntry>,
    db: &Database,
    nats_client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<serde_json::Value> {
    let has_changes =
        !diff.added.is_empty() || !diff.changed.is_empty() || !diff.removed.is_empty();

    if !has_changes {
        return Ok(serde_json::json!({ "status": "no_changes" }));
    }

    let mut response = serde_json::json!({});

    // Publish desired profiles.
    if !diff.added.is_empty() || !diff.changed.is_empty() {
        let (configs, custom) = compiler::compile_profile_map(db).await?;
        let published =
            compiler::publish_profile_configs(nats_client, js, &configs, &custom).await?;
        response["published"] = serde_json::json!(published);
    }

    // Delete KV entries and custom filter objects for removed profiles.
    if !diff.removed.is_empty() {
        let kv = js.get_key_value(BUCKET_CONFIG).await?;
        let bucket = js.get_object_store(BUCKET_FILTERS).await.ok();
        let mut removed_ids = Vec::new();

        for entry in &diff.removed {
            let key = format!("{KV_PROFILE_PREFIX}{}", entry.id);
            let _ = kv.delete(&key).await;

            // Clean up custom filter objects.
            if let Some(ref bucket) = bucket {
                let _ = bucket
                    .delete(&format!("profiles/{}/custom-allowlist.fst", entry.id))
                    .await;
                let _ = bucket
                    .delete(&format!("profiles/{}/custom-blocklist.xor", entry.id))
                    .await;
            }

            // Send reload signal so resolver evicts cached profile.
            compiler::send_reload(
                nats_client,
                ReloadSignal::Profile {
                    id: entry.id.clone(),
                },
            )
            .await;

            removed_ids.push(entry.id.clone());
        }

        response["removed"] = serde_json::json!(removed_ids);
        info!(removed = removed_ids.len(), "removed profile KV entries");
    }

    info!("profile apply completed");

    Ok(response)
}

/// Apply only geoip changes (compile + publish geoip table).
pub async fn apply_geoip_diff(
    diff: &GeoipDiffResult,
    db: &Database,
    nats_client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<serde_json::Value> {
    if diff.status != GeoipDiffStatus::Changed && diff.status != GeoipDiffStatus::NotPublished {
        return Ok(serde_json::json!({ "status": "no_changes" }));
    }

    crate::api::geoip::compile_and_publish_geoip(&db.pool, js).await?;

    // Store metadata in KV for future diffs.
    let geo_state = read_geoip_state(&db.pool).await;
    if let Some(geo) = geo_state {
        let meta = serde_json::json!({
            "checksum": geo.checksum,
            "entries": geo.entry_count,
        });
        if let Ok(kv) = js.get_key_value(BUCKET_CONFIG).await {
            let _ = kv
                .put(
                    KV_GEOIP_META,
                    serde_json::to_vec(&meta).unwrap_or_default().into(),
                )
                .await;
        }
    }

    compiler::send_reload(nats_client, ReloadSignal::Geoip).await;
    info!("geoip apply completed");

    Ok(serde_json::json!({ "status": "published" }))
}

// ---------------------------------------------------------------------------
// Full apply (delegates to per-resource)
// ---------------------------------------------------------------------------

/// Apply only the changes described by the diff.
/// Delegates to per-resource apply functions.
#[allow(dead_code)]
pub async fn apply_diff(
    diff: &StateDiff,
    db: &Database,
    nats_client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<serde_json::Value> {
    let mut response = serde_json::json!({});

    // 1. Filters.
    let filter_result = apply_filter_diff(&diff.filters, db, nats_client, js).await?;
    if filter_result.get("published").is_some() {
        response["published"] = filter_result["published"].clone();
    }
    if filter_result.get("removed").is_some() {
        response["removed"] = filter_result["removed"].clone();
    }

    // 2. Profiles.
    let profile_result = apply_profile_diff(&diff.profiles, db, nats_client, js).await;
    match profile_result {
        Ok(r) if r.get("published").is_some() => {
            response["profile_published"] = r["published"].clone();
        }
        Err(e) => {
            response["profile_error"] = serde_json::json!(e.to_string());
        }
        _ => {}
    }

    // 3. GeoIP.
    match apply_geoip_diff(&diff.geoip, db, nats_client, js).await {
        Ok(r) if r["status"] == "published" => {
            response["geoip"] = serde_json::json!("published");
        }
        Err(e) => {
            response["geoip_error"] = serde_json::json!(e.to_string());
        }
        _ => {}
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(name: &str, checksum: &str, entries: usize) -> FilterState {
        FilterState {
            id: FilterId::new(),
            name: name.to_string(),
            kind: FilterKind::DnBlocklist,
            source_checksum: checksum.to_string(),
            entry_count: entries,
            object_exists: true,
        }
    }

    fn profile(id: &str, hash: &str) -> ProfileState {
        ProfileState {
            id: id.to_string(),
            config_hash: hash.to_string(),
            detail: None,
        }
    }

    fn geo(checksum: &str, entries: u64) -> GeoipState {
        GeoipState {
            checksum: checksum.to_string(),
            entry_count: entries,
        }
    }

    #[test]
    fn empty_states_no_changes() {
        let actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        let desired = actual.clone();
        let d = diff(&actual, &desired);
        assert!(!d.has_changes);
        assert!(d.filters.added.is_empty());
        assert!(d.filters.removed.is_empty());
        assert!(d.profiles.added.is_empty());
        assert_eq!(d.geoip.status, GeoipDiffStatus::NoData);
    }

    #[test]
    fn filter_added() {
        let actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        let mut desired = actual.clone();
        desired
            .filters
            .insert("hagezi-pro".into(), filter("hagezi-pro", "abc", 100));

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.filters.added.len(), 1);
        assert_eq!(d.filters.added[0].name, "hagezi-pro");
    }

    #[test]
    fn filter_removed() {
        let mut actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        actual
            .filters
            .insert("old-list".into(), filter("old-list", "abc", 50));
        let desired = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: None,
        };

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.filters.removed.len(), 1);
        assert_eq!(d.filters.removed[0].name, "old-list");
    }

    #[test]
    fn filter_changed_by_checksum() {
        let f = filter("hagezi-pro", "old_checksum", 100);
        let actual = ClusterState {
            filters: BTreeMap::from([("hagezi-pro".into(), f)]),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        let mut desired = actual.clone();
        desired
            .filters
            .get_mut("hagezi-pro")
            .unwrap()
            .source_checksum = "new_checksum".into();

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.filters.changed.len(), 1);
        assert_eq!(d.filters.unchanged.len(), 0);
    }

    #[test]
    fn filter_changed_by_missing_object() {
        let mut f = filter("hagezi-pro", "abc", 100);
        f.object_exists = false;
        let actual = ClusterState {
            filters: BTreeMap::from([("hagezi-pro".into(), f)]),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        let mut desired = actual.clone();
        desired.filters.get_mut("hagezi-pro").unwrap().object_exists = true;

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.filters.changed.len(), 1);
    }

    #[test]
    fn filter_unchanged() {
        let f = filter("hagezi-pro", "abc", 100);
        let actual = ClusterState {
            filters: BTreeMap::from([("hagezi-pro".into(), f.clone())]),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        let desired = actual.clone();

        let d = diff(&actual, &desired);
        assert!(!d.has_changes);
        assert_eq!(d.filters.unchanged.len(), 1);
    }

    #[test]
    fn profile_changed() {
        let actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::from([("default".into(), profile("default", "hash_a"))]),
            geoip: None,
        };
        let desired = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::from([("default".into(), profile("default", "hash_b"))]),
            geoip: None,
        };

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.profiles.changed.len(), 1);
    }

    #[test]
    fn geoip_not_published() {
        let actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: None,
        };
        let desired = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: Some(geo("abc123", 500000)),
        };

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.geoip.status, GeoipDiffStatus::NotPublished);
    }

    #[test]
    fn geoip_unchanged() {
        let g = geo("abc123", 500000);
        let actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: Some(g.clone()),
        };
        let desired = actual.clone();

        let d = diff(&actual, &desired);
        assert!(!d.has_changes);
        assert_eq!(d.geoip.status, GeoipDiffStatus::Unchanged);
    }

    #[test]
    fn geoip_changed() {
        let actual = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: Some(geo("old", 400000)),
        };
        let desired = ClusterState {
            filters: BTreeMap::new(),
            profiles: BTreeMap::new(),
            geoip: Some(geo("new", 500000)),
        };

        let d = diff(&actual, &desired);
        assert!(d.has_changes);
        assert_eq!(d.geoip.status, GeoipDiffStatus::Changed);
    }
}
