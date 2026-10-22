use std::collections::{BTreeMap, HashMap};

use ipnetwork::IpNetwork;
use nameserver_common::admin::{FilterManifest, ProfileKvConfig, ReloadSignal};
use nameserver_common::filter::{
    DnAllowlistRef, DnBlocklistRef, FilterDescriptor, FilterId, FilterKind, IpBlocklistRef,
    domain_to_u64,
};
use nameserver_common::nats_subjects::{
    BUCKET_CONFIG, BUCKET_FILTERS, KV_FILTER_MANIFEST, KV_PROFILE_PREFIX, OBJ_SUFFIX_SET,
    SUBJECT_RELOAD,
};
use nameserver_common::types::enums::{BlockMode, FilterType, OutputFormat};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use xorf::BinaryFuse16;

use crate::db::Database;

/// A compiled filter (FST allowlist, XOR domain blocklist, or IPF IP blocklist).
pub struct CompiledFilter {
    pub name: String,
    pub filter_id: FilterId,
    pub kind: FilterKind,
    pub bytes: Vec<u8>,
    pub checksum: String,
    pub entry_count: usize,
}

/// Result of compiling all shared filters from the database.
pub struct CompileResult {
    pub allowlist: Option<CompiledFilter>,
    pub blocklists: Vec<CompiledFilter>,
}

/// Read filters table → indicator_domains/indicator_ips → compile to FST/XOR/IPF.
pub async fn compile_from_db(db: &Database) -> anyhow::Result<CompileResult> {
    // Read all filter definitions.
    let filter_rows = sqlx::query!(
        r#"SELECT f.id, f.slug, f.display_name, f.source_id,
                f.filter_type as "filter_type: FilterType",
                f.output_format as "output_format: OutputFormat",
                s.slug AS source_slug
         FROM filters f
         JOIN sources s ON f.source_id = s.id
         ORDER BY f.slug"#,
    )
    .fetch_all(&db.pool)
    .await?;

    let mut wl_domains: Vec<String> = Vec::new();
    let mut wl_filter_id: Option<FilterId> = None;
    let mut wl_name: Option<String> = None;

    let mut bl_by_filter: BTreeMap<String, (FilterId, Vec<String>)> = BTreeMap::new();
    let mut ip_by_filter: BTreeMap<String, (FilterId, Vec<String>)> = BTreeMap::new();

    for row in &filter_rows {
        let filter_id = FilterId::from_uuid(row.id);
        let slug = row.slug.clone();
        let source_id = row.source_id;
        let output_format = &row.output_format;

        match output_format {
            OutputFormat::Fst => {
                // Allowlist — read domains, merge into single FST
                let domains = sqlx::query_scalar!(
                    "SELECT domain FROM indicator_domains WHERE source = $1 ORDER BY domain",
                    source_id,
                )
                .fetch_all(&db.pool)
                .await?;
                // Add trailing dot for FST (DNS wire format for matching)
                for d in domains {
                    let fqdn = if d.ends_with('.') { d } else { format!("{d}.") };
                    wl_domains.push(fqdn);
                }
                wl_filter_id = Some(filter_id);
                wl_name = Some(slug);
            }
            OutputFormat::Xor => {
                // Domain blocklist — read domains for this filter's source
                let domains = sqlx::query_scalar!(
                    "SELECT domain FROM indicator_domains WHERE source = $1 ORDER BY domain",
                    source_id,
                )
                .fetch_all(&db.pool)
                .await?;
                // Add trailing dot for XOR hash (DNS wire format)
                let fqdn_domains: Vec<String> = domains
                    .into_iter()
                    .map(|d| if d.ends_with('.') { d } else { format!("{d}.") })
                    .collect();
                bl_by_filter.insert(slug, (filter_id, fqdn_domains));
            }
            OutputFormat::Ipf => {
                // IP blocklist — read IPs/CIDRs for this filter's source
                let ip_rows = sqlx::query!(
                    "SELECT ip FROM indicator_ips WHERE source = $1 ORDER BY ip",
                    source_id,
                )
                .fetch_all(&db.pool)
                .await?;
                let ips: Vec<String> = ip_rows.into_iter().map(|r| r.ip.to_string()).collect();
                ip_by_filter.insert(slug, (filter_id, ips));
            } // OutputFormat is exhaustive — no unknown case possible
        }
    }

    // Compile allowlist FST
    let allowlist = compile_allowlist(wl_domains, wl_filter_id, wl_name.as_deref())?;

    // Compile domain blocklists (XOR)
    let mut blocklists = Vec::new();
    for (slug, (filter_id, domains)) in &bl_by_filter {
        if let Some(cf) = compile_xor_blocklist(slug, *filter_id, domains)? {
            blocklists.push(cf);
        }
    }

    // Compile IP blocklists (LC-Trie)
    for (slug, (filter_id, ips)) in &ip_by_filter {
        if let Some(cf) = compile_ip_filter(slug, *filter_id, ips)? {
            blocklists.push(cf);
        }
    }

    // Update filters table with compiled metadata.
    let now = OffsetDateTime::now_utc();
    if let Some(ref al) = allowlist {
        update_filter_compiled(db, al.filter_id, &al.checksum, al.entry_count, now).await;
    }
    for bl in &blocklists {
        update_filter_compiled(db, bl.filter_id, &bl.checksum, bl.entry_count, now).await;
    }

    Ok(CompileResult {
        allowlist,
        blocklists,
    })
}

fn compile_allowlist(
    mut domains: Vec<String>,
    filter_id: Option<FilterId>,
    name: Option<&str>,
) -> anyhow::Result<Option<CompiledFilter>> {
    domains.sort();
    domains.dedup();

    if domains.is_empty() {
        return Ok(None);
    }

    let filter_id = filter_id.unwrap_or_default();
    let name = name.unwrap_or("allowlist").to_string();

    let set = fst::Set::from_iter(domains.iter().map(|s| s.as_str()))
        .map_err(|e| anyhow::anyhow!("FST build failed: {e}"))?;
    let bytes = set.into_fst().into_inner();
    let checksum = hex::encode(Sha256::digest(&bytes));

    info!(
        entries = domains.len(),
        bytes = bytes.len(),
        checksum = %checksum,
        filter_id = %filter_id,
        "compiled allowlist FST"
    );
    Ok(Some(CompiledFilter {
        name,
        filter_id,
        kind: FilterKind::DnAllowlist,
        bytes,
        checksum,
        entry_count: domains.len(),
    }))
}

fn compile_xor_blocklist(
    slug: &str,
    filter_id: FilterId,
    domains: &[String],
) -> anyhow::Result<Option<CompiledFilter>> {
    if domains.is_empty() {
        return Ok(None);
    }

    let mut keys: Vec<u64> = domains.iter().map(|d| domain_to_u64(d)).collect();
    keys.sort();
    keys.dedup();
    let filter = BinaryFuse16::try_from(&keys[..])
        .map_err(|e| anyhow::anyhow!("XOR build failed for {slug}: {e}"))?;
    let bytes = rmp_serde::to_vec(&filter)
        .map_err(|e| anyhow::anyhow!("XOR serialize failed for {slug}: {e}"))?;
    let checksum = hex::encode(Sha256::digest(&bytes));

    info!(
        slug = %slug,
        entries = domains.len(),
        keys = keys.len(),
        bytes = bytes.len(),
        checksum = %checksum,
        filter_id = %filter_id,
        "compiled blocklist XOR filter"
    );
    Ok(Some(CompiledFilter {
        name: slug.to_string(),
        filter_id,
        kind: FilterKind::DnBlocklist,
        bytes,
        checksum,
        entry_count: domains.len(),
    }))
}

fn compile_ip_filter(
    slug: &str,
    filter_id: FilterId,
    ips: &[String],
) -> anyhow::Result<Option<CompiledFilter>> {
    if ips.is_empty() {
        return Ok(None);
    }

    let refs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
    let filter = nameserver_common::ip_filter::IpFilter::build(&refs);
    let bytes = filter.to_bytes();
    let checksum = hex::encode(Sha256::digest(&bytes));

    info!(
        slug = %slug,
        entries = ips.len(),
        nodes = filter.node_count(),
        bytes = bytes.len(),
        checksum = %checksum,
        filter_id = %filter_id,
        "compiled IP filter (LC-Trie)"
    );
    Ok(Some(CompiledFilter {
        name: slug.to_string(),
        filter_id,
        kind: FilterKind::IpBlocklist,
        bytes,
        checksum,
        entry_count: ips.len(),
    }))
}

/// Update the filters row with compiled state.
async fn update_filter_compiled(
    db: &Database,
    filter_id: FilterId,
    checksum: &str,
    entry_count: usize,
    now: OffsetDateTime,
) {
    let entry_count_i32 = entry_count as i32;
    let uuid = filter_id.as_uuid();
    let _ = sqlx::query!(
        "UPDATE filters SET compiled_checksum = $1, compiled_entry_count = $2, compiled_at = $3, updated_at = $3
         WHERE id = $4",
        checksum,
        entry_count_i32,
        now,
        uuid,
    )
    .execute(&db.pool)
    .await;
}

// ---------------------------------------------------------------------------
// Profile map compilation
// ---------------------------------------------------------------------------

/// Build per-profile KV configs + custom filters from the database.
pub async fn compile_profile_map(
    db: &Database,
) -> anyhow::Result<(
    Vec<(String, ProfileKvConfig)>,
    Vec<(String, String, CompiledFilter)>,
)> {
    // Read all enabled profiles.
    let profile_rows = sqlx::query!(
        r#"SELECT id, display_name, block_mode as "block_mode: BlockMode", redirect_ip, is_default
         FROM profiles WHERE enabled = true ORDER BY is_default DESC, id"#,
    )
    .fetch_all(&db.pool)
    .await?;

    let mut configs = Vec::new();
    let mut custom_filters = Vec::new();

    for profile in &profile_rows {
        let id = &profile.id;
        let block_mode = profile.block_mode;
        let redirect_ip: Option<IpNetwork> = profile.redirect_ip;

        let mut dn_blocklists: Vec<DnBlocklistRef> = Vec::new();
        let mut dn_allowlists: Vec<DnAllowlistRef> = Vec::new();
        let mut ip_blocklists: Vec<IpBlocklistRef> = Vec::new();

        // Read subscribed filters (profile_filters -> filters).
        {
            let rows = sqlx::query!(
                r#"SELECT f.id,
                        f.filter_type as "filter_type: FilterType",
                        f.output_format as "output_format: OutputFormat"
                 FROM profile_filters pf
                 JOIN filters f ON f.id = pf.filter_id
                 WHERE pf.profile_id = $1"#,
                id,
            )
            .fetch_all(&db.pool)
            .await?;
            for row in &rows {
                let fid = FilterId::from_uuid(row.id);
                match (row.filter_type, row.output_format) {
                    (FilterType::Block, OutputFormat::Xor) => {
                        dn_blocklists.push(DnBlocklistRef::new(fid))
                    }
                    (FilterType::Block, OutputFormat::Ipf) => {
                        ip_blocklists.push(IpBlocklistRef::new(fid))
                    }
                    (FilterType::Allow, OutputFormat::Fst) => {
                        dn_allowlists.push(DnAllowlistRef::new(fid))
                    }
                    _ => {}
                }
            }
        }

        // Custom entries (profile_custom_entries table).
        let custom_allow: Vec<String> = sqlx::query_scalar!(
            "SELECT domain FROM profile_custom_entries WHERE profile_id = $1 AND list_type = 'allowlist' ORDER BY domain",
            id,
        )
        .fetch_all(&db.pool)
        .await
        .unwrap_or_default();

        let custom_block: Vec<String> = sqlx::query_scalar!(
            "SELECT domain FROM profile_custom_entries WHERE profile_id = $1 AND list_type = 'blocklist' ORDER BY domain",
            id,
        )
        .fetch_all(&db.pool)
        .await
        .unwrap_or_default();

        let has_custom_allowlist = !custom_allow.is_empty();
        let has_custom_blocklist = !custom_block.is_empty();

        let custom_entries_hash = if has_custom_allowlist || has_custom_blocklist {
            let mut hasher = Sha256::new();
            for d in &custom_allow {
                hasher.update(format!("a:{d}\n").as_bytes());
            }
            for d in &custom_block {
                hasher.update(format!("b:{d}\n").as_bytes());
            }
            Some(hex::encode(hasher.finalize()))
        } else {
            None
        };

        // Compile custom allowlist FST.
        if has_custom_allowlist
            && let Ok(Some(cf)) =
                compile_allowlist(custom_allow, Some(FilterId::new()), Some("allowlist"))
        {
            custom_filters.push((id.clone(), "allowlist".to_string(), cf));
        }

        // Compile custom blocklist XOR.
        if has_custom_blocklist {
            let fid = FilterId::new();
            // Add trailing dots for XOR hash
            let fqdn_block: Vec<String> = custom_block
                .into_iter()
                .map(|d| if d.ends_with('.') { d } else { format!("{d}.") })
                .collect();
            if let Ok(Some(cf)) = compile_xor_blocklist("custom-blocklist", fid, &fqdn_block) {
                custom_filters.push((id.clone(), "blocklist".to_string(), cf));
            }
        }

        configs.push((
            id.clone(),
            ProfileKvConfig {
                dn_blocklists,
                dn_allowlists,
                ip_blocklists,
                ip_allowlists: Vec::new(),
                has_custom_blocklist,
                has_custom_allowlist,
                custom_entries_hash,
                block_mode: block_mode.as_str().to_string(),
                redirect_ip: redirect_ip.map(|ip| ip.to_string()),
            },
        ));
    }

    Ok((configs, custom_filters))
}

// ---------------------------------------------------------------------------
// Source checksums (for filter manifest)
// ---------------------------------------------------------------------------

/// Read source checksums for all filters' underlying sources.
pub async fn read_source_checksums(db: &Database) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let rows = sqlx::query!(
        "SELECT f.slug, s.last_checksum
         FROM filters f
         JOIN sources s ON f.source_id = s.id
         WHERE s.last_checksum IS NOT NULL",
    )
    .fetch_all(&db.pool)
    .await;

    if let Ok(rows) = rows {
        for row in &rows {
            let slug = row.slug.clone();
            // last_checksum is NOT NULL due to WHERE clause, but sqlx infers Option
            if let Some(ref checksum) = row.last_checksum {
                map.insert(slug, checksum.clone());
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Publishing (unchanged — same NATS Object Store + KV logic)
// ---------------------------------------------------------------------------

pub async fn publish_filters_selective(
    client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
    result: &CompileResult,
    names: &std::collections::HashSet<String>,
) -> anyhow::Result<Vec<String>> {
    let bucket = js.get_object_store(BUCKET_FILTERS).await?;
    let mut published = Vec::new();

    let all: Vec<&CompiledFilter> = result
        .allowlist
        .iter()
        .chain(result.blocklists.iter())
        .collect();

    for cf in all {
        if !names.contains(&cf.name) {
            continue;
        }
        let name = format!("{}.{}", cf.filter_id, cf.kind.ext());
        let mut data: &[u8] = &cf.bytes;
        bucket.put(name.as_str(), &mut data).await?;
        info!(name = %name, entries = cf.entry_count, checksum = %cf.checksum, "published filter to Object Store");
        published.push(name.clone());

        send_reload(
            client,
            ReloadSignal::Filter {
                id: cf.filter_id,
                filter_kind: cf.kind,
                action: Default::default(),
            },
        )
        .await;
    }

    Ok(published)
}

pub async fn publish_filters(
    client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
    result: &CompileResult,
) -> anyhow::Result<Vec<String>> {
    let bucket = js.get_object_store(BUCKET_FILTERS).await?;
    let mut published = Vec::new();

    if let Some(ref al) = result.allowlist {
        let name = format!("{}.{}", al.filter_id, al.kind.ext());
        let mut data: &[u8] = &al.bytes;
        bucket.put(name.as_str(), &mut data).await?;
        info!(name = %name, checksum = %al.checksum, "published allowlist FST to Object Store");
        published.push(name);
    }

    for bl in &result.blocklists {
        let name = format!("{}.{}", bl.filter_id, bl.kind.ext());
        let mut data: &[u8] = &bl.bytes;
        bucket.put(name.as_str(), &mut data).await?;
        info!(name = %name, entries = bl.entry_count, checksum = %bl.checksum, "published filter to Object Store");
        published.push(name);
    }

    // Send reload signals.
    if let Some(ref al) = result.allowlist {
        send_reload(
            client,
            ReloadSignal::Filter {
                id: al.filter_id,
                filter_kind: al.kind,
                action: Default::default(),
            },
        )
        .await;
    }
    for bl in &result.blocklists {
        send_reload(
            client,
            ReloadSignal::Filter {
                id: bl.filter_id,
                filter_kind: bl.kind,
                action: Default::default(),
            },
        )
        .await;
    }

    Ok(published)
}

pub async fn send_reload(client: &async_nats::Client, signal: ReloadSignal) {
    let payload = match rmp_serde::to_vec_named(&signal) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, "failed to serialize reload signal");
            return;
        }
    };
    if let Err(e) = client.publish(SUBJECT_RELOAD, payload.into()).await {
        warn!(error = %e, "failed to publish reload signal");
    }
}

pub async fn publish_filter_manifest(
    js: &async_nats::jetstream::Context,
    result: &CompileResult,
    source_checksums: &HashMap<String, String>,
) -> anyhow::Result<()> {
    let mut filters = Vec::new();
    let all_compiled: Vec<&CompiledFilter> = result
        .allowlist
        .iter()
        .chain(result.blocklists.iter())
        .collect();
    for cf in all_compiled {
        filters.push(FilterDescriptor {
            id: cf.filter_id,
            kind: cf.kind,
            name: cf.name.clone(),
            source_checksum: source_checksums.get(&cf.name).cloned().unwrap_or_default(),
            compiled_checksum: cf.checksum.clone(),
            entry_count: cf.entry_count,
        });
    }

    let manifest = FilterManifest { filters };
    let bytes = rmp_serde::to_vec_named(&manifest)?;
    let kv = js.get_key_value(BUCKET_CONFIG).await?;
    kv.put(KV_FILTER_MANIFEST, bytes.into()).await?;
    info!(
        count = manifest.filters.len(),
        "published filter manifest to KV"
    );
    Ok(())
}

pub async fn publish_profile_configs(
    client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
    configs: &[(String, ProfileKvConfig)],
    custom_filters: &[(String, String, CompiledFilter)],
) -> anyhow::Result<Vec<String>> {
    let bucket = js.get_object_store(BUCKET_FILTERS).await?;
    let mut published = Vec::new();
    for (profile_id, filter_type, cf) in custom_filters {
        let name = format!(
            "profiles/{profile_id}/custom-{filter_type}.{}",
            cf.kind.ext()
        );
        let mut data: &[u8] = &cf.bytes;
        bucket.put(name.as_str(), &mut data).await?;
        info!(
            entries = cf.entry_count,
            "published custom filter to Object Store"
        );
        published.push(name);
    }

    let kv = js.get_key_value(BUCKET_CONFIG).await?;
    for (profile_id, config) in configs {
        let bytes = rmp_serde::to_vec_named(config)?;
        let key = format!("{KV_PROFILE_PREFIX}{profile_id}");
        kv.put(&key, bytes.into()).await?;
        debug!("published profile config to KV");

        send_reload(
            client,
            ReloadSignal::Profile {
                id: profile_id.clone(),
            },
        )
        .await;
    }

    Ok(published)
}

// ---------------------------------------------------------------------------
// Suffix set compilation
// ---------------------------------------------------------------------------

/// Compile all indicator_suffixes into a merged SuffixSet, publish to NATS,
/// and return the compiled set so the caller can update in-memory state.
pub async fn compile_and_publish_suffix_set(
    pool: &sqlx::PgPool,
    client: &async_nats::Client,
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<nameserver_common::suffix::SuffixSet> {
    use nameserver_common::suffix::SuffixSet;

    // Read all suffix rules from all sources.
    let rows =
        sqlx::query_as::<_, (String, String)>("SELECT suffix, rule_type FROM indicator_suffixes")
            .fetch_all(pool)
            .await?;

    // Reconstruct PSL text from DB rows and parse with the tested parser.
    let mut psl_text = String::new();
    for (suffix, rule_type) in &rows {
        match rule_type.as_str() {
            "wildcard" => {
                psl_text.push_str("*.");
                psl_text.push_str(suffix);
            }
            "exception" => {
                psl_text.push('!');
                psl_text.push_str(suffix);
            }
            _ => {
                psl_text.push_str(suffix);
            }
        }
        psl_text.push('\n');
    }
    let set = SuffixSet::from_psl_text(&psl_text);

    let entry_count = set.entry_count();
    let bytes = rmp_serde::to_vec_named(&set)?;
    let checksum = hex::encode(Sha256::digest(&bytes));

    // Publish to Object Store.
    let bucket = js.get_object_store(BUCKET_FILTERS).await?;
    let mut data: &[u8] = &bytes;
    bucket.put(OBJ_SUFFIX_SET, &mut data).await?;

    info!(
        entries = entry_count,
        checksum = %checksum,
        bytes = bytes.len(),
        "suffix set compiled and published"
    );

    // Send reload signal.
    send_reload(client, ReloadSignal::SuffixSet).await;

    Ok(set)
}
