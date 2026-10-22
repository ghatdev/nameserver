use std::collections::HashMap;
use std::sync::Arc;

use async_nats::jetstream;
use nameserver_common::admin::ProfileKvConfig;
use nameserver_common::filter::{DnAllowlistRef, DnBlocklistRef, IpAllowlistRef, IpBlocklistRef};
use nameserver_common::nats_subjects::{BUCKET_CONFIG, BUCKET_FILTERS, KV_PROFILE_PREFIX};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::BlockMode;
use crate::filter_set::FilterHolder;

/// Resolved profile configuration returned by `ProfileHolder::resolve()`.
pub struct ProfileConfig {
    pub profile_id: String,
    pub dn_blocklists: Vec<DnBlocklistRef>,
    pub dn_allowlists: Vec<DnAllowlistRef>,
    pub ip_blocklists: Vec<IpBlocklistRef>,
    pub ip_allowlists: Vec<IpAllowlistRef>,
    pub custom_filters: Option<Arc<FilterHolder>>,
    pub block_mode: BlockMode,
    pub redirect_ip: Option<String>,
}

/// Per-profile resolved data stored in the cache.
struct ResolvedProfile {
    dn_blocklists: Vec<DnBlocklistRef>,
    dn_allowlists: Vec<DnAllowlistRef>,
    ip_blocklists: Vec<IpBlocklistRef>,
    ip_allowlists: Vec<IpAllowlistRef>,
    custom_filters: Option<Arc<FilterHolder>>,
    block_mode: BlockMode,
    redirect_ip: Option<String>,
}

/// Thread-safe profile holder with lazy loading from NATS KV.
///
/// Profiles are loaded on first request and cached. Cache entries are evicted
/// via `ReloadSignal::Profile { id }`, causing a re-fetch on the next request.
///
/// The async Mutex is held for the entire KV fetch + cache insert cycle,
/// preventing thundering-herd / stampede on concurrent requests for the same
/// uncached profile.
pub struct ProfileHolder {
    /// Lazy-loaded profile cache. Protected by async Mutex for
    /// single-flight loading (only one KV fetch per profile at a time).
    cache: Mutex<HashMap<String, Arc<ResolvedProfile>>>,
    /// JetStream context for KV + Object Store reads. None if NATS not configured.
    js: Option<jetstream::Context>,
}

impl ProfileHolder {
    /// Create a new profile holder without NATS (no lazy loading).
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            js: None,
        }
    }

    /// Create a new profile holder with NATS lazy loading.
    pub fn with_js(js: jetstream::Context) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            js: Some(js),
        }
    }

    /// Resolve a profile by ID. Returns cached data on hit, or fetches from
    /// NATS KV on miss. Returns `None` if the profile ID is invalid, NATS is
    /// not configured, or the profile does not exist in KV.
    ///
    /// Single-flight: the async Mutex is held across the entire KV fetch +
    /// cache insert, so concurrent callers for the same missing profile will
    /// block rather than all hitting KV independently.
    pub async fn resolve(&self, profile_id: &str) -> Option<ProfileConfig> {
        if !validate_profile_id(profile_id) {
            debug!("invalid profile id rejected");
            return None;
        }

        // Hold the lock for the entire lookup-or-fetch cycle (single-flight).
        let mut cache = self.cache.lock().await;

        // Cache hit — return a clone.
        if let Some(profile) = cache.get(profile_id) {
            return Some(to_config(profile_id, profile));
        }

        // Cache miss — attempt lazy load from KV with timeout.
        let js = self.js.as_ref()?;
        let profile = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            load_profile_from_kv(js, profile_id),
        )
        .await
        {
            Ok(Ok(Some(p))) => Arc::new(p),
            Ok(Ok(None)) => return None,
            Ok(Err(e)) => {
                warn!(error = %e, "failed to load profile from KV");
                return None;
            }
            Err(_) => {
                warn!("profile KV load timed out");
                return None;
            }
        };

        let config = to_config(profile_id, &profile);
        cache.insert(profile_id.to_string(), profile);
        Some(config)
    }

    /// Evict a profile from the cache. The next `resolve()` call for this
    /// profile will re-fetch from KV.
    pub async fn evict(&self, profile_id: &str) {
        let mut cache = self.cache.lock().await;
        cache.remove(profile_id);
    }
}

/// Validate a profile ID: must be 1-32 ASCII alphanumeric characters.
pub fn validate_profile_id(id: &str) -> bool {
    let len = id.len();
    (1..=32).contains(&len) && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn to_config(profile_id: &str, profile: &ResolvedProfile) -> ProfileConfig {
    ProfileConfig {
        profile_id: profile_id.to_string(),
        dn_blocklists: profile.dn_blocklists.clone(),
        dn_allowlists: profile.dn_allowlists.clone(),
        ip_blocklists: profile.ip_blocklists.clone(),
        ip_allowlists: profile.ip_allowlists.clone(),
        custom_filters: profile.custom_filters.clone(),
        block_mode: profile.block_mode.clone(),
        redirect_ip: profile.redirect_ip.clone(),
    }
}

/// Load a single profile from NATS KV, building typed refs and (if needed)
/// loading custom filters from Object Store.
async fn load_profile_from_kv(
    js: &jetstream::Context,
    profile_id: &str,
) -> anyhow::Result<Option<ResolvedProfile>> {
    let kv = js.get_key_value(BUCKET_CONFIG).await?;
    let key = format!("{KV_PROFILE_PREFIX}{profile_id}");

    let bytes = match kv.get(&key).await? {
        Some(b) => b,
        None => return Ok(None),
    };

    let config: ProfileKvConfig = rmp_serde::from_slice(&bytes)?;

    let block_mode = match config.block_mode.as_str() {
        "redirect_ip" => BlockMode::RedirectIp,
        _ => BlockMode::Nxdomain,
    };

    // Only load custom filters from Object Store when the profile has them.
    let custom_filters = if config.has_custom_blocklist || config.has_custom_allowlist {
        Some(Arc::new(
            load_custom_filters(js, profile_id, &config).await?,
        ))
    } else {
        None
    };

    debug!(
        dn_blocklists = config.dn_blocklists.len(),
        dn_allowlists = config.dn_allowlists.len(),
        ip_blocklists = config.ip_blocklists.len(),
        ip_allowlists = config.ip_allowlists.len(),
        custom_blocklist = config.has_custom_blocklist,
        custom_allowlist = config.has_custom_allowlist,
        "loaded profile from KV"
    );

    Ok(Some(ResolvedProfile {
        dn_blocklists: config.dn_blocklists,
        dn_allowlists: config.dn_allowlists,
        ip_blocklists: config.ip_blocklists,
        ip_allowlists: config.ip_allowlists,
        custom_filters,
        block_mode,
        redirect_ip: config.redirect_ip,
    }))
}

/// Load per-profile custom blocklist / allowlist from Object Store into a
/// small FilterHolder. Uses the name-based swap methods.
async fn load_custom_filters(
    js: &jetstream::Context,
    profile_id: &str,
    config: &ProfileKvConfig,
) -> anyhow::Result<FilterHolder> {
    let holder = FilterHolder::new();
    let bucket = js.get_object_store(BUCKET_FILTERS).await?;
    if config.has_custom_blocklist {
        let data = read_filter_object(
            &bucket,
            &format!("profiles/{profile_id}/custom-blocklist.xor"),
        )
        .await?;
        holder.swap_blocklist(&format!("{profile_id}-blocklist"), &data)?;
    }
    if config.has_custom_allowlist {
        let data = read_filter_object(
            &bucket,
            &format!("profiles/{profile_id}/custom-allowlist.fst"),
        )
        .await?;
        holder.swap_allowlist(&format!("{profile_id}-allowlist"), data)?;
    }
    Ok(holder)
}

/// Read an object from Object Store (filter-sized, max 100 MB).
async fn read_filter_object(
    bucket: &async_nats::jetstream::object_store::ObjectStore,
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let object = bucket.get(name).await?;
    let size = object.info.size;
    if size > 100 * 1024 * 1024 {
        anyhow::bail!("object '{name}' too large: {size} bytes");
    }
    let mut reader = object;
    let mut bytes = Vec::with_capacity(size);
    reader.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

impl Default for ProfileHolder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_profile_id() {
        // Valid cases.
        assert!(validate_profile_id("a"));
        assert!(validate_profile_id("abc123"));
        assert!(validate_profile_id("A"));
        assert!(validate_profile_id("aB3"));
        assert!(validate_profile_id("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")); // 32 chars

        // Invalid: empty.
        assert!(!validate_profile_id(""));
        // Invalid: too long (33 chars).
        assert!(!validate_profile_id("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6X"));
        // Invalid: contains hyphen.
        assert!(!validate_profile_id("abc-def"));
        // Invalid: contains underscore.
        assert!(!validate_profile_id("abc_def"));
        // Invalid: contains dot.
        assert!(!validate_profile_id("abc.def"));
        // Invalid: contains space.
        assert!(!validate_profile_id("abc def"));
        // Invalid: unicode.
        assert!(!validate_profile_id("abc\u{00e9}"));
        // Invalid: path traversal attempt.
        assert!(!validate_profile_id("../etc"));
    }

    #[tokio::test]
    async fn test_evict_nonexistent() {
        let holder = ProfileHolder::new();
        // Should not panic.
        holder.evict("nonexistent").await;
    }

    #[tokio::test]
    async fn test_resolve_empty_returns_none() {
        let holder = ProfileHolder::new();
        // No NATS configured, so any resolve returns None.
        assert!(holder.resolve("abc123").await.is_none());
    }
}
