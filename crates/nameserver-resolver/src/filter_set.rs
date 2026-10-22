use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fst::Set;
use nameserver_common::admin::{FilterInfo, ListStatus};
use nameserver_common::filter::{
    DnAllowlistRef, DnBlocklistRef, FilterId, IpAllowlistRef, IpBlocklistRef, domain_to_u64,
};
use nameserver_common::ip_filter::IpFilter;
use nameserver_common::suffix::SuffixSet;
use tracing::{info, warn};
use xorf::{BinaryFuse16, Filter};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of checking a domain against the global filter set (non-profile path).
#[derive(Debug, Clone, PartialEq)]
pub enum FilterResult {
    AllowlistHit {
        filter_id: FilterId,
        matched: String,
    },
    BlocklistHit {
        filter_id: FilterId,
        matched: String,
    },
    NoMatch,
}

/// Result of a profile subset check — only returned on a hit.
#[derive(Debug, Clone)]
pub struct FilterHit {
    pub filter_id: FilterId,
    pub matched: String,
}

// ---------------------------------------------------------------------------
// Internal storage
// ---------------------------------------------------------------------------

type NamedFilter<T> = (Arc<str>, Arc<T>);

struct FilterSet {
    dn_blocklists: HashMap<FilterId, (Arc<str>, Arc<BinaryFuse16>)>,
    dn_allowlists: HashMap<FilterId, NamedFilter<Set<Vec<u8>>>>,
    ip_blocklists: HashMap<FilterId, (Arc<str>, Arc<IpFilter>)>,
    ip_allowlists: HashMap<FilterId, (Arc<str>, Arc<IpFilter>)>,
}

impl FilterSet {
    fn new() -> Self {
        Self {
            dn_blocklists: HashMap::new(),
            dn_allowlists: HashMap::new(),
            ip_blocklists: HashMap::new(),
            ip_allowlists: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// FilterHolder
// ---------------------------------------------------------------------------

/// Thread-safe, hot-swappable filter holder.
///
/// Uses `ArcSwap` for lock-free reads. Internally uses `HashMap<FilterId, ...>`
/// for O(1) lookup by filter ID.
pub struct FilterHolder {
    inner: ArcSwap<FilterSet>,
}

impl FilterHolder {
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(FilterSet::new()),
        }
    }

    // =======================================================================
    // Combined check (used by per-profile custom filters)
    // =======================================================================

    /// Check a domain against all allowlists then blocklists in this holder.
    /// Used for per-profile custom filter holders (not the shared filter set).
    pub fn check(
        &self,
        domain: &str,
        max_depth: usize,
        suffix_set: Option<&SuffixSet>,
    ) -> FilterResult {
        let lists = self.inner.load();
        let parts = decompose_domain(domain, max_depth, suffix_set);

        for part in &parts {
            for (&id, (_name, fst)) in &lists.dn_allowlists {
                if fst.contains(part) {
                    return FilterResult::AllowlistHit {
                        filter_id: id,
                        matched: part.to_string(),
                    };
                }
            }

            let hash = domain_to_u64(part);
            for (&id, (_name, xor)) in &lists.dn_blocklists {
                if xor.contains(&hash) {
                    return FilterResult::BlocklistHit {
                        filter_id: id,
                        matched: part.to_string(),
                    };
                }
            }
        }

        FilterResult::NoMatch
    }

    /// Check IPs against all IP allowlists and blocklists in this holder.
    pub fn check_ip(&self, ips: &[IpAddr]) -> Option<(FilterId, IpAddr)> {
        let lists = self.inner.load();

        for (_name, filter) in lists.ip_allowlists.values() {
            for &ip in ips {
                if filter.contains(ip) {
                    return None;
                }
            }
        }

        for (&id, (_name, filter)) in &lists.ip_blocklists {
            for &ip in ips {
                if filter.contains(ip) {
                    return Some((id, ip));
                }
            }
        }

        None
    }

    // =======================================================================
    // Profile subset checks (typed refs, O(1) per filter via HashMap)
    // =======================================================================

    /// A selected policy must never silently omit a missing compiled filter.
    pub fn profile_ready(&self, profile: &crate::profiles::ProfileConfig) -> bool {
        let filters = self.inner.load();
        profile
            .dn_blocklists
            .iter()
            .all(|reference| filters.dn_blocklists.contains_key(&reference.id()))
            && profile
                .dn_allowlists
                .iter()
                .all(|reference| filters.dn_allowlists.contains_key(&reference.id()))
            && profile
                .ip_blocklists
                .iter()
                .all(|reference| filters.ip_blocklists.contains_key(&reference.id()))
            && profile
                .ip_allowlists
                .iter()
                .all(|reference| filters.ip_allowlists.contains_key(&reference.id()))
    }

    /// Check domain against a subset of domain allowlists.
    pub fn check_dn_allowlists(
        &self,
        refs: &[DnAllowlistRef],
        domain: &str,
        max_depth: usize,
        suffix_set: Option<&SuffixSet>,
    ) -> Option<FilterHit> {
        let lists = self.inner.load();
        let parts = decompose_domain(domain, max_depth, suffix_set);

        for r in refs {
            if let Some((_name, fst)) = lists.dn_allowlists.get(&r.id()) {
                for part in &parts {
                    if fst.contains(part) {
                        return Some(FilterHit {
                            filter_id: r.id(),
                            matched: part.to_string(),
                        });
                    }
                }
            }
        }
        None
    }

    /// Check domain against a subset of domain blocklists.
    pub fn check_dn_blocklists(
        &self,
        refs: &[DnBlocklistRef],
        domain: &str,
        max_depth: usize,
        suffix_set: Option<&SuffixSet>,
    ) -> Option<FilterHit> {
        let lists = self.inner.load();
        let parts = decompose_domain(domain, max_depth, suffix_set);
        let hashes: Vec<u64> = parts.iter().map(|p| domain_to_u64(p)).collect();

        for r in refs {
            if let Some((_name, xor)) = lists.dn_blocklists.get(&r.id()) {
                for (i, &h) in hashes.iter().enumerate() {
                    if xor.contains(&h) {
                        return Some(FilterHit {
                            filter_id: r.id(),
                            matched: parts[i].to_string(),
                        });
                    }
                }
            }
        }
        None
    }

    /// Check IPs against a subset of IP allowlists.
    /// Returns true if any IP is allowlisted (should skip blocking).
    pub fn check_ip_allowlists(&self, refs: &[IpAllowlistRef], ips: &[IpAddr]) -> bool {
        let lists = self.inner.load();
        for r in refs {
            if let Some((_name, filter)) = lists.ip_allowlists.get(&r.id()) {
                for &ip in ips {
                    if filter.contains(ip) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check IPs against a subset of IP blocklists.
    pub fn check_ip_blocklists(
        &self,
        refs: &[IpBlocklistRef],
        ips: &[IpAddr],
    ) -> Option<(FilterId, IpAddr)> {
        let lists = self.inner.load();
        for r in refs {
            if let Some((_name, filter)) = lists.ip_blocklists.get(&r.id()) {
                for &ip in ips {
                    if filter.contains(ip) {
                        return Some((r.id(), ip));
                    }
                }
            }
        }
        None
    }

    // =======================================================================
    // Swap methods (UUID-based)
    // =======================================================================

    /// Replace or add a domain blocklist XOR filter.
    /// Uses rcu() for atomic read-copy-update (safe under concurrent swaps).
    pub fn swap_dn_blocklist(
        &self,
        id: FilterId,
        display_name: &str,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let filter = Arc::new(rmp_serde::from_slice::<BinaryFuse16>(data)?);
        let name: Arc<str> = Arc::from(display_name);
        self.inner.rcu(move |old| {
            let mut new = clone_filter_set(old);
            new.dn_blocklists
                .insert(id, (Arc::clone(&name), Arc::clone(&filter)));
            new
        });
        info!("domain blocklist swapped");
        Ok(())
    }

    /// Replace or add a domain allowlist FST.
    pub fn swap_dn_allowlist(
        &self,
        id: FilterId,
        display_name: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<usize> {
        let set = Arc::new(Set::new(data)?);
        let count = set.len();
        let name: Arc<str> = Arc::from(display_name);
        self.inner.rcu(move |old| {
            let mut new = clone_filter_set(old);
            new.dn_allowlists
                .insert(id, (Arc::clone(&name), Arc::clone(&set)));
            new
        });
        info!(entries = count, "domain allowlist swapped");
        Ok(count)
    }

    /// Replace or add an IP blocklist.
    pub fn swap_ip_blocklist(
        &self,
        id: FilterId,
        display_name: &str,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let filter = Arc::new(IpFilter::from_bytes(data).map_err(|e| anyhow::anyhow!("{e}"))?);
        let name: Arc<str> = Arc::from(display_name);
        self.inner.rcu(move |old| {
            let mut new = clone_filter_set(old);
            new.ip_blocklists
                .insert(id, (Arc::clone(&name), Arc::clone(&filter)));
            new
        });
        info!("IP blocklist swapped");
        Ok(())
    }

    /// Replace or add an IP allowlist.
    pub fn swap_ip_allowlist(
        &self,
        id: FilterId,
        display_name: &str,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let filter = Arc::new(IpFilter::from_bytes(data).map_err(|e| anyhow::anyhow!("{e}"))?);
        let name: Arc<str> = Arc::from(display_name);
        self.inner.rcu(move |old| {
            let mut new = clone_filter_set(old);
            new.ip_allowlists
                .insert(id, (Arc::clone(&name), Arc::clone(&filter)));
            new
        });
        info!("IP allowlist swapped");
        Ok(())
    }

    /// Remove a filter by ID from all maps.
    pub fn remove_by_id(&self, id: &FilterId) -> bool {
        let id = *id;
        let mut removed = false;
        self.inner.rcu(|old| {
            let mut new = clone_filter_set(old);
            removed = new.dn_blocklists.remove(&id).is_some()
                | new.dn_allowlists.remove(&id).is_some()
                | new.ip_blocklists.remove(&id).is_some()
                | new.ip_allowlists.remove(&id).is_some();
            new
        });
        if removed {
            info!("filter removed");
        }
        removed
    }

    // =======================================================================
    // Legacy swap methods (name-based, for disk loading + custom filters)
    // =======================================================================

    /// Swap a domain allowlist by name (generates a deterministic FilterId from name).
    pub fn swap_allowlist(&self, name: &str, data: Vec<u8>) -> anyhow::Result<usize> {
        let id = name_to_filter_id(name);
        self.swap_dn_allowlist(id, name, data)
    }

    /// Swap a domain blocklist by name.
    pub fn swap_blocklist(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        let id = name_to_filter_id(name);
        self.swap_dn_blocklist(id, name, data)
    }

    /// Load lists from disk paths (legacy). Fail-open.
    pub fn load_from_disk(&self, allowlist_path: Option<&Path>, blocklist_path: Option<&Path>) {
        if let Some(path) = allowlist_path {
            match std::fs::read(path) {
                Ok(data) => match self.swap_allowlist("default", data) {
                    Ok(count) => {
                        info!(path = %path.display(), count, "loaded allowlist from disk")
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "failed to parse allowlist FST")
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to read allowlist file")
                }
            }
        }
        if let Some(path) = blocklist_path {
            match std::fs::read(path) {
                Ok(data) => match self.swap_blocklist("default", &data) {
                    Ok(()) => info!(path = %path.display(), "loaded blocklist from disk"),
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "failed to parse blocklist XOR")
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to read blocklist file")
                }
            }
        }
    }

    // =======================================================================
    // Status
    // =======================================================================

    pub fn status(&self) -> ListStatus {
        let lists = self.inner.load();

        let allowlist_loaded = !lists.dn_allowlists.is_empty();
        let allowlist_entries: usize = lists.dn_allowlists.values().map(|(_, fst)| fst.len()).sum();
        let blocklist_loaded = !lists.dn_blocklists.is_empty();

        let mut filters = Vec::new();
        for (name, _fst) in lists.dn_allowlists.values() {
            filters.push(FilterInfo {
                name: name.to_string(),
                kind: "allowlist".to_string(),
                entries: None,
                checksum: None,
            });
        }
        for (name, _xor) in lists.dn_blocklists.values() {
            filters.push(FilterInfo {
                name: name.to_string(),
                kind: "blocklist".to_string(),
                entries: None,
                checksum: None,
            });
        }
        for (name, _filter) in lists.ip_blocklists.values() {
            filters.push(FilterInfo {
                name: name.to_string(),
                kind: "ip_blocklist".to_string(),
                entries: None,
                checksum: None,
            });
        }
        for (name, _filter) in lists.ip_allowlists.values() {
            filters.push(FilterInfo {
                name: name.to_string(),
                kind: "ip_allowlist".to_string(),
                entries: None,
                checksum: None,
            });
        }

        ListStatus {
            allowlist_loaded,
            allowlist_entries,
            allowlist_checksum: None,
            blocklist_loaded,
            blocklist_checksum: None,
            filters,
        }
    }
}

impl Default for FilterHolder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Clone a FilterSet, sharing Arc data pointers (cheap).
fn clone_filter_set(old: &FilterSet) -> FilterSet {
    FilterSet {
        dn_blocklists: old.dn_blocklists.clone(),
        dn_allowlists: old.dn_allowlists.clone(),
        ip_blocklists: old.ip_blocklists.clone(),
        ip_allowlists: old.ip_allowlists.clone(),
    }
}

/// Generate a deterministic FilterId from a name string.
/// Used for legacy name-based swap methods and custom per-profile filters.
fn name_to_filter_id(name: &str) -> FilterId {
    FilterId::from_uuid(uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        name.as_bytes(),
    ))
}

fn decompose_domain<'a>(
    domain: &'a str,
    max_depth: usize,
    suffix_set: Option<&SuffixSet>,
) -> Vec<&'a str> {
    let mut parts = Vec::with_capacity(max_depth);
    let mut remaining = domain;
    for _ in 0..max_depth {
        if remaining.is_empty() || remaining == "." {
            break;
        }
        // If we have a suffix set, stop before pushing public suffixes.
        if let Some(ss) = suffix_set
            && ss.is_public_suffix(remaining)
        {
            break;
        }
        parts.push(remaining);
        match remaining.find('.') {
            Some(dot) => remaining = &remaining[dot + 1..],
            None => break,
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompose_domain_fqdn() {
        let parts = decompose_domain("a.b.c.d.com.", 4, None);
        assert_eq!(
            parts,
            vec!["a.b.c.d.com.", "b.c.d.com.", "c.d.com.", "d.com."]
        );
    }

    #[test]
    fn test_decompose_domain_short_fqdn() {
        let parts = decompose_domain("example.com.", 4, None);
        assert_eq!(parts, vec!["example.com.", "com."]);
    }

    #[test]
    fn test_filter_holder_empty_no_match() {
        let holder = FilterHolder::new();
        let refs: Vec<DnBlocklistRef> = vec![];
        assert!(
            holder
                .check_dn_blocklists(&refs, "example.com.", 4, None)
                .is_none()
        );
    }

    #[test]
    fn test_allowlist_exact_match() {
        let holder = FilterHolder::new();
        let id = FilterId::new();
        let set = Set::from_iter(vec!["example.com.", "google.com."]).unwrap();
        holder
            .swap_dn_allowlist(id, "default", set.into_fst().into_inner())
            .unwrap();

        let refs = vec![DnAllowlistRef::new(id)];
        assert!(
            holder
                .check_dn_allowlists(&refs, "example.com.", 4, None)
                .is_some()
        );
        assert!(
            holder
                .check_dn_allowlists(&refs, "evil.com.", 4, None)
                .is_none()
        );
    }

    fn build_blocklist_with(domains: &[&str]) -> Vec<u8> {
        let mut keys: Vec<u64> = domains.iter().map(|d| domain_to_u64(d)).collect();
        for i in 0..200u64 {
            keys.push(i.wrapping_mul(0x517cc1b727220a95));
        }
        keys.sort();
        keys.dedup();
        let filter = BinaryFuse16::try_from(&keys[..]).unwrap();
        rmp_serde::to_vec(&filter).unwrap()
    }

    #[test]
    fn test_blocklist_match() {
        let holder = FilterHolder::new();
        let id = FilterId::new();
        let data = build_blocklist_with(&["evil.com."]);
        holder.swap_dn_blocklist(id, "default", &data).unwrap();

        let refs = vec![DnBlocklistRef::new(id)];
        assert!(
            holder
                .check_dn_blocklists(&refs, "evil.com.", 4, None)
                .is_some()
        );
        assert!(
            holder
                .check_dn_blocklists(&refs, "google.com.", 4, None)
                .is_none()
        );
    }

    #[test]
    fn test_ip_blocklist() {
        let holder = FilterHolder::new();
        let id = FilterId::new();
        let filter = IpFilter::build(&["10.0.0.0/8", "192.168.1.1"]);
        let bytes = filter.to_bytes();
        holder.swap_ip_blocklist(id, "feodo-ips", &bytes).unwrap();

        let refs = vec![IpBlocklistRef::new(id)];
        assert!(
            holder
                .check_ip_blocklists(&refs, &["10.1.2.3".parse().unwrap()])
                .is_some()
        );
        assert!(
            holder
                .check_ip_blocklists(&refs, &["11.0.0.1".parse().unwrap()])
                .is_none()
        );
    }

    #[test]
    fn test_remove_filter() {
        let holder = FilterHolder::new();
        let id = FilterId::new();
        let set = Set::from_iter(vec!["example.com."]).unwrap();
        holder
            .swap_dn_allowlist(id, "test", set.into_fst().into_inner())
            .unwrap();
        assert!(holder.remove_by_id(&id));
        let refs = vec![DnAllowlistRef::new(id)];
        assert!(
            holder
                .check_dn_allowlists(&refs, "example.com.", 4, None)
                .is_none()
        );
    }

    #[test]
    fn test_allowlist_priority_over_blocklist() {
        let holder = FilterHolder::new();
        let al_id = FilterId::new();
        let bl_id = FilterId::new();
        let set = Set::from_iter(vec!["example.com."]).unwrap();
        holder
            .swap_dn_allowlist(al_id, "default", set.into_fst().into_inner())
            .unwrap();
        let data = build_blocklist_with(&["example.com."]);
        holder.swap_dn_blocklist(bl_id, "default", &data).unwrap();

        // Allowlist checked first (per pipeline order).
        let al_refs = vec![DnAllowlistRef::new(al_id)];
        assert!(
            holder
                .check_dn_allowlists(&al_refs, "example.com.", 4, None)
                .is_some()
        );
    }

    #[test]
    fn test_subset_check_only_specified() {
        let holder = FilterHolder::new();

        // Add two blocklists with different FilterIds.
        let id1 = FilterId::new();
        let id2 = FilterId::new();
        let data1 = build_blocklist_with(&["evil.com."]);
        let data2 = build_blocklist_with(&["bad.org."]);
        holder.swap_dn_blocklist(id1, "list-a", &data1).unwrap();
        holder.swap_dn_blocklist(id2, "list-b", &data2).unwrap();

        // Profile subscribed to list-a only.
        let refs = vec![DnBlocklistRef::new(id1)];

        // evil.com should be caught (in list-a).
        assert!(
            holder
                .check_dn_blocklists(&refs, "evil.com.", 4, None)
                .is_some()
        );
        // bad.org should NOT be caught (in list-b, not subscribed).
        assert!(
            holder
                .check_dn_blocklists(&refs, "bad.org.", 4, None)
                .is_none()
        );

        // Subscribing to both catches both.
        let both = vec![DnBlocklistRef::new(id1), DnBlocklistRef::new(id2)];
        assert!(
            holder
                .check_dn_blocklists(&both, "bad.org.", 4, None)
                .is_some()
        );
    }

    #[test]
    fn test_uuid_swap_and_check() {
        let holder = FilterHolder::new();
        let id = FilterId::new();
        let data = build_blocklist_with(&["test.example.com."]);
        holder.swap_dn_blocklist(id, "test-filter", &data).unwrap();

        let refs = vec![DnBlocklistRef::new(id)];
        let hit = holder
            .check_dn_blocklists(&refs, "test.example.com.", 4, None)
            .unwrap();
        assert_eq!(hit.filter_id, id);
        assert_eq!(hit.matched, "test.example.com.");
    }

    #[test]
    fn test_remove_by_id() {
        let holder = FilterHolder::new();
        let id = FilterId::new();
        let data = build_blocklist_with(&["evil.com."]);
        holder.swap_dn_blocklist(id, "test", &data).unwrap();

        assert!(holder.remove_by_id(&id));
        assert!(!holder.remove_by_id(&id)); // already removed

        let refs = vec![DnBlocklistRef::new(id)];
        assert!(
            holder
                .check_dn_blocklists(&refs, "evil.com.", 4, None)
                .is_none()
        );
    }
}
