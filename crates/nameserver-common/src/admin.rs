use serde::{Deserialize, Serialize};

use crate::filter::{
    DnAllowlistRef, DnBlocklistRef, FilterDescriptor, FilterId, FilterKind, IpAllowlistRef,
    IpBlocklistRef,
};

/// Per-filter detail in list status.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FilterInfo {
    pub name: String,
    pub kind: String,
    pub entries: Option<usize>,
    pub checksum: Option<String>,
}

/// Response for list status request/reply.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListStatus {
    pub allowlist_loaded: bool,
    pub allowlist_entries: usize,
    pub allowlist_checksum: Option<String>,
    pub blocklist_loaded: bool,
    pub blocklist_checksum: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<FilterInfo>,
}

/// Response for health check request/reply.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthStatus {
    pub uptime_secs: u64,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub nats_connected: bool,
}

/// Reload signal sent from control plane to DNS server via NATS.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReloadSignal {
    /// Reload a specific shared filter from Object Store.
    Filter {
        id: FilterId,
        filter_kind: FilterKind,
        #[serde(default)]
        action: ReloadAction,
    },
    /// Evict a profile from the DNS server's cache.
    Profile { id: String },
    /// Reload the GeoIP table from Object Store.
    Geoip,
    /// Reload the public suffix set from Object Store.
    SuffixSet,
    /// Unknown signal — forward compatibility catch-all.
    #[serde(other)]
    Unknown,
}

/// Action for a reload signal.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReloadAction {
    /// Load or replace the item from Object Store (default).
    #[default]
    Update,
    /// Remove the item from the DNS server.
    Remove,
    /// Unknown action — forward compatibility, treated as Update.
    #[serde(other)]
    Unknown,
}

// ---------------------------------------------------------------------------
// Per-profile KV config
// ---------------------------------------------------------------------------

fn default_block_mode() -> String {
    "nxdomain".to_string()
}

/// Per-profile configuration stored in NATS KV.
/// Key: `profiles.{id}`, Value: MessagePack-encoded.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileKvConfig {
    #[serde(default)]
    pub dn_blocklists: Vec<DnBlocklistRef>,
    #[serde(default)]
    pub dn_allowlists: Vec<DnAllowlistRef>,
    #[serde(default)]
    pub ip_blocklists: Vec<IpBlocklistRef>,
    #[serde(default)]
    pub ip_allowlists: Vec<IpAllowlistRef>,
    #[serde(default)]
    pub has_custom_blocklist: bool,
    #[serde(default)]
    pub has_custom_allowlist: bool,
    /// SHA-256 of the sorted custom entry domains (allows diff to detect content changes).
    #[serde(default)]
    pub custom_entries_hash: Option<String>,
    #[serde(default = "default_block_mode")]
    pub block_mode: String,
    #[serde(default)]
    pub redirect_ip: Option<String>,
}

/// Manifest of all shared filters available in Object Store.
/// Stored in KV key `filters.manifest`, MessagePack-encoded.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FilterManifest {
    pub filters: Vec<FilterDescriptor>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::FilterId;

    #[test]
    fn profile_kv_config_msgpack_roundtrip() {
        let id1 = FilterId::new();
        let id2 = FilterId::new();
        let config = ProfileKvConfig {
            dn_blocklists: vec![DnBlocklistRef::new(id1)],
            dn_allowlists: vec![],
            ip_blocklists: vec![IpBlocklistRef::new(id2)],
            ip_allowlists: vec![],
            has_custom_blocklist: true,
            has_custom_allowlist: false,
            custom_entries_hash: None,
            block_mode: "nxdomain".to_string(),
            redirect_ip: None,
        };
        let bytes = rmp_serde::to_vec_named(&config).unwrap();
        let decoded: ProfileKvConfig = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.dn_blocklists.len(), 1);
        assert_eq!(decoded.dn_blocklists[0].id(), id1);
        assert_eq!(decoded.ip_blocklists.len(), 1);
        assert!(decoded.has_custom_blocklist);
    }

    #[test]
    fn filter_manifest_msgpack_roundtrip() {
        let manifest = FilterManifest {
            filters: vec![
                FilterDescriptor {
                    id: FilterId::new(),
                    kind: FilterKind::DnBlocklist,
                    name: "test-bl".to_string(),
                    source_checksum: String::new(),
                    compiled_checksum: String::new(),
                    entry_count: 0,
                },
                FilterDescriptor {
                    id: FilterId::new(),
                    kind: FilterKind::DnAllowlist,
                    name: "test-al".to_string(),
                    source_checksum: String::new(),
                    compiled_checksum: String::new(),
                    entry_count: 0,
                },
            ],
        };
        let bytes = rmp_serde::to_vec_named(&manifest).unwrap();
        let decoded: FilterManifest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.filters.len(), 2);
        assert_eq!(decoded.filters[0].kind, FilterKind::DnBlocklist);
    }

    #[test]
    fn reload_signal_filter_roundtrip() {
        let signal = ReloadSignal::Filter {
            id: FilterId::new(),
            filter_kind: FilterKind::DnBlocklist,
            action: ReloadAction::Update,
        };
        let bytes = rmp_serde::to_vec_named(&signal).unwrap();
        let decoded: ReloadSignal = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            ReloadSignal::Filter { filter_kind, .. } => {
                assert_eq!(filter_kind, FilterKind::DnBlocklist);
            }
            _ => panic!("expected Filter variant"),
        }
    }

    #[test]
    fn reload_signal_profile_roundtrip() {
        let signal = ReloadSignal::Profile {
            id: "z02o120w".to_string(),
        };
        let bytes = rmp_serde::to_vec_named(&signal).unwrap();
        let decoded: ReloadSignal = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            ReloadSignal::Profile { id } => assert_eq!(id, "z02o120w"),
            _ => panic!("expected Profile variant"),
        }
    }

    #[test]
    fn reload_signal_unknown_fallback() {
        let fake = serde_json::json!({"kind": "future_feature"});
        let decoded: ReloadSignal = serde_json::from_value(fake).unwrap();
        assert!(matches!(decoded, ReloadSignal::Unknown));
    }
}
