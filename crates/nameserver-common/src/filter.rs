/// Normalize a domain to FQDN format: IDN → Punycode, lowercase, trailing dot.
///
/// Examples:
/// - `"Example.COM"` → `"example.com."`
/// - `"example.com."` → `"example.com."`
/// - `"EXAMPLE.COM."` → `"example.com."`
/// - `"한국.kr"` → `"xn--3e0b707e.kr."`
/// - `"피싱.example.kr"` → `"xn--oi2bq65a.example.kr."`
pub fn normalize_domain(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('.');

    // Convert IDN (Unicode) labels to Punycode (ASCII).
    // If conversion fails (invalid domain), fall back to ASCII lowercase.
    let ascii = idna::domain_to_ascii(d).unwrap_or_else(|_| d.to_ascii_lowercase());

    format!("{ascii}.")
}

/// Hash a domain string to u64 for BinaryFuse filter lookup.
///
/// Uses FNV-1a hash for deterministic, cross-platform, cross-version consistency.
/// MUST be used by both data plane (lookup) and control plane (build).
pub fn domain_to_u64(domain: &str) -> u64 {
    fnv1a_64(domain.as_bytes())
}

/// FNV-1a 64-bit hash — simple, fast, deterministic.
fn fnv1a_64(data: &[u8]) -> u64 {
    const BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// Filter identity types
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Universally unique filter identity. UUIDv7 assigned at filter creation.
/// Copy-able, 16 bytes, globally unique, sortable by creation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FilterId(Uuid);

impl FilterId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(u: Uuid) -> Self {
        Self(u)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for FilterId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for FilterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for FilterId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

/// Classifies a filter by what it matches and what it does.
/// Determines the Object Store file extension and the check method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    /// Domain blocklist — XOR Binary Fuse filter (.xor)
    DnBlocklist,
    /// Domain allowlist — FST Finite State Transducer (.fst)
    DnAllowlist,
    /// IP blocklist — LC-Trie prefix filter (.ipf)
    IpBlocklist,
    /// IP allowlist — LC-Trie prefix filter (.ipf)
    IpAllowlist,
    /// Unknown kind — forward compatibility catch-all.
    #[serde(other)]
    Unknown,
}

impl FilterKind {
    /// Object Store file extension for this filter kind.
    pub fn ext(&self) -> &'static str {
        match self {
            Self::DnBlocklist => "xor",
            Self::DnAllowlist => "fst",
            Self::IpBlocklist | Self::IpAllowlist => "ipf",
            Self::Unknown => "unknown",
        }
    }
}

/// Full filter descriptor with publish metadata.
/// Stored in the filter manifest (NATS KV) for diff/reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilterDescriptor {
    pub id: FilterId,
    pub kind: FilterKind,
    /// Human-readable filter name (e.g., "hagezi-pro").
    #[serde(default)]
    pub name: String,
    /// SHA-256 of source data at publish time (from last pull, deterministic).
    #[serde(default)]
    pub source_checksum: String,
    /// SHA-256 of the compiled binary that was published.
    #[serde(default)]
    pub compiled_checksum: String,
    /// Number of entries (domains/IPs) at publish time.
    #[serde(default)]
    pub entry_count: usize,
}

// ---------------------------------------------------------------------------
// Typed filter references — compile-time safety for allow/block × dn/ip
// ---------------------------------------------------------------------------

/// Reference to a domain blocklist filter in the global FilterHolder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DnBlocklistRef(FilterId);

impl DnBlocklistRef {
    pub fn new(id: FilterId) -> Self {
        Self(id)
    }
    pub fn id(self) -> FilterId {
        self.0
    }
}

/// Reference to a domain allowlist filter in the global FilterHolder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DnAllowlistRef(FilterId);

impl DnAllowlistRef {
    pub fn new(id: FilterId) -> Self {
        Self(id)
    }
    pub fn id(self) -> FilterId {
        self.0
    }
}

/// Reference to an IP blocklist filter in the global FilterHolder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IpBlocklistRef(FilterId);

impl IpBlocklistRef {
    pub fn new(id: FilterId) -> Self {
        Self(id)
    }
    pub fn id(self) -> FilterId {
        self.0
    }
}

/// Reference to an IP allowlist filter in the global FilterHolder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IpAllowlistRef(FilterId);

impl IpAllowlistRef {
    pub fn new(id: FilterId) -> Self {
        Self(id)
    }
    pub fn id(self) -> FilterId {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(domain_to_u64("example.com"), domain_to_u64("example.com"));
    }

    #[test]
    fn fnv1a_different_inputs() {
        assert_ne!(domain_to_u64("a.com"), domain_to_u64("b.com"));
    }

    #[test]
    fn fnv1a_known_value() {
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn filter_id_display_parse_roundtrip() {
        let id = FilterId::new();
        let s = id.to_string();
        let parsed: FilterId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn filter_id_copy() {
        let id = FilterId::new();
        let id2 = id; // Copy
        assert_eq!(id, id2);
    }

    #[test]
    fn filter_id_msgpack_roundtrip() {
        let id = FilterId::new();
        let bytes = rmp_serde::to_vec_named(&id).unwrap();
        let decoded: FilterId = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn filter_kind_ext() {
        assert_eq!(FilterKind::DnBlocklist.ext(), "xor");
        assert_eq!(FilterKind::DnAllowlist.ext(), "fst");
        assert_eq!(FilterKind::IpBlocklist.ext(), "ipf");
        assert_eq!(FilterKind::IpAllowlist.ext(), "ipf");
    }

    #[test]
    fn filter_descriptor_msgpack_roundtrip() {
        let desc = FilterDescriptor {
            id: FilterId::new(),
            kind: FilterKind::DnBlocklist,
            name: "test".to_string(),
            source_checksum: "abc123".to_string(),
            compiled_checksum: "def456".to_string(),
            entry_count: 42,
        };
        let bytes = rmp_serde::to_vec_named(&desc).unwrap();
        let decoded: FilterDescriptor = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(desc, decoded);
    }

    #[test]
    fn typed_refs_not_interchangeable() {
        let id = FilterId::new();
        let dn_bl = DnBlocklistRef::new(id);
        let dn_al = DnAllowlistRef::new(id);
        // Same FilterId, but different types — can't accidentally swap them.
        assert_eq!(dn_bl.id(), dn_al.id()); // same underlying id
        // But dn_bl and dn_al are different types — won't compile if mixed.
    }

    #[test]
    fn normalize_domain_basic() {
        assert_eq!(normalize_domain("example.com"), "example.com.");
        assert_eq!(normalize_domain("example.com."), "example.com.");
        assert_eq!(normalize_domain("EXAMPLE.COM"), "example.com.");
        assert_eq!(normalize_domain("  example.com  "), "example.com.");
    }

    #[test]
    fn normalize_domain_idn_korean() {
        // 한국.kr → xn--3e0b707e.kr
        assert_eq!(normalize_domain("한국.kr"), "xn--3e0b707e.kr.");
    }

    #[test]
    fn normalize_domain_idn_mixed() {
        // Unicode label + ASCII label: 피싱 → xn--hw4bn84a
        assert_eq!(
            normalize_domain("피싱.example.kr"),
            "xn--hw4bn84a.example.kr."
        );
    }

    #[test]
    fn normalize_domain_already_punycode() {
        // Already Punycode — should pass through unchanged
        assert_eq!(normalize_domain("xn--3e0b707e.kr"), "xn--3e0b707e.kr.");
    }

    #[test]
    fn typed_ref_msgpack_roundtrip() {
        let id = FilterId::new();
        let r = DnBlocklistRef::new(id);
        let bytes = rmp_serde::to_vec_named(&r).unwrap();
        let decoded: DnBlocklistRef = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(r, decoded);
    }
}
