//! IP Filter: compiled IP/CIDR blocklist using prefix tries.
//!
//! Uses [`crate::prefix_trie`] as the underlying data structure.
//! Handles IPv4 + IPv6, CIDR ranges, and `.ipf` binary serialization.

use std::net::IpAddr;

use crate::{lc_trie, prefix_trie};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct IpFilterError(pub String);

impl std::fmt::Display for IpFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IpFilterError {}

// ---------------------------------------------------------------------------
// .ipf binary format
// ---------------------------------------------------------------------------

const MAGIC: u32 = 0x49504601; // "IPF\x01"
const VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// IpFilter
// ---------------------------------------------------------------------------

/// Compiled IP filter with IPv4 and IPv6 LC-Tries.
///
/// Build from IP/CIDR strings, serialize to `.ipf` for distribution,
/// deserialize on data plane for fast lookup.
///
/// Uses [`lc_trie`] for path-compressed lookups (fewer memory accesses
/// than a plain binary trie).
pub struct IpFilter {
    v4_nodes: Vec<lc_trie::LCNode>,
    v6_nodes: Vec<lc_trie::LCNode>,
}

impl IpFilter {
    /// Build from a list of IP addresses and/or CIDR prefixes.
    ///
    /// Accepts: `"1.2.3.4"`, `"10.0.0.0/8"`, `"2001:db8::/32"`, etc.
    /// Invalid entries are silently skipped.
    pub fn build(entries: &[&str]) -> Self {
        let mut v4 = prefix_trie::TrieBuilder::new();
        let mut v6 = prefix_trie::TrieBuilder::new();

        for entry in entries {
            if let Some((addr, prefix_len)) = parse_cidr(entry) {
                match addr {
                    IpAddr::V4(ip) => v4.insert(u32::from(ip) as u128, prefix_len, 32),
                    IpAddr::V6(ip) => v6.insert(u128::from(ip), prefix_len, 128),
                }
            }
        }

        // Build binary trie → compress to LC-Trie
        Self {
            v4_nodes: lc_trie::compress(&v4.finalize()),
            v6_nodes: lc_trie::compress(&v6.finalize()),
        }
    }

    /// Check if an IP address matches any prefix in the filter.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => lc_trie::lookup(&self.v4_nodes, u32::from(v4) as u128, 32),
            IpAddr::V6(v6) => lc_trie::lookup(&self.v6_nodes, u128::from(v6), 128),
        }
    }

    /// Number of trie nodes (IPv4 + IPv6).
    pub fn node_count(&self) -> usize {
        self.v4_nodes.len() + self.v6_nodes.len()
    }

    /// Is the filter empty (no prefixes)?
    pub fn is_empty(&self) -> bool {
        self.v4_nodes.is_empty() && self.v6_nodes.is_empty()
    }

    /// Serialize to `.ipf` binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let v4_bytes = lc_trie::nodes_as_bytes(&self.v4_nodes);
        let v6_bytes = lc_trie::nodes_as_bytes(&self.v6_nodes);

        let mut out = Vec::with_capacity(16 + v4_bytes.len() + v6_bytes.len());
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(self.v4_nodes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.v6_nodes.len() as u32).to_le_bytes());
        out.extend_from_slice(v4_bytes);
        out.extend_from_slice(v6_bytes);
        out
    }

    /// Deserialize from `.ipf` binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, IpFilterError> {
        if data.len() < 16 {
            return Err(IpFilterError("ipf too short".into()));
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let v4_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let v6_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

        if magic != MAGIC {
            return Err(IpFilterError(format!("invalid ipf magic: {magic:#x}")));
        }
        if version != VERSION {
            return Err(IpFilterError(format!("unsupported ipf version: {version}")));
        }

        let node_size = std::mem::size_of::<lc_trie::LCNode>();
        let v4_end = 16 + v4_count * node_size;
        let v6_end = v4_end + v6_count * node_size;

        if data.len() < v6_end {
            return Err(IpFilterError(format!(
                "ipf truncated: need {v6_end} bytes, got {}",
                data.len()
            )));
        }

        Ok(Self {
            v4_nodes: lc_trie::nodes_from_bytes(&data[16..v4_end]),
            v6_nodes: lc_trie::nodes_from_bytes(&data[v4_end..v6_end]),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    if let Some((addr_str, len_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().ok()?;
        let len: u8 = len_str.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if len > max {
            return None;
        }
        Some((addr, len))
    } else {
        let addr: IpAddr = s.parse().ok()?;
        let len = if addr.is_ipv4() { 32 } else { 128 };
        Some((addr, len))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter() {
        let f = IpFilter::build(&[]);
        assert_eq!(f.node_count(), 2); // 1 root per address family (v4 + v6)
        assert!(!f.contains("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn single_ipv4() {
        let f = IpFilter::build(&["192.168.1.1"]);
        assert!(f.contains("192.168.1.1".parse().unwrap()));
        assert!(!f.contains("192.168.1.2".parse().unwrap()));
        assert!(!f.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_cidr_8() {
        let f = IpFilter::build(&["10.0.0.0/8"]);
        assert!(f.contains("10.0.0.1".parse().unwrap()));
        assert!(f.contains("10.255.255.255".parse().unwrap()));
        assert!(!f.contains("11.0.0.1".parse().unwrap()));
        assert!(!f.contains("9.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ipv4_cidr_24() {
        let f = IpFilter::build(&["192.168.1.0/24"]);
        assert!(f.contains("192.168.1.0".parse().unwrap()));
        assert!(f.contains("192.168.1.255".parse().unwrap()));
        assert!(!f.contains("192.168.2.0".parse().unwrap()));
        assert!(!f.contains("192.168.0.255".parse().unwrap()));
    }

    #[test]
    fn multiple_prefixes() {
        let f = IpFilter::build(&["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "8.8.8.8"]);
        assert!(f.contains("10.1.2.3".parse().unwrap()));
        assert!(f.contains("192.168.1.1".parse().unwrap()));
        assert!(f.contains("172.20.0.1".parse().unwrap()));
        assert!(f.contains("8.8.8.8".parse().unwrap()));
        assert!(!f.contains("8.8.8.9".parse().unwrap()));
        assert!(!f.contains("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr() {
        let f = IpFilter::build(&["2001:db8::/32"]);
        assert!(f.contains("2001:db8::1".parse().unwrap()));
        assert!(f.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!f.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_host() {
        let f = IpFilter::build(&["::1"]);
        assert!(f.contains("::1".parse().unwrap()));
        assert!(!f.contains("::2".parse().unwrap()));
    }

    #[test]
    fn mixed_v4_v6() {
        let f = IpFilter::build(&["10.0.0.0/8", "2001:db8::/32"]);
        assert!(f.contains("10.1.1.1".parse().unwrap()));
        assert!(f.contains("2001:db8::1".parse().unwrap()));
        assert!(!f.contains("11.0.0.1".parse().unwrap()));
        assert!(!f.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn serialize_roundtrip() {
        let f = IpFilter::build(&["10.0.0.0/8", "192.168.1.0/24", "8.8.8.8", "2001:db8::/32"]);
        let bytes = f.to_bytes();
        let f2 = IpFilter::from_bytes(&bytes).unwrap();

        assert!(f2.contains("10.1.1.1".parse().unwrap()));
        assert!(f2.contains("192.168.1.100".parse().unwrap()));
        assert!(f2.contains("8.8.8.8".parse().unwrap()));
        assert!(f2.contains("2001:db8::1".parse().unwrap()));
        assert!(!f2.contains("1.1.1.1".parse().unwrap()));
        assert!(!f2.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn real_threat_ips() {
        let f = IpFilter::build(&["50.16.16.211", "5.188.86.0/24"]);
        assert!(f.contains("50.16.16.211".parse().unwrap()));
        assert!(f.contains("5.188.86.1".parse().unwrap()));
        assert!(f.contains("5.188.86.255".parse().unwrap()));
        assert!(!f.contains("50.16.16.212".parse().unwrap()));
        assert!(!f.contains("5.188.87.0".parse().unwrap()));
    }

    #[test]
    fn nested_prefixes() {
        let f = IpFilter::build(&["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"]);
        assert!(f.contains("10.0.0.1".parse().unwrap()));
        assert!(f.contains("10.1.0.1".parse().unwrap()));
        assert!(f.contains("10.1.1.1".parse().unwrap()));
        assert!(!f.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn invalid_ipf() {
        assert!(IpFilter::from_bytes(&[0u8; 16]).is_err());
        assert!(IpFilter::from_bytes(&[]).is_err());
    }

    // --- Edge cases ---

    #[test]
    fn cidr_0_matches_everything() {
        let f = IpFilter::build(&["0.0.0.0/0"]);
        assert!(f.contains("0.0.0.0".parse().unwrap()));
        assert!(f.contains("1.2.3.4".parse().unwrap()));
        assert!(f.contains("255.255.255.255".parse().unwrap()));
        // v6 should NOT match (separate trie)
        assert!(!f.contains("::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_0_matches_everything() {
        let f = IpFilter::build(&["::/0"]);
        assert!(f.contains("::1".parse().unwrap()));
        assert!(f.contains("2001:db8::1".parse().unwrap()));
        assert!(f.contains("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        // v4 should NOT match
        assert!(!f.contains("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn cidr_1_half_address_space() {
        let f = IpFilter::build(&["0.0.0.0/1"]); // 0.x.x.x - 127.x.x.x
        assert!(f.contains("0.0.0.1".parse().unwrap()));
        assert!(f.contains("127.255.255.255".parse().unwrap()));
        assert!(!f.contains("128.0.0.0".parse().unwrap()));
        assert!(!f.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn cidr_31_two_hosts() {
        let f = IpFilter::build(&["10.0.0.0/31"]);
        assert!(f.contains("10.0.0.0".parse().unwrap()));
        assert!(f.contains("10.0.0.1".parse().unwrap()));
        assert!(!f.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn adjacent_non_overlapping() {
        let f = IpFilter::build(&["10.0.0.0/24", "10.0.1.0/24"]);
        assert!(f.contains("10.0.0.1".parse().unwrap()));
        assert!(f.contains("10.0.0.255".parse().unwrap()));
        assert!(f.contains("10.0.1.0".parse().unwrap()));
        assert!(f.contains("10.0.1.255".parse().unwrap()));
        assert!(!f.contains("10.0.2.0".parse().unwrap()));
        assert!(!f.contains("9.255.255.255".parse().unwrap()));
    }

    #[test]
    fn duplicate_prefix() {
        // Same prefix inserted twice — should not cause issues
        let f = IpFilter::build(&["10.0.0.0/8", "10.0.0.0/8"]);
        assert!(f.contains("10.1.1.1".parse().unwrap()));
        assert!(!f.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_common_prefixes() {
        let f = IpFilter::build(&[
            "2001:db8::/32", // documentation
            "fc00::/7",      // unique local
            "fe80::/10",     // link-local
        ]);
        // /32
        assert!(f.contains("2001:db8::1".parse().unwrap()));
        assert!(!f.contains("2001:db9::1".parse().unwrap()));
        // /7 — fc00::/7 covers fc00:: to fdff::
        assert!(f.contains("fc00::1".parse().unwrap()));
        assert!(f.contains("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!f.contains("fe00::1".parse().unwrap())); // fe00 is NOT in fc00::/7
        // /10 — fe80::/10 covers fe80:: to febf::
        assert!(f.contains("fe80::1".parse().unwrap()));
        assert!(f.contains("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!f.contains("fec0::1".parse().unwrap())); // fec0 is NOT in fe80::/10
    }

    #[test]
    fn ipv6_48_and_64() {
        let f = IpFilter::build(&["2001:db8:abcd::/48", "2001:db8:1234:5678::/64"]);
        // /48
        assert!(f.contains("2001:db8:abcd::1".parse().unwrap()));
        assert!(f.contains("2001:db8:abcd:ffff::1".parse().unwrap()));
        assert!(!f.contains("2001:db8:abce::1".parse().unwrap()));
        // /64
        assert!(f.contains("2001:db8:1234:5678::1".parse().unwrap()));
        assert!(!f.contains("2001:db8:1234:5679::1".parse().unwrap()));
    }

    #[test]
    fn boundary_ips() {
        let f = IpFilter::build(&["0.0.0.0", "255.255.255.255"]);
        assert!(f.contains("0.0.0.0".parse().unwrap()));
        assert!(f.contains("255.255.255.255".parse().unwrap()));
        assert!(!f.contains("0.0.0.1".parse().unwrap()));
        assert!(!f.contains("255.255.255.254".parse().unwrap()));
    }

    #[test]
    fn invalid_cidr_input() {
        // Bad inputs should be silently skipped
        let f = IpFilter::build(&["not-an-ip", "10.0.0.0/33", "10.0.0.0/8"]);
        assert!(f.contains("10.1.1.1".parse().unwrap())); // valid entry works
        assert!(!f.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn many_entries() {
        // 1000 individual IPs
        let entries: Vec<String> = (0..1000)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect();
        let refs: Vec<&str> = entries.iter().map(|s| s.as_str()).collect();
        let f = IpFilter::build(&refs);

        assert!(f.contains("10.0.0.0".parse().unwrap()));
        assert!(f.contains("10.0.3.231".parse().unwrap()));
        assert!(!f.contains("10.0.4.0".parse().unwrap())); // 1000 = 3*256+232, so 10.0.4.0 is out
        assert!(!f.contains("11.0.0.0".parse().unwrap()));
    }

    #[test]
    fn v4_does_not_match_v6_and_vice_versa() {
        let f = IpFilter::build(&["10.0.0.0/8"]);
        assert!(f.contains("10.1.1.1".parse().unwrap()));
        // ::ffff:10.1.1.1 is IPv6-mapped IPv4 — should NOT match v4 trie
        assert!(!f.contains("::ffff:10.1.1.1".parse().unwrap()));
    }

    #[test]
    fn serialize_roundtrip_with_edge_cases() {
        let f = IpFilter::build(&[
            "192.168.1.0/31", // 2-host subnet
            "::1",            // single v6
        ]);
        let bytes = f.to_bytes();
        let f2 = IpFilter::from_bytes(&bytes).unwrap();

        assert!(f2.contains("192.168.1.0".parse().unwrap())); // /31 first
        assert!(f2.contains("192.168.1.1".parse().unwrap())); // /31 second
        assert!(!f2.contains("192.168.1.2".parse().unwrap())); // /31 miss
        assert!(f2.contains("::1".parse().unwrap())); // exact v6
        assert!(!f2.contains("::2".parse().unwrap())); // v6 miss
    }
}
