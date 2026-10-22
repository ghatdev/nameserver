//! NS-hostname → provider identity mapping.
//!
//! Used by both:
//! - Stability change-detection (set intersection at provider level)
//! - Similarity impersonation check (pairwise same-provider test)
//!
//! Patterns are chosen as the shortest unique substring covering all of a
//! provider's NS hostnames across registrables. E.g. AWS Route 53 uses
//! `awsdns-XX.{com,net,org,co.uk}` — without coalescing, the same operator
//! looks like four different providers.

use crate::suffix::{SuffixSet, extract_registrable};

pub const NS_PROVIDER_PATTERNS: &[&str] = &[
    "cloudflare",
    "awsdns",
    "google",
    "azure-dns",
    "msft.net",
    "akam",
    "akadns",
    "ultradns",
    "nsone.net",
    "dynect",
    "vercel-dns",
    "dnsimple",
    "digitalocean",
    "linode",
    "vultr",
    "name-services",
    "domaincontrol",
    "registrar-servers",
    "hetzner",
    "ovh.net",
    "oracle.com",
    "fastly",
];

/// Project an NS hostname to a canonical provider key for set-based grouping.
///
/// Resolution order:
/// 1. Known provider pattern → pattern string
/// 2. Registrable domain (e.g. `proton.me`)
/// 3. Raw lowercased hostname (no registrable extractable)
pub fn provider_key(ns_hostname: &str, suffix_set: &SuffixSet) -> String {
    let lower = ns_hostname.trim_end_matches('.').to_lowercase();
    for &pattern in NS_PROVIDER_PATTERNS {
        if lower.contains(pattern) {
            return pattern.to_string();
        }
    }
    let reg = extract_registrable(&lower, suffix_set);
    if !reg.is_empty() {
        reg.to_string()
    } else {
        lower
    }
}

/// Pairwise same-provider check. Matches similarity.rs historical behavior:
/// `provider_key` equality plus a 2nd-level label fallback for same-operator
/// cross-TLD cases (e.g. `ns1.naver.com` vs `ns1.naver.jp`).
pub fn same_provider(a: &str, b: &str, suffix_set: &SuffixSet) -> bool {
    let a_lower = a.trim_end_matches('.').to_lowercase();
    let b_lower = b.trim_end_matches('.').to_lowercase();
    if provider_key(&a_lower, suffix_set) == provider_key(&b_lower, suffix_set) {
        return true;
    }
    let a_parts: Vec<&str> = a_lower.split('.').collect();
    let b_parts: Vec<&str> = b_lower.split('.').collect();
    if a_parts.len() >= 2 && b_parts.len() >= 2 {
        let a_label = a_parts[a_parts.len() - 2];
        let b_label = b_parts[b_parts.len() - 2];
        if a_label.len() >= 3 && a_label == b_label {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suffix::SuffixSet;

    fn set() -> SuffixSet {
        SuffixSet::from_lines(["com", "net", "org", "jp", "me", "co.uk"].into_iter())
    }

    #[test]
    fn awsdns_coalesces_across_tlds() {
        let s = set();
        assert_eq!(provider_key("ns-1234.awsdns-56.com", &s), "awsdns");
        assert_eq!(provider_key("ns-9876.awsdns-21.net", &s), "awsdns");
        assert_eq!(provider_key("ns-555.awsdns-10.co.uk", &s), "awsdns");
        assert!(same_provider(
            "ns-1234.awsdns-56.com",
            "ns-9876.awsdns-21.net",
            &s
        ));
    }

    #[test]
    fn cloudflare_coalesces() {
        let s = set();
        assert_eq!(provider_key("adam.ns.cloudflare.com", &s), "cloudflare");
        assert_eq!(provider_key("eve.ns.cloudflare.com", &s), "cloudflare");
    }

    #[test]
    fn unknown_provider_uses_registrable() {
        let s = set();
        assert_eq!(provider_key("ns1.proton.me", &s), "proton.me");
        assert_eq!(provider_key("ns3.proton.me", &s), "proton.me");
        assert!(same_provider("ns1.proton.me", "ns3.proton.me", &s));
    }

    #[test]
    fn different_operators_differ() {
        let s = set();
        assert_ne!(
            provider_key("ns1.proton.me", &s),
            provider_key("ns1.attacker.com", &s)
        );
        assert!(!same_provider("ns1.proton.me", "ns1.attacker.com", &s));
    }

    #[test]
    fn cross_tld_label_match_pairwise_only() {
        let s = set();
        // Keys differ (naver.com vs naver.jp)
        assert_ne!(
            provider_key("ns1.naver.com", &s),
            provider_key("ns1.naver.jp", &s)
        );
        // But pairwise coalesces via label fallback
        assert!(same_provider("ns1.naver.com", "ns1.naver.jp", &s));
    }
}
