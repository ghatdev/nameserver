use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{
    AllRecords, DnssecStatus, FlowType, ListAction, QueryType, ResponseCode, ServfailReason,
    StepResponseType,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsFlow {
    pub flow_id: Uuid,
    pub r#type: FlowType,
    pub started_at: i64,
    pub completed_at: i64,
    pub total_ms: u32,
    pub query: DnsQuery,
    pub list_action: ListAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_country: Option<String>,
    #[serde(default)]
    pub geo_asn: u32,
    pub resolution_path: Vec<ResolveStep>,
    pub cname_chain: Option<Vec<String>>,
    pub response: DnsResponse,
    pub dnssec: DnssecResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servfail_reason: Option<ServfailReason>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub domain: String,
    pub qtype: QueryType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ResolveStep {
    pub step: u8,
    pub asked: String,
    pub server: String,
    pub server_name: Option<String>,
    pub response_type: StepResponseType,
    pub got: StepData,
    pub ms: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct StepData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaaa: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsResponse {
    pub rcode: ResponseCode,
    pub ips: Vec<String>,
    /// Minimum TTL across answer records (may be cache-decremented on cache hits).
    #[serde(alias = "ttl")]
    pub min_ttl: u32,
    /// Original TTL from the authoritative server (before cache decrement).
    /// For ML: distinguishes fast-flux (low auth_ttl) from cache age.
    #[serde(default)]
    pub auth_ttl: u32,
    pub all_records: AllRecords,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnssecResult {
    pub status: DnssecStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    pub ds_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rrsig_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Authoritative NS extraction
// ---------------------------------------------------------------------------

/// Authoritative NS evidence extracted from a flow's resolution path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthNs {
    /// Complete delegation NS RRset from a Referral step's `got.ns`.
    /// Sorted, lowercase, no trailing dot.
    Full(Vec<String>),
    /// Single server_name from terminal Answer step (cache hit).
    /// NOT the zone's NS RRset — only suitable for trust classification,
    /// not NS change detection.
    Partial(String),
}

impl AuthNs {
    /// Primary NS hostname for trust classification.
    ///
    /// For Full: returns the first entry (lexicographic, after sort).
    /// For Partial: returns the single server.
    pub fn primary(&self) -> &str {
        match self {
            AuthNs::Full(ns) => ns.first().map(|s| s.as_str()).unwrap_or(""),
            AuthNs::Partial(s) => s.as_str(),
        }
    }

    /// Full NS set, if available. Returns None for Partial.
    pub fn as_full(&self) -> Option<&[String]> {
        match self {
            AuthNs::Full(ns) => Some(ns.as_slice()),
            AuthNs::Partial(_) => None,
        }
    }

    /// All NS hostnames as a slice (Full) or single-element view (Partial).
    pub fn all_ns(&self) -> Vec<&str> {
        match self {
            AuthNs::Full(ns) => ns.iter().map(|s| s.as_str()).collect(),
            AuthNs::Partial(s) => vec![s.as_str()],
        }
    }
}

/// Extract authoritative NS set from a resolved flow.
///
/// **Primary:** Find the deepest `Referral` step whose `asked` name is a suffix
/// of (or equal to) the original query domain. The `got.ns` field of that
/// Referral contains the delegation NS RRset for the domain's zone.
///
/// **Fallback:** If no matching Referral exists (cache hit, partial failure),
/// use the terminal non-Error step's `server_name` as partial evidence.
///
/// Returns `None` if NS evidence is incomplete (all Error steps, empty path).
pub fn extract_auth_ns(flow: &DnsFlow) -> Option<AuthNs> {
    let original = flow.query.domain.trim_end_matches('.');

    // Primary: deepest Referral whose `asked` is a suffix of the original query.
    // Walk backwards to get the most specific (deepest) referral first.
    let referral_ns = flow
        .resolution_path
        .iter()
        .rev()
        .filter(|s| s.response_type == StepResponseType::Referral)
        .filter(|s| {
            let asked = s.asked.trim_end_matches('.');
            is_name_or_ancestor(asked, original)
        })
        .find_map(|s| s.got.ns.as_ref())
        .filter(|ns| !ns.is_empty());

    if let Some(ns_list) = referral_ns {
        return Some(AuthNs::Full(normalize_ns_set(ns_list)));
    }

    // Fallback: terminal non-Error step's server_name (cache hit, etc.)
    let terminal = flow.resolution_path.last()?;
    if terminal.response_type == StepResponseType::Error {
        return None;
    }
    terminal
        .server_name
        .as_deref()
        .filter(|n| !n.is_empty())
        .map(|n| AuthNs::Partial(n.trim_end_matches('.').to_lowercase()))
}

/// Canonical form: lowercase, no trailing dot, sorted, deduped.
pub fn normalize_ns_set(ns_list: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = ns_list
        .iter()
        .map(|n| n.trim_end_matches('.').to_lowercase())
        .collect();
    set.into_iter().collect() // BTreeSet iterates in sorted order
}

/// Check if `ancestor` is `name` itself or a parent zone of `name`.
/// e.g., `is_name_or_ancestor("com", "example.com")` → true
///       `is_name_or_ancestor("example.com", "example.com")` → true
///       `is_name_or_ancestor("other.com", "example.com")` → false
fn is_name_or_ancestor(ancestor: &str, name: &str) -> bool {
    let a = ancestor.to_lowercase();
    let n = name.to_lowercase();
    if a == n {
        return true;
    }
    // ancestor must be a proper suffix preceded by a dot
    n.ends_with(&format!(".{a}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn msgpack_roundtrip() {
        let flow = DnsFlow {
            flow_id: Uuid::now_v7(),
            r#type: FlowType::DnsResolution,
            started_at: 1710000000000,
            completed_at: 1710000000100,
            total_ms: 100,
            query: DnsQuery {
                domain: "example.com.".to_string(),
                qtype: QueryType::A,
            },
            list_action: ListAction::Pass,
            list_filter: None,
            profile_id: Some("k7m2x9pa".to_string()),
            geo_country: Some("US".to_string()),
            geo_asn: 13335,
            resolution_path: vec![ResolveStep {
                step: 1,
                asked: "example.com.".to_string(),
                server: "198.41.0.4".to_string(),
                server_name: Some("a.root-servers.net.".to_string()),
                response_type: StepResponseType::Referral,
                got: StepData {
                    ns: Some(vec!["ns1.example.com.".to_string()]),
                    a: Some(vec!["93.184.216.34".to_string()]),
                    aaaa: None,
                    cname: None,
                    ttl: Some(300),
                    error: None,
                },
                ms: 15,
            }],
            cname_chain: None,
            response: DnsResponse {
                rcode: ResponseCode::Noerror,
                ips: vec!["93.184.216.34".to_string()],
                min_ttl: 300,
                auth_ttl: 300,
                all_records: AllRecords::default(),
            },
            dnssec: DnssecResult {
                status: DnssecStatus::Secure,
                algorithm: Some("ECDSAP256SHA256".to_string()),
                ds_present: true,
                rrsig_expiry: Some(1710100000),
                failure_reason: None,
            },
            servfail_reason: None,
        };

        let bytes = rmp_serde::to_vec_named(&flow).expect("serialize");
        let decoded: DnsFlow = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(flow, decoded);
    }

    fn make_step(
        step: u8,
        asked: &str,
        server_name: Option<&str>,
        response_type: StepResponseType,
        ns: Option<Vec<&str>>,
    ) -> ResolveStep {
        ResolveStep {
            step,
            asked: asked.to_string(),
            server: "198.41.0.4".to_string(),
            server_name: server_name.map(|s| s.to_string()),
            response_type,
            got: StepData {
                ns: ns.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            },
            ms: 10,
        }
    }

    fn make_flow(domain: &str, steps: Vec<ResolveStep>) -> DnsFlow {
        DnsFlow {
            flow_id: Uuid::nil(),
            r#type: FlowType::DnsResolution,
            started_at: 0,
            completed_at: 0,
            total_ms: 0,
            query: DnsQuery {
                domain: domain.to_string(),
                qtype: QueryType::A,
            },
            list_action: ListAction::Pass,
            list_filter: None,
            profile_id: None,
            geo_country: None,
            geo_asn: 0,
            resolution_path: steps,
            cname_chain: None,
            response: DnsResponse {
                rcode: ResponseCode::Noerror,
                ips: vec![],
                min_ttl: 300,
                auth_ttl: 300,
                all_records: AllRecords::default(),
            },
            dnssec: DnssecResult {
                status: DnssecStatus::Insecure,
                algorithm: None,
                ds_present: false,
                rrsig_expiry: None,
                failure_reason: None,
            },
            servfail_reason: None,
        }
    }

    #[test]
    fn auth_ns_normal_resolution() {
        // Root → TLD referral → Authoritative referral → Answer
        let flow = make_flow(
            "example.com.",
            vec![
                make_step(
                    1,
                    "example.com.",
                    Some("a.root-servers.net."),
                    StepResponseType::Referral,
                    Some(vec!["a.gtld-servers.net."]),
                ),
                make_step(
                    2,
                    "example.com.",
                    Some("a.gtld-servers.net."),
                    StepResponseType::Referral,
                    Some(vec!["ns1.cloudflare.com.", "ns2.cloudflare.com."]),
                ),
                make_step(
                    3,
                    "example.com.",
                    Some("ns1.cloudflare.com."),
                    StepResponseType::Answer,
                    None,
                ),
            ],
        );
        let auth = extract_auth_ns(&flow);
        assert_eq!(
            auth,
            Some(AuthNs::Full(vec![
                "ns1.cloudflare.com".to_string(),
                "ns2.cloudflare.com".to_string(),
            ]))
        );
    }

    #[test]
    fn auth_ns_subdomain_query() {
        // Referral for parent zone "example.com" when querying "sub.example.com"
        let flow = make_flow(
            "sub.example.com.",
            vec![
                make_step(
                    1,
                    "sub.example.com.",
                    Some("a.root-servers.net."),
                    StepResponseType::Referral,
                    Some(vec!["a.gtld-servers.net."]),
                ),
                make_step(
                    2,
                    "sub.example.com.",
                    Some("a.gtld-servers.net."),
                    StepResponseType::Referral,
                    Some(vec!["ns1.example.com."]),
                ),
                make_step(
                    3,
                    "sub.example.com.",
                    Some("ns1.example.com."),
                    StepResponseType::Answer,
                    None,
                ),
            ],
        );
        // "sub.example.com" asked, referral asked is also "sub.example.com" with
        // ancestor match on "com" and "sub.example.com" itself
        let auth = extract_auth_ns(&flow);
        assert_eq!(
            auth,
            Some(AuthNs::Full(vec!["ns1.example.com".to_string()]))
        );
    }

    #[test]
    fn auth_ns_cname_chain() {
        // Original: foo.example.com → CNAME bar.cdn.com
        // Referral for cdn.com zone should be excluded (asked = bar.cdn.com)
        let flow = make_flow(
            "foo.example.com.",
            vec![
                make_step(
                    1,
                    "foo.example.com.",
                    Some("a.gtld-servers.net."),
                    StepResponseType::Referral,
                    Some(vec!["ns1.example.com."]),
                ),
                make_step(
                    2,
                    "foo.example.com.",
                    Some("ns1.example.com."),
                    StepResponseType::Cname,
                    None,
                ),
                make_step(
                    3,
                    "bar.cdn.com.",
                    Some("a.gtld-servers.net."),
                    StepResponseType::Referral,
                    Some(vec!["ns1.cdn.com."]),
                ),
                make_step(
                    4,
                    "bar.cdn.com.",
                    Some("ns1.cdn.com."),
                    StepResponseType::Answer,
                    None,
                ),
            ],
        );
        let auth = extract_auth_ns(&flow);
        // Should get example.com's NS, not cdn.com's
        assert_eq!(
            auth,
            Some(AuthNs::Full(vec!["ns1.example.com".to_string()]))
        );
    }

    #[test]
    fn auth_ns_cache_hit() {
        // Single Answer step (from cache)
        let flow = make_flow(
            "google.com.",
            vec![make_step(
                1,
                "google.com.",
                Some("ns1.google.com."),
                StepResponseType::Answer,
                None,
            )],
        );
        let auth = extract_auth_ns(&flow);
        assert_eq!(auth, Some(AuthNs::Partial("ns1.google.com".to_string())));
    }

    #[test]
    fn auth_ns_all_errors() {
        let flow = make_flow(
            "fail.example.com.",
            vec![make_step(
                1,
                "fail.example.com.",
                Some("ns1.example.com."),
                StepResponseType::Error,
                None,
            )],
        );
        assert_eq!(extract_auth_ns(&flow), None);
    }

    #[test]
    fn auth_ns_empty_path() {
        let flow = make_flow("empty.com.", vec![]);
        assert_eq!(extract_auth_ns(&flow), None);
    }

    #[test]
    fn auth_ns_normalize_sorts_and_dedupes() {
        let ns = normalize_ns_set(&[
            "Ns2.Example.COM.".to_string(),
            "ns1.example.com.".to_string(),
            "ns2.example.com.".to_string(),
        ]);
        assert_eq!(ns, vec!["ns1.example.com", "ns2.example.com"]);
    }

    #[test]
    fn is_name_or_ancestor_cases() {
        assert!(is_name_or_ancestor("example.com", "example.com"));
        assert!(is_name_or_ancestor("com", "example.com"));
        assert!(is_name_or_ancestor("example.com", "sub.example.com"));
        assert!(!is_name_or_ancestor("other.com", "example.com"));
        assert!(!is_name_or_ancestor("ample.com", "example.com")); // not a zone boundary
    }
}
