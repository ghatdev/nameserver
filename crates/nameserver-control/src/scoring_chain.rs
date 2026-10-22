//! Scoring chain v2: combines ML pattern score with contextual signals.
//!
//! Design principle: the ML model (with Group F reputation features) handles
//! continuous pattern recognition. The chain adds signals the model cannot
//! capture: per-flow DNSSEC status, live list matching (NRD), infrastructure
//! similarity comparison, and hosting platform impersonation detection.
//!
//! Adjustment range: [-0.25, +0.65] (down from [-0.95, +0.95] in v1).
//! See ml/docs/feature-design.md for full design rationale.

use nameserver_common::messages::flow::DnsFlow;
use sqlx::PgPool;
use tracing::warn;

use crate::similarity;

/// Map an NRD source slug to its maximum age window in days.
///
/// Hagezi NRD sources use disjoint weekly windows:
///   hagezi-nrd-7d  → 0-7 days,  hagezi-nrd-14d → 8-14 days, etc.
/// Returns the upper bound of the window.
pub fn nrd_max_age_days(slug: &str) -> Option<u32> {
    match slug {
        "hagezi-nrd-7d" => Some(7),
        "hagezi-nrd-14d" => Some(14),
        "hagezi-nrd-21d" => Some(21),
        "hagezi-nrd-28d" => Some(28),
        "hagezi-nrd-35d" => Some(35),
        _ => None,
    }
}

/// Graduated NRD score adjustment — younger domains get a stronger signal.
fn nrd_adjustment(age_days: u32) -> f32 {
    match age_days {
        0..=7 => 0.15,
        8..=14 => 0.10,
        15..=21 => 0.07,
        22..=28 => 0.05,
        29..=35 => 0.03,
        _ => 0.0,
    }
}

/// Known NS providers — trusted infrastructure.
pub(crate) const KNOWN_NS_PROVIDERS: &[&str] = &[
    "awsdns",
    "cloudflare.com",
    "google.com",
    "googledomains.com",
    "msft.net",
    "apple.com",
    "akam",
    "akadns",
    "ultradns",
    "nsone.net",
    "dynect.net",
    "azure-dns",
    "ns.oracle.com",
    "registrar-servers.com",
    "domaincontrol.com",
    "fastly",
];

/// NS patterns that indicate registrar default (just registered, no custom setup).
pub(crate) const REGISTRAR_DEFAULT_NS: &[&str] = &[
    "registrar-servers.com",
    "domaincontrol.com",
    "name-services.com",
    "sedoparking.com",
    "parkingcrew.net",
    "bodis.com",
    "dns-parking",
];

/// Free/dynamic DNS providers — common in malware.
pub(crate) const FREE_DNS_NS: &[&str] = &[
    "duckdns.org",
    "afraid.org",
    "no-ip.com",
    "dynu.com",
    "hopto.org",
    "zapto.org",
    "ddns.net",
    "sytes.net",
    "serveblog.net",
];

/// Hosting platforms where anyone can create subdomains.
const HOSTING_PLATFORMS: &[&str] = &[
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "herokuapp.com",
    "github.io",
    "firebaseapp.com",
    "web.app",
    "weebly.com",
    "wixsite.com",
    "squarespace.com",
    "wordpress.com",
    "blogspot.com",
    "azurewebsites.net",
    "appspot.com",
    "pythonanywhere.com",
    "glitch.me",
    "repl.co",
    "surge.sh",
    "fly.dev",
];

/// Korean institution seed domains for impersonation detection.
const SEED_LABELS: &[&str] = &[
    "kbstar",
    "shinhan",
    "wooribank",
    "hanabank",
    "ibk",
    "nhbank",
    "kfcc",
    "epostbank",
    "toss",
    "tossbank",
    "naver",
    "daum",
    "kakao",
    "kakaocorp",
    "line",
    "cjlogistics",
    "hanjin",
    "lotteglogis",
    "epost",
    "baemin",
    "skt",
    "kt",
    "lguplus",
    "coupang",
    "musinsa",
    "ssg",
    "samsungcard",
    "hyundaicard",
    "lottecard",
];

/// Service keywords that indicate impersonation when on hosting platforms.
const SERVICE_KEYWORDS: &[&str] = &[
    "login", "verify", "pay", "secure", "auth", "bank", "banking", "card", "account", "mypage",
    "cert", "check", "update", "alert", "delivery", "track", "official", "service", "app",
];

/// Per-step adjustment tracking for debugging.
#[derive(Debug, Clone, Default)]
pub struct ChainSignals {
    pub dnssec_adj: f32,
    pub ns_adj: f32,
    pub similarity_adj: f32,
    pub hosting_adj: f32,
    pub nrd_adj: f32,
}

/// Result of the scoring chain evaluation.
pub struct ChainResult {
    pub final_score: f32,
    pub verdict: String,
    pub ns_trust: NsTrust,
    pub is_hosting_platform: bool,
    pub impersonation_detected: bool,
    pub is_nrd: bool,
    pub signals: ChainSignals,
}

/// NS trust level determined by the chain.
///
/// Recent NS changes are no longer represented as a trust state. The
/// `last_ns_change_at` timestamp on `domain_reputation` carries that signal,
/// and it reaches the model via the `days_since_ns_change` feature.
#[derive(Debug, Clone)]
pub enum NsTrust {
    /// Same NS seen for 30+ days with many observations.
    Stable,
    /// NS is a known major provider (Cloudflare, AWS, Google, etc.).
    KnownProvider,
    /// NS is a registrar default (just registered).
    RegistrarDefault,
    /// NS is a free/dynamic DNS provider.
    FreeDns,
    /// First time seeing this domain+NS combination.
    New,
    /// No NS data available.
    Unknown,
}

impl std::fmt::Display for NsTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NsTrust::Stable => f.write_str("stable"),
            NsTrust::KnownProvider => f.write_str("known_provider"),
            NsTrust::RegistrarDefault => f.write_str("registrar_default"),
            NsTrust::FreeDns => f.write_str("free_dns"),
            NsTrust::New => f.write_str("new"),
            NsTrust::Unknown => f.write_str("unknown"),
        }
    }
}

/// Step 0: Should this domain be skipped entirely?
pub fn should_skip(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    // PTR domains
    if d.ends_with(".in-addr.arpa") || d.ends_with(".ip6.arpa") {
        return true;
    }
    // mDNS / DNS-SD
    if d.contains("._dns-sd.") || d.contains("._tcp.") || d.contains("._udp.") {
        return true;
    }
    // .local domains
    if d.ends_with(".local") || d.ends_with(".localdomain") {
        return true;
    }
    false
}

/// Check if the domain belongs to one of the operator's own zones.
pub fn is_own_zone(domain: &str, own_zones: &[String]) -> bool {
    let d = domain.trim_end_matches('.');
    own_zones.iter().any(|zone| {
        let z = zone.trim_end_matches('.');
        d == z || d.ends_with(&format!(".{z}"))
    })
}

/// Steps 1-8: Evaluate the scoring chain and produce a final verdict.
///
/// v2 design: model handles continuous patterns (Group F reputation features),
/// chain handles per-flow signals, list matching, and similarity comparison.
pub async fn evaluate(
    domain: &str,
    ml_score: f32,
    flow: &DnsFlow,
    pool: &PgPool,
    label: Option<&str>,
    sim_embedding: Option<&[f32]>,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> ChainResult {
    let domain_stripped = domain.trim_end_matches('.');
    let registrable = extract_registrable(domain_stripped, suffix_set);

    // ── Single-query reputation read ──
    let rep = sqlx::query!(
        r#"SELECT ns_trust, is_nrd, nrd_source as "nrd_source?"
         FROM domain_reputation WHERE registrable_domain = $1"#,
        registrable,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Parse NS trust from reputation (or classify from flow)
    let ns_trust = if let Some(ref row) = rep {
        parse_ns_trust(&row.ns_trust)
    } else {
        classify_ns(flow, pool, suffix_set).await
    };

    // ── Step 1: ML threshold gate ──
    if ml_score < 0.15 {
        return ChainResult {
            final_score: ml_score,
            verdict: "safe".to_string(),
            ns_trust,
            is_hosting_platform: false,
            impersonation_detected: false,
            is_nrd: false,
            signals: ChainSignals::default(),
        };
    }

    let mut signals = ChainSignals::default();
    let mut adjustment: f32 = 0.0;

    // ── Step 3: DNSSEC (per-flow signal) ──
    if matches!(
        flow.dnssec.status,
        nameserver_common::types::DnssecStatus::Bogus
    ) {
        signals.dnssec_adj = 0.1;
        adjustment += 0.1;
    }

    // ── Step 4: NS edge cases (only free_dns) ──
    // Model handles stable/known_provider/new via ns_observation_count and
    // days_since_ns_change. Chain only handles free_dns because it requires
    // live pattern matching against the FREE_DNS_NS list.
    let ns_adj = match &ns_trust {
        NsTrust::FreeDns => 0.05,
        _ => 0.0,
    };
    signals.ns_adj = ns_adj;
    adjustment += ns_adj;

    // ── Step 5: NRD (graduated — younger domains get stronger signal) ──
    let (is_nrd, nrd_age) = if let Some(ref row) = rep {
        let age = row.nrd_source.as_deref().and_then(nrd_max_age_days);
        (row.is_nrd, age)
    } else {
        // Fallback: direct indicator_domains query via enrichment_bindings
        let slug = sqlx::query_scalar!(
            "SELECT s.slug FROM indicator_domains d \
             JOIN enrichment_bindings eb ON d.source = eb.source_id \
             JOIN sources s ON s.id = d.source \
             WHERE eb.enrichment_type = 'nrd' AND d.domain = $1 \
             LIMIT 1",
            registrable,
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        let age = slug.as_deref().and_then(nrd_max_age_days);
        (slug.is_some(), age)
    };
    if is_nrd {
        let adj = nrd_age.map(nrd_adjustment).unwrap_or(0.1);
        signals.nrd_adj = adj;
        adjustment += adj;
    }

    // ── Step 6: Similarity / Impersonation ──
    let mut impersonation = false;

    if let Some(label) = label {
        let mut similarity_resolved = false;

        // Tier 0: infra fingerprint comparison (pgvector cosine distance)
        if rep.is_some() {
            // Need infra_fingerprint for tier 0 — separate query since main query is slim
            if let Ok(Some(fp_row)) = sqlx::query!(
                r#"SELECT infra_fingerprint as "infra_fingerprint?: pgvector::Vector" FROM domain_reputation WHERE registrable_domain = $1"#,
                registrable,
            )
            .fetch_optional(pool)
            .await
                && let Some(ref fp) = fp_row.infra_fingerprint {
                    let infra_result = similarity::search_infra_similar(
                        pool, fp.as_slice(), label, &registrable,
                    ).await;
                    match infra_result {
                        similarity::InfraSimilarity::SameInfra => {
                            signals.similarity_adj = -0.15;
                            adjustment -= 0.15;
                            similarity_resolved = true;
                        }
                        similarity::InfraSimilarity::DifferentInfra => {
                            signals.similarity_adj = 0.2;
                            adjustment += 0.2;
                            impersonation = true;
                            similarity_resolved = true;
                        }
                        similarity::InfraSimilarity::Unknown => {}
                    }
                }
        }

        // Tier 1: exact label match + NS comparison (fallback)
        if !similarity_resolved {
            let chain_ns = extract_chain_ns(flow);
            if !chain_ns.is_empty() {
                let tier1_matches = similarity::search_exact_label(pool, label, &registrable).await;
                for (_matched_domain, ns_list) in &tier1_matches {
                    match similarity::compare_ns(&chain_ns, ns_list, suffix_set) {
                        similarity::NsComparison::SameInfra => {
                            signals.similarity_adj = -0.15;
                            adjustment -= 0.15;
                            similarity_resolved = true;
                            break;
                        }
                        similarity::NsComparison::DifferentInfra => {
                            signals.similarity_adj = 0.2;
                            adjustment += 0.2;
                            impersonation = true;
                            similarity_resolved = true;
                            break;
                        }
                        similarity::NsComparison::Unknown => {}
                    }
                }
            }

            // Tier 2: lexical-similarity neighbors + NS comparison.
            //
            // Single HNSW cosine ANN over the contrastive
            // `sim_embedding` column. When the ML worker isn't
            // shipping a sim embedding for this flow (e.g. label too
            // short, or the contrastive ONNX model failed to load),
            // tier-2 simply doesn't fire — tier 0 (infra fingerprint)
            // and tier 1 (exact label match) above already had their
            // chance.
            if !similarity_resolved && let Some(sim_emb) = sim_embedding {
                let chain_ns = extract_chain_ns(flow);
                if !chain_ns.is_empty() {
                    let tier2_matches =
                        similarity::search_sim_neighbors(pool, label, sim_emb, 5).await;
                    for (_matched_label, ns_list) in &tier2_matches {
                        match similarity::compare_ns(&chain_ns, ns_list, suffix_set) {
                            similarity::NsComparison::SameInfra => {
                                signals.similarity_adj = -0.15;
                                adjustment -= 0.15;
                                break;
                            }
                            similarity::NsComparison::DifferentInfra => {
                                signals.similarity_adj = 0.2;
                                adjustment += 0.2;
                                impersonation = true;
                                break;
                            }
                            similarity::NsComparison::Unknown => {}
                        }
                    }
                }
            }
        }
    }

    // ── Step 7: Hosting platform (tightened: keyword AND brand required) ──
    let is_hosting = is_hosting_platform(domain_stripped);

    if is_hosting {
        if check_subdomain_impersonation(domain_stripped) {
            // Requires BOTH a brand seed match AND a service keyword
            impersonation = true;
            signals.hosting_adj = 0.2;
            adjustment += 0.2;
        } else {
            // Clean hosting platform usage (developer project, etc.)
            signals.hosting_adj = -0.1;
            adjustment -= 0.1;
        }
    }

    // ── Step 8: Final verdict ──
    let final_score = (ml_score + adjustment).clamp(0.0, 1.0);

    let verdict = if final_score >= 0.9 {
        "malicious"
    } else if final_score >= 0.5 {
        "suspicious"
    } else if final_score >= 0.1 {
        "unknown"
    } else {
        "safe"
    };

    ChainResult {
        final_score,
        verdict: verdict.to_string(),
        ns_trust,
        is_hosting_platform: is_hosting,
        signals,
        impersonation_detected: impersonation,
        is_nrd,
    }
}

/// Parse NS trust string from domain_reputation back to enum.
fn parse_ns_trust(s: &str) -> NsTrust {
    match s {
        "stable" => NsTrust::Stable,
        "known_provider" => NsTrust::KnownProvider,
        "registrar_default" => NsTrust::RegistrarDefault,
        "free_dns" => NsTrust::FreeDns,
        "new" => NsTrust::New,
        _ => NsTrust::Unknown,
    }
}

/// Classify the NS trust level from the flow's resolution path.
async fn classify_ns(
    flow: &DnsFlow,
    pool: &PgPool,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> NsTrust {
    use nameserver_common::messages::flow::extract_auth_ns;

    let auth_ns = extract_auth_ns(flow);
    let primary = match &auth_ns {
        Some(a) => a.primary().to_string(),
        None => return NsTrust::Unknown,
    };
    if primary.is_empty() {
        return NsTrust::Unknown;
    }

    let ns_lower = primary.to_lowercase();

    // Check free DNS first (strongest negative signal)
    if FREE_DNS_NS.iter().any(|pat| ns_lower.contains(pat)) {
        return NsTrust::FreeDns;
    }

    // Check registrar default
    if REGISTRAR_DEFAULT_NS
        .iter()
        .any(|pat| ns_lower.contains(pat))
    {
        return NsTrust::RegistrarDefault;
    }

    // Check known provider
    if KNOWN_NS_PROVIDERS.iter().any(|pat| ns_lower.contains(pat)) {
        let registrable = extract_registrable(flow.query.domain.trim_end_matches('.'), suffix_set);
        let ns_clean = primary.trim_end_matches('.');
        if let Some(row) = sqlx::query!(
            "SELECT observation_count FROM domain_ns_map WHERE registrable_domain = $1 AND ns_domain = $2",
            registrable,
            ns_clean,
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
            && row.observation_count >= 10 {
                return NsTrust::Stable;
            }
        return NsTrust::KnownProvider;
    }

    // Check domain_ns_map for historical data
    let registrable = extract_registrable(flow.query.domain.trim_end_matches('.'), suffix_set);
    let ns_clean = primary.trim_end_matches('.');

    if let Some(row) = sqlx::query!(
        "SELECT observation_count, first_seen FROM domain_ns_map WHERE registrable_domain = $1 AND ns_domain = $2",
        registrable,
        ns_clean,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| warn!(error = %e, "scoring chain query failed"))
    .ok()
    .flatten()
    {
        let now = time::OffsetDateTime::now_utc();
        let age_days = (now - row.first_seen).whole_days();
        if (age_days >= 30 && row.observation_count >= 10) || row.observation_count >= 50 {
            return NsTrust::Stable;
        }
        return NsTrust::New;
    }

    // No (registrable, ns_domain) row → first time seeing this combination.
    NsTrust::New
}

/// Check if the domain is on a known hosting platform.
fn is_hosting_platform(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    HOSTING_PLATFORMS
        .iter()
        .any(|platform| lower.ends_with(platform))
}

/// Check if the subdomain on a hosting platform contains impersonation signals.
/// v2: requires BOTH a brand seed AND a service keyword (tightened from OR).
fn check_subdomain_impersonation(domain: &str) -> bool {
    let lower = domain.to_lowercase();

    // Find which hosting platform suffix matches
    let subdomain = HOSTING_PLATFORMS.iter().find_map(|platform| {
        if lower.ends_with(platform) {
            let prefix_len = lower.len() - platform.len();
            if prefix_len > 1 {
                Some(&lower[..prefix_len - 1])
            } else {
                None
            }
        } else {
            None
        }
    });

    let subdomain = match subdomain {
        Some(s) => s,
        None => return false,
    };

    // v2: require BOTH brand seed AND service keyword
    let has_brand = SEED_LABELS.iter().any(|seed| subdomain.contains(seed));
    let has_keyword = SERVICE_KEYWORDS.iter().any(|kw| subdomain.contains(kw));

    has_brand && has_keyword
}

/// Extract ALL non-empty NS server names from the full resolution chain.
fn extract_chain_ns(flow: &DnsFlow) -> Vec<String> {
    flow.resolution_path
        .iter()
        .filter_map(|step| step.server_name.as_deref())
        .filter(|name| !name.is_empty())
        .map(|ns| ns.trim_end_matches('.').to_string())
        .collect()
}

/// Extract the registrable domain using the public suffix set.
pub fn extract_registrable(
    domain: &str,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> String {
    nameserver_common::suffix::extract_registrable(domain, suffix_set).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_registrable() {
        // Default empty SuffixSet: only implicit TLD rule (single labels).
        let set = nameserver_common::suffix::SuffixSet::default();
        assert_eq!(extract_registrable("google.com", &set), "google.com");
        assert_eq!(extract_registrable("sub.google.com", &set), "google.com");
        assert_eq!(extract_registrable("a.b.c.google.com", &set), "google.com");
    }

    #[test]
    fn test_extract_registrable_with_suffix_set() {
        let set = nameserver_common::suffix::SuffixSet::from_psl_text("com\nco.kr\n");
        assert_eq!(extract_registrable("google.com", &set), "google.com");
        assert_eq!(extract_registrable("sub.google.com", &set), "google.com");
        assert_eq!(extract_registrable("example.co.kr", &set), "example.co.kr");
        assert_eq!(
            extract_registrable("shop.example.co.kr", &set),
            "example.co.kr"
        );
    }

    #[test]
    fn test_hosting_impersonation_requires_brand_and_keyword() {
        // Brand + keyword = impersonation
        assert!(check_subdomain_impersonation("shinhan-login.vercel.app"));
        assert!(check_subdomain_impersonation("naver-verify.netlify.app"));

        // Keyword only = NOT impersonation (v2 tightening)
        assert!(!check_subdomain_impersonation("login.vercel.app"));
        assert!(!check_subdomain_impersonation("my-auth-app.netlify.app"));

        // Brand only = NOT impersonation
        assert!(!check_subdomain_impersonation("shinhan-test.vercel.app"));

        // Neither = NOT impersonation
        assert!(!check_subdomain_impersonation("my-cool-project.vercel.app"));
    }

    #[test]
    fn test_should_skip() {
        assert!(should_skip("1.0.168.192.in-addr.arpa."));
        assert!(should_skip("_tcp.local"));
        assert!(should_skip("host.local"));
        assert!(!should_skip("google.com"));
    }

    #[test]
    fn test_is_own_zone() {
        let zones = vec!["example.test".to_string()];
        assert!(is_own_zone("example.test", &zones));
        assert!(is_own_zone("example.test.", &zones));
        assert!(is_own_zone("ns1.example.test", &zones));
        assert!(is_own_zone("dns.example.test.", &zones));
        assert!(is_own_zone("deep.sub.example.test", &zones));
        assert!(!is_own_zone("notexample.test", &zones));
        assert!(!is_own_zone("evil-example.test", &zones));
        assert!(!is_own_zone("google.com", &zones));
        assert!(!is_own_zone("example.test.evil.com", &zones));
    }
}
