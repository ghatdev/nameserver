//! Domain reputation system: pre-computed, per-registrable-domain reputation
//! built incrementally from DNS flow resolution data.
//!
//! Replaces the scattered multi-table query pattern in the scoring chain with a
//! single `domain_reputation` row read. Includes a 27-dim infrastructure
//! fingerprint vector for pgvector similarity search.

use std::collections::HashSet;

use nameserver_common::messages::flow::DnsFlow;
use nameserver_common::types::{DnssecStatus, StepResponseType};
use sqlx::PgPool;
use time::OffsetDateTime;
use tracing::{debug, warn};

use crate::scoring_chain::{
    FREE_DNS_NS, KNOWN_NS_PROVIDERS, REGISTRAR_DEFAULT_NS, extract_registrable,
};

/// Infrastructure fingerprint dimensionality.
pub const INFRA_DIM: usize = 27;

/// Cosine distance threshold above which a flow is considered a potential hijack
/// for trusted domains.
const HIJACK_DISTANCE_THRESHOLD: f32 = 0.5;

/// Free TLDs commonly abused for phishing.
const FREE_TLDS: &[&str] = &["tk", "ml", "ga", "cf", "gq"];

/// New gTLDs (higher risk than established gTLDs).
const NEW_GTLDS: &[&str] = &[
    "xyz", "top", "club", "online", "site", "store", "fun", "icu", "buzz", "space", "website",
    "tech", "click", "link", "work", "life", "live", "host", "press", "pw", "cam", "rest", "surf",
];

// ---------------------------------------------------------------------------
// Infrastructure fingerprint computation
// ---------------------------------------------------------------------------

/// Compute a 27-dimensional infrastructure fingerprint from a single DNS flow.
/// Pure function — no I/O.
pub fn compute_infra_fingerprint(
    flow: &DnsFlow,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> Vec<f32> {
    let mut fp = vec![0.0f32; INFRA_DIM];
    let path = &flow.resolution_path;
    let total_steps = path.len() as f32;

    // --- Dimensions 0-5: Resolution topology ---

    // [0] chain_depth_norm
    fp[0] = (total_steps / 6.0).min(1.0);

    // [1] has_cname_chain
    fp[1] = if flow.cname_chain.as_ref().is_some_and(|c| !c.is_empty()) {
        1.0
    } else {
        0.0
    };

    // [2] cname_depth_norm
    let cname_depth = flow.cname_chain.as_ref().map(|c| c.len()).unwrap_or(0);
    fp[2] = (cname_depth as f32 / 5.0).min(1.0);

    // [3] answer_step_ratio
    let answer_steps = path
        .iter()
        .filter(|s| matches!(s.response_type, StepResponseType::Answer))
        .count() as f32;
    fp[3] = if total_steps > 0.0 {
        answer_steps / total_steps
    } else {
        0.0
    };

    // [4] referral_step_ratio
    let referral_steps = path
        .iter()
        .filter(|s| matches!(s.response_type, StepResponseType::Referral))
        .count() as f32;
    fp[4] = if total_steps > 0.0 {
        referral_steps / total_steps
    } else {
        0.0
    };

    // [5] multi_ns_providers — distinct NS provider registrable domains in chain
    let distinct_ns: HashSet<String> = path
        .iter()
        .filter_map(|s| s.server_name.as_deref())
        .filter(|n| !n.is_empty())
        .map(|n| extract_registrable(n.trim_end_matches('.'), suffix_set))
        .collect();
    fp[5] = if distinct_ns.len() >= 2 { 1.0 } else { 0.0 };

    // --- Dimensions 6-11: DNS record profile ---

    // [6] auth_ttl_log_norm — authoritative TTL, not cache-adjusted
    let auth_ttl = flow.response.auth_ttl.max(1) as f32;
    fp[6] = (auth_ttl.log2() / 20.0).clamp(0.0, 1.0);

    // [7] has_dnssec
    fp[7] = if matches!(flow.dnssec.status, DnssecStatus::Secure) {
        1.0
    } else {
        0.0
    };

    // [8] has_mx
    fp[8] = if flow
        .response
        .all_records
        .mx
        .as_ref()
        .is_some_and(|v| !v.is_empty())
    {
        1.0
    } else {
        0.0
    };

    // [9] has_txt
    fp[9] = if flow
        .response
        .all_records
        .txt
        .as_ref()
        .is_some_and(|v| !v.is_empty())
    {
        1.0
    } else {
        0.0
    };

    // [10] has_soa
    fp[10] = if flow.response.all_records.soa.is_some() {
        1.0
    } else {
        0.0
    };

    // [11] a_record_count_norm
    let a_count = flow
        .response
        .all_records
        .a
        .as_ref()
        .map(|v| v.len())
        .unwrap_or(0);
    fp[11] = (a_count as f32 / 8.0).min(1.0);

    // --- Dimensions 12-17: NS classification ---

    let auth_ns = nameserver_common::messages::flow::extract_auth_ns(flow);
    let ns_lower = auth_ns
        .as_ref()
        .map(|a| a.primary().to_string())
        .unwrap_or_default();

    // [12] ns_enterprise_cdn
    fp[12] = if KNOWN_NS_PROVIDERS.iter().any(|p| ns_lower.contains(p)) {
        1.0
    } else {
        0.0
    };

    // [13] ns_registrar_default
    fp[13] = if REGISTRAR_DEFAULT_NS.iter().any(|p| ns_lower.contains(p)) {
        1.0
    } else {
        0.0
    };

    // [14] ns_free_dns
    fp[14] = if FREE_DNS_NS.iter().any(|p| ns_lower.contains(p)) {
        1.0
    } else {
        0.0
    };

    // [15] ns_self_hosted — NS registrable domain == queried domain's registrable
    let domain_reg = extract_registrable(flow.query.domain.trim_end_matches('.'), suffix_set);
    let primary_ns = auth_ns.as_ref().map(|a| a.primary()).unwrap_or("");
    let ns_reg = if !primary_ns.is_empty() {
        extract_registrable(primary_ns.trim_end_matches('.'), suffix_set)
    } else {
        String::new()
    };
    fp[15] = if !ns_reg.is_empty() && ns_reg == domain_reg {
        1.0
    } else {
        0.0
    };

    // [16] ns_provider_diversity
    fp[16] = (distinct_ns.len() as f32 / 4.0).min(1.0);

    // [17] ns_observation_norm — set to 0.0 initially, converges via EMA blend
    fp[17] = 0.0;

    // --- Dimensions 18-23: IP/hosting profile ---

    // [18] unique_ip_norm
    fp[18] = (flow.response.ips.len() as f32 / 16.0).min(1.0);

    // [19] unique_asn_norm — single ASN per flow, enriched via EMA
    fp[19] = if flow.geo_asn > 0 { 0.25 } else { 0.0 };

    // [20] is_cdn — enriched asynchronously from ips table, initial 0
    fp[20] = 0.0;

    // [21] is_bulletproof — enriched asynchronously, initial 0
    fp[21] = 0.0;

    // [22] resolve_ms_log_norm
    let ms = flow.total_ms.max(1) as f32;
    fp[22] = (ms.log2() / 15.0).clamp(0.0, 1.0);

    // [23] ip_stability — initial 1.0, decays via EMA if IPs change
    fp[23] = 1.0;

    // --- Dimensions 24-26: TLD + chain structure ---

    // [24] tld_risk
    let tld = extract_tld(flow.query.domain.trim_end_matches('.'), suffix_set);
    fp[24] = classify_tld_risk(&tld);

    // [25] cname_target_diversity
    let cname_unique: HashSet<&str> = flow
        .cname_chain
        .as_ref()
        .map(|c| c.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();
    fp[25] = (cname_unique.len() as f32 / 4.0).min(1.0);

    // [26] delegation_depth_norm — referral hops only
    fp[26] = (referral_steps / 4.0).min(1.0);

    fp
}

/// Extract the effective TLD from a domain.
///
/// Uses the SuffixSet-based registrable domain extraction: the TLD is whatever
/// remains after stripping the registrable label. Falls back to the last label
/// if no suffix set is available.
fn extract_tld(domain: &str, suffix_set: &nameserver_common::suffix::SuffixSet) -> String {
    let d = domain.strip_suffix('.').unwrap_or(domain);
    match suffix_set.registrable_domain(d) {
        Some(reg) => {
            // TLD = domain minus the first label of the registrable part.
            if let Some(dot) = reg.find('.') {
                reg[dot + 1..].to_string()
            } else {
                d.rsplit('.').next().unwrap_or(d).to_string()
            }
        }
        None => {
            // Domain is itself a suffix — return as-is.
            d.to_string()
        }
    }
}

/// Classify TLD risk: 1.0 = free, 0.7 = new gTLD, 0.3 = ccTLD, 0.0 = established gTLD.
fn classify_tld_risk(tld: &str) -> f32 {
    if FREE_TLDS.contains(&tld) {
        return 1.0;
    }
    if NEW_GTLDS.contains(&tld) {
        return 0.7;
    }
    // ccTLDs are 2 chars (kr, uk, jp, ...) or multi-part (co.kr, co.uk)
    if tld.len() == 2 || tld.contains('.') {
        return 0.3;
    }
    // Established gTLDs
    0.0
}

/// Classify TLD type as a string.
fn classify_tld_type(tld: &str) -> &'static str {
    if FREE_TLDS.contains(&tld) {
        "free"
    } else if NEW_GTLDS.contains(&tld) {
        "new_gtld"
    } else if tld.len() == 2 || tld.contains('.') {
        "cctld"
    } else {
        "gtld"
    }
}

// ---------------------------------------------------------------------------
// Reputation upsert
// ---------------------------------------------------------------------------

/// Detect whether the incoming authoritative NS represents a provider-level
/// change from the currently stored NS set for this registrable.
///
/// Rules:
/// - Only `AuthNs::Full` observations can trigger a change. Partials are noise.
/// - Empty stored set (first observation) is never a change.
/// - Change = empty intersection of provider-coalesced sets. See
///   [`nameserver_common::ns_provider::provider_key`] for coalescing rules.
///
/// MUST be called BEFORE the `domain_ns_map` upsert for this flow, so that the
/// stored snapshot does not already contain the incoming NS.
pub async fn detect_ns_change(
    pool: &PgPool,
    registrable: &str,
    auth_ns: &Option<nameserver_common::messages::flow::AuthNs>,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> bool {
    let incoming = match auth_ns.as_ref().and_then(|a| a.as_full()) {
        Some(ns) if !ns.is_empty() => ns,
        _ => return false,
    };
    let incoming_providers: HashSet<String> = incoming
        .iter()
        .map(|n| nameserver_common::ns_provider::provider_key(n, suffix_set))
        .collect();

    let stored_rows = match sqlx::query!(
        "SELECT ns_domain FROM domain_ns_map WHERE registrable_domain = $1",
        registrable,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return false,
    };
    if stored_rows.is_empty() {
        return false;
    }
    let stored_providers: HashSet<String> = stored_rows
        .iter()
        .map(|r| nameserver_common::ns_provider::provider_key(&r.ns_domain, suffix_set))
        .collect();

    incoming_providers.is_disjoint(&stored_providers)
}

/// Upsert domain reputation from a DNS flow. Includes hijack detection for
/// trusted domains.
///
/// `ns_changed` comes from [`detect_ns_change`] and must be computed from the
/// pre-upsert `domain_ns_map` snapshot.
pub async fn upsert_reputation(
    pool: &PgPool,
    flow: &DnsFlow,
    ns_changed: bool,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) {
    let registrable = extract_registrable(flow.query.domain.trim_end_matches('.'), suffix_set);
    if registrable.is_empty() {
        return;
    }

    let now = OffsetDateTime::now_utc();
    let fp = compute_infra_fingerprint(flow, suffix_set);
    let fp_vec = pgvector::Vector::from(fp.clone());

    let tld = extract_tld(flow.query.domain.trim_end_matches('.'), suffix_set);
    let tld_type = classify_tld_type(&tld);

    // Extract authoritative NS from resolution path
    let auth_ns = nameserver_common::messages::flow::extract_auth_ns(flow);
    let ns_domains: Vec<String> = auth_ns
        .as_ref()
        .and_then(|a| a.as_full())
        .map(|ns| ns.to_vec())
        .unwrap_or_default();
    let ns_json = serde_json::json!(ns_domains);

    // Classify NS trust from authoritative NS (full set precedence)
    let ns_trust = classify_ns_trust_from_auth(&auth_ns);

    // CNAME targets
    let cname_targets = serde_json::json!(flow.cname_chain.as_deref().unwrap_or_default());

    let auth_ttl = flow.response.auth_ttl as f32;
    let resolve_ms = flow.total_ms as f32;
    let chain_depth = flow.resolution_path.len() as f32;
    let has_cname = flow.cname_chain.as_ref().is_some_and(|c| !c.is_empty());
    let has_dnssec = matches!(flow.dnssec.status, DnssecStatus::Secure);
    let has_mx = flow
        .response
        .all_records
        .mx
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    let ip_count = flow.response.ips.len() as i16;
    let a_count = flow
        .response
        .all_records
        .a
        .as_ref()
        .map(|v| v.len())
        .unwrap_or(0) as i16;

    // Read existing row for hijack detection + EMA blend
    // (pgvector doesn't support scalar * vector in SQL, so we blend in Rust)
    let existing = sqlx::query!(
        r#"SELECT is_trusted,
                  trusted_fingerprint as "trusted_fingerprint: pgvector::Vector",
                  infra_fingerprint as "infra_fingerprint: pgvector::Vector"
           FROM domain_reputation
           WHERE registrable_domain = $1"#,
        &registrable,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Hijack detection for trusted domains
    if let Some(ref row) = existing
        && row.is_trusted
        && let Some(ref trusted_fp) = row.trusted_fingerprint
    {
        let distance = cosine_distance(&fp, trusted_fp.as_slice());
        if distance > HIJACK_DISTANCE_THRESHOLD {
            debug!(
                distance,
                "reputation anomaly detected for trusted domain, skipping update"
            );
            let flow_ips = serde_json::json!(flow.response.ips);
            let _ = sqlx::query!(
                "INSERT INTO reputation_anomalies \
                         (registrable_domain, detected_at, flow_fingerprint, trusted_fingerprint, \
                          cosine_distance, flow_ns, flow_ips) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &registrable,
                now,
                &fp_vec as &pgvector::Vector,
                trusted_fp as &pgvector::Vector,
                distance,
                &ns_json,
                &flow_ips,
            )
            .execute(pool)
            .await;
            return;
        }
    }

    // EMA blend: 0.9 * old + 0.1 * new (computed in Rust because pgvector
    // doesn't support scalar * vector).
    let blended_fp = match &existing {
        Some(row) => {
            if let Some(ref old_fp) = row.infra_fingerprint {
                let old = old_fp.as_slice();
                let blended: Vec<f32> = fp
                    .iter()
                    .zip(old.iter())
                    .map(|(new, old)| 0.9 * old + 0.1 * new)
                    .collect();
                pgvector::Vector::from(blended)
            } else {
                fp_vec.clone()
            }
        }
        _ => fp_vec.clone(),
    };

    // Upsert reputation.
    // ns_domains / delegation_ns columns are legacy duplicates of domain_ns_map
    // and are not written here. NS change detection is computed in Rust
    // via detect_ns_change() against the pre-upsert domain_ns_map snapshot.
    let result = sqlx::query!(
        "INSERT INTO domain_reputation (
            registrable_domain, total_flow_count, first_seen, last_seen,
            tld, tld_type, ns_trust, ns_observation_count,
            infra_fingerprint,
            avg_auth_ttl, min_auth_ttl, avg_resolve_ms, avg_chain_depth,
            has_cname, cname_targets,
            has_dnssec, has_mx,
            unique_ip_count, a_record_count,
            last_ns_change_at,
            updated_at
        ) VALUES (
            $1, 1, $2, $2,
            $3, $4, $5, 1,
            $6,
            $7, $7, $8, $9,
            $10, $11,
            $12, $13,
            $14, $15,
            NULL,
            $2
        )
        ON CONFLICT (registrable_domain) DO UPDATE SET
            total_flow_count = domain_reputation.total_flow_count + 1,
            last_seen = GREATEST(domain_reputation.last_seen, $2),
            ns_trust = CASE
                -- NS changed (provider-level) → reset trust to fresh classification
                WHEN $16 THEN $5
                -- Stable: NS unchanged for 30+ days AND (50 flows OR 30d + 10 flows)
                WHEN (domain_reputation.last_ns_change_at IS NULL
                      OR EXTRACT(EPOCH FROM ($2 - domain_reputation.last_ns_change_at)) / 86400 >= 30)
                     AND (domain_reputation.ns_observation_count >= 50
                          OR (EXTRACT(EPOCH FROM ($2 - domain_reputation.first_seen)) / 86400 >= 30
                              AND domain_reputation.ns_observation_count >= 10))
                THEN 'stable'
                ELSE COALESCE(domain_reputation.ns_trust, $5)
            END,
            last_ns_change_at = CASE
                WHEN $16 THEN $2
                ELSE domain_reputation.last_ns_change_at
            END,
            ns_observation_count = domain_reputation.ns_observation_count + 1,
            infra_fingerprint = $6,
            avg_auth_ttl = 0.9 * COALESCE(domain_reputation.avg_auth_ttl, $7) + 0.1 * $7,
            min_auth_ttl = LEAST(COALESCE(domain_reputation.min_auth_ttl, $7), $7),
            avg_resolve_ms = 0.9 * COALESCE(domain_reputation.avg_resolve_ms, $8) + 0.1 * $8,
            avg_chain_depth = 0.9 * COALESCE(domain_reputation.avg_chain_depth, $9) + 0.1 * $9,
            has_cname = domain_reputation.has_cname OR $10,
            cname_targets = (
                SELECT COALESCE(jsonb_agg(e.elem), '[]'::jsonb)
                FROM (
                    SELECT DISTINCT elem
                    FROM jsonb_array_elements_text(domain_reputation.cname_targets || $11) AS elem
                    LIMIT 50
                ) e
            ),
            has_dnssec = domain_reputation.has_dnssec OR $12,
            has_mx = domain_reputation.has_mx OR $13,
            unique_ip_count = GREATEST(domain_reputation.unique_ip_count, $14),
            a_record_count = GREATEST(domain_reputation.a_record_count, $15),
            updated_at = $2",
        &registrable,                     // $1
        now,                              // $2
        &tld,                             // $3
        tld_type,                         // $4
        ns_trust,                         // $5
        &blended_fp as &pgvector::Vector, // $6 — pre-blended EMA fingerprint
        auth_ttl,                         // $7
        resolve_ms,                       // $8
        chain_depth,                      // $9
        has_cname,                        // $10
        &cname_targets,                   // $11
        has_dnssec,                       // $12
        has_mx,                           // $13
        ip_count,                         // $14
        a_count,                          // $15
        ns_changed,                       // $16
    )
    .execute(pool)
    .await;

    if let Err(e) = result {
        warn!(error = %e, "failed to upsert domain reputation");
    }

    // Auto-trust: if well-known + enough observations, promote to trusted
    // (check is_well_known which is batch-updated from well_known_domains table)
    if existing.is_none() || !existing.as_ref().is_some_and(|row| row.is_trusted) {
        let _ = sqlx::query!(
            "UPDATE domain_reputation SET
                is_trusted = TRUE,
                trusted_at = $2,
                trusted_fingerprint = infra_fingerprint,
                trust_source = 'auto_stable'
             WHERE registrable_domain = $1
               AND is_well_known = TRUE
               AND total_flow_count >= 100
               AND ns_observation_count >= 20
               AND is_trusted = FALSE",
            &registrable,
            now,
        )
        .execute(pool)
        .await;
    }
}

/// Classify NS trust from a single NS hostname without querying the database.
pub fn classify_ns_trust(ns: &str) -> &'static str {
    if ns.is_empty() {
        return "unknown";
    }
    let lower = ns.to_lowercase();
    if FREE_DNS_NS.iter().any(|p| lower.contains(p)) {
        return "free_dns";
    }
    if REGISTRAR_DEFAULT_NS.iter().any(|p| lower.contains(p)) {
        return "registrar_default";
    }
    if KNOWN_NS_PROVIDERS.iter().any(|p| lower.contains(p)) {
        return "known_provider";
    }
    "new"
}

fn classify_ns_trust_from_auth(
    auth_ns: &Option<nameserver_common::messages::flow::AuthNs>,
) -> &'static str {
    let ns_list: Vec<&str> = match auth_ns {
        Some(a) => a.all_ns(),
        None => return "unknown",
    };
    if ns_list.is_empty() {
        return "unknown";
    }

    // Check all NS hostnames with worst-wins precedence
    let mut has_known_provider = false;
    let mut has_registrar_default = false;

    for ns in &ns_list {
        let lower = ns.to_lowercase();
        if FREE_DNS_NS.iter().any(|p| lower.contains(p)) {
            return "free_dns"; // worst — immediate return
        }
        if REGISTRAR_DEFAULT_NS.iter().any(|p| lower.contains(p)) {
            has_registrar_default = true;
        }
        if KNOWN_NS_PROVIDERS.iter().any(|p| lower.contains(p)) {
            has_known_provider = true;
        }
    }

    if has_registrar_default {
        "registrar_default"
    } else if has_known_provider {
        "known_provider"
    } else {
        "new"
    }
}

/// Cosine distance between two vectors: 1 - cosine_similarity.
fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom < 1e-10 {
        return 1.0;
    }
    1.0 - (dot / denom)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_extraction() {
        let ss = nameserver_common::suffix::SuffixSet::default();
        assert_eq!(extract_tld("google.com", &ss), "com");
        assert_eq!(extract_tld("example.tk", &ss), "tk");
        assert_eq!(extract_tld("test.xyz", &ss), "xyz");

        // With a real suffix set, multi-part TLDs work correctly.
        let psl = nameserver_common::suffix::SuffixSet::from_psl_text("com\nco.kr\n");
        assert_eq!(extract_tld("shinhan.co.kr", &psl), "co.kr");
    }

    #[test]
    fn tld_risk_classification() {
        assert_eq!(classify_tld_risk("tk"), 1.0);
        assert_eq!(classify_tld_risk("xyz"), 0.7);
        assert_eq!(classify_tld_risk("kr"), 0.3);
        assert_eq!(classify_tld_risk("co.kr"), 0.3);
        assert_eq!(classify_tld_risk("com"), 0.0);
        assert_eq!(classify_tld_risk("net"), 0.0);
    }

    #[test]
    fn cosine_distance_identical() {
        let a = vec![1.0, 0.0, 1.0];
        assert!(cosine_distance(&a, &a) < 0.001);
    }

    #[test]
    fn cosine_distance_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!((cosine_distance(&a, &b) - 1.0).abs() < 0.001);
    }

    #[test]
    fn ns_trust_classification() {
        assert_eq!(classify_ns_trust("ns1.cloudflare.com"), "known_provider");
        assert_eq!(classify_ns_trust("ns1.afraid.org"), "free_dns");
        assert_eq!(
            classify_ns_trust("ns1.sedoparking.com"),
            "registrar_default"
        );
        assert_eq!(classify_ns_trust("ns1.custom-dns.example.com"), "new");
        assert_eq!(classify_ns_trust(""), "unknown");
    }
}
