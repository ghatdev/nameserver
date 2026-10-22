//! Domain similarity index for impersonation detection (Step 3.5).
//!
//! Two-tier detection using PostgreSQL + pgvector:
//! - Tier 1: exact registrable label match (SQL query)
//! - Tier 2: Levenshtein edit distance on label + pgvector cosine similarity (future)
//!
//! When a match is found, compares NS infrastructure:
//! - Same NS → legitimate variant (safe adjustment)
//! - Different NS → possible impersonation (suspicious adjustment)
//!
//! Domain label embeddings are inserted by the ML worker as flows arrive,
//! building the index from live traffic. PostgreSQL maintains the HNSW index
//! automatically.

use sqlx::PgPool;
use tracing::debug;

use crate::scoring_chain::extract_registrable;

// ---------------------------------------------------------------------------
// NS comparison
// ---------------------------------------------------------------------------

/// Result of NS comparison.
#[derive(Debug, PartialEq)]
pub enum NsComparison {
    /// Auth NS matches known domain's NS (same operator).
    SameInfra,
    /// Auth NS differs from known domain's NS (possible impersonation).
    DifferentInfra,
    /// Cannot determine (no NS data available).
    Unknown,
}

/// Known NS provider patterns for provider-level grouping.
/// Use the shortest unique substring that covers all of a provider's domains.
/// E.g., "akam" matches akam.net, akamai.net, akamaiedge.net.
const NS_PROVIDER_PATTERNS: &[&str] = &[
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

/// Compare the scored domain's full resolution chain NS against known NS list.
/// If ANY NS in the chain matches ANY known NS (by provider), it's SameInfra.
/// This catches CNAME chains like azure-dns → akam.net → akamaiedge where
/// the seed domain also uses akamai somewhere in its infrastructure.
pub fn compare_ns(
    chain_ns: &[String],
    known_ns_list: &[String],
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> NsComparison {
    if known_ns_list.is_empty() || chain_ns.is_empty() {
        return NsComparison::Unknown;
    }

    for chain_entry in chain_ns {
        let chain_lower = chain_entry.to_lowercase();
        for known_ns in known_ns_list {
            let known_lower = known_ns.to_lowercase();
            if ns_same_provider(&chain_lower, &known_lower, suffix_set) {
                return NsComparison::SameInfra;
            }
        }
    }

    NsComparison::DifferentInfra
}

/// Check if two NS hostnames belong to the same provider.
fn ns_same_provider(a: &str, b: &str, suffix_set: &nameserver_common::suffix::SuffixSet) -> bool {
    for &pattern in NS_PROVIDER_PATTERNS {
        if a.contains(pattern) && b.contains(pattern) {
            return true;
        }
    }
    // Fallback 1: same registrable domain (ns1.proton.me and ns3.proton.me)
    let a_reg = extract_registrable(a.trim_end_matches('.'), suffix_set);
    let b_reg = extract_registrable(b.trim_end_matches('.'), suffix_set);
    if !a_reg.is_empty() && a_reg == b_reg {
        return true;
    }
    // Fallback 2: same operator across TLDs (ns1.naver.com and ns2.naver.jp)
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();
    if a_parts.len() >= 2 && b_parts.len() >= 2 {
        let a_label = a_parts[a_parts.len() - 2];
        let b_label = b_parts[b_parts.len() - 2];
        if !a_label.is_empty() && a_label.len() >= 3 && a_label == b_label {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Infrastructure fingerprint similarity
// ---------------------------------------------------------------------------

/// Result of infrastructure fingerprint comparison.
#[derive(Debug, PartialEq)]
pub enum InfraSimilarity {
    SameInfra,
    DifferentInfra,
    Unknown,
}

/// Search well-known domains with the same label and compare infrastructure
/// fingerprints via pgvector cosine distance.
///
/// Returns SameInfra if the closest match has cosine distance < 0.3,
/// DifferentInfra if > 0.7, Unknown otherwise (fall back to NS comparison).
pub async fn search_infra_similar(
    pool: &PgPool,
    query_fingerprint: &[f32],
    label: &str,
    exclude_registrable: &str,
) -> InfraSimilarity {
    let fp_vec = pgvector::Vector::from(query_fingerprint.to_vec());
    let row = sqlx::query!(
        r#"SELECT dr.infra_fingerprint <=> $1 AS "distance!"
           FROM domain_reputation dr
           WHERE dr.is_well_known = TRUE
             AND dr.registrable_domain <> $2
             AND dr.infra_fingerprint IS NOT NULL
             AND split_part(dr.registrable_domain, '.', 1) = $3
           ORDER BY dr.infra_fingerprint <=> $1
           LIMIT 1"#,
        &fp_vec as &pgvector::Vector,
        exclude_registrable,
        label,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    match row {
        Some(row) => {
            let distance: f64 = row.distance;
            if distance < 0.3 {
                InfraSimilarity::SameInfra
            } else if distance > 0.7 {
                InfraSimilarity::DifferentInfra
            } else {
                InfraSimilarity::Unknown
            }
        }
        None => InfraSimilarity::Unknown,
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL-based similarity search (chain NS comparison — fallback)
// ---------------------------------------------------------------------------

/// Tier 1: find domains sharing the exact same registrable label.
/// Returns Vec<(domain, ns_domains)>.
pub async fn search_exact_label(
    pool: &PgPool,
    label: &str,
    exclude_registrable: &str,
) -> Vec<(String, Vec<String>)> {
    // Search domain_ns_map for domains with this label (joined with well-known indicators or domains)
    let rows = match sqlx::query!(
        "SELECT DISTINCT d.registrable_domain, array_agg(DISTINCT d.ns_domain) AS ns_list \
         FROM domain_ns_map d \
         WHERE d.registrable_domain IN ( \
             SELECT DISTINCT ind.domain FROM indicator_domains ind \
             JOIN enrichment_bindings eb ON eb.source_id = ind.source \
             WHERE eb.enrichment_type = 'well_known' AND split_part(ind.domain, '.', 1) = $1 \
             UNION \
             SELECT DISTINCT dm.domain FROM domains dm \
             WHERE split_part(dm.domain, '.', 1) = $1 AND dm.query_count >= 5 \
         ) \
         AND d.registrable_domain <> $2 \
         GROUP BY d.registrable_domain \
         LIMIT 10",
        label,
        exclude_registrable,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            debug!(error = %e, "similarity tier1 query failed");
            return Vec::new();
        }
    };

    rows.iter()
        .map(|row| {
            let domain = row.registrable_domain.clone();
            let ns_list: Vec<String> = row.ns_list.clone().unwrap_or_default();
            (domain, ns_list)
        })
        .collect()
}

/// Tier 2 (Stage 2c, preferred): find lexically similar labels via HNSW
/// cosine ANN over the contrastive `sim_embedding` column.
///
/// Replaces the pg_trgm + levenshtein scan in `search_edit_distance`
/// with a single HNSW probe. Returns up to `top_k` `(label, ns_list)`
/// pairs ordered by cosine distance.
///
/// `sim_embedding` is the query label's 64-dim contrastive embedding
/// produced by `models/detector_cnn_sim_v1/cnn_sim_embedding.onnx`.
/// Caller is responsible for embedding the query — this keeps
/// `similarity` decoupled from the ONNX session lifecycle.
///
/// Rows where `sim_embedding IS NULL` (not yet backfilled) are
/// excluded by the index plan automatically — no explicit filter
/// needed.
pub async fn search_sim_neighbors(
    pool: &PgPool,
    query_label: &str,
    query_embedding: &[f32],
    top_k: i64,
) -> Vec<(String, Vec<String>)> {
    if query_embedding.is_empty() {
        return Vec::new();
    }

    let query_vec = pgvector::Vector::from(query_embedding.to_vec());

    // `e.label <> $1` excludes self-matches (the query label itself
    // may live in the corpus from prior flows). We pull `top_k + 1`
    // and trim because the HNSW operator <=> drives the ORDER BY but
    // doesn't know about the equality predicate; the +1 guards
    // against the rare case where the index returns the self-match
    // first.
    let rows = match sqlx::query!(
        "SELECT e.label, COALESCE(e.ns_domains, '[]'::jsonb) AS \"ns_domains!\" \
         FROM domain_label_embeddings e \
         WHERE e.sim_embedding IS NOT NULL AND e.label <> $1 \
         ORDER BY e.sim_embedding <=> $2 \
         LIMIT $3",
        query_label,
        &query_vec as &pgvector::Vector,
        top_k,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            debug!(error = %e, "similarity sim_neighbors query failed");
            return Vec::new();
        }
    };

    rows.iter()
        .map(|row| {
            let matched_label = row.label.clone();
            let ns_json: serde_json::Value = row.ns_domains.clone();
            let ns_list: Vec<String> = serde_json::from_value(ns_json).unwrap_or_default();
            (matched_label, ns_list)
        })
        .collect()
}

/// Insert or update a domain label embedding (called from ML worker).
///
/// Writes both the 32-dim classification embedding (consumed by
/// LightGBM as a lexical feature) and the 64-dim contrastive
/// embedding (drives the HNSW ANN tier-2 lookup in
/// `search_sim_neighbors`). Both are required — production must ship
/// the contrastive ONNX model alongside the classification model.
pub async fn upsert_label_embedding(
    pool: &PgPool,
    label: &str,
    embedding: &[f32],
    sim_embedding: &[f32],
    domain: &str,
    ns_domains: &[String],
) {
    let embedding_vec = pgvector::Vector::from(embedding.to_vec());
    let sim_vec = pgvector::Vector::from(sim_embedding.to_vec());
    let domains_json = serde_json::json!([domain]);
    let ns_json = serde_json::json!(ns_domains);

    let result = sqlx::query!(
        "INSERT INTO domain_label_embeddings \
           (label, embedding, sim_embedding, domains, ns_domains, updated_at) \
         VALUES ($1, $2, $3, $4, $5, NOW()) \
         ON CONFLICT (label) DO UPDATE SET \
           embedding = EXCLUDED.embedding, \
           sim_embedding = EXCLUDED.sim_embedding, \
           domains = domain_label_embeddings.domains || EXCLUDED.domains, \
           ns_domains = EXCLUDED.ns_domains, \
           updated_at = NOW()",
        label,
        &embedding_vec as &pgvector::Vector,
        &sim_vec as &pgvector::Vector,
        &domains_json,
        &ns_json,
    )
    .execute(pool)
    .await;

    if let Err(e) = result {
        debug!(error = %e, "failed to upsert label embedding");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(ns: &[&str]) -> Vec<String> {
        ns.iter().map(|s| s.to_string()).collect()
    }

    fn ss() -> nameserver_common::suffix::SuffixSet {
        nameserver_common::suffix::SuffixSet::default()
    }

    #[test]
    fn ns_same_cloudflare() {
        let known = vec!["ns1.cloudflare.com".to_string()];
        assert_eq!(
            compare_ns(&chain(&["ns2.cloudflare.com"]), &known, &ss()),
            NsComparison::SameInfra
        );
    }

    #[test]
    fn ns_same_registrable() {
        let known = vec!["ns1.proton.me".to_string()];
        assert_eq!(
            compare_ns(&chain(&["ns3.proton.me"]), &known, &ss()),
            NsComparison::SameInfra
        );
    }

    #[test]
    fn ns_same_operator_cross_tld() {
        let known = vec!["ns1.naver.com".to_string()];
        assert_eq!(
            compare_ns(&chain(&["ns2.naver.jp"]), &known, &ss()),
            NsComparison::SameInfra
        );
    }

    #[test]
    fn ns_different_provider() {
        let known = vec!["ns1.vercel-dns.com".to_string()];
        assert_eq!(
            compare_ns(&chain(&["ns1.cheaphosting.xyz"]), &known, &ss()),
            NsComparison::DifferentInfra,
        );
    }

    #[test]
    fn ns_empty_known() {
        let known: Vec<String> = vec![];
        assert_eq!(
            compare_ns(&chain(&["ns1.example.com"]), &known, &ss()),
            NsComparison::Unknown
        );
    }

    #[test]
    fn ns_awsdns_match() {
        let known = vec!["ns-824.awsdns-39.net".to_string()];
        assert_eq!(
            compare_ns(&chain(&["ns-1249.awsdns-28.org"]), &known, &ss()),
            NsComparison::SameInfra,
        );
    }

    #[test]
    fn chain_any_step_matches() {
        // Even if first NS in chain doesn't match, later step (akamai) should match
        let known = vec!["a28-192.akamaiedge.net".to_string()];
        assert_eq!(
            compare_ns(
                &chain(&["ns1-38.azure-dns.com", "a1-115.akam.net"]),
                &known,
                &ss()
            ),
            NsComparison::SameInfra,
        );
    }

    #[test]
    fn chain_no_match() {
        let known = vec!["ns1.proton.me".to_string()];
        assert_eq!(
            compare_ns(
                &chain(&["ns1-38.azure-dns.com", "a1-115.akam.net"]),
                &known,
                &ss()
            ),
            NsComparison::DifferentInfra,
        );
    }

    #[test]
    fn empty_chain() {
        let known = vec!["ns1.example.com".to_string()];
        assert_eq!(
            compare_ns(&chain(&[]), &known, &ss()),
            NsComparison::Unknown
        );
    }
}
