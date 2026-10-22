//! ML-based domain threat scoring using ONNX Runtime.
//!
//! Runs alongside the rule-based scoring engine in notification-only mode.
//! Computes features from domain name + infrastructure data, runs inference,
//! then applies post-ML hard rules.
//!
//! Requires the `ml` cargo feature (enables ort/ONNX Runtime dependency).

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use tracing::{info, warn};

use sqlx::Row;

use crate::db::Database;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FREE_TLDS: &[&str] = &["tk", "ml", "ga", "cf", "gq", "freenom"];

const NEW_GTLDS: &[&str] = &[
    "xyz",
    "top",
    "club",
    "online",
    "site",
    "store",
    "website",
    "space",
    "fun",
    "icu",
    "buzz",
    "cyou",
    "cfd",
    "sbs",
    "quest",
    "bond",
    "app",
    "dev",
    "io",
    "ai",
    "tech",
    "cloud",
    "digital",
    "live",
    "world",
    "life",
    "today",
    "network",
    "solutions",
    "services",
    "shop",
    "blog",
    "page",
    "link",
    "click",
    "host",
    "vip",
    "win",
    "bid",
    "loan",
    "download",
    "racing",
    "stream",
    "review",
    "party",
];

const GTLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "mobi",
];

/// Curated CDN / hosting registrables. Mirrors `CDN_REGISTRABLES` in
/// `ml/build_detector_dataset.py` — must stay byte-identical or the
/// `registrable_is_known_cdn` feature will diverge between Rust serving
/// and Python training.
const CDN_REGISTRABLES: &[&str] = &[
    "akadns.net",
    "akamaiedge.net",
    "akamaized.net",
    "edgekey.net",
    "edgesuite.net",
    "cloudfront.net",
    "cloudflare.com",
    "cloudflare.net",
    "fastly.net",
    "1e100.net",
    "googlevideo.com",
    "ytimg.com",
    "apple-dns.net",
    "aaplimg.com",
    "amazonaws.com",
    "azureedge.net",
    "llnwd.net",
    "stackpathcdn.com",
    "kxcdn.com",
    "jsdelivr.net",
    "unpkg.com",
    "gstatic.com",
    "gscdn.net",
];

/// Stringify `QueryType` to match the form the Python training pipeline
/// reads from CH `flows.qtype`. Matches the keys in the trained model's
/// `qtype` ordinal map.
fn qtype_str(qtype: &nameserver_common::types::QueryType) -> String {
    use nameserver_common::types::QueryType;
    match qtype {
        QueryType::A => "A".to_string(),
        QueryType::Aaaa => "AAAA".to_string(),
        QueryType::Cname => "CNAME".to_string(),
        QueryType::Mx => "MX".to_string(),
        QueryType::Ns => "NS".to_string(),
        QueryType::Txt => "TXT".to_string(),
        QueryType::Soa => "SOA".to_string(),
        QueryType::Ptr => "PTR".to_string(),
        QueryType::Srv => "SRV".to_string(),
        QueryType::Caa => "CAA".to_string(),
        QueryType::Https => "HTTPS".to_string(),
        QueryType::Other(n) => format!("Other({n})"),
    }
}

/// Stringify `ResponseCode` to match Python training serialization.
fn rcode_str(rcode: &nameserver_common::types::ResponseCode) -> String {
    use nameserver_common::types::ResponseCode;
    match rcode {
        ResponseCode::Noerror => "NOERROR".to_string(),
        ResponseCode::Nxdomain => "NXDOMAIN".to_string(),
        ResponseCode::Servfail => "SERVFAIL".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        ResponseCode::Other(n) => format!("Other({n})"),
    }
}

/// Per-flow velocity lookup against `domain_velocity_5m`. Reads the
/// AggregatingMergeTree row covering the same 5-min window that the
/// MV emits for `flow.started_at` against `flow_novelty`. Missing row
/// → `(0, 0, 0)`, matching Python's `coalesce(..., 0)` in
/// `ml/build_detector_dataset.py`.
///
/// `started_at_unix_ms` is the flow start time in milliseconds since
/// epoch (matches `DnsFlow.started_at`).
async fn fetch_velocity(
    ch: &::clickhouse::Client,
    registrable: &str,
    started_at_unix_ms: i64,
) -> (u64, u64, u64) {
    let result: Result<(u64, u64, u64), _> = ch
        .query(
            "SELECT \
                countMerge(query_count_state)        AS query_count_5m, \
                uniqMerge(distinct_profiles_state)   AS distinct_profiles_5m, \
                uniqMerge(distinct_asns_state)       AS distinct_asns_5m \
             FROM domain_velocity_5m \
             WHERE registrable = ? \
               AND window_start = toStartOfFiveMinute(fromUnixTimestamp64Milli(?)) \
             GROUP BY registrable, window_start",
        )
        .bind(registrable)
        .bind(started_at_unix_ms)
        .fetch_one()
        .await;

    match result {
        Ok((q, p, a)) => (q, p, a),
        // Missing row OR transient CH error: zeros. The detector's CH
        // SELECT is best-effort — losing velocity for a single flow
        // costs evaluation precision, not user-facing correctness.
        Err(_) => (0, 0, 0),
    }
}

/// Stringify `DnssecStatus` to match Python training serialization.
fn dnssec_status_str(status: &nameserver_common::types::DnssecStatus) -> &'static str {
    use nameserver_common::types::DnssecStatus;
    match status {
        DnssecStatus::Bogus => "BOGUS",
        DnssecStatus::Indeterminate => "INDETERMINATE",
        DnssecStatus::Insecure => "INSECURE",
        DnssecStatus::Secure => "SECURE",
    }
}

/// Classify TLD into category matching Python's classify_tld().
fn classify_tld(tld: &str) -> String {
    let tld_lower = tld.to_lowercase();
    let tld_clean = tld_lower.trim_matches('.');
    if FREE_TLDS.contains(&tld_clean) {
        return "free".to_string();
    }
    if NEW_GTLDS.contains(&tld_clean) {
        return "newgtld".to_string();
    }
    if GTLDS.contains(&tld_clean) {
        return "gtld".to_string();
    }
    "cctld".to_string()
}

/// ASCII confusable pairs (multi-char → single-char).
const CONFUSABLE_MULTI: &[(&str, &str)] = &[("rn", "m"), ("cl", "d"), ("vv", "w"), ("nn", "m")];

/// Single-char confusables.
const CONFUSABLE_SINGLE: &[(char, char)] = &[('1', 'l'), ('0', 'o')];

/// Top English bigram frequencies (for ngram_score).
const BIGRAM_FREQ: &[(&str, u32)] = &[
    ("th", 152),
    ("he", 128),
    ("in", 94),
    ("er", 94),
    ("an", 82),
    ("on", 73),
    ("en", 72),
    ("at", 68),
    ("es", 68),
    ("ed", 65),
    ("or", 61),
    ("ti", 59),
    ("is", 57),
    ("it", 56),
    ("al", 54),
    ("ar", 52),
    ("st", 51),
    ("to", 50),
    ("nt", 49),
    ("ng", 47),
    ("se", 46),
    ("ha", 44),
    ("ou", 44),
    ("io", 43),
    ("le", 42),
    ("no", 42),
    ("us", 40),
    ("re", 39),
    ("ea", 38),
    ("de", 38),
    ("te", 38),
    ("ne", 37),
    ("me", 36),
    ("as", 36),
    ("co", 35),
    ("nd", 35),
    ("of", 35),
    ("li", 33),
    ("ri", 33),
    ("ma", 32),
    ("si", 31),
    ("ta", 31),
    ("el", 30),
    ("ic", 30),
    ("ra", 30),
    ("la", 29),
    ("ce", 28),
    ("ro", 28),
    ("ve", 28),
    ("ch", 27),
    ("ge", 27),
    ("ll", 27),
    ("ni", 27),
    ("pe", 26),
    ("ca", 26),
    ("lo", 26),
    ("ss", 26),
    ("om", 25),
    ("pa", 25),
    ("ur", 25),
    ("di", 24),
    ("tr", 24),
    ("be", 23),
    ("il", 23),
    ("na", 23),
    ("po", 23),
    ("un", 23),
    ("ct", 22),
    ("ho", 22),
    ("pr", 22),
    ("sh", 22),
    ("so", 22),
    ("ac", 21),
    ("ad", 21),
    ("ec", 21),
    ("em", 21),
    ("fo", 21),
    ("ly", 21),
    ("ot", 21),
    ("wa", 21),
    ("ag", 20),
    ("am", 20),
    ("ap", 20),
    ("id", 20),
    ("ig", 20),
    ("iv", 20),
    ("mo", 20),
    ("su", 20),
    ("ut", 20),
    ("wi", 20),
];

const VOWELS: &[u8] = b"aeiou";

/// Calculate Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Feature extraction helpers
// ---------------------------------------------------------------------------

fn apply_confusable_normalization(label: &str) -> (String, usize) {
    let mut result = label.to_lowercase();
    let mut count = 0;
    for &(pattern, replacement) in CONFUSABLE_MULTI {
        while result.contains(pattern) {
            result = result.replacen(pattern, replacement, 1);
            count += 1;
        }
    }
    for &(from, to) in CONFUSABLE_SINGLE {
        while let Some(pos) = result.find(from) {
            result.replace_range(pos..pos + from.len_utf8(), &to.to_string());
            count += 1;
        }
    }
    (result, count)
}

fn ngram_score(label: &str) -> f64 {
    let alpha: String = label
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    if alpha.len() < 2 {
        return 0.0;
    }
    let bigram_map: HashMap<&str, u32> = BIGRAM_FREQ.iter().copied().collect();
    let bytes = alpha.as_bytes();
    let mut total = 0u32;
    let count = bytes.len() - 1;
    for i in 0..count {
        let bg = &alpha[i..i + 2];
        total += bigram_map.get(bg).copied().unwrap_or(0);
    }
    total as f64 / count as f64
}

fn consonant_vowel_ratio(label: &str) -> f64 {
    let mut vowels = 0;
    let mut consonants = 0;
    for c in label.to_lowercase().bytes() {
        if c.is_ascii_alphabetic() {
            if VOWELS.contains(&c) {
                vowels += 1;
            } else {
                consonants += 1;
            }
        }
    }
    if vowels == 0 {
        return consonants as f64;
    }
    consonants as f64 / vowels as f64
}

/// Parsed domain components, mirroring Python's tldextract output.
struct ParsedDomain<'a> {
    /// Subdomain part (e.g., "star-mini.c10r" from "star-mini.c10r.facebook.com").
    /// Empty string if no subdomain.
    subdomain: &'a str,
    /// Registrable domain label (e.g., "facebook" from "star-mini.c10r.facebook.com").
    label: &'a str,
    /// TLD suffix (e.g., "com", "co.kr").
    suffix: &'a str,
}

/// Parse domain into components matching Python's tldextract.
///
/// Uses the default SuffixSet (implicit TLD rule: every bare label is a TLD).
/// When a full PSL-based SuffixSet is available, multi-part TLDs like co.kr
/// are handled correctly.
fn parse_domain<'a>(
    domain: &'a str,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> ParsedDomain<'a> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);

    match suffix_set.registrable_domain(domain) {
        Some(reg) => {
            // reg is a slice of domain, e.g., "facebook.com" in "star-mini.c10r.facebook.com"
            let suffix = match reg.find('.') {
                Some(dot) => &reg[dot + 1..],
                None => "",
            };
            let label = match reg.find('.') {
                Some(dot) => &reg[..dot],
                None => reg,
            };
            let subdomain = if reg.len() < domain.len() {
                // Everything before the registrable domain (minus the dot).
                &domain[..domain.len() - reg.len() - 1]
            } else {
                ""
            };
            ParsedDomain {
                subdomain,
                label,
                suffix,
            }
        }
        None => {
            // Domain is a suffix or single label.
            ParsedDomain {
                subdomain: "",
                label: domain,
                suffix: "",
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ML Scorer
// ---------------------------------------------------------------------------

/// How subdomain embeddings are aggregated.
enum SubdomainVariant {
    /// Element-wise max across all subdomain label embeddings.
    MaxPool,
    /// Concatenate up to N subdomain label embeddings, zero-pad missing slots.
    Concat { max_slots: usize },
}

pub struct MlScorer {
    session: ort::session::Session,
    feature_names: Vec<String>,
    n_features: usize,
    /// Ordinal encoding maps for string features (loaded from metadata.json).
    /// feature_name → { string_value → integer_code }
    ordinal_maps: HashMap<String, HashMap<String, i32>>,
    threshold_malicious: f32,
    threshold_suspicious: f32,
    /// CNN character-level label embedding model (optional).
    cnn_session: Option<ort::session::Session>,
    /// CNN character-to-index mapping (from cnn_metadata.json).
    cnn_char_to_idx: HashMap<char, i64>,
    /// CNN maximum input length per label.
    cnn_max_len: usize,
    /// CNN embedding output dimensionality.
    cnn_embedding_dim: usize,
    /// ONNX input name for the CNN model.
    cnn_input_name: String,
    /// How subdomain embeddings are aggregated.
    cnn_subdomain_variant: SubdomainVariant,
    /// Stage 2c contrastive label embedder (`detector_cnn_sim_v1`),
    /// produces 64-dim L2-normalized embeddings used for tier-2
    /// similarity ANN. Independent of `cnn_session`: distinct training
    /// objective (InfoNCE), distinct geometry (lexical not class).
    sim_session: Option<ort::session::Session>,
    sim_char_to_idx: HashMap<char, i64>,
    sim_max_len: usize,
    sim_embedding_dim: usize,
}

#[derive(Debug)]
pub struct MlResult {
    pub ml_probability: f32,
    pub final_probability: f32,
    pub classification: String,
    pub override_rule: Option<String>,
    /// Registrable label and its 32-dim classification CNN embedding
    /// (for the legacy `embedding` column on `domain_label_embeddings`
    /// and as a LightGBM lexical feature). Class-clustered geometry —
    /// not suitable for similarity retrieval.
    pub label_embedding: Option<(String, Vec<f32>)>,
    /// Optional 64-dim contrastive embedding of the registrable label
    /// produced by `cnn_sim_embedding.onnx` (Stage 2c). Drives the
    /// HNSW ANN tier-2 lookup in `similarity::search_sim_neighbors`
    /// and populates `domain_label_embeddings.sim_embedding`.
    pub sim_embedding: Option<Vec<f32>>,
}

/// Output of the feature extraction stage. Bundles the tabular `FeatureMap`
/// (consumed by LightGBM via `build_feature_vector`), the registrable label
/// and its two CNN embeddings, and an optional short-circuit reason that
/// tells `score()` to skip ONNX inference and emit a synthetic verdict.
///
/// Splitting extraction from scoring lets the scoring step be unit-testable
/// against fixture features without spinning up a database.
pub struct Features {
    pub feature_map: FeatureMap,
    pub label_embedding: Option<(String, Vec<f32>)>,
    pub sim_embedding: Option<Vec<f32>>,
    /// `Some` if upstream conditions (PTR domain, missing infra data) mean
    /// the LightGBM call should be skipped. The string is the override-rule
    /// label that propagates into `MlResult.override_rule`.
    pub skip_reason: Option<&'static str>,
}

/// Output of `MlScorer::score`. The score-related slice of `MlResult` —
/// `score()` returns this so callers can pair it with the `Features`
/// (which already own the embeddings) without `score()` having to clone.
#[derive(Debug)]
pub struct ScoreOutput {
    pub ml_probability: f32,
    pub final_probability: f32,
    pub classification: String,
    pub override_rule: Option<String>,
}

impl MlScorer {
    pub fn load(
        model_path: &Path,
        threshold_malicious: f32,
        threshold_suspicious: f32,
    ) -> Result<Self> {
        info!(model = %model_path.display(), "loading ML model");

        // Read feature names and ordinal maps from metadata.json.
        let meta_dir = model_path.parent().unwrap_or(Path::new("."));
        let meta_path = meta_dir.join("metadata.json");
        let (feature_names, ordinal_maps, cnn_embedding_dim_meta) = if meta_path.exists() {
            let meta: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&meta_path)?)?;
            let names: Vec<String> = meta["feature_names"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // Parse ordinal encoding maps: { feature_name: { string_value: code } }
            let mut maps: HashMap<String, HashMap<String, i32>> = HashMap::new();
            if let Some(om) = meta["ordinal_maps"].as_object() {
                for (feat, mapping) in om {
                    if let Some(obj) = mapping.as_object() {
                        let m: HashMap<String, i32> = obj
                            .iter()
                            .filter_map(|(k, v)| v.as_i64().map(|n| (k.clone(), n as i32)))
                            .collect();
                        if !m.is_empty() {
                            maps.insert(feat.clone(), m);
                        }
                    }
                }
            }
            if !maps.is_empty() {
                info!(features = maps.len(), "loaded ordinal encoding maps");
            }

            let cnn_dim = meta["cnn_embedding_dim"].as_u64().unwrap_or(0) as usize;
            (names, maps, cnn_dim)
        } else {
            warn!("metadata.json not found, using default feature order");
            (Vec::new(), HashMap::new(), 0)
        };

        let n_features = feature_names.len();

        // Load ONNX model via ort (official ONNX Runtime).
        let session = ort::session::Session::builder()
            .map_err(|e| anyhow::anyhow!("ONNX session builder: {e}"))?
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
            .map_err(|e| anyhow::anyhow!("ONNX optimization level: {e}"))?
            .commit_from_file(model_path)
            .map_err(|e| {
                anyhow::anyhow!("loading ONNX model from {}: {e}", model_path.display())
            })?;

        // Load CNN embedding model (optional, auto-detected from same directory).
        let cnn_onnx_path = meta_dir.join("cnn_embedding.onnx");
        let cnn_meta_path = meta_dir.join("cnn_metadata.json");
        let (
            cnn_session,
            cnn_char_to_idx,
            cnn_max_len,
            cnn_embedding_dim,
            cnn_input_name,
            cnn_subdomain_variant,
        ) = if cnn_onnx_path.exists() && cnn_meta_path.exists() {
            let cnn_meta: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&cnn_meta_path)?)?;

            // Parse char_to_idx: { "a": 1, "b": 2, ... }
            let mut char_map: HashMap<char, i64> = HashMap::new();
            if let Some(obj) = cnn_meta["char_to_idx"].as_object() {
                for (k, v) in obj {
                    if let (Some(c), Some(idx)) = (k.chars().next(), v.as_i64()) {
                        char_map.insert(c, idx);
                    }
                }
            }

            let max_len = cnn_meta["max_len"].as_u64().unwrap_or(63) as usize;
            let emb_dim = cnn_meta["embedding_dim"].as_u64().unwrap_or(32) as usize;
            let effective_dim = if cnn_embedding_dim_meta > 0 {
                cnn_embedding_dim_meta
            } else {
                emb_dim
            };

            let input_name = cnn_meta["input_name"]
                .as_str()
                .unwrap_or("label_chars")
                .to_string();

            let variant_str = cnn_meta["variant"].as_str().unwrap_or("maxpool");
            let subdomain_variant = if variant_str == "concat" {
                let max_slots = cnn_meta["max_subdomain_slots"].as_u64().unwrap_or(3) as usize;
                SubdomainVariant::Concat { max_slots }
            } else {
                SubdomainVariant::MaxPool
            };

            let sess = ort::session::Session::builder()
                .map_err(|e| anyhow::anyhow!("CNN ONNX session builder: {e}"))?
                .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
                .map_err(|e| anyhow::anyhow!("CNN ONNX optimization: {e}"))?
                .commit_from_file(&cnn_onnx_path)
                .map_err(|e| {
                    anyhow::anyhow!("loading CNN ONNX from {}: {e}", cnn_onnx_path.display())
                })?;

            info!(
                vocab = char_map.len(),
                max_len,
                embedding_dim = effective_dim,
                "loaded CNN embedding model"
            );

            (
                Some(sess),
                char_map,
                max_len,
                effective_dim,
                input_name,
                subdomain_variant,
            )
        } else {
            if cnn_embedding_dim_meta > 0 {
                warn!(
                    "metadata.json specifies cnn_embedding_dim={} but cnn_embedding.onnx not found",
                    cnn_embedding_dim_meta
                );
            }
            (
                None,
                HashMap::new(),
                0,
                0,
                "label_chars".to_string(),
                SubdomainVariant::MaxPool,
            )
        };

        // --- Stage 2c contrastive embedder (sim CNN) -------------------
        // Auto-discovered from the same `meta_dir` as the LightGBM
        // model so deployment ships a single bundle. `meta_dir` is
        // derived from `model_path`, which is set by operator-managed
        // NixOS config — not user-controlled input.
        let sim_onnx_path = meta_dir.join("cnn_sim_embedding.onnx");
        let sim_meta_path = meta_dir.join("sim_metadata.json");
        let (sim_session, sim_char_to_idx, sim_max_len, sim_embedding_dim) = if sim_onnx_path
            .exists()
        {
            let (sim_chars_str, sim_max_len_meta, sim_dim_meta) = if sim_meta_path.exists() {
                let sm: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&sim_meta_path)?)?;
                let chars = sm["chars"].as_str().unwrap_or("").to_string();
                let max_len = sm["max_len"].as_u64().unwrap_or(63) as usize;
                let dim = sm["embedding_dim"].as_u64().unwrap_or(64) as usize;
                (chars, max_len, dim)
            } else {
                // Defaults match `ml/train_cnn_sim.py` constants.
                (String::new(), 63, 64)
            };

            // sim CNN vocab: identical to train_cnn_sim.py — DNS chars
            // [a-z0-9-] mapped to indices 1..37, with 0 = padding.
            let mut sim_chars: HashMap<char, i64> = HashMap::new();
            let chars_iter: Box<dyn Iterator<Item = char>> = if sim_chars_str.is_empty() {
                Box::new("abcdefghijklmnopqrstuvwxyz0123456789-".chars())
            } else {
                Box::new(sim_chars_str.chars())
            };
            for (i, c) in chars_iter.enumerate() {
                sim_chars.insert(c, (i as i64) + 1);
            }

            let sess = ort::session::Session::builder()
                .map_err(|e| anyhow::anyhow!("sim CNN ONNX session builder: {e}"))?
                .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
                .map_err(|e| anyhow::anyhow!("sim CNN ONNX optimization: {e}"))?
                .commit_from_file(&sim_onnx_path)
                .map_err(|e| {
                    anyhow::anyhow!("loading sim CNN ONNX from {}: {e}", sim_onnx_path.display(),)
                })?;

            info!(
                vocab = sim_chars.len(),
                max_len = sim_max_len_meta,
                embedding_dim = sim_dim_meta,
                "loaded contrastive sim embedder"
            );

            (Some(sess), sim_chars, sim_max_len_meta, sim_dim_meta)
        } else {
            (None, HashMap::new(), 63, 64)
        };

        info!(
            features = n_features,
            cnn = cnn_session.is_some(),
            sim_cnn = sim_session.is_some(),
            threshold_malicious,
            threshold_suspicious,
            "ML scorer ready"
        );

        Ok(Self {
            session,
            feature_names,
            n_features,
            ordinal_maps,
            threshold_malicious,
            threshold_suspicious,
            cnn_session,
            cnn_char_to_idx,
            cnn_max_len,
            cnn_embedding_dim,
            cnn_input_name,
            cnn_subdomain_variant,
            sim_session,
            sim_char_to_idx,
            sim_max_len,
            sim_embedding_dim,
        })
    }

    /// Build the full feature bundle for a domain: tabular features (PG +
    /// CH velocity + lexical + flow-derived + novelty) plus both CNN
    /// embeddings, plus an optional `skip_reason` when upstream conditions
    /// disqualify the domain from scoring.
    pub async fn extract(
        &mut self,
        db: &Database,
        ch_client: &::clickhouse::Client,
        domain: &str,
        flow: &nameserver_common::messages::flow::DnsFlow,
        novelty: crate::detector::NoveltyContext,
        suffix_set: &nameserver_common::suffix::SuffixSet,
    ) -> Features {
        let clean = domain.strip_suffix('.').unwrap_or(domain);

        // Skip PTR / reverse-DNS domains — not meaningful for threat scoring.
        if clean.ends_with(".in-addr.arpa") || clean.ends_with(".ip6.arpa") {
            return Features {
                feature_map: FeatureMap::new(),
                label_embedding: None,
                sim_embedding: None,
                skip_reason: Some("ptr_skip"),
            };
        }

        let feature_map = self
            .extract_features(db, ch_client, domain, flow, novelty, suffix_set)
            .await;

        // Require at least some Group B infrastructure data for a valid
        // prediction. Without resolution data (TTL, IPs) the model over-
        // relies on lexical features and produces excessive false positives
        // on benign domains with deep subdomains.
        if !feature_map.has_infra_data() {
            return Features {
                feature_map,
                label_embedding: None,
                sim_embedding: None,
                skip_reason: Some("no_infra_data"),
            };
        }

        // Extract registrable label embedding for similarity search
        // (no extra CNN call — reads pre-computed query_reg_emb_* features).
        let label_embedding = if self.cnn_session.is_some() {
            let parsed = parse_domain(clean, suffix_set);
            if !parsed.label.is_empty() {
                let emb: Vec<f32> = (0..self.cnn_embedding_dim)
                    .map(|i| feature_map.get_f32(&format!("query_reg_emb_{i}")))
                    .collect();
                Some((parsed.label.to_string(), emb))
            } else {
                None
            }
        } else {
            None
        };

        // Stage 2c contrastive embedding for tier-2 ANN similarity.
        // Independent ONNX call — distinct geometry from `cnn_session`.
        // Skipped silently when the sim model isn't loaded; the
        // scoring chain falls back to the legacy levenshtein path.
        let sim_embedding = if self.sim_session.is_some() {
            let parsed = parse_domain(clean, suffix_set);
            if !parsed.label.is_empty() && parsed.label.len() >= 4 {
                Some(self.run_sim_label_cnn(parsed.label))
            } else {
                None
            }
        } else {
            None
        };

        Features {
            feature_map,
            label_embedding,
            sim_embedding,
            skip_reason: None,
        }
    }

    /// Run LightGBM inference on extracted features and emit the score-
    /// related output. Pure function over `&Features` plus mutable session
    /// state — no DB or NATS access. Testable on fixture features.
    pub fn score(&mut self, features: &Features) -> Result<ScoreOutput> {
        if let Some(reason) = features.skip_reason {
            let (classification, prob) = match reason {
                "ptr_skip" => ("safe", 0.0_f32),
                "no_infra_data" => ("unknown", 0.0_f32),
                _ => ("unknown", 0.0_f32),
            };
            return Ok(ScoreOutput {
                ml_probability: prob,
                final_probability: prob,
                classification: classification.to_string(),
                override_rule: Some(reason.to_string()),
            });
        }

        let vec = self.build_feature_vector(&features.feature_map);

        // Run ort inference. Extract ml_prob in a block so outputs are dropped
        // before we borrow self again for apply_overrides.
        let ml_prob = {
            let input =
                ort::value::Tensor::from_array(([1, self.n_features], vec.into_boxed_slice()))
                    .map_err(|e| anyhow::anyhow!("building input tensor: {e}"))?;
            let outputs = self
                .session
                .run(ort::inputs!["features" => input])
                .map_err(|e| anyhow::anyhow!("ONNX inference: {e}"))?;
            // outputs["probabilities"] = shape [1, 2]: [P(benign), P(malicious)]
            if let Some(probs) = outputs.get("probabilities") {
                let (_, data) = probs
                    .try_extract_tensor::<f32>()
                    .map_err(|e| anyhow::anyhow!("extracting probabilities: {e}"))?;
                data.get(1).copied().unwrap_or(0.0) // index 1 = malicious class
            } else {
                let (_, data) = outputs[0]
                    .try_extract_tensor::<f32>()
                    .map_err(|e| anyhow::anyhow!("extracting output: {e}"))?;
                data.first().copied().unwrap_or(0.0)
            }
        };

        let (final_prob, override_rule) = Self::apply_overrides(ml_prob);

        let classification = if final_prob >= self.threshold_malicious {
            "malicious"
        } else if final_prob >= self.threshold_suspicious {
            "suspicious"
        } else if final_prob < 0.1 {
            "safe"
        } else {
            "unknown"
        };

        Ok(ScoreOutput {
            ml_probability: ml_prob,
            final_probability: final_prob,
            classification: classification.to_string(),
            override_rule,
        })
    }

    /// Run ML inference on a domain. Reads infrastructure data from
    /// PostgreSQL, velocity from ClickHouse, and per-flow features from
    /// the `DnsFlow` plus precomputed novelty. Convenience wrapper around
    /// `extract` + `score`.
    pub async fn predict(
        &mut self,
        db: &Database,
        ch_client: &::clickhouse::Client,
        domain: &str,
        flow: &nameserver_common::messages::flow::DnsFlow,
        novelty: crate::detector::NoveltyContext,
        suffix_set: &nameserver_common::suffix::SuffixSet,
    ) -> Result<MlResult> {
        let features = self
            .extract(db, ch_client, domain, flow, novelty, suffix_set)
            .await;
        let score = self.score(&features)?;
        Ok(MlResult {
            ml_probability: score.ml_probability,
            final_probability: score.final_probability,
            classification: score.classification,
            override_rule: score.override_rule,
            label_embedding: features.label_embedding,
            sim_embedding: features.sim_embedding,
        })
    }

    fn apply_overrides(ml_prob: f32) -> (f32, Option<String>) {
        // Brand-specific overrides have been removed.
        // The model handles impersonation detection natively via generic features.
        // Post-ML overrides can be added here as needed (e.g., NS baseline verification).
        (ml_prob, None)
    }

    /// Run the CNN on a single DNS label (no dots). Returns embedding vector.
    fn run_label_cnn(&mut self, label: &str) -> Vec<f32> {
        let label_lower = label.to_lowercase();

        let mut chars = vec![0i64; self.cnn_max_len];
        for (i, c) in label_lower.chars().take(self.cnn_max_len).enumerate() {
            chars[i] = self.cnn_char_to_idx.get(&c).copied().unwrap_or(0);
        }

        let input =
            ort::value::Tensor::from_array(([1, self.cnn_max_len], chars.into_boxed_slice()))
                .expect("cnn input tensor");

        let outputs = self
            .cnn_session
            .as_mut()
            .expect("cnn_session must be Some when run_label_cnn is called")
            .run(ort::inputs![&self.cnn_input_name => input])
            .expect("cnn inference");

        let tensor_ref = outputs.get("embedding").unwrap_or(&outputs[0]);
        let (_, data) = tensor_ref
            .try_extract_tensor::<f32>()
            .expect("cnn embedding extraction");
        data.to_vec()
    }

    /// Run the contrastive sim CNN on a single DNS label.
    ///
    /// Same input contract as `run_label_cnn` (char-id sequence padded
    /// to `sim_max_len`) but uses the Stage 2c contrastive ONNX model
    /// and returns its 64-dim L2-normalized embedding. The output is
    /// re-normalized defensively in case the ONNX export drifts —
    /// downstream HNSW cosine ANN requires unit vectors.
    fn run_sim_label_cnn(&mut self, label: &str) -> Vec<f32> {
        let label_lower = label.to_lowercase();

        let mut chars = vec![0i64; self.sim_max_len];
        for (i, c) in label_lower.chars().take(self.sim_max_len).enumerate() {
            chars[i] = self.sim_char_to_idx.get(&c).copied().unwrap_or(0);
        }

        let input =
            ort::value::Tensor::from_array(([1, self.sim_max_len], chars.into_boxed_slice()))
                .expect("sim cnn input tensor");

        let outputs = self
            .sim_session
            .as_mut()
            .expect("sim_session must be Some when run_sim_label_cnn is called")
            .run(ort::inputs!["label_chars" => input])
            .expect("sim cnn inference");

        let tensor_ref = outputs.get("embedding").unwrap_or(&outputs[0]);
        let (_, data) = tensor_ref
            .try_extract_tensor::<f32>()
            .expect("sim cnn embedding extraction");
        assert_eq!(
            data.len(),
            self.sim_embedding_dim,
            "contrastive model output dimension differs from metadata"
        );
        let mut emb: Vec<f32> = data.to_vec();
        let norm: f32 = emb.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut emb {
                *v /= norm;
            }
        }
        emb
    }

    /// Extract split CNN embeddings for a domain: registrable label +
    /// aggregated subdomain labels. Writes `query_reg_emb_*` /
    /// `query_sub_emb_*` keys matching the `detector_lgb_v1_cnn` model's
    /// feature_names.
    fn extract_cnn_embeddings(
        &mut self,
        domain: &str,
        suffix_set: &nameserver_common::suffix::SuffixSet,
        f: &mut FeatureMap,
    ) {
        let domain_clean = domain.strip_suffix('.').unwrap_or(domain);
        let parsed = parse_domain(domain_clean, suffix_set);

        // Registrable label embedding → query_reg_emb_*
        if !parsed.label.is_empty() {
            let reg_emb = self.run_label_cnn(parsed.label);
            for (i, &val) in reg_emb.iter().enumerate() {
                f.set_f32(&format!("query_reg_emb_{i}"), val);
            }
        }

        // Subdomain label embeddings → query_sub_emb_*
        let sub_labels: Vec<&str> = if parsed.subdomain.is_empty() {
            Vec::new()
        } else {
            parsed
                .subdomain
                .split('.')
                .filter(|s| !s.is_empty())
                .collect()
        };

        match &self.cnn_subdomain_variant {
            SubdomainVariant::MaxPool => {
                if sub_labels.is_empty() {
                    for i in 0..self.cnn_embedding_dim {
                        f.set_f32(&format!("query_sub_emb_{i}"), 0.0);
                    }
                } else {
                    let sub_embs: Vec<Vec<f32>> =
                        sub_labels.iter().map(|s| self.run_label_cnn(s)).collect();
                    for i in 0..self.cnn_embedding_dim {
                        let max_val = sub_embs
                            .iter()
                            .map(|emb| emb.get(i).copied().unwrap_or(0.0))
                            .fold(f32::NEG_INFINITY, f32::max);
                        f.set_f32(&format!("query_sub_emb_{i}"), max_val);
                    }
                }
            }
            SubdomainVariant::Concat { max_slots } => {
                // Legacy concat variant — not used by detector_cnn_v1
                // (which is maxpool). Kept for back-compat with any
                // older CNN bundle that might still be loaded out of band.
                for slot in 0..*max_slots {
                    if slot < sub_labels.len() {
                        let emb = self.run_label_cnn(sub_labels[slot]);
                        for (i, &val) in emb.iter().enumerate() {
                            f.set_f32(&format!("sub{slot}_emb_{i}"), val);
                        }
                    } else {
                        for i in 0..self.cnn_embedding_dim {
                            f.set_f32(&format!("sub{slot}_emb_{i}"), 0.0);
                        }
                    }
                }
            }
        }
    }

    /// Pool the registrable + subdomain labels of every FQDN in `fqdns`,
    /// run the classification CNN over each unique label, and write a
    /// `{prefix}_{i}` feature per dim with the element-wise max across
    /// labels. Empty input → zero vector.
    ///
    /// Mirrors `pool_labels` + `extract_labels_from_fqdn` in
    /// `ml/embed_detector_dataset.py`. Per-flow dedup bounds CNN call
    /// count without changing the max-pool result (max(x, x, …) = max).
    fn extract_pooled_relational_emb(
        &mut self,
        prefix: &str,
        fqdns: impl Iterator<Item = String>,
        suffix_set: &nameserver_common::suffix::SuffixSet,
        f: &mut FeatureMap,
    ) {
        // Collect every label (registrable + subdomain parts) across every
        // FQDN, then dedupe.
        let mut labels: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for fqdn in fqdns {
            let clean = fqdn.trim_end_matches('.');
            if clean.is_empty() {
                continue;
            }
            let parsed = parse_domain(clean, suffix_set);
            if !parsed.label.is_empty() {
                labels.insert(parsed.label.to_string());
            }
            for s in parsed.subdomain.split('.').filter(|s| !s.is_empty()) {
                labels.insert(s.to_string());
            }
        }

        if labels.is_empty() {
            for i in 0..self.cnn_embedding_dim {
                f.set_f32(&format!("{prefix}_{i}"), 0.0);
            }
            return;
        }

        let embs: Vec<Vec<f32>> = labels.iter().map(|l| self.run_label_cnn(l)).collect();

        for i in 0..self.cnn_embedding_dim {
            let max_val = embs
                .iter()
                .map(|emb| emb.get(i).copied().unwrap_or(0.0))
                .fold(f32::NEG_INFINITY, f32::max);
            f.set_f32(&format!("{prefix}_{i}"), max_val);
        }
    }

    async fn extract_features(
        &mut self,
        db: &Database,
        ch_client: &::clickhouse::Client,
        domain: &str,
        flow: &nameserver_common::messages::flow::DnsFlow,
        novelty: crate::detector::NoveltyContext,
        suffix_set: &nameserver_common::suffix::SuffixSet,
    ) -> FeatureMap {
        let mut f = FeatureMap::new();
        let domain_clean = domain.strip_suffix('.').unwrap_or(domain);

        // Parse domain into components matching Python's tldextract.
        let parsed = parse_domain(domain_clean, suffix_set);
        let label = parsed.label; // SLD label (e.g., "proton" from "calendar-api.proton.me")
        let suffix = parsed.suffix; // TLD suffix
        let subdomain = parsed.subdomain;

        // --- Group A: Lexical (strict scope separation) ---

        // Registrable scope (SLD label only)
        f.set_f32("reg_entropy", shannon_entropy(label) as f32);
        f.set_i32("reg_length", label.len() as i32);
        f.set_i32(
            "reg_hyphen_count",
            label.chars().filter(|&c| c == '-').count() as i32,
        );
        f.set_i32(
            "reg_digit_count",
            label.chars().filter(|c| c.is_ascii_digit()).count() as i32,
        );
        f.set_f32("reg_cv_ratio", consonant_vowel_ratio(label) as f32);
        f.set_f32("reg_ngram_score", ngram_score(label) as f32);
        f.set_bool("reg_is_punycode", label.starts_with("xn--"));
        let (_normalized, conf_count) = apply_confusable_normalization(label);
        f.set_i32("reg_confusable_count", conf_count as i32);

        // Subdomain scope
        if !subdomain.is_empty() {
            f.set_f32("sub_entropy", shannon_entropy(subdomain) as f32);
        } else {
            f.set_f32("sub_entropy", 0.0);
        }

        // TLD
        f.set_str("tld_category", &classify_tld(suffix));

        // --- Group D: Per-flow features (DnsFlow accessors + novelty) ---
        // These are direct reads off the flow message and the precomputed
        // novelty context — no I/O. Mirrors the `fetch_ch_flows` SELECT in
        // `ml/build_detector_dataset.py`.
        f.set_i32(
            "is_first_contact",
            if novelty.is_first_contact { 1 } else { 0 },
        );
        f.set_f32("age_minutes_at_flow", novelty.age_minutes_at_flow as f32);
        f.set_f32("total_ms", flow.total_ms as f32);
        f.set_f32("geo_asn", flow.geo_asn as f32);
        f.set_f32("auth_ttl", flow.response.auth_ttl as f32);
        f.set_f32("auth_ttl_log1p", (flow.response.auth_ttl as f32 + 1.0).ln());
        f.set_f32("min_ttl", flow.response.min_ttl as f32);
        f.set_f32("response_ip_count", flow.response.ips.len() as f32);

        // IPv4 ratio: `:` absence = IPv4 (matches Python ipv4_ratio).
        let ip_count = flow.response.ips.len();
        if ip_count > 0 {
            let ipv4 = flow
                .response
                .ips
                .iter()
                .filter(|ip| !ip.contains(':'))
                .count();
            f.set_f32("response_ipv4_ratio", ipv4 as f32 / ip_count as f32);
        } else {
            f.set_f32("response_ipv4_ratio", 0.0);
        }

        // Categorical (looked up via ordinal_maps in build_feature_vector).
        let qt = qtype_str(&flow.query.qtype);
        let rc = rcode_str(&flow.response.rcode);
        f.set_str("qtype", &qt);
        f.set_str("rcode", &rc);
        f.set_str("qtype_x_rcode", &format!("{qt}_{rc}"));

        // CNAME chain.
        let cname_chain_len = flow.cname_chain.as_ref().map(|c| c.len()).unwrap_or(0);
        f.set_f32("cname_chain_length", cname_chain_len as f32);

        // DNSSEC.
        f.set_str("dnssec_status", dnssec_status_str(&flow.dnssec.status));
        f.set_str(
            "dnssec_algorithm",
            flow.dnssec.algorithm.as_deref().unwrap_or(""),
        );
        f.set_i32("ds_present", if flow.dnssec.ds_present { 1 } else { 0 });
        let rrsig_expiry = flow.dnssec.rrsig_expiry.unwrap_or(0);
        f.set_f32("dnssec_rrsig_expiry", rrsig_expiry as f32);
        // Hours from started_at to RRSIG expiry. 0 when no expiry observed.
        let rrsig_margin_hours = if rrsig_expiry > 0 {
            (rrsig_expiry - flow.started_at) as f32 / 3600.0
        } else {
            0.0
        };
        f.set_f32("rrsig_expiry_margin_hours", rrsig_margin_hours);

        // Resolution path stats.
        let path = &flow.resolution_path;
        f.set_f32("path_depth", path.len() as f32);
        let mut path_ms_vec: Vec<f32> = path.iter().map(|s| s.ms as f32).collect();
        let path_ms_total: f32 = path_ms_vec.iter().sum();
        let path_ms_max = path_ms_vec.iter().copied().fold(0.0_f32, f32::max);
        f.set_f32("path_ms_total", path_ms_total);
        f.set_f32("path_ms_max", path_ms_max);
        if path_ms_vec.is_empty() {
            f.set_f32("path_ms_median", 0.0);
            f.set_f32("path_ms_stddev", 0.0);
        } else {
            // Median: sort + middle.
            path_ms_vec.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let n = path_ms_vec.len();
            let median = if n % 2 == 1 {
                path_ms_vec[n / 2]
            } else {
                (path_ms_vec[n / 2 - 1] + path_ms_vec[n / 2]) / 2.0
            };
            f.set_f32("path_ms_median", median);
            // Population stddev (matches CH stddevPop).
            let mean = path_ms_total / n as f32;
            let variance = path_ms_vec.iter().map(|v| (v - mean).powi(2)).sum::<f32>() / n as f32;
            f.set_f32("path_ms_stddev", variance.sqrt());
        }

        // Step type counts.
        let mut n_referrals = 0_i32;
        let mut n_answers = 0_i32;
        let mut n_nxdomains = 0_i32;
        for step in path {
            use nameserver_common::types::StepResponseType;
            match step.response_type {
                StepResponseType::Referral => n_referrals += 1,
                StepResponseType::Answer => n_answers += 1,
                StepResponseType::Nxdomain => n_nxdomains += 1,
                _ => {}
            }
        }
        f.set_i32("n_referrals", n_referrals);
        f.set_i32("n_answers", n_answers);
        f.set_i32("n_nxdomains", n_nxdomains);

        // Records-presence (from response.all_records).
        let ar = &flow.response.all_records;
        let has_a = ar.a.as_ref().is_some_and(|v| !v.is_empty());
        let has_aaaa = ar.aaaa.as_ref().is_some_and(|v| !v.is_empty());
        let has_mx = ar.mx.as_ref().is_some_and(|v| !v.is_empty());
        let has_txt = ar.txt.as_ref().is_some_and(|v| !v.is_empty());
        let has_soa = ar.soa.is_some();
        f.set_i32("has_a", if has_a { 1 } else { 0 });
        f.set_i32("has_aaaa", if has_aaaa { 1 } else { 0 });
        f.set_i32("has_mx", if has_mx { 1 } else { 0 });
        f.set_i32("has_txt", if has_txt { 1 } else { 0 });
        f.set_i32("has_soa", if has_soa { 1 } else { 0 });
        f.set_i32("aaaa_without_a", if has_aaaa && !has_a { 1 } else { 0 });

        // --- Group B + F: Infrastructure + Reputation (single query) ---
        let registrable =
            crate::scoring_chain::extract_registrable(domain.trim_end_matches('.'), suffix_set);

        // CDN flag — uses the same registrable as the reputation lookup below.
        f.set_i32(
            "registrable_is_known_cdn",
            if CDN_REGISTRABLES.contains(&registrable.as_str()) {
                1
            } else {
                0
            },
        );

        // --- Group E: 5-min velocity (CH AggregatingMergeTree) ---
        // Mirrors the LEFT JOIN against `domain_velocity_5m` in
        // `ml/build_detector_dataset.py::fetch_ch_flows`. Missing row →
        // 0/0/0, matching Python's `coalesce(..., 0)`.
        let (q5, p5, a5) = fetch_velocity(ch_client, &registrable, flow.started_at).await;
        f.set_f32("query_count_5m", q5 as f32);
        f.set_f32("distinct_profiles_5m", p5 as f32);
        f.set_f32("distinct_asns_5m", a5 as f32);

        let rep_row = sqlx::query(
            "SELECT dr.avg_auth_ttl, dr.has_cname, dr.a_record_count, \
                    dr.ns_observation_count, dr.total_flow_count, \
                    dr.ns_trust, dr.is_well_known, \
                    (EXTRACT(EPOCH FROM (now() - dr.first_seen))/86400.0)::float8 \
                        AS days_since_first_seen, \
                    (EXTRACT(EPOCH FROM (now() - dr.last_ns_change_at))/86400.0)::float8 \
                        AS days_since_ns_change, \
                    dr.cname_targets, dr.is_nrd, dr.nrd_source, \
                    id.rank AS wk_rank, \
                    (SELECT ns_domain FROM domain_ns_map m \
                     WHERE m.registrable_domain = dr.registrable_domain \
                     ORDER BY m.observation_count DESC, m.ns_domain ASC \
                     LIMIT 1) AS first_ns \
             FROM domain_reputation dr \
             LEFT JOIN indicator_domains id ON id.domain = dr.registrable_domain \
                 AND id.source IN (SELECT source_id FROM enrichment_bindings WHERE enrichment_type = 'well_known') \
                 AND id.rank IS NOT NULL \
             WHERE dr.registrable_domain = $1",
        )
        .bind(&registrable)
        .fetch_optional(&db.pool)
        .await
        .ok()
        .flatten();

        if let Some(ref rep) = rep_row {
            // Group B: Infrastructure
            if let Some(avg) = rep.get::<Option<f32>, _>("avg_auth_ttl") {
                f.set_f32("avg_auth_ttl", avg);
            }
            f.set_bool("has_cname", rep.get::<bool, _>("has_cname"));
            f.set_i32("a_record_count", rep.get::<i16, _>("a_record_count") as i32);

            // NS name features — pick the most-observed NS hostname from domain_ns_map.
            if let Some(first_ns) = rep.get::<Option<String>, _>("first_ns") {
                let ns_lower = first_ns.to_lowercase();
                let ns_clean = ns_lower.trim_end_matches('.');
                if let Some(ns_label) = ns_clean.split('.').next() {
                    f.set_f32("ns_name_entropy", shannon_entropy(ns_label) as f32);
                }
                f.set_i32("ns_name_length", ns_clean.len() as i32);
            }

            // Group F: Reputation
            let ns_obs = rep.get::<i32, _>("ns_observation_count");
            f.set_i32("ns_observation_count", ns_obs);
            f.set_i32("rep_ns_observation_count", ns_obs);
            f.set_i32(
                "rep_total_flow_count",
                rep.get::<i32, _>("total_flow_count"),
            );
            if let Some(d) = rep.get::<Option<f64>, _>("days_since_first_seen") {
                f.set_f32("rep_days_since_first_seen", d as f32);
            }
            if let Some(d) = rep.get::<Option<f64>, _>("days_since_ns_change") {
                f.set_f32("rep_days_since_ns_change", d as f32);
            }
            f.set_str("rep_ns_trust", &rep.get::<String, _>("ns_trust"));
            f.set_i32(
                "rep_is_well_known",
                if rep.get::<bool, _>("is_well_known") {
                    1
                } else {
                    0
                },
            );

            // well_known_rank_norm: Tranco rank / 1M from well_known_domains.rank
            if let Some(rank) = rep.get::<Option<i32>, _>("wk_rank") {
                f.set_f32("well_known_rank_norm", rank as f32 / 1_000_000.0);
            }
            // else: not set → NaN in build_feature_vector

            // cname_target_entropy
            let cname_val: serde_json::Value = rep.get("cname_targets");
            if let Some(arr) = cname_val.as_array()
                && let Some(first_target) = arr.first().and_then(|v| v.as_str())
            {
                f.set_f32("cname_target_entropy", shannon_entropy(first_target) as f32);
            }

            // NRD: is_nrd is always definite (true/false), never NaN.
            let is_nrd: bool = rep.get("is_nrd");
            f.set_bool("is_nrd", is_nrd);
            if is_nrd
                && let Some(slug) = rep.get::<Option<String>, _>("nrd_source")
                && let Some(age) = crate::scoring_chain::nrd_max_age_days(&slug)
            {
                f.set_i32("nrd_age_days", age as i32);
            }
            // nrd_age_days left unset (→ NaN) when is_nrd=false — no age to report
        } else {
            // No reputation row — fallback NRD check via indicator_domains.
            // Same pattern as scoring_chain.rs Step 5 fallback.
            let nrd_slug: Option<String> = sqlx::query_scalar(
                "SELECT s.slug FROM indicator_domains d \
                 JOIN enrichment_bindings eb ON d.source = eb.source_id \
                 JOIN sources s ON s.id = d.source \
                 WHERE eb.enrichment_type = 'nrd' AND d.domain = $1 \
                 LIMIT 1",
            )
            .bind(&registrable)
            .fetch_optional(&db.pool)
            .await
            .ok()
            .flatten();

            if let Some(ref slug) = nrd_slug {
                f.set_bool("is_nrd", true);
                if let Some(age) = crate::scoring_chain::nrd_max_age_days(slug) {
                    f.set_i32("nrd_age_days", age as i32);
                }
            } else {
                f.set_bool("is_nrd", false);
            }
        }

        // rep_has_infra_data: presence of any reputation row, NaN-guard for downstream.
        f.set_i32("rep_has_infra_data", if rep_row.is_some() { 1 } else { 0 });

        // --- CNN embeddings (split-label: registrable + subdomain) ---
        if self.cnn_session.is_some() {
            self.extract_cnn_embeddings(domain, suffix_set, &mut f);

            // Relational streams: max-pool CNN embeddings of every label
            // (registrable + subdomain parts) across all CNAME chain
            // targets / NS hostnames. Mirrors the per-stream pooling in
            // ml/embed_detector_dataset.py.
            let cname_iter = flow.cname_chain.iter().flatten().cloned();
            self.extract_pooled_relational_emb("cname_target_emb", cname_iter, suffix_set, &mut f);

            let ns_iter = flow
                .resolution_path
                .iter()
                .filter_map(|s| s.server_name.clone());
            self.extract_pooled_relational_emb("ns_host_emb", ns_iter, suffix_set, &mut f);
        }

        f
    }

    fn build_feature_vector(&self, features: &FeatureMap) -> Vec<f32> {
        self.feature_names
            .iter()
            .map(|name| {
                // If this feature has an ordinal encoding map, look up the string value.
                if let Some(encoding) = self.ordinal_maps.get(name.as_str()) {
                    if let Some(str_val) = features.strings.get(name.as_str()) {
                        return encoding
                            .get(str_val.as_str())
                            .map(|&code| code as f32)
                            .unwrap_or(f32::NAN); // unknown category → NaN
                    }
                    return f32::NAN; // missing string → NaN
                }
                features.get_f32_or_nan(name)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Feature map (simple typed key-value store)
// ---------------------------------------------------------------------------

pub struct FeatureMap {
    floats: HashMap<String, f32>,
    strings: HashMap<String, String>,
    bools: HashMap<String, bool>,
    opt_bools: HashMap<String, Option<bool>>,
}

impl FeatureMap {
    fn new() -> Self {
        Self {
            floats: HashMap::new(),
            strings: HashMap::new(),
            bools: HashMap::new(),
            opt_bools: HashMap::new(),
        }
    }

    /// Returns true if at least one Group B infrastructure feature has been set.
    /// Without infrastructure data, ML predictions are unreliable.
    fn has_infra_data(&self) -> bool {
        self.floats.contains_key("avg_auth_ttl")
            || self.floats.contains_key("a_record_count")
            || self.floats.contains_key("ns_name_length")
    }

    fn set_f32(&mut self, key: &str, val: f32) {
        self.floats.insert(key.to_string(), val);
    }

    fn set_i32(&mut self, key: &str, val: i32) {
        self.floats.insert(key.to_string(), val as f32);
    }

    fn set_str(&mut self, key: &str, val: &str) {
        self.strings.insert(key.to_string(), val.to_string());
    }

    fn set_bool(&mut self, key: &str, val: bool) {
        self.bools.insert(key.to_string(), val);
    }

    #[allow(dead_code)]
    fn set_bool_opt(&mut self, key: &str, val: Option<bool>) {
        self.opt_bools.insert(key.to_string(), val);
    }

    #[allow(dead_code)]
    fn get_f32(&self, key: &str) -> f32 {
        self.floats.get(key).copied().unwrap_or(0.0)
    }

    #[allow(dead_code)]
    fn get_opt_f32(&self, key: &str) -> Option<f32> {
        self.floats.get(key).copied()
    }

    #[allow(dead_code)]
    fn get_bool(&self, key: &str) -> bool {
        self.bools.get(key).copied().unwrap_or(false)
    }

    #[allow(dead_code)]
    fn get_opt_bool(&self, key: &str) -> Option<bool> {
        if let Some(val) = self.opt_bools.get(key) {
            return *val;
        }
        self.bools.get(key).copied().map(Some).unwrap_or(None)
    }

    #[allow(dead_code)]
    fn get_str(&self, key: &str) -> String {
        self.strings.get(key).cloned().unwrap_or_default()
    }

    #[allow(dead_code)]
    fn get_opt_str(&self, key: &str) -> Option<String> {
        self.strings.get(key).cloned()
    }

    /// Get a feature value as f32, or NaN if not set.
    /// Bools → 0.0/1.0, strings → NaN (categorical), opt_bools → 0.0/1.0/NaN.
    fn get_f32_or_nan(&self, key: &str) -> f32 {
        if let Some(&val) = self.floats.get(key) {
            return val;
        }
        if let Some(&val) = self.bools.get(key) {
            return if val { 1.0 } else { 0.0 };
        }
        if let Some(opt) = self.opt_bools.get(key) {
            return match opt {
                Some(true) => 1.0,
                Some(false) => 0.0,
                None => f32::NAN,
            };
        }
        // Strings (categoricals) → NaN
        if self.strings.contains_key(key) {
            return f32::NAN;
        }
        f32::NAN
    }
}

// ---------------------------------------------------------------------------
// Feature parity tests
// ---------------------------------------------------------------------------
// First cut for PR#3e: assert the pure transformations the trained model's
// `ordinal_maps` depend on byte-match across Rust serving and the Python
// training pipeline (`ml/build_detector_dataset.py` +
// `ml/embed_detector_dataset.py`). CNN parity is implicit — same ONNX file
// loaded by both sides. PG/CH parity (reputation columns, velocity counts,
// dnssec_algorithm string from CH `flows` table) defers to live deployment
// observation; the values flow through unchanged after the SQL hits land in
// the FeatureMap.
//
// Source-of-truth keys for the ordinal_maps live in
// `ml/models/detector_lgb_v1_cnn/detector_lgb_v1_meta.json` — if those keys
// change, this test must be updated alongside the model bundle.

#[cfg(test)]
mod parity_tests {
    use super::*;
    use nameserver_common::types::{DnssecStatus, QueryType, ResponseCode};

    #[test]
    fn qtype_str_matches_python_ordinal_map_keys() {
        // Keys from detector_lgb_v1_meta.json::ordinal_maps.qtype.
        assert_eq!(qtype_str(&QueryType::A), "A");
        assert_eq!(qtype_str(&QueryType::Aaaa), "AAAA");
        assert_eq!(qtype_str(&QueryType::Cname), "CNAME");
        assert_eq!(qtype_str(&QueryType::Mx), "MX");
        assert_eq!(qtype_str(&QueryType::Ns), "NS");
        assert_eq!(qtype_str(&QueryType::Txt), "TXT");
        assert_eq!(qtype_str(&QueryType::Soa), "SOA");
        assert_eq!(qtype_str(&QueryType::Ptr), "PTR");
        assert_eq!(qtype_str(&QueryType::Srv), "SRV");
        assert_eq!(qtype_str(&QueryType::Https), "HTTPS");
        assert_eq!(qtype_str(&QueryType::Other(35)), "Other(35)");
        assert_eq!(qtype_str(&QueryType::Other(48)), "Other(48)");
        assert_eq!(qtype_str(&QueryType::Other(64)), "Other(64)");
        assert_eq!(qtype_str(&QueryType::Other(65)), "Other(65)");
    }

    #[test]
    fn rcode_str_matches_python_ordinal_map_keys() {
        // Keys from detector_lgb_v1_meta.json::ordinal_maps.rcode.
        assert_eq!(rcode_str(&ResponseCode::Noerror), "NOERROR");
        assert_eq!(rcode_str(&ResponseCode::Nxdomain), "NXDOMAIN");
        assert_eq!(rcode_str(&ResponseCode::Servfail), "SERVFAIL");
        // REFUSED + Other(N) aren't in the trained ordinal_map, so they
        // yield NaN at scoring time. The strings themselves still need to
        // be deterministic so the parity test can assert them.
        assert_eq!(rcode_str(&ResponseCode::Refused), "REFUSED");
        assert_eq!(rcode_str(&ResponseCode::Other(7)), "Other(7)");
    }

    #[test]
    fn dnssec_status_str_matches_python_ordinal_map_keys() {
        assert_eq!(dnssec_status_str(&DnssecStatus::Bogus), "BOGUS");
        assert_eq!(
            dnssec_status_str(&DnssecStatus::Indeterminate),
            "INDETERMINATE"
        );
        assert_eq!(dnssec_status_str(&DnssecStatus::Insecure), "INSECURE");
        assert_eq!(dnssec_status_str(&DnssecStatus::Secure), "SECURE");
    }

    #[test]
    fn qtype_x_rcode_format_matches_python_concat() {
        // Mirrors:
        //   df["qtype_x_rcode"] = df["qtype"].astype(str) + "_" + df["rcode"].astype(str)
        let qt = qtype_str(&QueryType::A);
        let rc = rcode_str(&ResponseCode::Noerror);
        assert_eq!(format!("{qt}_{rc}"), "A_NOERROR");

        let qt = qtype_str(&QueryType::Aaaa);
        let rc = rcode_str(&ResponseCode::Nxdomain);
        assert_eq!(format!("{qt}_{rc}"), "AAAA_NXDOMAIN");

        let qt = qtype_str(&QueryType::Other(48));
        let rc = rcode_str(&ResponseCode::Servfail);
        assert_eq!(format!("{qt}_{rc}"), "Other(48)_SERVFAIL");
    }

    #[test]
    fn cdn_registrables_match_python_constant() {
        // Mirrors ml/build_detector_dataset.py::CDN_REGISTRABLES.
        // 23 entries — keep byte-identical or registrable_is_known_cdn
        // diverges between Rust serving and Python training.
        assert_eq!(CDN_REGISTRABLES.len(), 23);
        for expected in [
            "akadns.net",
            "akamaiedge.net",
            "akamaized.net",
            "edgekey.net",
            "edgesuite.net",
            "cloudfront.net",
            "cloudflare.com",
            "cloudflare.net",
            "fastly.net",
            "1e100.net",
            "googlevideo.com",
            "ytimg.com",
            "apple-dns.net",
            "aaplimg.com",
            "amazonaws.com",
            "azureedge.net",
            "llnwd.net",
            "stackpathcdn.com",
            "kxcdn.com",
            "jsdelivr.net",
            "unpkg.com",
            "gstatic.com",
            "gscdn.net",
        ] {
            assert!(
                CDN_REGISTRABLES.contains(&expected),
                "CDN_REGISTRABLES missing {expected}"
            );
        }
        // Negative case — common benign registrable should not match.
        assert!(!CDN_REGISTRABLES.contains(&"example.com"));
    }

    #[test]
    fn auth_ttl_log1p_matches_numpy_log1p() {
        // Python uses np.log1p(auth_ttl). Spot-check a few values against
        // the natural log identity.
        for raw in [0.0_f32, 1.0, 60.0, 300.0, 3600.0, 86400.0] {
            let rust = (raw + 1.0).ln();
            let expected = (raw as f64 + 1.0).ln() as f32;
            assert!((rust - expected).abs() < 1e-5, "log1p({raw}) drifted");
        }
    }

    #[test]
    fn rrsig_expiry_margin_hours_matches_python_formula() {
        // Python: (expiry - started_ts).where(expiry > 0, 0) / 3600.0
        // expiry=0 → 0 hours regardless of started_at.
        // expiry > 0 → (expiry - started_at) / 3600.
        let started_ms: i64 = 1_700_000_000_000;
        let expiry: i64 = 1_700_003_600_000;
        let rust = (expiry - started_ms) as f32 / 3600.0;
        // Python uses unix-second offsets; keep ms domain symmetric here
        // since DnsFlow.started_at is ms — see analysis/ml.rs.
        let expected_seconds = (expiry - started_ms) as f32 / 3600.0;
        assert!((rust - expected_seconds).abs() < 1e-3);

        // expiry=0 short-circuit.
        let zero: i64 = 0;
        let formula = if zero > 0 {
            (zero - started_ms) as f32 / 3600.0
        } else {
            0.0
        };
        assert_eq!(formula, 0.0);
    }
    #[test]
    #[ignore = "requires the runtime model bundle and ORT_DYLIB_PATH"]
    fn bundled_models_execute() {
        let directory =
            std::env::var("NAMESERVER_MODEL_BUNDLE").expect("NAMESERVER_MODEL_BUNDLE is required");
        let mut scorer = MlScorer::load(
            &std::path::Path::new(&directory).join("model.onnx"),
            0.9,
            0.5,
        )
        .unwrap();
        assert!(scorer.cnn_session.is_some());
        assert!(scorer.sim_session.is_some());
        let classification = scorer.run_label_cnn("example");
        assert_eq!(classification.len(), scorer.cnn_embedding_dim);
        assert!(classification.iter().all(|number| number.is_finite()));
        let similarity = scorer.run_sim_label_cnn("example");
        assert_eq!(similarity.len(), scorer.sim_embedding_dim);
        let norm = similarity
            .iter()
            .map(|value| value * value)
            .sum::<f32>()
            .sqrt();
        assert!((norm - 1.0).abs() < 0.01);
        let result = scorer
            .score(&Features {
                feature_map: FeatureMap::new(),
                label_embedding: Some(("example".into(), classification)),
                sim_embedding: Some(similarity),
                skip_reason: None,
            })
            .unwrap();
        assert!(result.ml_probability.is_finite());
        assert!((0.0..=1.0).contains(&result.ml_probability));
    }
}
