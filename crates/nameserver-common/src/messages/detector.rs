use serde::{Deserialize, Serialize};

/// Score from the ML-based detector, published to NATS `ns.detector.score`
/// after every scored flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorScore {
    /// Domain that was scored.
    pub domain: String,
    /// Raw ML model probability (0.0-1.0).
    pub ml_probability: f32,
    /// Final probability after scoring chain adjustments.
    pub final_probability: f32,
    /// Classification: "malicious", "suspicious", "safe", "unknown".
    pub classification: String,
    /// Whether this score is considered divergent from expectations.
    pub divergent: bool,
    /// Post-ML override rule that was applied, if any.
    pub override_rule: Option<String>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// NS trust classification from scoring chain.
    #[serde(default)]
    pub ns_trust: String,
    /// DNSSEC adjustment (+ for bogus).
    #[serde(default)]
    pub dnssec_adj: f32,
    /// NS reputation adjustment.
    #[serde(default)]
    pub ns_adj: f32,
    /// Domain similarity adjustment (impersonation detection).
    #[serde(default)]
    pub similarity_adj: f32,
    /// Hosting platform adjustment.
    #[serde(default)]
    pub hosting_adj: f32,
    /// Newly registered domain adjustment.
    #[serde(default)]
    pub nrd_adj: f32,
    /// Temporal history adjustment.
    #[serde(default)]
    pub temporal_adj: f32,
}
