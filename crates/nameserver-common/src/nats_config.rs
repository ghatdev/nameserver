use serde::Deserialize;

/// NATS connection configuration shared across all crates.
#[derive(Debug, Clone, Deserialize)]
pub struct NatsConfig {
    #[serde(default = "default_nats_url")]
    pub url: String,
    #[serde(default = "default_stream_replicas")]
    pub stream_replicas: usize,
    /// Storage reservation for a newly created flow stream, in bytes.
    #[serde(default = "default_flow_max_bytes")]
    pub flow_max_bytes: i64,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: default_nats_url(),
            stream_replicas: default_stream_replicas(),
            flow_max_bytes: default_flow_max_bytes(),
        }
    }
}

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

fn default_stream_replicas() -> usize {
    1
}

fn default_flow_max_bytes() -> i64 {
    crate::nats_subjects::FLOWS_MAX_BYTES
}
