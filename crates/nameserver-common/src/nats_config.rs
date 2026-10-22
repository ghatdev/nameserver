use serde::Deserialize;

/// NATS connection configuration shared across all crates.
#[derive(Debug, Clone, Deserialize)]
pub struct NatsConfig {
    #[serde(default = "default_nats_url")]
    pub url: String,
    #[serde(default = "default_stream_replicas")]
    pub stream_replicas: usize,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: default_nats_url(),
            stream_replicas: default_stream_replicas(),
        }
    }
}

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

fn default_stream_replicas() -> usize {
    1
}
