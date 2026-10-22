use serde::Deserialize;

const DEFAULT_CONTROL_URL: &str = "http://localhost:8080";

/// CLI configuration.
///
/// Resolution order: CLI flags > env vars > config.toml > defaults.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub control_url: String,
    pub dns_server: String,
    /// Server IP addresses for stamps and mobileconfig (e.g., ["192.0.2.1", "192.0.2.2"])
    #[serde(default)]
    pub dns_addrs: Vec<String>,
}

impl Config {
    pub fn load() -> Self {
        // 1. Try ./config.toml
        let mut cfg = std::fs::read_to_string("config.toml")
            .ok()
            .and_then(|s| toml::from_str::<Config>(&s).ok())
            .unwrap_or_default();

        // 2. Env vars override file values
        if let Ok(url) = std::env::var("NAMESERVER_CONTROL_URL") {
            cfg.control_url = url;
        }
        if let Ok(server) = std::env::var("NAMESERVER_DNS_SERVER") {
            cfg.dns_server = server;
        }

        // 3. Fill in defaults for anything still empty
        if cfg.control_url.is_empty() {
            cfg.control_url = DEFAULT_CONTROL_URL.to_string();
        }

        cfg
    }

    pub fn with_url(mut self, url: String) -> Self {
        self.control_url = url;
        self
    }
}
