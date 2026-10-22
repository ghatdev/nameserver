use std::path::PathBuf;

use nameserver_common::nats_config::NatsConfig;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub nats: NatsConfig,
    #[serde(default)]
    pub clickhouse: ClickHouseConfig,
    #[serde(default = "default_postgres_url")]
    pub postgres_url: String,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub ml: MlConfig,
    #[serde(default)]
    pub injector: InjectorConfig,
    #[serde(default)]
    pub benign_sampler: BenignSamplerConfig,
    #[serde(default)]
    pub auto_rdap: bool,
    #[serde(default)]
    pub auto_pull: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseConfig {
    #[serde(default = "default_clickhouse_url")]
    pub url: String,
    #[serde(default = "default_clickhouse_database")]
    pub database: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen")]
    pub listen: String,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&content)?;
        if config.ml.model_path.is_relative() {
            config.ml.model_path = path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(&config.ml.model_path);
        }
        config.validate()?;
        info!("loaded control-plane configuration");
        Ok(config)
    }

    /// Validate config values that are interpolated into queries or connection strings.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.clickhouse.database.is_empty(),
            "clickhouse.database cannot be empty"
        );
        anyhow::ensure!(
            !self.ml.enabled || cfg!(feature = "ml"),
            "ml.enabled requires building nameserver-control with --features ml"
        );
        if !self
            .clickhouse
            .database
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            anyhow::bail!(
                "clickhouse.database must be alphanumeric/underscore only, got: {}",
                self.clickhouse.database
            );
        }
        Ok(())
    }

    pub fn clickhouse_client(&self) -> clickhouse::Client {
        let mut client = clickhouse::Client::default()
            .with_option("network_compression_method", "lz4")
            .with_url(&self.clickhouse.url)
            .with_database(&self.clickhouse.database);
        if let Some(ref user) = self.clickhouse.user {
            client = client.with_user(user);
        }
        if let Some(ref password) = self.clickhouse.password {
            client = client.with_password(password);
        }
        client
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nats: NatsConfig::default(),
            clickhouse: ClickHouseConfig::default(),
            postgres_url: default_postgres_url(),
            api: ApiConfig::default(),
            dns: DnsConfig::default(),
            ml: MlConfig::default(),
            injector: InjectorConfig::default(),
            benign_sampler: BenignSamplerConfig::default(),
            auto_rdap: false,
            auto_pull: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenignSamplerConfig {
    /// Enable the tranco/majestic sampler. Required for PR-C's
    /// anti-contamination property — without benign-labeled rows
    /// flowing through the same injector path, the detector can learn
    /// "injector-origin" ⇒ "malicious."
    #[serde(default)]
    pub enabled: bool,
    /// Which well-known list to sample from. Must match a row in the
    /// `sources` table (e.g. "majestic-1m", "tranco-100k").
    #[serde(default = "default_benign_source_slug")]
    pub source_slug: String,
    /// Rows to sample per tick.
    #[serde(default = "default_benign_sampler_batch")]
    pub batch_size: i64,
    /// Seconds between ticks. Pair with batch_size to set the desired
    /// enqueue rate — default 50 rows every 600s ≈ 7,200/day, roughly
    /// 1:4 with the daily TIF/DGA inflow.
    #[serde(default = "default_benign_sampler_interval_secs")]
    pub interval_secs: u64,
}

impl Default for BenignSamplerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source_slug: default_benign_source_slug(),
            batch_size: default_benign_sampler_batch(),
            interval_secs: default_benign_sampler_interval_secs(),
        }
    }
}

fn default_benign_source_slug() -> String {
    "majestic-1m".to_string()
}
fn default_benign_sampler_batch() -> i64 {
    50
}
fn default_benign_sampler_interval_secs() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize)]
pub struct InjectorConfig {
    /// Enable the resolution injector background task.
    #[serde(default)]
    pub enabled: bool,
    /// Pool of DoH resolvers to rotate through per query. Each entry
    /// produces an HTTP client pinned to a specific IP (via reqwest
    /// `.resolve(host, ip)`) so the connection pool can't collapse
    /// into a single resolver node. Rotating resolvers independently
    /// of profile_ids gives us (profiles × resolvers) signature
    /// combinations — without this, every injected query exits through
    /// whichever resolver IP won the first DNS round-robin at startup,
    /// which is itself a fingerprint.
    #[serde(default)]
    pub doh_resolvers: Vec<DohResolver>,
    /// Pool of profile_ids to rotate through on each injection. Spreading
    /// queries across many profiles is the primary anti-signature
    /// mitigation — a single profile_id is what let us detect our own
    /// prior bulk resolution.
    #[serde(default)]
    pub profile_pool: Vec<String>,
    /// Max number of rows to claim per scheduler tick.
    #[serde(default = "default_injector_batch_size")]
    pub batch_size: i64,
    /// How often the scheduler loop runs. Combined with batch_size this
    /// sets the effective rate cap. Default 15s × 30 rows with
    /// concurrent dispatch ≈ 7200/hour, enough to stay ahead of the
    /// TIF+Pro diffs while keeping ticks inside the DoH 10s timeout.
    #[serde(default = "default_injector_tick_secs")]
    pub tick_secs: u64,
    /// Per-row retry budget before a row is marked `abandoned`.
    #[serde(default = "default_injector_max_attempts")]
    pub max_attempts: i32,
    /// Backoff applied to scheduled_for when an attempt fails.
    #[serde(default = "default_injector_retry_backoff_secs")]
    pub retry_backoff_secs: u64,
    /// Per-DoH-request timeout. Too-long flows are rare but do occur.
    #[serde(default = "default_injector_doh_timeout_secs")]
    pub doh_timeout_secs: u64,
    /// When true, the injector validates the resolver's TLS certificate.
    /// Turn OFF only when pointing at a local dev resolver with a
    /// self-signed cert. Defaults on.
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            doh_resolvers: Vec::new(),
            profile_pool: Vec::new(),
            batch_size: default_injector_batch_size(),
            tick_secs: default_injector_tick_secs(),
            max_attempts: default_injector_max_attempts(),
            retry_backoff_secs: default_injector_retry_backoff_secs(),
            doh_timeout_secs: default_injector_doh_timeout_secs(),
            verify_tls: true,
        }
    }
}

/// A single DoH resolver endpoint. Identified by a display `name` (used
/// in logs and metrics), reached over TLS with SNI/Host = `host`, on a
/// connection pinned to `ip:port`. Pinning bypasses DNS, so the HTTP
/// client always hits the intended node regardless of what `host`
/// resolves to at runtime.
#[derive(Debug, Clone, Deserialize)]
pub struct DohResolver {
    pub name: String,
    pub host: String,
    pub ip: std::net::IpAddr,
    #[serde(default = "default_doh_resolver_port")]
    pub port: u16,
}

fn default_doh_resolver_port() -> u16 {
    443
}
fn default_injector_batch_size() -> i64 {
    30
}
fn default_injector_tick_secs() -> u64 {
    15
}
fn default_injector_max_attempts() -> i32 {
    3
}
fn default_injector_retry_backoff_secs() -> u64 {
    600
}
fn default_injector_doh_timeout_secs() -> u64 {
    10
}
fn default_true() -> bool {
    true
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: default_clickhouse_url(),
            database: default_clickhouse_database(),
            user: None,
            password: None,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: default_api_listen(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_server")]
    pub server: String,
    #[serde(default)]
    pub addrs: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            server: default_dns_server(),
            addrs: Vec::new(),
        }
    }
}

fn default_dns_server() -> String {
    "dns.example.test".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct MlConfig {
    /// Enable ML inference.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the ONNX model file.
    #[serde(default = "default_ml_model_path")]
    pub model_path: PathBuf,
    /// Threshold for malicious classification.
    #[serde(default = "default_ml_threshold_malicious")]
    pub threshold_malicious: f32,
    /// Threshold for suspicious classification.
    #[serde(default = "default_ml_threshold_suspicious")]
    pub threshold_suspicious: f32,
    /// Own zone origins to exclude from ML scoring (e.g. ["example.test"]).
    #[serde(default)]
    pub own_zones: Vec<String>,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: default_ml_model_path(),
            threshold_malicious: default_ml_threshold_malicious(),
            threshold_suspicious: default_ml_threshold_suspicious(),
            own_zones: Vec::new(),
        }
    }
}

fn default_ml_model_path() -> PathBuf {
    PathBuf::from("model.onnx")
}

fn default_ml_threshold_malicious() -> f32 {
    0.9
}

fn default_ml_threshold_suspicious() -> f32 {
    0.5
}

fn default_clickhouse_url() -> String {
    "http://localhost:8123".to_string()
}

fn default_clickhouse_database() -> String {
    "nameserver".to_string()
}

fn default_postgres_url() -> String {
    "postgres://nameserver@localhost/nameserver".to_string()
}

fn default_api_listen() -> String {
    "127.0.0.1:8080".to_string()
}
