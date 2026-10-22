pub use nameserver_common::nats_config::NatsConfig;
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
    // manual mode
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    // acme mode
    pub acme_domain: Option<String>,
    /// Additional SAN domains for the certificate (e.g., "*.dns.example.test").
    #[serde(default)]
    pub acme_san: Vec<String>,
    pub acme_email: Option<String>,
    #[serde(default)]
    pub acme_directory: AcmeDirectory,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    // DNS-01 challenge via Cloudflare API (required for wildcard certs).
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_zone_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    Acme,
    Manual,
    #[default]
    SelfSigned,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AcmeDirectory {
    #[default]
    Production,
    Staging,
}

fn default_cert_dir() -> PathBuf {
    PathBuf::from("/var/lib/nameserver/certs")
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    #[default]
    Nxdomain,
    RedirectIp,
}
