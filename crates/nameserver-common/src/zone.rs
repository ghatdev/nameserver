use serde::{Deserialize, Serialize};

/// Zone configuration stored in NATS KV (MessagePack).
/// Single source of truth for zone data shared across all NS nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneKvConfig {
    #[serde(default = "default_zone_version")]
    pub version: u32,
    pub origin: String,
    #[serde(default)]
    pub nameservers: Vec<String>,
    #[serde(default)]
    pub soa: SoaParams,
    #[serde(default)]
    pub records: Vec<ZoneRecord>,
    #[serde(default)]
    pub dnssec: Option<ZoneDnssecConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneRecord {
    pub name: String,
    #[serde(rename = "type", alias = "rtype")]
    pub rtype: String,
    pub value: String,
    #[serde(default = "default_record_ttl")]
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaParams {
    #[serde(default = "default_soa_refresh")]
    pub refresh: u32,
    #[serde(default = "default_soa_retry")]
    pub retry: u32,
    #[serde(default = "default_soa_expire")]
    pub expire: u32,
    #[serde(default = "default_soa_minimum")]
    pub minimum: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDnssecConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dnssec_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_nsec_mode")]
    pub nsec_mode: String,
    #[serde(default)]
    pub nsec3_iterations: u16,
    #[serde(default)]
    pub nsec3_salt: String,
}

impl Default for SoaParams {
    fn default() -> Self {
        Self {
            refresh: default_soa_refresh(),
            retry: default_soa_retry(),
            expire: default_soa_expire(),
            minimum: default_soa_minimum(),
        }
    }
}

fn default_zone_version() -> u32 {
    1
}

fn default_record_ttl() -> u32 {
    3600
}

fn default_soa_refresh() -> u32 {
    7200
}

fn default_soa_retry() -> u32 {
    1800
}

fn default_soa_expire() -> u32 {
    1209600
}

fn default_soa_minimum() -> u32 {
    300
}

fn default_dnssec_algorithm() -> String {
    "ECDSAP256SHA256".to_string()
}

fn default_nsec_mode() -> String {
    "nsec3".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_kv_config_serde_roundtrip() {
        let config = ZoneKvConfig {
            version: 1,
            origin: "example.com".to_string(),
            nameservers: vec!["ns1.example.com.".to_string()],
            soa: SoaParams::default(),
            records: vec![ZoneRecord {
                name: "ns1".to_string(),
                rtype: "A".to_string(),
                value: "1.2.3.4".to_string(),
                ttl: 3600,
            }],
            dnssec: None,
        };
        let bytes = rmp_serde::to_vec_named(&config).unwrap();
        let decoded: ZoneKvConfig = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.origin, config.origin);
        assert_eq!(decoded.records.len(), config.records.len());
    }
}
