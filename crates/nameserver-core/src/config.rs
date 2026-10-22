use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use ipnet::IpNet;
use serde::{Deserialize, de::DeserializeOwned};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Args {
    /// TOML configuration file; relative data paths are resolved beside this file.
    #[arg(short, long)]
    pub config: PathBuf,
    /// Validate configuration, data files, keys, and certificates without binding sockets.
    #[arg(long)]
    pub check: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Each address serves both UDP and TCP DNS.
    pub listen: Vec<SocketAddr>,
    pub listen_dot: Vec<SocketAddr>,
    pub listen_doh: Vec<SocketAddr>,
    /// An explicit allow list across both address families.
    pub allow_networks: Vec<IpNet>,
    pub max_in_flight: usize,
    pub query_timeout_secs: u64,
    pub tcp_idle_timeout_secs: u64,
    pub tls: Option<TlsSettings>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    #[serde(default = "default_certificate")]
    pub certificate: PathBuf,
    #[serde(default = "default_private_key")]
    pub private_key: PathBuf,
    /// Optional expected HTTP authority for DoH; omit when serving several hostnames.
    pub dns_name: Option<String>,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen: vec![SocketAddr::from(([127, 0, 0, 1], 5353))],
            listen_dot: vec![],
            listen_doh: vec![],
            allow_networks: vec![
                "127.0.0.0/8".parse().expect("constant CIDR"),
                "::1/128".parse().expect("constant CIDR"),
            ],
            max_in_flight: 256,
            query_timeout_secs: 30,
            tcp_idle_timeout_secs: 10,
            tls: None,
        }
    }
}

impl ServerSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.listen.is_empty() || !self.listen_dot.is_empty() || !self.listen_doh.is_empty(),
            "at least one listener is required"
        );
        ensure!(
            !self.allow_networks.is_empty(),
            "allow_networks must explicitly identify permitted clients"
        );
        ensure!(
            (1..=65_536).contains(&self.max_in_flight),
            "max_in_flight must be between 1 and 65536"
        );
        ensure!(
            (1..=300).contains(&self.query_timeout_secs),
            "query_timeout_secs must be between 1 and 300"
        );
        ensure!(
            (1..=300).contains(&self.tcp_idle_timeout_secs),
            "tcp_idle_timeout_secs must be between 1 and 300"
        );
        ensure!(
            (self.listen_dot.is_empty() && self.listen_doh.is_empty()) || self.tls.is_some(),
            "encrypted listeners require server.tls"
        );
        let mut addresses = HashSet::new();
        for address in self
            .listen
            .iter()
            .chain(&self.listen_dot)
            .chain(&self.listen_doh)
        {
            ensure!(
                addresses.insert(address),
                "TCP, DoT, and DoH listeners must use distinct addresses"
            );
        }
        Ok(())
    }

    pub fn permits(&self, address: std::net::IpAddr) -> bool {
        let address = address.to_canonical();
        self.allow_networks
            .iter()
            .any(|network| network.contains(&address))
    }
}

pub fn read_config<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("cannot read configuration {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("invalid configuration {}", path.display()))
}

pub fn relative_to(config: &Path, file: &Path) -> PathBuf {
    if file.is_absolute() {
        file.to_owned()
    } else {
        config.parent().unwrap_or_else(|| Path::new(".")).join(file)
    }
}

fn default_certificate() -> PathBuf {
    PathBuf::from("cert.pem")
}
fn default_private_key() -> PathBuf {
    PathBuf::from("key.pem")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_does_not_open_an_omitted_address_family() {
        let settings = ServerSettings {
            allow_networks: vec!["10.0.0.0/8".parse().unwrap()],
            ..Default::default()
        };
        assert!(settings.permits("10.0.1.2".parse().unwrap()));
        assert!(settings.permits("::ffff:10.0.1.2".parse().unwrap()));
        assert!(!settings.permits("2001:db8::1".parse().unwrap()));
        assert!(!settings.permits("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn empty_acl_and_missing_tls_are_rejected() {
        let mut settings = ServerSettings {
            allow_networks: vec![],
            ..Default::default()
        };
        assert!(settings.validate().is_err());
        settings = ServerSettings::default();
        settings.listen_dot.push("127.0.0.1:8853".parse().unwrap());
        assert!(settings.validate().is_err());
    }

    #[test]
    fn paths_are_relative_to_the_config_not_the_working_directory() {
        assert_eq!(
            relative_to(
                Path::new("/etc/nameserver/resolver.toml"),
                Path::new("lists/block.txt")
            ),
            PathBuf::from("/etc/nameserver/lists/block.txt")
        );
    }
}
