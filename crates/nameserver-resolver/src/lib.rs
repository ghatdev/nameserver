use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, ensure};
use hickory_server::{
    net::runtime::TokioRuntimeProvider,
    proto::rr::Name,
    resolver::{
        config::{NameServerConfig, ResolverOpts},
        recursor::{DnssecPolicyConfig, RecursiveConfig, RecursorOptions},
    },
    store::{
        forwarder::{ForwardConfig, ForwardZoneHandler},
        recursor::RecursiveZoneHandler,
    },
    zone_handler::{Catalog, ZoneHandler, ZoneType},
};
use nameserver_core::{
    Filter, FilterSettings, Prepared, ServerSettings, Snapshot, read_config, relative_to,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    server: ServerSettings,
    resolver: ResolverSettings,
    #[serde(default)]
    filters: FilterSettings,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Recursive,
    Forward,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResolverSettings {
    mode: Mode,
    root_hints: Option<PathBuf>,
    upstreams: Vec<SocketAddr>,
    dnssec_validation: bool,
    trust_anchor: Option<PathBuf>,
    response_cache_size: u64,
    nameserver_cache_size: usize,
    recursion_limit: u8,
}

impl Default for ResolverSettings {
    fn default() -> Self {
        Self {
            mode: Mode::Recursive,
            root_hints: None,
            upstreams: vec![],
            dnssec_validation: true,
            trust_anchor: None,
            response_cache_size: 4096,
            nameserver_cache_size: 1024,
            recursion_limit: 24,
        }
    }
}

pub async fn build(path: PathBuf) -> Result<Prepared> {
    let config: Config = read_config(&path)?;
    config.server.validate()?;
    let options = config.resolver;
    ensure!(
        options.response_cache_size > 0 && options.nameserver_cache_size > 0,
        "cache sizes must be positive"
    );
    ensure!(
        options.recursion_limit > 0,
        "recursion_limit must be positive"
    );
    ensure!(
        options.dnssec_validation || options.trust_anchor.is_none(),
        "trust_anchor requires dnssec_validation"
    );
    let catalog = build_catalog(&options, &path, options.dnssec_validation).await?;
    // RFC 4035: CD=1 requests bypass validation. Isolate their cache and trust state.
    let unchecked_catalog = if options.dnssec_validation {
        Some(build_catalog(&options, &path, false).await?)
    } else {
        None
    };
    Ok(Prepared {
        server: config.server,
        snapshot: Snapshot {
            catalog,
            unchecked_catalog,
            filter: Filter::load(&config.filters, &path)?,
            recursive: true,
        },
        refresh_after: None,
    })
}

async fn build_catalog(options: &ResolverSettings, path: &Path, validate: bool) -> Result<Catalog> {
    let anchor = if validate {
        options
            .trust_anchor
            .as_ref()
            .map(|file| relative_to(path, file))
    } else {
        None
    };
    let zone: Arc<dyn ZoneHandler> = match options.mode {
        Mode::Recursive => {
            ensure!(
                options.upstreams.is_empty(),
                "upstreams are only used in forward mode"
            );
            let roots = relative_to(
                path,
                options
                    .root_hints
                    .as_ref()
                    .context("recursive mode requires resolver.root_hints")?,
            );
            let dnssec_policy = if validate {
                DnssecPolicyConfig::ValidateWithStaticKey {
                    path: anchor,
                    nsec3_soft_iteration_limit: None,
                    nsec3_hard_iteration_limit: None,
                    validation_cache_size: None,
                }
            } else {
                DnssecPolicyConfig::ValidationDisabled
            };
            let config = RecursiveConfig {
                roots,
                dnssec_policy,
                options: RecursorOptions {
                    response_cache_size: options.response_cache_size,
                    ns_cache_size: options.nameserver_cache_size,
                    recursion_limit: options.recursion_limit,
                    ..Default::default()
                },
            };
            Arc::new(
                RecursiveZoneHandler::try_from_config(
                    Name::root(),
                    ZoneType::External,
                    config,
                    None,
                    TokioRuntimeProvider::default(),
                )
                .await
                .map_err(|error| anyhow!(error))?,
            )
        }
        Mode::Forward => {
            ensure!(
                options.root_hints.is_none(),
                "root_hints are only used in recursive mode"
            );
            ensure!(
                !options.upstreams.is_empty(),
                "forward mode requires at least one upstream"
            );
            let mut name_servers = Vec::new();
            for address in &options.upstreams {
                ensure!(address.port() != 0, "upstream port must be nonzero");
                let mut server = NameServerConfig::udp_and_tcp(address.ip());
                for connection in &mut server.connections {
                    connection.port = address.port();
                }
                name_servers.push(server);
            }
            let mut resolver_options = ResolverOpts::default();
            resolver_options.validate = validate;
            resolver_options.trust_anchor = anchor;
            resolver_options.cache_size = options.response_cache_size;
            resolver_options.preserve_intermediates = true;
            let config = ForwardConfig {
                name_servers,
                options: Some(resolver_options),
            };
            Arc::new(
                ForwardZoneHandler::builder_tokio(config)
                    .build()
                    .map_err(|error| anyhow!(error))?,
            )
        }
    };
    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![zone]);
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forward_mode_requires_explicit_upstreams() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("resolver.toml");
        std::fs::write(&path, "[resolver]\nmode = 'forward'\n").unwrap();
        assert!(build(path).await.is_err());
    }

    #[tokio::test]
    async fn invalid_blocklist_prevents_startup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("resolver.toml");
        std::fs::write(temp.path().join("blocked.txt"), "||bad.example^").unwrap();
        std::fs::write(&path, "[resolver]\nmode = 'forward'\nupstreams = ['127.0.0.1:5354']\n[filters]\nblocklists = ['blocked.txt']\n").unwrap();
        assert!(build(path).await.is_err());
    }
}
