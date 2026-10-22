use crate::{
    config::BlockMode, filter_set::FilterHolder, geo::GeoHolder, nats, pipeline::AppState,
    profiles::ProfileHolder, suffix::SuffixHolder,
};
use anyhow::Result;
use hickory_server::{
    proto::serialize::binary::{BinEncodable, BinEncoder},
    server::Request,
};
use nameserver_common::nats_config::NatsConfig;
use nameserver_core::{Processor, Snapshot};
use serde::Deserialize;
use std::{path::Path, sync::Arc};

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub nats: NatsConfig,
    pub node_name: String,
    pub block_mode: BlockMode,
    pub redirect_ip: Option<String>,
    pub max_domain_depth: usize,
    pub canary_domains: Vec<String>,
    pub tls: Option<crate::config::TlsConfig>,
    pub default_profile: Option<String>,
    pub allowlist_fst: Option<std::path::PathBuf>,
    pub blocklist_xor: Option<std::path::PathBuf>,
    pub geoip_path: Option<std::path::PathBuf>,
    pub suffix_path: Option<std::path::PathBuf>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            nats: NatsConfig::default(),
            node_name: "local".into(),
            block_mode: BlockMode::Nxdomain,
            redirect_ip: None,
            max_domain_depth: 10,
            canary_domains: vec![],
            tls: None,
            default_profile: None,
            allowlist_fst: None,
            blocklist_xor: None,
            geoip_path: None,
            suffix_path: None,
        }
    }
}

pub struct Connected {
    pub processor: Arc<dyn Processor>,
    pub certificate: Option<Arc<dyn rustls::server::ResolvesServerCert>>,
    pub background: Vec<tokio::task::AbortHandle>,
}

pub async fn connect(settings: Settings, path: &Path) -> Result<Connected> {
    let mut background = Vec::new();
    anyhow::ensure!(
        (1..=128).contains(&settings.max_domain_depth),
        "management.max_domain_depth must be 1..128"
    );
    if matches!(settings.block_mode, BlockMode::RedirectIp) {
        let _: std::net::IpAddr = settings
            .redirect_ip
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("redirect_ip is required"))?
            .parse()?;
    }
    let (client, js) = nats::connect(&settings.nats).await?;
    nats::provision(&js, &settings.nats).await?;
    let filters = Arc::new(FilterHolder::new());
    let geo = Arc::new(GeoHolder::new());
    let suffix = Arc::new(SuffixHolder::new());
    filters.load_from_disk(
        settings
            .allowlist_fst
            .as_ref()
            .map(|p| nameserver_core::relative_to(path, p))
            .as_deref(),
        settings
            .blocklist_xor
            .as_ref()
            .map(|p| nameserver_core::relative_to(path, p))
            .as_deref(),
    );
    geo.load_from_disk(
        settings
            .geoip_path
            .as_ref()
            .map(|p| nameserver_core::relative_to(path, p))
            .as_deref(),
    );
    suffix.load_from_disk(
        settings
            .suffix_path
            .as_ref()
            .map(|p| nameserver_core::relative_to(path, p))
            .as_deref(),
    );
    nats::load_shared_data(&js, &filters, &geo, &suffix).await?;
    let profiles = Arc::new(ProfileHolder::with_js(js.clone()));
    if let Some(id) = &settings.default_profile {
        anyhow::ensure!(
            profiles.resolve(id).await.is_some(),
            "management.default_profile does not exist or cannot be loaded"
        );
    }
    let certificate = if let Some(mut options) = settings.tls {
        options.cert_dir = nameserver_core::relative_to(path, &options.cert_dir);
        options.cert_path = options
            .cert_path
            .map(|p| nameserver_core::relative_to(path, &p));
        options.key_path = options
            .key_path
            .map(|p| nameserver_core::relative_to(path, &p));
        let key = match options.mode {
            crate::config::TlsMode::Acme => {
                nats::provision_cert_bucket(&js).await?;
                nats::provision_acme_lock(&js).await?;
                crate::acme::provision_with_nats(&options, &client, &js).await?
            }
            crate::config::TlsMode::Manual => crate::tls::load_from_pem(
                options
                    .cert_path
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("manual TLS requires cert_path"))?,
                options
                    .key_path
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("manual TLS requires key_path"))?,
            )?,
            crate::config::TlsMode::SelfSigned => crate::tls::generate_self_signed()?,
        };
        let resolver = crate::tls::HotSwapCertResolver::new(key);
        if options.mode == crate::config::TlsMode::Acme {
            background.push(
                crate::acme::spawn_renewal_task(
                    resolver.clone(),
                    options,
                    Some((client.clone(), js.clone())),
                )
                .abort_handle(),
            );
        }
        Some(resolver as Arc<dyn rustls::server::ResolvesServerCert>)
    } else {
        None
    };

    let (tx, rx) = tokio::sync::mpsc::channel(nats::FLOW_CHANNEL_CAPACITY);
    background.push(nats::spawn_flow_publisher(js.clone(), rx).abort_handle());
    background.push(
        nats::spawn_reload_listener(
            client.clone(),
            js.clone(),
            filters.clone(),
            profiles.clone(),
            geo.clone(),
            suffix.clone(),
        )
        .abort_handle(),
    );
    let state = AppState::new(
        filters.clone(),
        profiles,
        geo,
        suffix,
        crate::pipeline::Policy {
            block_mode: settings.block_mode,
            redirect_ip: settings.redirect_ip,
            max_domain_depth: settings.max_domain_depth,
            node_name: settings.node_name,
            canary_domains: settings
                .canary_domains
                .into_iter()
                .map(|name| format!("{}.", name.trim_end_matches('.').to_lowercase()))
                .collect(),
        },
        Some(tx),
    );
    background.push(
        nats::spawn_health_responder(
            client.clone(),
            std::time::Instant::now(),
            state.query_counter(),
            state.block_counter(),
        )
        .abort_handle(),
    );
    background.push(nats::spawn_list_status_responder(client.clone(), filters).abort_handle());
    Ok(Connected {
        processor: Arc::new(Managed {
            state,
            default_profile: settings.default_profile,
        }),
        certificate,
        background,
    })
}

struct Managed {
    state: AppState,
    default_profile: Option<String>,
}
#[async_trait::async_trait]
impl Processor for Managed {
    async fn profile_exists(&self, profile: &str) -> bool {
        self.state
            .profiles
            .resolve(profile)
            .await
            .is_some_and(|profile| self.state.filters.profile_ready(&profile))
    }
    async fn process(
        &self,
        snapshot: Arc<Snapshot>,
        request: &Request,
        profile: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut wire = Vec::new();
        request.emit(&mut BinEncoder::new(&mut wire))?;
        let message = hickory_proto::op::Message::from_vec(&wire)?;
        let profile = profile.or(self.default_profile.as_deref());
        let config = match profile {
            Some(id) => Some(
                self.state
                    .profiles
                    .resolve(id)
                    .await
                    .ok_or_else(|| anyhow::anyhow!("profile no longer exists"))?,
            ),
            None => None,
        };
        if let Some(profile) = &config {
            anyhow::ensure!(
                self.state.filters.profile_ready(profile),
                "profile filters are not available"
            );
        }
        Ok(
            crate::pipeline::process_dns_query(&self.state, snapshot, message, config.as_ref())
                .await
                .wire,
        )
    }
}
