use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_nats::jetstream;
use async_nats::jetstream::object_store;
use futures::StreamExt;
use nameserver_common::admin::{
    FilterManifest, HealthStatus, ListStatus, ReloadAction, ReloadSignal,
};
use nameserver_common::filter::FilterKind;
use nameserver_common::messages::flow::DnsFlow;
use nameserver_common::nats_subjects::*;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::NatsConfig;
use crate::filter_set::FilterHolder;
use crate::geo::GeoHolder;
use crate::profiles::ProfileHolder;
use crate::tls;

/// Bounded channel capacity for flow publishing.
pub const FLOW_CHANNEL_CAPACITY: usize = 4096;

/// Connect to NATS and return client + JetStream context.
pub async fn connect(
    config: &NatsConfig,
) -> anyhow::Result<(async_nats::Client, jetstream::Context)> {
    let client = async_nats::connect(&config.url).await?;
    let js = jetstream::new(client.clone());
    info!("connected to NATS");
    Ok((client, js))
}

pub use nameserver_common::broker::provision;

/// Load shared filters + geoip + suffix set from NATS before serving traffic.
pub async fn load_shared_data(
    js: &jetstream::Context,
    filters: &FilterHolder,
    geo: &GeoHolder,
    suffix: &crate::suffix::SuffixHolder,
) -> anyhow::Result<()> {
    // Load filter manifest from KV.
    let manifest_loaded = match js.get_key_value(BUCKET_CONFIG).await {
        Ok(kv) => match kv.get(KV_FILTER_MANIFEST).await {
            Ok(Some(bytes)) => match rmp_serde::from_slice::<FilterManifest>(&bytes) {
                Ok(manifest) => {
                    load_filters_from_manifest(js, filters, &manifest).await;
                    true
                }
                Err(e) => {
                    warn!(error = %e, "corrupt filter manifest in KV, skipping");
                    false
                }
            },
            _ => false,
        },
        Err(_) => false,
    };

    if !manifest_loaded {
        warn!("filter manifest not found in KV");
    }

    // Load geoip (independent of manifest — always attempt).
    if let Ok(geo_bucket) = js.get_object_store(BUCKET_GEO).await {
        match read_object(&geo_bucket, OBJ_GEOIP_BIN).await {
            Ok(data) => match geo.swap(&data) {
                Ok((v4, v6)) => info!(v4, v6, "loaded geo table from Object Store"),
                Err(e) => warn!(error = %e, "failed to parse geo table"),
            },
            Err(e) => {
                warn!(error = %e, "geo table not found in Object Store (will retry on signal)")
            }
        }
    }

    // Load suffix set (independent — always attempt).
    if let Ok(filter_bucket) = js.get_object_store(BUCKET_FILTERS).await {
        match read_object(&filter_bucket, OBJ_SUFFIX_SET).await {
            Ok(data) => match suffix.swap(&data) {
                Ok(count) => info!(entries = count, "loaded suffix set from Object Store"),
                Err(e) => warn!(error = %e, "failed to parse suffix set"),
            },
            Err(e) => {
                warn!(error = %e, "suffix set not found in Object Store (will use fallback)")
            }
        }
    }

    info!("shared data loaded, ready to serve");
    Ok(())
}

/// Load all filters listed in a manifest from Object Store.
async fn load_filters_from_manifest(
    js: &jetstream::Context,
    filters: &FilterHolder,
    manifest: &FilterManifest,
) {
    let bucket = match js.get_object_store(BUCKET_FILTERS).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to get filter bucket");
            return;
        }
    };

    for desc in &manifest.filters {
        let obj_name = format!("{}.{}", desc.id, desc.kind.ext());
        match read_object(&bucket, &obj_name).await {
            Ok(data) => {
                let display_name = desc.id.to_string();
                let result = match desc.kind {
                    FilterKind::DnBlocklist => {
                        filters.swap_dn_blocklist(desc.id, &display_name, &data)
                    }
                    FilterKind::DnAllowlist => filters
                        .swap_dn_allowlist(desc.id, &display_name, data)
                        .map(|_| ()),
                    FilterKind::IpBlocklist => {
                        filters.swap_ip_blocklist(desc.id, &display_name, &data)
                    }
                    FilterKind::IpAllowlist => {
                        filters.swap_ip_allowlist(desc.id, &display_name, &data)
                    }
                    FilterKind::Unknown => {
                        warn!("unknown filter kind in manifest, skipping");
                        continue;
                    }
                };
                if let Err(e) = result {
                    warn!(error = %e, "failed to load filter from Object Store");
                }
            }
            Err(e) => warn!(error = %e, "failed to read filter from Object Store"),
        }
    }
    info!(
        count = manifest.filters.len(),
        "loaded shared filters from manifest"
    );
}

/// Spawn a background task that consumes flows from an MPSC channel
/// and publishes them to JetStream.
pub fn spawn_flow_publisher(
    js: jetstream::Context,
    mut rx: mpsc::Receiver<DnsFlow>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!("NATS flow publisher started");
        while let Some(flow) = rx.recv().await {
            let payload = match rmp_serde::to_vec_named(&flow) {
                Ok(bytes) => bytes,
                Err(e) => {
                    debug!(error = %e, "failed to serialize flow");
                    continue;
                }
            };
            if let Err(e) = js.publish(SUBJECT_FLOW, payload.into()).await {
                debug!(error = %e, "failed to publish flow to NATS");
            }
        }
        info!("NATS flow publisher stopped (channel closed)");
    })
}

// ---------------------------------------------------------------------------
// Reload listener
// ---------------------------------------------------------------------------

/// Spawn a listener for reload signals from the control plane.
pub fn spawn_reload_listener(
    client: async_nats::Client,
    js: jetstream::Context,
    filters: Arc<FilterHolder>,
    profiles: Arc<ProfileHolder>,
    geo: Arc<GeoHolder>,
    suffix: Arc<crate::suffix::SuffixHolder>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listen_for_reloads(&client, &js, &filters, &profiles, &geo, &suffix).await {
                Ok(()) => {
                    info!("reload listener subscription ended, restarting");
                }
                Err(e) => {
                    warn!(error = %e, "reload listener error, retrying in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    })
}

async fn listen_for_reloads(
    client: &async_nats::Client,
    js: &jetstream::Context,
    filters: &FilterHolder,
    profiles: &ProfileHolder,
    geo: &GeoHolder,
    suffix: &crate::suffix::SuffixHolder,
) -> anyhow::Result<()> {
    let mut sub = client.subscribe(SUBJECT_RELOAD).await?;
    info!(subject = SUBJECT_RELOAD, "reload listener ready");

    while let Some(msg) = sub.next().await {
        let signal: ReloadSignal = match rmp_serde::from_slice(&msg.payload) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to deserialize reload signal, skipping");
                continue;
            }
        };

        debug!(signal = ?signal, "received reload signal");

        match signal {
            ReloadSignal::Filter {
                id,
                filter_kind,
                action,
            } => {
                handle_filter_reload(js, filters, id, filter_kind, &action).await;
            }
            ReloadSignal::Profile { id } => {
                profiles.evict(&id).await;
                debug!("evicted profile from cache");
            }
            ReloadSignal::Geoip => {
                handle_geoip_reload(js, geo).await;
            }
            ReloadSignal::SuffixSet => {
                handle_suffix_reload(js, suffix).await;
            }
            ReloadSignal::Unknown => {
                debug!("received unknown reload signal, ignoring");
            }
        }
    }

    Ok(())
}

/// Handle a single filter reload signal.
async fn handle_filter_reload(
    js: &jetstream::Context,
    filters: &FilterHolder,
    id: nameserver_common::filter::FilterId,
    kind: FilterKind,
    action: &ReloadAction,
) {
    if *action == ReloadAction::Remove {
        let removed = filters.remove_by_id(&id);
        if removed {
            info!("filter removed via reload signal");
        }
        return;
    }

    let obj_name = format!("{}.{}", id, kind.ext());
    let bucket = match js.get_object_store(BUCKET_FILTERS).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to get filter bucket for reload");
            return;
        }
    };

    match read_object(&bucket, &obj_name).await {
        Ok(data) => {
            let display_name = id.to_string();
            let result = match kind {
                FilterKind::DnBlocklist => filters.swap_dn_blocklist(id, &display_name, &data),
                FilterKind::DnAllowlist => filters
                    .swap_dn_allowlist(id, &display_name, data)
                    .map(|_| ()),
                FilterKind::IpBlocklist => filters.swap_ip_blocklist(id, &display_name, &data),
                FilterKind::IpAllowlist => filters.swap_ip_allowlist(id, &display_name, &data),
                FilterKind::Unknown => {
                    warn!("unknown filter kind in reload signal, skipping");
                    return;
                }
            };
            if let Err(e) = result {
                warn!(error = %e, "failed to swap filter from reload");
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to read filter from Object Store for reload");
        }
    }
}

/// Handle a GeoIP reload signal.
async fn handle_geoip_reload(js: &jetstream::Context, geo: &GeoHolder) {
    let bucket = match js.get_object_store(BUCKET_GEO).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to get geo bucket for reload");
            return;
        }
    };

    match read_object(&bucket, OBJ_GEOIP_BIN).await {
        Ok(data) => match geo.swap(&data) {
            Ok((v4, v6)) => info!(v4, v6, "geo table reloaded via signal"),
            Err(e) => warn!(error = %e, "failed to parse geo table"),
        },
        Err(e) => {
            warn!(error = %e, "failed to read geoip.bin from Object Store");
        }
    }
}

/// Handle a suffix set reload signal.
async fn handle_suffix_reload(js: &jetstream::Context, suffix: &crate::suffix::SuffixHolder) {
    let bucket = match js.get_object_store(BUCKET_FILTERS).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to get filter bucket for suffix reload");
            return;
        }
    };

    match read_object(&bucket, OBJ_SUFFIX_SET).await {
        Ok(data) => match suffix.swap(&data) {
            Ok(count) => info!(entries = count, "suffix set reloaded via signal"),
            Err(e) => warn!(error = %e, "failed to parse suffix set"),
        },
        Err(e) => {
            warn!(error = %e, "failed to read suffix set from Object Store");
        }
    }
}

/// Maximum Object Store object size (100 MB).
const MAX_OBJECT_SIZE: usize = 100 * 1024 * 1024;

/// Read an object's full contents from an Object Store bucket.
pub async fn read_object(
    bucket: &object_store::ObjectStore,
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let object = bucket.get(name).await?;
    let size = object.info.size;
    if size > MAX_OBJECT_SIZE {
        anyhow::bail!("object '{name}' too large: {size} bytes (max {MAX_OBJECT_SIZE})");
    }
    let mut reader = object;
    let mut bytes = Vec::with_capacity(size);
    reader.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// ACME certificate distribution
// ---------------------------------------------------------------------------

/// Provision the ACME certificate Object Store bucket (idempotent).
pub async fn provision_cert_bucket(
    js: &jetstream::Context,
) -> anyhow::Result<object_store::ObjectStore> {
    match js
        .create_object_store(object_store::Config {
            bucket: BUCKET_CERTS.to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(store) => Ok(store),
        Err(_) => Ok(js.get_object_store(BUCKET_CERTS).await?),
    }
}

/// Provision the ACME leader lock KV bucket (5-min TTL for auto-expiry).
pub async fn provision_acme_lock(
    js: &jetstream::Context,
) -> anyhow::Result<async_nats::jetstream::kv::Store> {
    match js
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: BUCKET_ACME.to_string(),
            max_age: Duration::from_secs(300), // 5 min lock TTL
            ..Default::default()
        })
        .await
    {
        Ok(store) => Ok(store),
        Err(_) => Ok(js.get_key_value(BUCKET_ACME).await?),
    }
}

/// Try to acquire the ACME leader lock. Returns true if this node won.
/// Uses atomic `create` — only the first writer succeeds.
pub async fn try_acme_leader_lock(js: &jetstream::Context) -> anyhow::Result<bool> {
    let kv = provision_acme_lock(js).await?;
    match kv.create(KV_ACME_LEADER, "locked".into()).await {
        Ok(_) => {
            info!("acquired ACME leader lock");
            Ok(true)
        }
        Err(_) => {
            info!("ACME leader lock held by another node");
            Ok(false)
        }
    }
}

/// Release the ACME leader lock so another node can acquire it.
pub async fn release_acme_leader_lock(js: &jetstream::Context) -> anyhow::Result<()> {
    let kv = provision_acme_lock(js).await?;
    kv.purge(KV_ACME_LEADER).await?;
    info!("released ACME leader lock");
    Ok(())
}

/// Store cert+key bundle in Object Store for distribution to other nodes.
pub async fn store_acme_cert(
    js: &jetstream::Context,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<()> {
    let store = provision_cert_bucket(js).await?;
    let bundle = serde_json::json!({
        "cert_pem": cert_pem,
        "key_pem": key_pem,
    });
    let data = serde_json::to_vec(&bundle)?;
    let mut reader: &[u8] = &data;
    store.put(OBJ_CERT_BUNDLE, &mut reader).await?;
    info!("stored ACME certificate bundle in Object Store");
    Ok(())
}

/// Load cert from Object Store. Returns None if bucket/object doesn't exist.
pub async fn load_acme_cert(
    js: &jetstream::Context,
) -> anyhow::Result<Option<rustls::sign::CertifiedKey>> {
    let store = match js.get_object_store(BUCKET_CERTS).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let data = match read_object(&store, OBJ_CERT_BUNDLE).await {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let bundle: serde_json::Value = serde_json::from_slice(&data)?;
    let cert_pem = bundle["cert_pem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing cert_pem in cert bundle"))?;
    let key_pem = bundle["key_pem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing key_pem in cert bundle"))?;
    let key = tls::pem_to_certified_key(cert_pem, key_pem)?;
    Ok(Some(key))
}

/// Watch the cert Object Store and return as soon as a valid cert appears.
/// Uses NATS Object Store `watch()` for instant notification — no polling delay.
/// Falls back to timeout if no cert appears within the given duration.
pub async fn wait_for_acme_cert(
    js: &jetstream::Context,
    timeout: Duration,
) -> anyhow::Result<rustls::sign::CertifiedKey> {
    let store = provision_cert_bucket(js).await?;
    let mut watcher = store
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("failed to watch cert Object Store: {e}"))?;
    info!("watching Object Store for ACME certificate");

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, watcher.next()).await {
            Ok(Some(Ok(info))) if info.name == OBJ_CERT_BUNDLE && !info.deleted => {
                info!("cert change detected in Object Store, loading");
                match load_acme_cert(js).await? {
                    Some(key) => return Ok(key),
                    None => continue,
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("cert watch stream ended unexpectedly"),
            Err(_) => anyhow::bail!("timed out waiting for ACME certificate in Object Store"),
        }
    }
}

// ---------------------------------------------------------------------------
// Health + status responders
// ---------------------------------------------------------------------------

/// Spawn a responder for health check request/reply.
pub fn spawn_health_responder(
    client: async_nats::Client,
    start_time: Instant,
    query_counter: Arc<AtomicU64>,
    block_counter: Arc<AtomicU64>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sub = match client.subscribe(SUBJECT_HEALTH).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to subscribe to health subject");
                return;
            }
        };
        info!(subject = SUBJECT_HEALTH, "health responder listening");

        while let Some(msg) = sub.next().await {
            let Some(reply) = msg.reply else { continue };
            let health = HealthStatus {
                uptime_secs: start_time.elapsed().as_secs(),
                total_queries: query_counter.load(Ordering::Relaxed),
                blocked_queries: block_counter.load(Ordering::Relaxed),
                nats_connected: true,
            };
            let payload = serde_json::to_vec(&health).unwrap_or_default();
            if let Err(e) = client.publish(reply, payload.into()).await {
                warn!(error = %e, "failed to respond to health check");
            }
        }
    })
}

/// Spawn a responder for list status request/reply.
pub fn spawn_list_status_responder(
    client: async_nats::Client,
    filters: Arc<FilterHolder>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sub = match client.subscribe(SUBJECT_LIST_STATUS).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to subscribe to list status subject");
                return;
            }
        };
        info!(
            subject = SUBJECT_LIST_STATUS,
            "list status responder listening"
        );

        while let Some(msg) = sub.next().await {
            let Some(reply) = msg.reply else { continue };
            let status: ListStatus = filters.status();
            let payload = serde_json::to_vec(&status).unwrap_or_default();
            if let Err(e) = client.publish(reply, payload.into()).await {
                warn!(error = %e, "failed to respond to list status request");
            }
        }
    })
}
