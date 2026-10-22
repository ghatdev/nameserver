use anyhow::{Context, Result, anyhow, ensure};
use arc_swap::ArcSwap;
use async_nats::jetstream::{self, kv::Operation};
use futures::StreamExt;
use hickory_server::{
    dnssec::NxProofKind,
    proto::{
        dnssec::{
            Algorithm, DnssecSigner, Nsec3HashAlgorithm, SigningKey, crypto::EcdsaSigningKey,
            rdata::DNSKEY,
        },
        rr::Name,
        serialize::txt::Parser,
    },
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType},
};
use nameserver_common::{nats_config::NatsConfig, nats_subjects::*, zone::ZoneKvConfig};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Settings {
    pub nats: NatsConfig,
    pub origins: Vec<String>,
}

type Zones = BTreeMap<String, (u64, ZoneKvConfig)>;
type Handlers = BTreeMap<String, Arc<dyn ZoneHandler>>;

pub async fn connect(
    settings: Settings,
    files: Handlers,
) -> Result<(Arc<ArcSwap<Catalog>>, Vec<tokio::task::AbortHandle>)> {
    let client = async_nats::connect(&settings.nats.url).await?;
    let js = jetstream::new(client.clone());
    let kv = match js.get_key_value(BUCKET_CONFIG).await {
        Ok(kv) => kv,
        Err(_) => {
            js.create_key_value(jetstream::kv::Config {
                bucket: BUCKET_CONFIG.into(),
                num_replicas: settings.nats.stream_replicas,
                ..Default::default()
            })
            .await?
        }
    };
    // Subscribe before reading the current keys so updates during startup cannot be lost.
    let watch = kv.watch_with_history(format!("{KV_ZONE_PREFIX}>")).await?;
    let mut zones = Zones::new();
    let mut keys = kv.keys().await?;
    while let Some(key) = keys.next().await {
        let key = key?;
        if key.starts_with(KV_ZONE_PREFIX)
            && let Some(entry) = kv.entry(&key).await?
            && entry.operation == Operation::Put
        {
            let config: ZoneKvConfig = rmp_serde::from_slice(&entry.value)?;
            if includes(&settings, &config.origin) {
                zones.insert(key, (entry.revision, config));
            }
        }
    }
    let challenges = BTreeMap::new();
    let initial = rebuild(&zones, &files, &challenges, &js).await?;
    let catalog = Arc::new(ArcSwap::from_pointee(initial));
    let shared = catalog.clone();
    let job = tokio::spawn(async move {
        let mut watch = watch;
        let mut zones = zones;
        let mut challenges: BTreeMap<String, Vec<String>> = challenges;
        let mut set = match client.subscribe(SUBJECT_ACME_TXT_SET).await {
            Ok(sub) => sub,
            Err(error) => {
                tracing::error!(error = %error, "cannot subscribe to certificate challenges");
                return;
            }
        };
        let mut clear = match client.subscribe(SUBJECT_ACME_TXT_CLEAR).await {
            Ok(sub) => sub,
            Err(error) => {
                tracing::error!(error = %error, "cannot subscribe to certificate challenge cleanup");
                return;
            }
        };
        let mut interval = tokio::time::interval(Duration::from_secs(86_400));
        interval.tick().await;
        loop {
            let mut next_zones = zones.clone();
            let mut next_challenges = challenges.clone();
            tokio::select! {
                entry = watch.next() => {
                    match entry {
                        Some(Ok(entry)) => {
                            if zones.get(&entry.key).is_some_and(|(revision, _)| *revision >= entry.revision) { continue; }
                            if entry.operation != Operation::Put { next_zones.remove(&entry.key); }
                            else {
                                match rmp_serde::from_slice::<ZoneKvConfig>(&entry.value) {
                                    Ok(config) if includes(&settings, &config.origin) => { next_zones.insert(entry.key, (entry.revision, config)); }
                                    Ok(_) => continue,
                                    Err(error) => { tracing::debug!(error = %error, "invalid managed zone update"); tracing::warn!("managed zone update rejected"); continue; }
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("zone watch interrupted; retaining current zones and reconnecting");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            match kv.watch_with_history(format!("{KV_ZONE_PREFIX}>" )).await { Ok(next) => watch = next, Err(_) => continue }
                            continue;
                        }
                    }
                }
                message = set.next() => {
                    let Some(message) = message else { break; };
                    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&message.payload) else { continue; };
                    let (Some(fqdn), Some(token)) = (value["fqdn"].as_str(), value["value"].as_str()) else { continue; };
                    let Ok(name) = fqdn.parse::<Name>() else { continue; };
                    if !zones.values().any(|(_, config)| zone_contains(&config.origin, &name)) { continue; }
                    let values = next_challenges.entry(name.to_lowercase().to_ascii()).or_default();
                    if !values.contains(&token.to_owned()) { values.push(token.to_owned()); }
                }
                message = clear.next() => {
                    let Some(message) = message else { break; };
                    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&message.payload) else { continue; };
                    let Some(fqdn) = value["fqdn"].as_str() else { continue; };
                    let Ok(name) = fqdn.parse::<Name>() else { continue; };
                    next_challenges.remove(&name.to_lowercase().to_ascii());
                }
                _ = interval.tick() => {}
            }
            match rebuild(&next_zones, &files, &next_challenges, &js).await {
                Ok(next) => {
                    shared.store(Arc::new(next));
                    zones = next_zones;
                    challenges = next_challenges;
                    tracing::info!("managed authoritative zones updated");
                }
                Err(error) => {
                    tracing::debug!(error = %error, "managed zone rebuild failed");
                    tracing::warn!("zone rebuild rejected; retaining current signed zones");
                }
            }
        }
    });
    Ok((catalog, vec![job.abort_handle()]))
}

fn includes(settings: &Settings, origin: &str) -> bool {
    settings.origins.is_empty()
        || settings.origins.iter().any(|name| {
            name.trim_end_matches('.')
                .eq_ignore_ascii_case(origin.trim_end_matches('.'))
        })
}
fn zone_contains(origin: &str, name: &Name) -> bool {
    Name::from_utf8(format!("{}.", origin.trim_end_matches('.')))
        .is_ok_and(|zone| zone.zone_of(name))
}

async fn object(js: &jetstream::Context, name: &str) -> Result<Vec<u8>> {
    let store = js.get_object_store(BUCKET_DNSSEC).await?;
    let mut object = store.get(name).await?;
    ensure!(object.info.size <= 16384, "DNSSEC key exceeds size limit");
    let mut bytes = Vec::new();
    object.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

async fn rebuild(
    zones: &Zones,
    files: &Handlers,
    challenges: &BTreeMap<String, Vec<String>>,
    js: &jetstream::Context,
) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    for (origin, handler) in files {
        catalog.upsert(Name::from_utf8(origin)?.into(), vec![handler.clone()]);
    }
    let mut signed = false;
    for (_, config) in zones.values() {
        let origin =
            Name::from_utf8(format!("{}.", config.origin.trim_end_matches('.')))?.to_lowercase();
        ensure!(
            !files.contains_key(&origin.to_ascii()),
            "zone configured both locally and through management"
        );
        let mut handler = zone(config, challenges)?;
        if config
            .dnssec
            .as_ref()
            .is_some_and(|settings| settings.enabled)
        {
            let ksk = object(js, OBJ_DNSSEC_KSK)
                .await
                .context("enabled DNSSEC requires KSK")?;
            let zsk = object(js, OBJ_DNSSEC_ZSK)
                .await
                .context("enabled DNSSEC requires ZSK")?;
            let mut published_keys = Vec::new();
            for (bytes, sep) in [(ksk, true), (zsk, false)] {
                let key = EcdsaSigningKey::from_pkcs8(
                    &rustls::pki_types::PrivatePkcs8KeyDer::from(bytes),
                    Algorithm::ECDSAP256SHA256,
                )
                .map_err(|error| anyhow!(error))?;
                let public = key.to_public_key().map_err(|error| anyhow!(error))?;
                published_keys.push(DNSKEY::new(true, sep, false, public.clone()));
                let signer = DnssecSigner::new(
                    DNSKEY::new(true, sep, false, public),
                    Box::new(key),
                    origin.clone(),
                    Duration::from_secs(7 * 86_400),
                );
                handler
                    .add_zone_signing_key_mut(signer)
                    .map_err(|error| anyhow!(error))?;
            }
            // Keep the published flags identical to the signers' key tags.
            let mut rrset = hickory_server::proto::rr::RecordSet::new(
                origin.clone(),
                hickory_server::proto::rr::RecordType::DNSKEY,
                0,
            );
            for key in published_keys {
                rrset.insert(
                    hickory_server::proto::rr::Record::from_rdata(
                        origin.clone(),
                        300,
                        hickory_server::proto::rr::RData::DNSSEC(
                            hickory_server::proto::dnssec::rdata::DNSSECRData::DNSKEY(key),
                        ),
                    ),
                    0,
                );
            }
            handler.records_get_mut().insert(
                hickory_server::proto::rr::RrKey::new(
                    origin.clone().into(),
                    hickory_server::proto::rr::RecordType::DNSKEY,
                ),
                Arc::new(rrset),
            );
            handler.secure_zone_mut().map_err(|error| anyhow!(error))?;
            signed = true;
        }
        catalog.upsert(
            origin.into(),
            vec![Arc::new(crate::managed_zone::ManagedZone(handler))],
        );
    }
    if signed {
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?;
        js.get_key_value(BUCKET_CONFIG)
            .await?
            .put(KV_DNSSEC_LAST_SIGNED_AT, timestamp.into())
            .await?;
    }
    Ok(catalog)
}

fn quoted(value: &str) -> String {
    let mut escaped = String::from("\"");
    for byte in value.bytes() {
        match byte {
            b'"' | b'\\' => {
                escaped.push('\\');
                escaped.push(byte as char);
            }
            32..=126 => escaped.push(byte as char),
            _ => escaped.push_str(&format!("\\{byte:03}")),
        }
    }
    escaped.push('"');
    escaped
}

fn zone(
    config: &ZoneKvConfig,
    challenges: &BTreeMap<String, Vec<String>>,
) -> Result<InMemoryZoneHandler> {
    ensure!(
        config.version >= 1,
        "unsupported zone configuration version"
    );
    let origin =
        Name::from_utf8(format!("{}.", config.origin.trim_end_matches('.')))?.to_lowercase();
    let nameservers: Vec<Name> = config
        .nameservers
        .iter()
        .map(|name| Name::from_utf8(format!("{}.", name.trim_end_matches('.'))))
        .collect::<Result<_, _>>()?;
    let mname = nameservers.first().unwrap_or(&origin);
    let serial = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        & 0xffff_ffff) as u32;
    let mut text = format!(
        "$ORIGIN {origin}\n$TTL 3600\n@ IN SOA {mname} admin.{origin} {serial} {} {} {} {}\n",
        config.soa.refresh, config.soa.retry, config.soa.expire, config.soa.minimum
    );
    for ns in nameservers {
        text.push_str(&format!("@ IN NS {ns}\n"));
    }
    for record in &config.records {
        ensure!(
            !record.name.chars().any(char::is_whitespace),
            "invalid record owner"
        );
        let owner = if record.name == "@" {
            origin.clone()
        } else {
            Name::from_utf8(&record.name)?.append_domain(&origin)?
        };
        ensure!(origin.zone_of(&owner), "record lies outside its zone");
        let rtype = record.rtype.to_ascii_uppercase();
        let _: hickory_server::proto::rr::RecordType = rtype.parse()?;
        ensure!(
            !matches!(
                rtype.as_str(),
                "SOA" | "DNSKEY" | "RRSIG" | "NSEC" | "NSEC3" | "AXFR" | "ANY"
            ),
            "record type is generated or unsuitable for managed zone data"
        );
        let value = if rtype == "TXT" {
            quoted(&record.value)
        } else {
            ensure!(
                !record.value.contains(['\n', '\r', ';', '(', ')']),
                "invalid record data"
            );
            record.value.clone()
        };
        text.push_str(&format!("{owner} {} IN {rtype} {value}\n", record.ttl));
    }
    for (fqdn, values) in challenges {
        let name = Name::from_utf8(fqdn)?;
        if origin.zone_of(&name) {
            for value in values {
                text.push_str(&format!("{name} 60 IN TXT {}\n", quoted(value)));
            }
        }
    }
    let (_, records) = Parser::new(text, None, Some(origin.clone())).parse()?;
    let proof = match config.dnssec.as_ref().filter(|settings| settings.enabled) {
        None => None,
        Some(settings) => {
            ensure!(
                settings.algorithm == "ECDSAP256SHA256",
                "only ECDSAP256SHA256 signing is supported"
            );
            match settings.nsec_mode.as_str() {
                "nsec" => Some(NxProofKind::Nsec),
                "nsec3" => {
                    ensure!(
                        settings.nsec3_iterations == 0 && settings.nsec3_salt.is_empty(),
                        "NSEC3 requires zero iterations and an empty salt"
                    );
                    Some(NxProofKind::Nsec3 {
                        algorithm: Nsec3HashAlgorithm::SHA1,
                        salt: Arc::from([]),
                        iterations: 0,
                        opt_out: false,
                    })
                }
                _ => anyhow::bail!("unsupported denial proof mode"),
            }
        }
    };
    InMemoryZoneHandler::new(origin, records, ZoneType::Primary, AxfrPolicy::Deny, proof)
        .map_err(|error| anyhow!(error))
}
