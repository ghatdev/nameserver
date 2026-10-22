mod managed;
mod managed_zone;

use std::{
    collections::HashSet,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use hickory_server::{
    dnssec::NxProofKind,
    proto::{
        dnssec::{Algorithm, DnssecSigner, SigningKey, crypto::EcdsaSigningKey, rdata::DNSKEY},
        rr::Name,
    },
    store::file::{FileConfig, FileZoneHandler},
    zone_handler::{AxfrPolicy, Catalog, DnssecZoneHandler, ZoneType},
};
use nameserver_core::{Filter, Prepared, ServerSettings, Snapshot, read_config, relative_to};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "default_server")]
    server: ServerSettings,
    #[serde(default)]
    zones: Vec<ZoneSettings>,
    management: Option<managed::Settings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneSettings {
    origin: String,
    file: PathBuf,
    dnssec: Option<DnssecSettings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnssecSettings {
    /// PKCS#8 PEM ECDSA P-256 combined signing key (DNSKEY flags 257).
    private_key: PathBuf,
    #[serde(default = "default_signature_days")]
    signature_validity_days: u16,
}

fn default_signature_days() -> u16 {
    7
}

fn default_server() -> ServerSettings {
    ServerSettings {
        listen: vec!["127.0.0.1:5354".parse().expect("constant socket address")],
        ..Default::default()
    }
}

pub async fn build(path: PathBuf) -> Result<Prepared> {
    let config: Config = read_config(&path)?;
    config.server.validate()?;
    ensure!(
        !config.zones.is_empty() || config.management.is_some(),
        "at least one authoritative zone is required"
    );
    let mut catalog = Catalog::new();
    let mut file_handlers = std::collections::BTreeMap::new();
    let mut seen = HashSet::new();
    let mut refresh_after: Option<Duration> = None;
    for zone in config.zones {
        let origin = Name::from_utf8(format!("{}.", zone.origin.trim_end_matches('.')))
            .context("invalid zone origin")?
            .to_lowercase();
        ensure!(seen.insert(origin.clone()), "duplicate zone origin");
        let handler = FileZoneHandler::try_from_config(
            origin.clone(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
            None,
            &FileConfig {
                zone_path: relative_to(&path, &zone.file),
            },
            zone.dnssec.as_ref().map(|_| NxProofKind::Nsec),
        )
        .map_err(|error| anyhow!(error))?;
        if let Some(settings) = zone.dnssec {
            ensure!(
                (1..=30).contains(&settings.signature_validity_days),
                "signature_validity_days must be between 1 and 30"
            );
            sign(
                &handler,
                &origin,
                &relative_to(&path, &settings.private_key),
                settings.signature_validity_days,
            )
            .await?;
            let interval = Duration::from_secs(
                (u64::from(settings.signature_validity_days) * 86_400 / 3).min(86_400),
            );
            refresh_after = Some(refresh_after.map_or(interval, |current| current.min(interval)));
        }
        let handler = Arc::new(handler);
        file_handlers.insert(
            origin.to_ascii(),
            handler.clone() as Arc<dyn hickory_server::zone_handler::ZoneHandler>,
        );
        catalog.upsert(origin.into(), vec![handler]);
    }
    let (catalog, background) = match config.management {
        Some(settings) => managed::connect(settings, file_handlers).await?,
        None => (Arc::new(arc_swap::ArcSwap::from_pointee(catalog)), vec![]),
    };
    Ok(Prepared {
        server: config.server,
        certificate: None,
        snapshot: Snapshot {
            catalog,
            background,
            processor: None,
            unchecked_catalog: None,
            filter: Filter::default(),
            recursive: false,
        },
        refresh_after,
    })
}

async fn sign(zone: &FileZoneHandler, origin: &Name, key_path: &Path, days: u16) -> Result<()> {
    let mut reader =
        BufReader::new(File::open(key_path).context("cannot open DNSSEC signing key")?);
    let key =
        rustls_pemfile::private_key(&mut reader)?.context("DNSSEC private key PEM is empty")?;
    let rustls::pki_types::PrivateKeyDer::Pkcs8(key) = key else {
        bail!("DNSSEC signing key must be in PKCS#8 PEM format");
    };
    let key = EcdsaSigningKey::from_pkcs8(&key, Algorithm::ECDSAP256SHA256)
        .map_err(|error| anyhow!("invalid ECDSA P-256 DNSSEC key: {error}"))?;
    let public = key
        .to_public_key()
        .map_err(|error| anyhow!("cannot derive DNSSEC public key: {error}"))?;
    let dnskey = DNSKEY::new(true, true, false, public);
    let signer = DnssecSigner::new(
        dnskey,
        Box::new(key),
        origin.clone(),
        Duration::from_secs(u64::from(days) * 86_400),
    );
    zone.add_zone_signing_key(signer)
        .await
        .map_err(|error| anyhow!("cannot add DNSSEC signing key: {error}"))?;
    zone.secure_zone()
        .await
        .map_err(|error| anyhow!("cannot sign zone: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dnssec_never_falls_back_to_unsigned_when_key_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("example.zone"),
            include_str!("../../../examples/zones/example.test.zone"),
        )
        .unwrap();
        let path = temp.path().join("authority.toml");
        std::fs::write(&path, "[[zones]]\norigin = 'example.test'\nfile = 'example.zone'\n[zones.dnssec]\nprivate_key = 'missing.pem'\n").unwrap();
        assert!(build(path).await.is_err());
    }

    #[tokio::test]
    async fn duplicate_zones_are_rejected_case_insensitively() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("example.zone"),
            include_str!("../../../examples/zones/example.test.zone"),
        )
        .unwrap();
        let path = temp.path().join("authority.toml");
        std::fs::write(&path, "[[zones]]\norigin = 'example.test'\nfile = 'example.zone'\n[[zones]]\norigin = 'EXAMPLE.TEST.'\nfile = 'example.zone'\n").unwrap();
        assert!(build(path).await.is_err());
    }
}
