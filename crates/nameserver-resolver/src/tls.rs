use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Certificate resolver that supports atomic hot-swapping for renewal.
#[derive(Debug)]
pub struct HotSwapCertResolver(ArcSwap<CertifiedKey>);

impl ResolvesServerCert for HotSwapCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.load_full())
    }
}

impl HotSwapCertResolver {
    pub fn new(key: CertifiedKey) -> Arc<Self> {
        Arc::new(Self(ArcSwap::from_pointee(key)))
    }

    pub fn swap(&self, key: CertifiedKey) {
        self.0.store(Arc::new(key));
    }
}

pub fn load_from_pem(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        cert_path.display()
    );

    let key_file = std::fs::File::open(key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    let key = CertifiedKey::new(certs, signing_key);
    key.keys_match()?;
    Ok(key)
}

pub fn generate_self_signed() -> Result<CertifiedKey> {
    use rcgen::{CertificateParams, KeyPair, SanType};

    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST,
        )));

    let cert_der = params.self_signed(&key_pair)?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(CertifiedKey::new(vec![cert_der.into()], signing_key))
}

/// Build a CertifiedKey from PEM-encoded certificate chain and private key strings.
pub fn pem_to_certified_key(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;

    anyhow::ensure!(!certs.is_empty(), "no certificates found in PEM data");

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM data"))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    let key = CertifiedKey::new(certs, signing_key);
    key.keys_match()?;
    Ok(key)
}
