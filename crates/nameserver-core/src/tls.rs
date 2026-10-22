use std::{fmt, fs::File, io::BufReader, path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{TlsSettings, relative_to};

pub struct CertificateResolver(pub ArcSwap<CertifiedKey>);

impl fmt::Debug for CertificateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertificateResolver")
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.load_full())
    }
}

pub fn load(settings: &TlsSettings, config: &Path) -> Result<CertifiedKey> {
    let cert_path = relative_to(config, &settings.certificate);
    let key_path = relative_to(config, &settings.private_key);
    let mut reader = BufReader::new(File::open(&cert_path).context("cannot open TLS certificate")?);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("invalid TLS certificate PEM")?;
    ensure!(!certificates.is_empty(), "TLS certificate chain is empty");
    let mut reader = BufReader::new(File::open(&key_path).context("cannot open TLS private key")?);
    let key = rustls_pemfile::private_key(&mut reader)?.context("TLS private key PEM is empty")?;
    let key = rustls::crypto::ring::sign::any_supported_type(&key)
        .context("unsupported TLS private key")?;
    let certified = CertifiedKey::new(certificates, key);
    certified
        .keys_match()
        .context("TLS certificate and private key do not match")?;
    Ok(certified)
}

/// Stable listener identity whose certificate source can change on reload.
#[derive(Debug)]
pub struct CertificateSource(std::sync::RwLock<Arc<dyn ResolvesServerCert>>);
impl CertificateSource {
    pub fn new(provider: Arc<dyn ResolvesServerCert>) -> Self {
        Self(std::sync::RwLock::new(provider))
    }
    pub fn swap(&self, provider: Arc<dyn ResolvesServerCert>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = provider;
    }
}
impl ResolvesServerCert for CertificateSource {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .resolve(hello)
    }
}
