use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use async_nats::jetstream;

use nameserver_common::nats_subjects::{SUBJECT_ACME_TXT_CLEAR, SUBJECT_ACME_TXT_SET};

use crate::config::{AcmeDirectory, TlsConfig};
use crate::tls::{self, HotSwapCertResolver};

const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60); // 12 hours
const RENEWAL_THRESHOLD_DAYS: i64 = 30;
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Load existing ACME account from disk or create a new one.
async fn get_or_create_account(config: &TlsConfig) -> Result<Account> {
    let account_path = config.cert_dir.join("account.json");

    if account_path.exists() {
        info!(path = %account_path.display(), "loading existing ACME account");
        let json = tokio::fs::read_to_string(&account_path)
            .await
            .context("failed to read ACME account file")?;
        let credentials: AccountCredentials =
            serde_json::from_str(&json).context("failed to parse ACME account credentials")?;
        let account = Account::builder()?
            .from_credentials(credentials)
            .await
            .context("failed to restore ACME account")?;
        return Ok(account);
    }

    let email = config
        .acme_email
        .as_deref()
        .context("acme_email is required for ACME mode")?;

    let directory_url = match config.acme_directory {
        AcmeDirectory::Production => LetsEncrypt::Production.url(),
        AcmeDirectory::Staging => LetsEncrypt::Staging.url(),
    };

    info!(
        email,
        directory = directory_url,
        "creating new ACME account"
    );
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[&format!("mailto:{email}")],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            None,
        )
        .await
        .context("failed to create ACME account")?;

    // Persist account credentials
    tokio::fs::create_dir_all(&config.cert_dir)
        .await
        .context("failed to create cert directory")?;
    let json = serde_json::to_string_pretty(&credentials)?;
    write_restricted(&account_path, json.as_bytes())
        .await
        .context("failed to save ACME account credentials")?;
    info!(path = %account_path.display(), "saved ACME account credentials");

    Ok(account)
}

/// Whether DNS-01 challenge is available (Cloudflare credentials configured).
fn has_dns01(config: &TlsConfig) -> bool {
    config.cloudflare_api_token.is_some() && config.cloudflare_zone_id.is_some()
}

/// Run the full ACME issuance flow: order → challenge → finalize → certificate.
/// Uses in-zone DNS-01 via NATS (authority process handles TXT records),
/// Cloudflare DNS-01 if configured, otherwise falls back to HTTP-01.
async fn issue_certificate(
    account: &Account,
    config: &TlsConfig,
    nats_client: Option<&async_nats::Client>,
) -> Result<(String, String)> {
    let domain = config
        .acme_domain
        .as_deref()
        .context("acme_domain is required for ACME mode")?;

    info!("starting ACME certificate issuance");

    // Build identifiers: primary domain + any SANs (e.g., *.dns.example.test).
    let mut identifiers = vec![Identifier::Dns(domain.to_string())];
    for san in &config.acme_san {
        identifiers.push(Identifier::Dns(san.clone()));
    }

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("failed to create ACME order")?;

    // Solve all authorizations.
    //
    // IMPORTANT: challenge TXT records are published (appended) and only cleared
    // AFTER `poll_ready` below. Let's Encrypt validates DNS-01 asynchronously and
    // from multiple MPIC vantage points after `set_ready`, so the records must
    // stay live through validation. A wildcard-SAN cert produces two
    // authorizations at the same `_acme-challenge.<base>` name with different
    // tokens — both must coexist (the authority's set_acme_txt appends).
    let use_dns01 = has_dns01(config);
    let mut nats_txt_to_clear: Vec<String> = Vec::new();
    let mut nats_cleaned: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cf_record_ids: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("failed to fetch authorization")?;

        if authz.status == AuthorizationStatus::Valid {
            info!("authorization already valid, skipping");
            continue;
        }

        if nats_client.is_some() || use_dns01 {
            // DNS-01 challenge (via NATS to authority process, or Cloudflare).
            let domain = authz.identifier().to_string();
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| anyhow::anyhow!("no dns-01 challenge offered"))?;

            let key_auth = challenge.key_authorization();
            let digest = {
                use base64::Engine;
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(key_auth.as_str().as_bytes());
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
            };

            let clean_domain = domain.strip_prefix("*.").unwrap_or(&domain);
            let record_name = format!("_acme-challenge.{clean_domain}");

            if let Some(client) = nats_client {
                // Clean slate once per record name this attempt: a prior
                // interrupted attempt may have left stale tokens (set_acme_txt
                // appends, so we must not accumulate across attempts).
                if nats_cleaned.insert(record_name.clone()) {
                    let clear = serde_json::json!({"fqdn": record_name});
                    let subject: async_nats::Subject = SUBJECT_ACME_TXT_CLEAR.into();
                    let _ = client.publish(subject, clear.to_string().into()).await;
                }
                // In-zone DNS-01 via NATS: append this authorization's token.
                info!(record = %record_name, "publishing DNS-01 TXT record via NATS");
                let payload = serde_json::json!({"fqdn": record_name, "value": digest});
                let subject: async_nats::Subject = SUBJECT_ACME_TXT_SET.into();
                let _ = client.publish(subject, payload.to_string().into()).await;
                nats_txt_to_clear.push(record_name.clone());
                // Wait for DNS propagation — LE MPIC queries multiple vantage points.
                tokio::time::sleep(Duration::from_secs(15)).await;
            } else {
                // Cloudflare DNS-01 (legacy/development fallback).
                let api_token = config
                    .cloudflare_api_token
                    .as_deref()
                    .context("cloudflare_api_token required for DNS-01")?;
                let zone_id = config
                    .cloudflare_zone_id
                    .as_deref()
                    .context("cloudflare_zone_id required for DNS-01")?;

                info!(record = %record_name, "creating DNS-01 TXT record via Cloudflare");
                cf_record_ids
                    .push(cloudflare_create_txt(api_token, zone_id, &record_name, &digest).await?);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }

            challenge
                .set_ready()
                .await
                .context("failed to notify ACME server that DNS-01 challenge is ready")?;
            // Do NOT clear the TXT here — validation happens asynchronously after
            // set_ready. Cleanup is performed after poll_ready below.
        } else {
            // HTTP-01 challenge (existing behavior).
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("no http-01 challenge offered"))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();

            info!(token = %token, "serving http-01 challenge on port 80");
            let server_handle = tokio::spawn(serve_http01_challenge(token, key_auth));

            challenge
                .set_ready()
                .await
                .context("failed to notify ACME server that challenge is ready")?;

            server_handle
                .await?
                .context("http-01 challenge server failed")?;
        }
    }

    // Wait for order to become ready (challenge validation may still be processing).
    let poll_result = order.poll_ready(&RetryPolicy::default()).await;

    // Clear challenge TXT records now that validation has completed (or failed) —
    // never before, so LE's asynchronous/MPIC validation always sees them.
    if let Some(client) = nats_client {
        let mut seen = std::collections::HashSet::new();
        for name in &nats_txt_to_clear {
            if seen.insert(name.clone()) {
                let payload = serde_json::json!({"fqdn": name});
                let subject: async_nats::Subject = SUBJECT_ACME_TXT_CLEAR.into();
                if let Err(e) = client
                    .publish::<async_nats::Subject>(subject, payload.to_string().into())
                    .await
                {
                    warn!(error = %e, "failed to publish ACME TXT clear (non-fatal)");
                }
            }
        }
    }
    if !cf_record_ids.is_empty() {
        let api_token = config.cloudflare_api_token.as_deref().unwrap_or_default();
        let zone_id = config.cloudflare_zone_id.as_deref().unwrap_or_default();
        for rid in &cf_record_ids {
            if let Err(e) = cloudflare_delete_txt(api_token, zone_id, rid).await {
                warn!(error = %e, "failed to clean up Cloudflare DNS-01 TXT (non-fatal)");
            }
        }
    }

    let status = poll_result.context("failed while polling order readiness")?;
    if status != OrderStatus::Ready {
        anyhow::bail!("unexpected order status after challenges: {status:?}");
    }

    // Finalize order — instant-acme generates CSR internally and returns private key PEM
    let private_key_pem = order
        .finalize()
        .await
        .context("failed to finalize ACME order")?;

    // Retrieve the issued certificate chain
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("failed to retrieve certificate from ACME server")?;

    // Persist to disk
    let cert_path = config.cert_dir.join("cert.pem");
    let key_path = config.cert_dir.join("key.pem");

    tokio::fs::create_dir_all(&config.cert_dir).await?;
    write_restricted(&cert_path, cert_chain_pem.as_bytes()).await?;
    write_restricted(&key_path, private_key_pem.as_bytes()).await?;

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "saved ACME certificate and key"
    );

    Ok((cert_chain_pem, private_key_pem))
}

/// Create a TXT record via Cloudflare API. Returns the record ID.
async fn cloudflare_create_txt(
    api_token: &str,
    zone_id: &str,
    name: &str,
    content: &str,
) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
    let body = serde_json::json!({
        "type": "TXT",
        "name": name,
        "content": content,
        "ttl": 60,
    });

    let resp = client
        .post(&url)
        .bearer_auth(api_token)
        .json(&body)
        .send()
        .await
        .context("Cloudflare API request failed")?;

    let status = resp.status();
    let json: serde_json::Value = resp.json().await?;

    if !status.is_success() || !json["success"].as_bool().unwrap_or(false) {
        let errors = json["errors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e["message"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        anyhow::bail!("Cloudflare create TXT failed: {errors}");
    }

    json["result"]["id"]
        .as_str()
        .map(String::from)
        .context("Cloudflare response missing record ID")
}

/// Delete a TXT record via Cloudflare API.
async fn cloudflare_delete_txt(api_token: &str, zone_id: &str, record_id: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url =
        format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}");

    let resp = client
        .delete(&url)
        .bearer_auth(api_token)
        .send()
        .await
        .context("Cloudflare delete request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Cloudflare delete TXT failed: HTTP {}", resp.status());
    }

    Ok(())
}

/// Serve the http-01 challenge response on port 80.
/// Binds a minimal TCP server that responds to
/// `GET /.well-known/acme-challenge/{token}` with the key authorization string.
/// Keeps serving until timeout to support Let's Encrypt MPIC (multi-perspective validation).
async fn serve_http01_challenge(token: String, key_auth: String) -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:80")
        .await
        .context("failed to bind port 80 for ACME http-01 challenge")?;

    info!("http-01 challenge server listening on port 80");

    let expected_path = format!("/.well-known/acme-challenge/{token}");

    // Keep serving until timeout — Let's Encrypt validates from multiple IPs (MPIC).
    let deadline = tokio::time::Instant::now() + CHALLENGE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            info!("http-01 challenge server timeout, shutting down");
            return Ok(());
        }

        let accept = tokio::time::timeout(remaining, listener.accept()).await;

        let (mut stream, addr) = match accept {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                warn!(error = %e, "failed to accept connection on port 80");
                continue;
            }
            Err(_) => {
                info!("http-01 challenge server timeout, shutting down");
                return Ok(());
            }
        };

        // Read the HTTP request
        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };

        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse the request line to check the path
        let request_line = request.lines().next().unwrap_or("");
        let path = request_line.split_whitespace().nth(1).unwrap_or("");

        if path == expected_path {
            info!(addr = %addr, "serving http-01 challenge response");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n{}",
                key_auth.len(),
                key_auth,
            );
            let _ = stream.write_all(response.as_bytes()).await;
            // Continue serving — more validators may connect
            continue;
        }

        // Not the challenge path — return 404
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

/// Load cached certificate from disk. Returns None if files are missing
/// or the certificate expires within the renewal threshold.
fn load_cached_cert(config: &TlsConfig) -> Result<Option<CertifiedKey>> {
    let cert_path = config.cert_dir.join("cert.pem");
    let key_path = config.cert_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let cert_pem = std::fs::read_to_string(&cert_path).context("failed to read cached cert.pem")?;
    let key_pem = std::fs::read_to_string(&key_path).context("failed to read cached key.pem")?;

    // Check if the certificate is still valid (not expiring within threshold)
    if is_cert_expiring_soon(&cert_pem) {
        info!("cached certificate is expiring soon, will renew");
        return Ok(None);
    }

    let key = tls::pem_to_certified_key(&cert_pem, &key_pem)?;
    info!(
        cert = %cert_path.display(),
        "loaded cached ACME certificate"
    );
    Ok(Some(key))
}

/// Check if the first certificate in the PEM chain expires within the renewal threshold.
fn is_cert_expiring_soon(cert_pem: &str) -> bool {
    use rustls::pki_types::CertificateDer;

    let certs: Vec<CertificateDer<'static>> =
        match rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>() {
            Ok(c) => c,
            Err(_) => return true, // can't parse → treat as expired
        };

    let cert = match certs.first() {
        Some(c) => c,
        None => return true,
    };

    // Parse the X.509 certificate to read the notAfter field.
    // We do a minimal ASN.1 parse to extract the validity period.
    match parse_x509_not_after(cert.as_ref()) {
        Some(not_after) => {
            let now = std::time::SystemTime::now();
            let threshold = Duration::from_secs(RENEWAL_THRESHOLD_DAYS as u64 * 24 * 60 * 60);
            match not_after.duration_since(now) {
                Ok(remaining) => remaining < threshold,
                Err(_) => true, // already expired
            }
        }
        None => true, // can't determine expiry → treat as expiring
    }
}

/// Minimal ASN.1 DER parser to extract notAfter from an X.509 certificate.
/// Returns the expiry time as SystemTime, or None if parsing fails.
fn parse_x509_not_after(der: &[u8]) -> Option<std::time::SystemTime> {
    // X.509 structure (simplified):
    //   Certificate ::= SEQUENCE {
    //     tbsCertificate SEQUENCE {
    //       version [0] EXPLICIT ...,
    //       serialNumber INTEGER,
    //       signature AlgorithmIdentifier,
    //       issuer Name,
    //       validity SEQUENCE {
    //         notBefore Time,
    //         notAfter Time     <-- we want this
    //       },
    //       ...
    //     },
    //     ...
    //   }

    let (_, cert_inner) = read_der_sequence(der)?;
    let (_, tbs_inner) = read_der_sequence(cert_inner)?;

    let mut pos = tbs_inner;

    // Skip version (context tag [0] EXPLICIT)
    if pos.first()? & 0xe0 == 0xa0 {
        let (rest, _) = read_der_tlv(pos)?;
        pos = rest;
    }

    // Skip serialNumber
    let (rest, _) = read_der_tlv(pos)?;
    pos = rest;

    // Skip signature AlgorithmIdentifier
    let (rest, _) = read_der_tlv(pos)?;
    pos = rest;

    // Skip issuer Name
    let (rest, _) = read_der_tlv(pos)?;
    pos = rest;

    // Validity SEQUENCE { notBefore, notAfter }
    let (_, validity_inner) = read_der_sequence(pos)?;

    // Skip notBefore
    let (rest, _) = read_der_tlv(validity_inner)?;

    // notAfter
    let (_, not_after_bytes) = read_der_tlv(rest)?;
    // The tag byte was consumed; we need the raw TLV to get the tag
    let tag = rest[0];

    parse_der_time(tag, not_after_bytes)
}

/// Read a DER SEQUENCE, returning (remaining bytes after sequence, sequence content bytes).
fn read_der_sequence(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.first()? != &0x30 {
        return None;
    }
    let (rest, content) = read_der_tlv(data)?;
    Some((rest, content))
}

/// Read a DER TLV (tag-length-value), returning (remaining bytes, value bytes).
fn read_der_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }

    let mut pos = 1; // skip tag

    // Read length
    let first_len = *data.get(pos)?;
    pos += 1;

    let length = if first_len < 0x80 {
        first_len as usize
    } else {
        let num_bytes = (first_len & 0x7f) as usize;
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = len.checked_shl(8)?;
            len |= *data.get(pos)? as usize;
            pos += 1;
        }
        len
    };

    let value = data.get(pos..pos + length)?;
    let rest = data.get(pos + length..)?;
    Some((rest, value))
}

/// Parse a DER UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) into SystemTime.
fn parse_der_time(tag: u8, value: &[u8]) -> Option<std::time::SystemTime> {
    let s = std::str::from_utf8(value).ok()?;

    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, s.get(2..)?)
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            let yyyy: i32 = s.get(0..4)?.parse().ok()?;
            (yyyy, s.get(4..)?)
        }
        _ => return None,
    };

    let month: u32 = rest.get(0..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    let hour: u64 = rest.get(4..6)?.parse().ok()?;
    let min: u64 = rest.get(6..8)?.parse().ok()?;
    let sec: u64 = rest.get(8..10)?.parse().ok()?;

    // Convert to days since Unix epoch (simplified, no leap second handling)
    let days = days_from_civil(year, month, day)?;
    let secs = days as u64 * 86400 + hour * 3600 + min * 60 + sec;

    Some(std::time::UNIX_EPOCH + Duration::from_secs(secs))
}

/// Write a file with restricted permissions (0600) for sensitive data (keys, credentials).
#[cfg(unix)]
async fn write_restricted(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = path.to_owned();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&data)
            })
    })
    .await?
    .context("failed to write restricted file")
}

#[cfg(not(unix))]
async fn write_restricted(path: &std::path::Path, data: &[u8]) -> Result<()> {
    tokio::fs::write(path, data).await?;
    Ok(())
}

/// Convert a civil date to days since Unix epoch (1970-01-01).
/// Algorithm from Howard Hinnant's date algorithms.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let doy = if month > 2 {
        (153 * (month as u64 - 3) + 2) / 5 + day as u64 - 1
    } else {
        (153 * (month as u64 + 9) + 2) / 5 + day as u64 - 1
    };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i64 - 719468)
}

/// Provision with retry — blocks until a certificate is obtained.
/// Tries cached cert first, then retries ACME with exponential backoff.
/// Auth zone keeps serving DNS throughout retries.
pub async fn provision_certificate_with_retry(
    config: &TlsConfig,
    nats_client: Option<&async_nats::Client>,
) -> Result<CertifiedKey> {
    // Fast path: cached cert
    if let Some(key) = load_cached_cert(config)? {
        info!("using cached ACME certificate");
        return Ok(key);
    }

    let mut backoff = Duration::from_secs(30);
    let max_backoff = Duration::from_secs(300);

    loop {
        match provision_certificate(config, nats_client).await {
            Ok(key) => return Ok(key),
            Err(e) => {
                warn!(error = %e, retry_in = ?backoff, "ACME provisioning failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// Provision an ACME certificate, returning the initial CertifiedKey.
/// If a valid cached certificate exists, uses that. Otherwise issues a new one.
async fn provision_certificate(
    config: &TlsConfig,
    nats_client: Option<&async_nats::Client>,
) -> Result<CertifiedKey> {
    // Try cached cert first
    if let Some(key) = load_cached_cert(config)? {
        return Ok(key);
    }

    // No valid cached cert — issue a new one
    let account = get_or_create_account(config).await?;
    let (cert_pem, key_pem) = issue_certificate(&account, config, nats_client).await?;
    tls::pem_to_certified_key(&cert_pem, &key_pem)
}

/// Check if a CertifiedKey's certificate is expiring within the renewal threshold.
pub fn is_key_expiring_soon(key: &CertifiedKey) -> bool {
    let Some(cert) = key.cert.first() else {
        return true;
    };
    match parse_x509_not_after(cert.as_ref()) {
        Some(not_after) => {
            let now = std::time::SystemTime::now();
            let threshold = Duration::from_secs(RENEWAL_THRESHOLD_DAYS as u64 * 24 * 60 * 60);
            match not_after.duration_since(now) {
                Ok(remaining) => remaining < threshold,
                Err(_) => true, // already expired
            }
        }
        None => true,
    }
}

/// Full ACME provisioning with NATS coordination.
/// Handles leader election, cert distribution via Object Store, and TXT sync.
/// Retries indefinitely with backoff — auth zone keeps serving throughout.
pub async fn provision_with_nats(
    config: &TlsConfig,
    client: &async_nats::Client,
    js: &jetstream::Context,
) -> Result<CertifiedKey> {
    // Fast path: check Object Store for valid cert from another node.
    match crate::nats::load_acme_cert(js).await {
        Ok(Some(key)) if !is_key_expiring_soon(&key) => {
            info!("loaded valid certificate from NATS Object Store");
            return Ok(key);
        }
        _ => {}
    }

    // Fast path: check local disk cache.
    if let Some(key) = load_cached_cert(config)? {
        info!("using cached ACME certificate from disk");
        return Ok(key);
    }

    // No valid cert — enter leader election loop.
    let mut leader_backoff = Duration::from_secs(30);
    let max_backoff = Duration::from_secs(300);

    loop {
        // Check Object Store each iteration (another node may have issued).
        match crate::nats::load_acme_cert(js).await {
            Ok(Some(key)) if !is_key_expiring_soon(&key) => {
                info!("loaded certificate from NATS Object Store (issued by another node)");
                return Ok(key);
            }
            _ => {}
        }

        if crate::nats::try_acme_leader_lock(js).await.unwrap_or(false) {
            // Leader: issue certificate.
            match provision_certificate(config, Some(client)).await {
                Ok(key) => {
                    // Store in Object Store for other nodes.
                    let cert_pem = std::fs::read_to_string(config.cert_dir.join("cert.pem"))
                        .context("failed to read cert.pem for Object Store")?;
                    let key_pem = std::fs::read_to_string(config.cert_dir.join("key.pem"))
                        .context("failed to read key.pem for Object Store")?;
                    if let Err(e) = crate::nats::store_acme_cert(js, &cert_pem, &key_pem).await {
                        warn!(error = %e, "failed to store cert in Object Store (non-fatal)");
                    }
                    // Release lock.
                    crate::nats::release_acme_leader_lock(js).await.ok();
                    return Ok(key);
                }
                Err(e) => {
                    warn!(error = %e, retry_in = ?leader_backoff, "leader ACME attempt failed");
                    crate::nats::release_acme_leader_lock(js).await.ok();
                    // Leader failed — backoff before retrying.
                    tokio::time::sleep(leader_backoff).await;
                    leader_backoff = (leader_backoff * 2).min(max_backoff);
                }
            }
        } else {
            // Follower: watch Object Store for cert (instant notification, no polling).
            match crate::nats::wait_for_acme_cert(js, Duration::from_secs(300)).await {
                Ok(key) if !is_key_expiring_soon(&key) => {
                    info!("loaded certificate from Object Store via watch");
                    return Ok(key);
                }
                Ok(_) => {
                    warn!("cert from Object Store is expiring soon, retrying");
                }
                Err(e) => {
                    warn!(error = %e, "follower cert watch failed, retrying leader election");
                }
            }
        }
    }
}

/// Spawn a background task that checks for certificate renewal every 12 hours.
/// When NATS is available, uses leader election and Object Store for coordination.
pub fn spawn_renewal_task(
    resolver: Arc<HotSwapCertResolver>,
    config: TlsConfig,
    nats: Option<(async_nats::Client, jetstream::Context)>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;

            info!("checking if ACME certificate needs renewal");

            // With NATS: check Object Store for a fresh cert first.
            if let Some((_, ref js)) = nats {
                match crate::nats::load_acme_cert(js).await {
                    Ok(Some(key)) if !is_key_expiring_soon(&key) => {
                        resolver.swap(key);
                        info!("hot-swapped certificate from Object Store");
                        continue;
                    }
                    _ => {}
                }
            }

            let cert_path = config.cert_dir.join("cert.pem");
            let needs_renewal = match std::fs::read_to_string(&cert_path) {
                Ok(pem) => is_cert_expiring_soon(&pem),
                Err(_) => true,
            };

            if !needs_renewal {
                info!("certificate is still valid, no renewal needed");
                continue;
            }

            info!("certificate needs renewal, starting ACME issuance");

            // With NATS: use leader election.
            if let Some((ref client, ref js)) = nats {
                let is_leader = crate::nats::try_acme_leader_lock(js).await.unwrap_or(false);
                if !is_leader {
                    info!("another node is handling ACME renewal");
                    continue;
                }

                let result = async {
                    let account = get_or_create_account(&config).await?;
                    let (cert_pem, key_pem) =
                        issue_certificate(&account, &config, Some(client)).await?;
                    crate::nats::store_acme_cert(js, &cert_pem, &key_pem).await?;
                    tls::pem_to_certified_key(&cert_pem, &key_pem)
                }
                .await;

                crate::nats::release_acme_leader_lock(js).await.ok();

                match result {
                    Ok(new_key) => {
                        resolver.swap(new_key);
                        info!("ACME certificate renewed and hot-swapped");
                    }
                    Err(e) => {
                        error!(error = %e, "ACME renewal failed, will retry next cycle");
                    }
                }
            } else {
                // No NATS: local-only renewal.
                let result = async {
                    let account = get_or_create_account(&config).await?;
                    let (cert_pem, key_pem) = issue_certificate(&account, &config, None).await?;
                    tls::pem_to_certified_key(&cert_pem, &key_pem)
                }
                .await;

                match result {
                    Ok(new_key) => {
                        resolver.swap(new_key);
                        info!("ACME certificate renewed and hot-swapped");
                    }
                    Err(e) => {
                        error!(error = %e, "ACME renewal failed, will retry next cycle");
                    }
                }
            }
        }
    })
}
