use std::io::Cursor;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::x509::der::{Any, Decode, Encode, Tag};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use nameserver_common::nats_subjects::{BUCKET_CERTS, OBJ_CERT_BUNDLE};
use rsa::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tracing::debug;
use x509_cert::Certificate;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::AppState;

#[derive(serde::Deserialize)]
pub struct MobileconfigRequest {
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub dot: bool,
    #[serde(default)]
    pub unsigned: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn post_mobileconfig(
    State(state): State<AppState>,
    Json(req): Json<MobileconfigRequest>,
) -> impl IntoResponse {
    let server = &state.dns_config.server;
    let addrs = &state.dns_config.addrs;
    let name = req.name.as_deref().unwrap_or("Nameserver DNS");
    let desc = req
        .description
        .as_deref()
        .unwrap_or("Encrypted DNS settings for Nameserver");

    let doh_path = match &req.profile_id {
        Some(pid) => format!("/{pid}"),
        None => "/dns-query".to_string(),
    };

    let xml = generate_mobileconfig_xml(
        server,
        addrs,
        &doh_path,
        req.dot,
        name,
        desc,
        &req.profile_id,
    );

    if req.unsigned {
        let filename = profile_filename(&req.profile_id, req.dot);
        return (
            StatusCode::OK,
            [
                ("content-type", "application/x-apple-asn1".to_string()),
                (
                    "content-disposition",
                    format!("attachment; filename=\"{filename}\""),
                ),
            ],
            xml.into_bytes(),
        )
            .into_response();
    }

    // Fetch cert bundle from NATS and sign.
    let signed = match sign_mobileconfig(&state, xml.as_bytes()).await {
        Ok(der) => der,
        Err(e) => {
            tracing::warn!(error = %e, "mobileconfig signing failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "signing failed" })),
            )
                .into_response();
        }
    };

    let filename = profile_filename(&req.profile_id, req.dot);
    (
        StatusCode::OK,
        [
            ("content-type", "application/x-apple-asn1".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        signed,
    )
        .into_response()
}

fn profile_filename(profile_id: &Option<String>, dot: bool) -> String {
    let proto = if dot { "dot" } else { "doh" };
    match profile_id {
        Some(pid) => format!("nameserver-{proto}-{pid}.mobileconfig"),
        None => format!("nameserver-{proto}.mobileconfig"),
    }
}

// ---------------------------------------------------------------------------
// XML generation (ported from nameserver-cli cmd/profile.rs)
// ---------------------------------------------------------------------------

fn deterministic_uuid(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        hash[0],
        hash[1],
        hash[2],
        hash[3],
        hash[4],
        hash[5],
        (hash[6] & 0x0F) | 0x50,
        hash[7],
        (hash[8] & 0x3F) | 0x80,
        hash[9],
        hash[10],
        hash[11],
        hash[12],
        hash[13],
        hash[14],
        hash[15]
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn generate_mobileconfig_xml(
    server_raw: &str,
    addrs: &[String],
    doh_path: &str,
    dot: bool,
    name: &str,
    desc: &str,
    profile_id: &Option<String>,
) -> String {
    let desc = xml_escape(desc);
    let name = xml_escape(name);
    let server = xml_escape(server_raw);

    let identifier = match profile_id {
        Some(pid) => format!("io.nameserver.dns.{}.{pid}", server_raw.replace('.', "-")),
        None => format!("io.nameserver.dns.{}", server_raw.replace('.', "-")),
    };

    let uuid_seed = match profile_id {
        Some(pid) => format!("nameserver-profile-{}-{pid}", server_raw),
        None => format!("nameserver-profile-{}", server_raw),
    };
    let profile_uuid = deterministic_uuid(&uuid_seed);

    let server_addrs_xml = if addrs.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = addrs
            .iter()
            .map(|a| format!("                    <string>{}</string>", xml_escape(a)))
            .collect();
        format!(
            "\n                <key>ServerAddresses</key>\n                <array>\n{}\n                </array>",
            entries.join("\n")
        )
    };

    let (dns_settings, payload_name, payload_id, payload_uuid) = if dot {
        let settings = format!(
            "\
                <key>DNSProtocol</key>
                <string>TLS</string>
                <key>ServerName</key>
                <string>{server}</string>{server_addrs_xml}"
        );
        let uuid = deterministic_uuid(&format!("nameserver-dot-{}", server_raw));
        (
            settings,
            format!("{name} (DoT)"),
            format!("{identifier}.dot"),
            uuid,
        )
    } else {
        let url = format!("https://{}{}", server, xml_escape(doh_path));
        let settings = format!(
            "\
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>{url}</string>{server_addrs_xml}"
        );
        let uuid = deterministic_uuid(&format!("nameserver-doh-{}", server_raw));
        (
            settings,
            format!("{name} (DoH)"),
            format!("{identifier}.doh"),
            uuid,
        )
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                {dns_settings}
            </dict>
            <key>PayloadDisplayName</key>
            <string>{payload_name}</string>
            <key>PayloadIdentifier</key>
            <string>{payload_id}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>{desc}</string>
    <key>PayloadDisplayName</key>
    <string>{name}</string>
    <key>PayloadIdentifier</key>
    <string>{identifier}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"#
    )
}

// ---------------------------------------------------------------------------
// PKCS#7 / CMS signing
// ---------------------------------------------------------------------------

/// Fetch the ACME cert bundle from NATS Object Store and sign `data` as
/// PKCS#7 SignedData (DER). Supports both RSA and ECDSA (P-256) keys.
async fn sign_mobileconfig(state: &AppState, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let store = state.js.get_object_store(BUCKET_CERTS).await?;
    let bundle_data = tokio::time::timeout(Duration::from_secs(5), async {
        let mut obj = store.get(OBJ_CERT_BUNDLE).await?;
        let mut buf = Vec::new();
        obj.read_to_end(&mut buf).await?;
        Ok::<_, anyhow::Error>(buf)
    })
    .await
    .map_err(|_| anyhow::anyhow!("timeout fetching cert bundle"))??;

    let bundle: serde_json::Value = serde_json::from_slice(&bundle_data)?;
    let cert_pem = bundle["cert_pem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing cert_pem in cert bundle"))?;
    let key_pem = bundle["key_pem"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing key_pem in cert bundle"))?;

    // Parse all certificates from PEM chain.
    let certs = parse_pem_certificates(cert_pem)?;
    debug!(count = certs.len(), "parsed certificates from ACME bundle");

    // Try RSA first, then ECDSA P-256.
    if let Ok(rsa_key) = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem) {
        sign_cms_rsa(data, &certs, rsa_key)
    } else if let Ok(ec_key) = p256::ecdsa::SigningKey::from_pkcs8_pem(key_pem) {
        sign_cms_ecdsa(data, &certs, ec_key)
    } else {
        anyhow::bail!("unsupported private key type (expected RSA or ECDSA P-256)")
    }
}

fn parse_pem_certificates(pem_data: &str) -> anyhow::Result<Vec<Certificate>> {
    let mut certs = Vec::new();
    let mut reader = Cursor::new(pem_data.as_bytes());
    for item in rustls_pemfile::certs(&mut reader) {
        let cert_der = item?;
        let cert = Certificate::from_der(cert_der.as_ref())?;
        certs.push(cert);
    }
    anyhow::ensure!(!certs.is_empty(), "no certificates found in PEM data");
    Ok(certs)
}

/// Map `cms::builder::Error` to `anyhow::Error` (it doesn't impl StdError).
fn cms_err(e: cms::builder::Error) -> anyhow::Error {
    anyhow::anyhow!("CMS signing error: {e:?}")
}

fn sign_cms_rsa(
    data: &[u8],
    certs: &[Certificate],
    rsa_key: rsa::RsaPrivateKey,
) -> anyhow::Result<Vec<u8>> {
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key);
    let signing_cert = &certs[0];

    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(Tag::OctetString, data.to_vec())?),
    };

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signing_cert.tbs_certificate.issuer.clone(),
        serial_number: signing_cert.tbs_certificate.serial_number.clone(),
    });

    let signer_info = SignerInfoBuilder::new(
        &signing_key,
        signer_id,
        digest_algorithm.clone(),
        &content,
        None,
    )
    .map_err(cms_err)?;

    let mut builder = SignedDataBuilder::new(&content);
    builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(cms_err)?;
    for cert in certs {
        builder
            .add_certificate(CertificateChoices::Certificate(cert.clone()))
            .map_err(cms_err)?;
    }
    builder
        .add_signer_info::<rsa::pkcs1v15::SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info)
        .map_err(cms_err)?;

    let content_info = builder.build().map_err(cms_err)?;
    Ok(content_info.to_der()?)
}

fn sign_cms_ecdsa(
    data: &[u8],
    certs: &[Certificate],
    ec_key: p256::ecdsa::SigningKey,
) -> anyhow::Result<Vec<u8>> {
    let signing_cert = &certs[0];

    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(Tag::OctetString, data.to_vec())?),
    };

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signing_cert.tbs_certificate.issuer.clone(),
        serial_number: signing_cert.tbs_certificate.serial_number.clone(),
    });

    let signer_info =
        SignerInfoBuilder::new(&ec_key, signer_id, digest_algorithm.clone(), &content, None)
            .map_err(cms_err)?;

    let mut builder = SignedDataBuilder::new(&content);
    builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(cms_err)?;
    for cert in certs {
        builder
            .add_certificate(CertificateChoices::Certificate(cert.clone()))
            .map_err(cms_err)?;
    }
    builder
        .add_signer_info::<p256::ecdsa::SigningKey, p256::ecdsa::DerSignature>(signer_info)
        .map_err(cms_err)?;

    let content_info = builder.build().map_err(cms_err)?;
    Ok(content_info.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("test-input");
        let b = deterministic_uuid("test-input");
        assert_eq!(a, b);
    }

    #[test]
    fn xml_generation_doh() {
        let xml = generate_mobileconfig_xml(
            "dns.example.test",
            &["1.2.3.4".to_string()],
            "/test123",
            false,
            "Nameserver DNS",
            "Test profile",
            &Some("test123".to_string()),
        );
        assert!(xml.contains("https://dns.example.test/test123"));
        assert!(xml.contains("<string>1.2.3.4</string>"));
        assert!(xml.contains("com.apple.dnsSettings.managed"));
    }

    #[test]
    fn xml_generation_dot() {
        let xml = generate_mobileconfig_xml(
            "dns.example.test",
            &[],
            "/dns-query",
            true,
            "Nameserver DNS",
            "Test profile",
            &None,
        );
        assert!(xml.contains("<string>TLS</string>"));
        assert!(!xml.contains("ServerAddresses"));
    }
}
