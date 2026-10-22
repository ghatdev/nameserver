use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};

use crate::output;

// ─── CLI ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct StampArgs {
    #[command(subcommand)]
    command: StampCommand,
}

#[derive(Subcommand)]
pub enum StampCommand {
    /// Generate DNS stamps for a server
    Generate(GenerateArgs),
    /// Decode and inspect an sdns:// stamp
    Decode(DecodeArgs),
}

#[derive(Args)]
pub struct GenerateArgs {
    /// DNS server hostname (e.g., dns.nameserver.io)
    #[arg(long)]
    server: String,

    /// DoH URL path (overridden by --profile-id)
    #[arg(long, default_value = "/dns-query")]
    doh_path: String,

    /// Nameserver profile ID — sets DoH path to /{profile_id} and DoT SNI to {profile_id}.{server}
    #[arg(long)]
    profile_id: Option<String>,

    /// Resolver IP address for bootstrapping (skip auto-resolve)
    #[arg(long)]
    addr: Option<String>,

    /// Server supports DNSSEC validation
    #[arg(long, default_value = "true")]
    dnssec: bool,

    /// Server does not log queries
    #[arg(long)]
    no_log: bool,

    /// Server does not filter queries
    #[arg(long)]
    no_filter: bool,

    /// Fetch TLS certificate and embed pin hash in stamp
    #[arg(long)]
    pin: bool,
}

#[derive(Args)]
pub struct DecodeArgs {
    /// The sdns:// stamp URI to decode
    stamp: String,
}

// ─── Protocol IDs (https://dnscrypt.info/stamps-specifications/) ────────

const PROTO_DOH: u8 = 0x02;
const PROTO_DOT: u8 = 0x03;

/// Property flag bits (little-endian u64).
const PROP_DNSSEC: u64 = 1 << 0;
const PROP_NO_LOG: u64 = 1 << 1;
const PROP_NO_FILTER: u64 = 1 << 2;

// ─── LP / VLP encoding ─────────────────────────────────────────────────

/// Encode a length-prefixed string (LP): 1-byte length + content.
fn lp(s: &str) -> Result<Vec<u8>> {
    let len = s.len();
    anyhow::ensure!(len <= 255, "LP string exceeds 255 bytes: '{s}'");
    let mut buf = Vec::with_capacity(1 + len);
    buf.push(len as u8);
    buf.extend_from_slice(s.as_bytes());
    Ok(buf)
}

/// Decode a length-prefixed string, advancing `pos`.
fn lp_decode(data: &[u8], pos: &mut usize) -> Result<String> {
    anyhow::ensure!(*pos < data.len(), "LP: unexpected end of data");
    let len = data[*pos] as usize;
    *pos += 1;
    anyhow::ensure!(*pos + len <= data.len(), "LP: string extends beyond data");
    let s = std::str::from_utf8(&data[*pos..*pos + len]).context("LP: invalid UTF-8")?;
    *pos += len;
    Ok(s.to_string())
}

/// Encode a variable-length packed set. High bit on length byte = more elements follow.
fn vlp_encode(elements: &[&[u8]]) -> Vec<u8> {
    if elements.is_empty() {
        return vec![0x00];
    }
    let mut buf = Vec::new();
    for (i, elem) in elements.iter().enumerate() {
        let is_last = i == elements.len() - 1;
        let len_byte = if is_last {
            elem.len() as u8
        } else {
            0x80 | elem.len() as u8
        };
        buf.push(len_byte);
        buf.extend_from_slice(elem);
    }
    buf
}

/// Decode a VLP set, advancing `pos`.
fn vlp_decode(data: &[u8], pos: &mut usize) -> Result<Vec<Vec<u8>>> {
    let mut elements = Vec::new();
    anyhow::ensure!(*pos < data.len(), "VLP: unexpected end of data");

    loop {
        anyhow::ensure!(*pos < data.len(), "VLP: unexpected end in element");
        let len_byte = data[*pos];
        *pos += 1;

        let is_last = (len_byte & 0x80) == 0;
        let len = (len_byte & 0x7F) as usize;

        // 0x00 = empty VLP terminator
        if len == 0 && is_last {
            break;
        }

        anyhow::ensure!(*pos + len <= data.len(), "VLP: element extends beyond data");
        elements.push(data[*pos..*pos + len].to_vec());
        *pos += len;

        if is_last {
            break;
        }
    }

    Ok(elements)
}

// ─── DER helpers (for TBS extraction) ───────────────────────────────────

/// Read a DER length field, advancing `pos`.
fn der_read_length(data: &[u8], pos: &mut usize) -> Result<usize> {
    anyhow::ensure!(*pos < data.len(), "DER: unexpected end of data");
    let first = data[*pos];
    *pos += 1;

    if first < 0x80 {
        Ok(first as usize)
    } else if first == 0x80 {
        anyhow::bail!("DER: indefinite length not supported");
    } else {
        let num_bytes = (first & 0x7F) as usize;
        anyhow::ensure!(
            num_bytes <= 4 && *pos + num_bytes <= data.len(),
            "DER: invalid length encoding"
        );
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | data[*pos] as usize;
            *pos += 1;
        }
        Ok(len)
    }
}

/// Extract the TBSCertificate DER bytes (tag + length + value) from an X.509 certificate.
fn extract_tbs(cert_der: &[u8]) -> Result<&[u8]> {
    let mut pos = 0;

    // Outer Certificate SEQUENCE
    anyhow::ensure!(
        cert_der.first() == Some(&0x30),
        "not a valid X.509 certificate"
    );
    pos += 1;
    let _outer_len = der_read_length(cert_der, &mut pos)?;

    // TBSCertificate is the first child SEQUENCE
    let tbs_start = pos;
    anyhow::ensure!(
        cert_der.get(pos) == Some(&0x30),
        "TBSCertificate is not a SEQUENCE"
    );
    pos += 1;
    let tbs_content_len = der_read_length(cert_der, &mut pos)?;
    let tbs_end = pos + tbs_content_len;
    anyhow::ensure!(
        tbs_end <= cert_der.len(),
        "TBSCertificate extends beyond certificate"
    );

    Ok(&cert_der[tbs_start..tbs_end])
}

// ─── TLS pin hash ───────────────────────────────────────────────────────

/// Connect to `hostname:port` via TLS, extract the leaf certificate,
/// and return the SHA-256 hash of its TBSCertificate.
async fn fetch_tbs_hash(hostname: &str, port: u16) -> Result<[u8; 32]> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect((hostname, port))
        .await
        .with_context(|| format!("failed to connect to {hostname}:{port}"))?;
    let domain = ServerName::try_from(hostname.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let tls = connector
        .connect(domain, tcp)
        .await
        .context("TLS handshake failed")?;

    let (_, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .context("server returned no certificates")?;
    let leaf = certs.first().context("empty certificate chain")?;

    let tbs = extract_tbs(leaf.as_ref())?;
    Ok(Sha256::digest(tbs).into())
}

// ─── DNS resolution ─────────────────────────────────────────────────────

/// Resolve a hostname to a bootstrap IP address. Prefers IPv4.
async fn resolve_addr(hostname: &str) -> Option<String> {
    let addrs = tokio::net::lookup_host((hostname, 443)).await.ok()?;
    let mut ipv4 = None;
    let mut ipv6 = None;
    for addr in addrs {
        match addr {
            std::net::SocketAddr::V4(v4) if ipv4.is_none() => {
                ipv4 = Some(v4.ip().to_string());
            }
            std::net::SocketAddr::V6(v6) if ipv6.is_none() => {
                ipv6 = Some(v6.ip().to_string());
            }
            _ => {}
        }
    }
    ipv4.or(ipv6)
}

// ─── Stamp building ─────────────────────────────────────────────────────

/// Build the properties bitmask from CLI flags.
fn props_bits(args: &GenerateArgs) -> u64 {
    let mut p: u64 = 0;
    if args.dnssec {
        p |= PROP_DNSSEC;
    }
    if args.no_log {
        p |= PROP_NO_LOG;
    }
    if args.no_filter {
        p |= PROP_NO_FILTER;
    }
    p
}

/// Build a DNS stamp and return the `sdns://` URI.
fn build_stamp(
    protocol: u8,
    prop_bits: u64,
    addr: &str,
    hashes: &[&[u8]],
    hostname: &str,
    path: Option<&str>,
) -> Result<String> {
    let mut buf = Vec::new();

    buf.push(protocol);
    buf.extend_from_slice(&prop_bits.to_le_bytes());
    buf.extend_from_slice(&lp(addr)?);
    buf.extend_from_slice(&vlp_encode(hashes));
    buf.extend_from_slice(&lp(hostname)?);

    if let Some(path) = path {
        buf.extend_from_slice(&lp(path)?);
    }

    let encoded = URL_SAFE_NO_PAD.encode(&buf);
    Ok(format!("sdns://{encoded}"))
}

// ─── Stamp decoding ─────────────────────────────────────────────────────

struct DecodedStamp {
    protocol: u8,
    props: u64,
    addr: String,
    hashes: Vec<Vec<u8>>,
    hostname: String,
    path: Option<String>,
}

fn proto_name(id: u8) -> &'static str {
    match id {
        0x00 => "Plain DNS",
        0x01 => "DNSCrypt",
        0x02 => "DoH",
        0x03 => "DoT",
        0x04 => "DoQ",
        0x05 => "ODoH Target",
        0x81 => "Anonymized DNSCrypt",
        0x85 => "ODoH Relay",
        _ => "Unknown",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_stamp(stamp_uri: &str) -> Result<DecodedStamp> {
    let encoded = stamp_uri
        .strip_prefix("sdns://")
        .context("stamp must start with sdns://")?;
    let data = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invalid base64url encoding")?;
    anyhow::ensure!(data.len() >= 10, "stamp too short");

    let mut pos = 0;

    let protocol = data[pos];
    pos += 1;

    let props = u64::from_le_bytes(
        data[pos..pos + 8]
            .try_into()
            .context("failed to read properties")?,
    );
    pos += 8;

    let addr = lp_decode(&data, &mut pos)?;
    let hashes = vlp_decode(&data, &mut pos)?;
    let hostname = lp_decode(&data, &mut pos)?;

    let path = if protocol == PROTO_DOH && pos < data.len() {
        Some(lp_decode(&data, &mut pos)?)
    } else {
        None
    };

    Ok(DecodedStamp {
        protocol,
        props,
        addr,
        hashes,
        hostname,
        path,
    })
}

// ─── Subcommand: generate ───────────────────────────────────────────────

async fn run_generate(args: GenerateArgs) -> Result<()> {
    let prop_bits = props_bits(&args);

    // Resolve bootstrap address
    let addr = if let Some(ref a) = args.addr {
        a.clone()
    } else {
        match resolve_addr(&args.server).await {
            Some(ip) => {
                eprintln!("Resolved {}: {ip}", args.server);
                ip
            }
            None => {
                eprintln!(
                    "Warning: could not resolve {}; stamp will have no bootstrap address",
                    args.server
                );
                String::new()
            }
        }
    };

    // Fetch TLS pin hash
    let pin_hash: Option<[u8; 32]> = if args.pin {
        let hash = fetch_tbs_hash(&args.server, 443)
            .await
            .context("failed to fetch TLS certificate pin")?;
        eprintln!("TLS pin: sha256:{}", hex_encode(&hash));
        Some(hash)
    } else {
        None
    };

    let hashes: Vec<&[u8]> = match &pin_hash {
        Some(h) => vec![h.as_slice()],
        None => vec![],
    };

    // Profile-aware paths/hostnames
    let doh_path = match &args.profile_id {
        Some(pid) => format!("/{pid}"),
        None => args.doh_path.clone(),
    };
    let dot_hostname = match &args.profile_id {
        Some(pid) => format!("{pid}.{}", args.server),
        None => args.server.clone(),
    };

    let doh_stamp = build_stamp(
        PROTO_DOH,
        prop_bits,
        &addr,
        &hashes,
        &args.server,
        Some(&doh_path),
    )?;
    let dot_stamp = build_stamp(PROTO_DOT, prop_bits, &addr, &hashes, &dot_hostname, None)?;

    if output::is_json() {
        let mut data = serde_json::json!({
            "server": args.server,
            "doh_path": doh_path,
            "dot_hostname": dot_hostname,
            "addr": if addr.is_empty() { serde_json::Value::Null } else { serde_json::json!(addr) },
            "dnssec": args.dnssec,
            "no_log": args.no_log,
            "no_filter": args.no_filter,
            "pin": pin_hash.map(|h| hex_encode(&h)),
            "stamps": {
                "doh": doh_stamp,
                "dot": dot_stamp,
            }
        });
        if let Some(ref pid) = args.profile_id {
            data["profile_id"] = serde_json::json!(pid);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        println!("Server:  {}", args.server);
        if let Some(ref pid) = args.profile_id {
            println!("Profile: {pid}");
        }
        if !addr.is_empty() {
            println!("Addr:    {addr}");
        }
        println!("DNSSEC:  {}", if args.dnssec { "yes" } else { "no" });
        if let Some(ref h) = pin_hash {
            println!("Pin:     sha256:{}", hex_encode(h));
        }
        println!();
        println!("DoH: {doh_stamp}");
        println!("     https://{}{doh_path}", args.server);
        println!("DoT: {dot_stamp}");
        println!("     tls://{dot_hostname}:853");
    }

    Ok(())
}

// ─── Subcommand: decode ─────────────────────────────────────────────────

async fn run_decode(args: DecodeArgs) -> Result<()> {
    let stamp = decode_stamp(&args.stamp)?;

    if output::is_json() {
        let data = serde_json::json!({
            "protocol": proto_name(stamp.protocol),
            "protocol_id": stamp.protocol,
            "properties": {
                "dnssec": stamp.props & PROP_DNSSEC != 0,
                "no_log": stamp.props & PROP_NO_LOG != 0,
                "no_filter": stamp.props & PROP_NO_FILTER != 0,
            },
            "addr": if stamp.addr.is_empty() { serde_json::Value::Null } else { serde_json::json!(stamp.addr) },
            "hashes": stamp.hashes.iter().map(|h| format!("sha256:{}", hex_encode(h))).collect::<Vec<_>>(),
            "hostname": stamp.hostname,
            "path": stamp.path,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        println!(
            "Protocol:   {} (0x{:02x})",
            proto_name(stamp.protocol),
            stamp.protocol
        );

        let mut prop_strs = Vec::new();
        if stamp.props & PROP_DNSSEC != 0 {
            prop_strs.push("DNSSEC");
        }
        if stamp.props & PROP_NO_LOG != 0 {
            prop_strs.push("NO_LOG");
        }
        if stamp.props & PROP_NO_FILTER != 0 {
            prop_strs.push("NO_FILTER");
        }
        if prop_strs.is_empty() {
            println!("Properties: (none)");
        } else {
            println!("Properties: {}", prop_strs.join(", "));
        }

        if stamp.addr.is_empty() {
            println!("Address:    (none)");
        } else {
            println!("Address:    {}", stamp.addr);
        }

        if stamp.hashes.is_empty() {
            println!("Pins:       (none)");
        } else {
            for (i, h) in stamp.hashes.iter().enumerate() {
                let label = if i == 0 {
                    "Pins:       "
                } else {
                    "            "
                };
                println!("{label}sha256:{}", hex_encode(h));
            }
        }

        println!("Hostname:   {}", stamp.hostname);

        if let Some(ref path) = stamp.path {
            println!("Path:       {path}");
        }

        match stamp.protocol {
            PROTO_DOH => {
                let path = stamp.path.as_deref().unwrap_or("/dns-query");
                println!();
                println!("URL:        https://{}{path}", stamp.hostname);
            }
            PROTO_DOT => {
                println!();
                println!("URL:        tls://{}:853", stamp.hostname);
            }
            _ => {}
        }
    }

    Ok(())
}

// ─── Entry point ────────────────────────────────────────────────────────

pub async fn run(args: StampArgs) -> Result<()> {
    match args.command {
        StampCommand::Generate(a) => run_generate(a).await,
        StampCommand::Decode(a) => run_decode(a).await,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lp_encoding() {
        let encoded = lp("hello").unwrap();
        assert_eq!(encoded[0], 5);
        assert_eq!(&encoded[1..], b"hello");
    }

    #[test]
    fn lp_empty_string() {
        let encoded = lp("").unwrap();
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn lp_roundtrip() {
        let encoded = lp("dns.example.com").unwrap();
        let mut pos = 0;
        let decoded = lp_decode(&encoded, &mut pos).unwrap();
        assert_eq!(decoded, "dns.example.com");
        assert_eq!(pos, encoded.len());
    }

    #[test]
    fn vlp_empty_roundtrip() {
        let encoded = vlp_encode(&[]);
        assert_eq!(encoded, vec![0x00]);
        let mut pos = 0;
        let decoded = vlp_decode(&encoded, &mut pos).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn vlp_single_hash() {
        let hash = [0xAB; 32];
        let encoded = vlp_encode(&[&hash]);
        // 0x20 = 32, no high bit (last element)
        assert_eq!(encoded[0], 32);
        assert_eq!(&encoded[1..], &hash);

        let mut pos = 0;
        let decoded = vlp_decode(&encoded, &mut pos).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], hash);
    }

    #[test]
    fn vlp_two_hashes() {
        let h1 = [0xAA; 32];
        let h2 = [0xBB; 32];
        let encoded = vlp_encode(&[&h1, &h2]);
        // First: 0xA0 = 0x80 | 32 (more follow)
        assert_eq!(encoded[0], 0xA0);
        assert_eq!(&encoded[1..33], &h1);
        // Second: 0x20 = 32 (last element)
        assert_eq!(encoded[33], 0x20);
        assert_eq!(&encoded[34..66], &h2);

        let mut pos = 0;
        let decoded = vlp_decode(&encoded, &mut pos).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], h1);
        assert_eq!(decoded[1], h2);
    }

    #[test]
    fn protocol_ids_match_spec() {
        assert_eq!(PROTO_DOH, 0x02);
        assert_eq!(PROTO_DOT, 0x03);
    }

    #[test]
    fn stamp_starts_with_sdns() {
        let stamp = build_stamp(
            PROTO_DOH,
            PROP_DNSSEC,
            "",
            &[],
            "dns.example.com",
            Some("/dns-query"),
        )
        .unwrap();
        assert!(stamp.starts_with("sdns://"));
    }

    #[test]
    fn doh_stamp_roundtrip() {
        let stamp = build_stamp(
            PROTO_DOH,
            PROP_DNSSEC,
            "1.2.3.4",
            &[],
            "dns.example.com",
            Some("/dns-query"),
        )
        .unwrap();
        let decoded = decode_stamp(&stamp).unwrap();

        assert_eq!(decoded.protocol, PROTO_DOH);
        assert_eq!(decoded.props, PROP_DNSSEC);
        assert_eq!(decoded.addr, "1.2.3.4");
        assert!(decoded.hashes.is_empty());
        assert_eq!(decoded.hostname, "dns.example.com");
        assert_eq!(decoded.path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn dot_stamp_roundtrip() {
        let stamp = build_stamp(PROTO_DOT, PROP_NO_LOG, "", &[], "dns.example.com", None).unwrap();
        let decoded = decode_stamp(&stamp).unwrap();

        assert_eq!(decoded.protocol, PROTO_DOT);
        assert_eq!(decoded.props, PROP_NO_LOG);
        assert_eq!(decoded.addr, "");
        assert!(decoded.hashes.is_empty());
        assert_eq!(decoded.hostname, "dns.example.com");
        assert!(decoded.path.is_none());
    }

    #[test]
    fn stamp_with_single_pin() {
        let hash = [0x42; 32];
        let stamp = build_stamp(
            PROTO_DOH,
            PROP_DNSSEC,
            "1.2.3.4",
            &[&hash],
            "dns.example.com",
            Some("/dns-query"),
        )
        .unwrap();
        let decoded = decode_stamp(&stamp).unwrap();

        assert_eq!(decoded.hashes.len(), 1);
        assert_eq!(decoded.hashes[0], hash);
        assert_eq!(decoded.hostname, "dns.example.com");
    }

    #[test]
    fn stamp_with_two_pins() {
        let h1 = [0xAA; 32];
        let h2 = [0xBB; 32];
        let stamp =
            build_stamp(PROTO_DOH, 0, "", &[&h1, &h2], "dns.example.com", Some("/")).unwrap();
        let decoded = decode_stamp(&stamp).unwrap();

        assert_eq!(decoded.hashes.len(), 2);
        assert_eq!(decoded.hashes[0], h1);
        assert_eq!(decoded.hashes[1], h2);
    }

    #[test]
    fn stamp_all_props() {
        let stamp = build_stamp(
            PROTO_DOH,
            PROP_DNSSEC | PROP_NO_LOG | PROP_NO_FILTER,
            "",
            &[],
            "x.com",
            Some("/"),
        )
        .unwrap();
        let decoded = decode_stamp(&stamp).unwrap();
        assert_eq!(decoded.props, 0x07);
    }

    #[test]
    fn stamp_with_bootstrap_addr() {
        let stamp = build_stamp(
            PROTO_DOH,
            0,
            "1.2.3.4",
            &[],
            "dns.example.com",
            Some("/dns-query"),
        )
        .unwrap();
        let decoded = decode_stamp(&stamp).unwrap();
        assert_eq!(decoded.addr, "1.2.3.4");
    }

    #[test]
    fn stamp_with_ipv6_addr() {
        let stamp = build_stamp(
            PROTO_DOH,
            0,
            "[2606:4700::1111]",
            &[],
            "dns.example.com",
            Some("/dns-query"),
        )
        .unwrap();
        let decoded = decode_stamp(&stamp).unwrap();
        assert_eq!(decoded.addr, "[2606:4700::1111]");
    }

    #[test]
    fn decode_invalid_prefix() {
        assert!(decode_stamp("https://example.com").is_err());
    }

    #[test]
    fn decode_invalid_base64() {
        assert!(decode_stamp("sdns://!!!invalid!!!").is_err());
    }

    #[test]
    fn extract_tbs_from_synthetic_cert() {
        // Build a minimal DER structure:
        // SEQUENCE { SEQUENCE { <tbs> } SEQUENCE { <sigalgo> } BIT STRING { <sig> } }
        let tbs_content = vec![0x01, 0x02, 0x03];
        let tbs = der_sequence(&tbs_content);
        let sig_algo = der_sequence(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        let sig_value = vec![0x03, 0x02, 0x00, 0xFF]; // BIT STRING

        let mut cert_inner = Vec::new();
        cert_inner.extend_from_slice(&tbs);
        cert_inner.extend_from_slice(&sig_algo);
        cert_inner.extend_from_slice(&sig_value);
        let cert = der_sequence(&cert_inner);

        let extracted = extract_tbs(&cert).unwrap();
        assert_eq!(extracted, &tbs[..]);
    }

    #[test]
    fn extract_tbs_hash_deterministic() {
        let tbs_content = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let tbs = der_sequence(&tbs_content);
        let cert_inner = [tbs.as_slice(), &der_sequence(&[]), &[0x03, 0x01, 0x00]].concat();
        let cert = der_sequence(&cert_inner);

        let extracted = extract_tbs(&cert).unwrap();
        let hash1: [u8; 32] = Sha256::digest(extracted).into();
        let hash2: [u8; 32] = Sha256::digest(extracted).into();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn proto_name_coverage() {
        assert_eq!(proto_name(PROTO_DOH), "DoH");
        assert_eq!(proto_name(PROTO_DOT), "DoT");
        assert_eq!(proto_name(0x04), "DoQ");
        assert_eq!(proto_name(0x00), "Plain DNS");
        assert_eq!(proto_name(0xFF), "Unknown");
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[]), "");
    }

    /// Helper: build a DER SEQUENCE from content bytes.
    fn der_sequence(content: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x30];
        if content.len() < 128 {
            buf.push(content.len() as u8);
        } else {
            let len_bytes = content.len().to_be_bytes();
            let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let num_bytes = 8 - first_nonzero;
            buf.push(0x80 | num_bytes as u8);
            buf.extend_from_slice(&len_bytes[first_nonzero..]);
        }
        buf.extend_from_slice(content);
        buf
    }
}
