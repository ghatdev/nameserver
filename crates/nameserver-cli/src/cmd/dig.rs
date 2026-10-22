use anyhow::{Context, Result};
use clap::Args;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::output;

#[derive(Args)]
pub struct DigArgs {
    /// Domain name to query
    domain: String,

    /// Record type(s) (A, AAAA, CNAME, MX, NS, TXT, SOA, etc.)
    types: Vec<String>,

    /// DNS server hostname (falls back to dns_server in config.toml)
    #[arg(long)]
    server: Option<String>,

    /// Use DoT (DNS over TLS) instead of DoH
    #[arg(long)]
    dot: bool,

    /// DoH URL path
    #[arg(long, default_value = "/dns-query")]
    doh_path: String,

    /// Show only answer data (like dig +short)
    #[arg(long)]
    short: bool,

    /// Set Checking Disabled flag (skip DNSSEC validation)
    #[arg(long)]
    cd: bool,

    /// Trace delegation path from root (like dig +trace)
    #[arg(long)]
    trace: bool,
}

fn build_query(domain: &str, rtype: RecordType, cd: bool) -> Result<Vec<u8>> {
    let fqdn = if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    };
    let name = Name::from_utf8(&fqdn).context("invalid domain name")?;
    let mut msg = Message::new();
    msg.set_id(std::process::id() as u16);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.set_checking_disabled(cd);
    msg.add_query(Query::query(name, rtype));
    msg.to_vec().context("failed to encode DNS query")
}

async fn query_doh(server: &str, path: &str, wire: &[u8]) -> Result<Vec<u8>> {
    let url = format!("https://{server}{path}");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire.to_vec())
        .send()
        .await
        .context("DoH request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("DoH server returned {}", resp.status());
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .context("failed to read DoH response body")
}

async fn query_dot(server: &str, wire: &[u8]) -> Result<Vec<u8>> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ignore if already installed

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect((server, 853))
        .await
        .with_context(|| format!("failed to connect to {server}:853"))?;
    let domain = ServerName::try_from(server.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let mut tls = connector
        .connect(domain, tcp)
        .await
        .context("TLS handshake failed")?;

    // DNS over TLS: 2-byte length prefix (RFC 7858)
    let len = (wire.len() as u16).to_be_bytes();
    tls.write_all(&len).await?;
    tls.write_all(wire).await?;
    tls.flush().await?;

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tls.read_exact(&mut resp).await?;

    Ok(resp)
}

fn record_data_str(record: &hickory_proto::rr::Record) -> String {
    record.data().to_string()
}

fn display_response(
    response: &Message,
    rtype_str: &str,
    domain: &str,
    server: &str,
    protocol: &str,
    query_time_ms: u128,
    short: bool,
) {
    if short {
        for record in response.answers() {
            println!("{}", record_data_str(record));
        }
        return;
    }

    println!("; <<>> nameserver dig <<>> {domain} {rtype_str}");
    println!(";; SERVER: {server} ({protocol})");
    println!(";; QUERY TIME: {query_time_ms} msec");
    println!(
        ";; MSG SIZE rcvd: {}",
        response.to_vec().map(|v| v.len()).unwrap_or(0)
    );
    println!(
        ";; STATUS: {:?}, ID: {}",
        response.response_code(),
        response.id()
    );

    let mut flags = String::new();
    if response.authoritative() {
        flags.push_str(" aa");
    }
    if response.truncated() {
        flags.push_str(" tc");
    }
    if response.recursion_desired() {
        flags.push_str(" rd");
    }
    if response.recursion_available() {
        flags.push_str(" ra");
    }
    if response.authentic_data() {
        flags.push_str(" ad");
    }
    if response.checking_disabled() {
        flags.push_str(" cd");
    }
    println!(";; FLAGS:{flags}");
    println!();

    if !response.queries().is_empty() {
        println!(";; QUESTION SECTION:");
        for q in response.queries() {
            println!(
                ";{:<31} {:?}\t{:?}",
                q.name(),
                q.query_class(),
                q.query_type()
            );
        }
        println!();
    }

    if !response.answers().is_empty() {
        println!(";; ANSWER SECTION:");
        for r in response.answers() {
            println!(
                "{:<32} {}\t{:?}\t{:?}\t{}",
                r.name(),
                r.ttl(),
                r.dns_class(),
                r.record_type(),
                record_data_str(r),
            );
        }
        println!();
    }

    if !response.name_servers().is_empty() {
        println!(";; AUTHORITY SECTION:");
        for r in response.name_servers() {
            println!(
                "{:<32} {}\t{:?}\t{:?}\t{}",
                r.name(),
                r.ttl(),
                r.dns_class(),
                r.record_type(),
                record_data_str(r),
            );
        }
        println!();
    }

    let additionals: Vec<_> = response
        .additionals()
        .iter()
        .filter(|r| r.record_type() != RecordType::OPT)
        .collect();
    if !additionals.is_empty() {
        println!(";; ADDITIONAL SECTION:");
        for r in &additionals {
            println!(
                "{:<32} {}\t{:?}\t{:?}\t{}",
                r.name(),
                r.ttl(),
                r.dns_class(),
                r.record_type(),
                record_data_str(r),
            );
        }
        println!();
    }
}

pub async fn run(server: &str, args: DigArgs) -> Result<()> {
    if args.trace {
        let rtype_str = args.types.first().map(|s| s.as_str()).unwrap_or("A");
        let rtype = RecordType::from_str(&rtype_str.to_uppercase())
            .map_err(|_| anyhow::anyhow!("unknown record type: {rtype_str}"))?;
        return run_trace(&args.domain, rtype).await;
    }

    let server = args.server.as_deref().unwrap_or(server);
    if server.is_empty() {
        anyhow::bail!(
            "no DNS server specified; use --server <host> or set dns_server in config.toml"
        );
    }

    let types = if args.types.is_empty() {
        vec!["A".to_string()]
    } else {
        args.types.clone()
    };

    let protocol = if args.dot { "DoT" } else { "DoH" };

    for type_str in &types {
        let rtype = RecordType::from_str(&type_str.to_uppercase())
            .map_err(|_| anyhow::anyhow!("unknown record type: {type_str}"))?;

        let wire = build_query(&args.domain, rtype, args.cd)?;

        let start = Instant::now();
        let response_bytes = if args.dot {
            query_dot(server, &wire).await?
        } else {
            query_doh(server, &args.doh_path, &wire).await?
        };
        let elapsed = start.elapsed();

        let response =
            Message::from_vec(&response_bytes).context("failed to parse DNS response")?;

        if output::is_json() {
            let mut answers = Vec::new();
            for r in response.answers() {
                answers.push(serde_json::json!({
                    "name": r.name().to_string(),
                    "type": format!("{:?}", r.record_type()),
                    "ttl": r.ttl(),
                    "data": record_data_str(r),
                }));
            }
            let data = serde_json::json!({
                "server": server,
                "protocol": protocol,
                "domain": args.domain,
                "type": type_str.to_uppercase(),
                "status": format!("{:?}", response.response_code()),
                "flags": {
                    "aa": response.authoritative(),
                    "tc": response.truncated(),
                    "rd": response.recursion_desired(),
                    "ra": response.recursion_available(),
                    "ad": response.authentic_data(),
                    "cd": response.checking_disabled(),
                },
                "query_time_ms": elapsed.as_millis(),
                "answers": answers,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        } else {
            display_response(
                &response,
                &type_str.to_uppercase(),
                &args.domain,
                server,
                protocol,
                elapsed.as_millis(),
                args.short,
            );
        }
    }

    Ok(())
}

// --- Trace (dig +trace) implementation ---

const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "170.247.170.2",  // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

const MAX_TRACE_DEPTH: usize = 20;

fn build_trace_query(domain: &str, rtype: RecordType) -> Result<Vec<u8>> {
    let fqdn = if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    };
    let name = Name::from_utf8(&fqdn).context("invalid domain name")?;
    let mut msg = Message::new();
    msg.set_id(std::process::id() as u16);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false); // iterative
    msg.add_query(Query::query(name, rtype));
    msg.to_vec().context("failed to encode trace query")
}

async fn query_udp(server_ip: &str, wire: &[u8]) -> Result<(Vec<u8>, Duration)> {
    let addr = format!("{server_ip}:53");
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(wire, &addr).await?;

    let mut buf = vec![0u8; 4096];
    let start = Instant::now();
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .context("UDP query timed out")?
        .context("UDP recv failed")?;
    buf.truncate(n);
    Ok((buf, start.elapsed()))
}

async fn run_trace(domain: &str, rtype: RecordType) -> Result<()> {
    let rtype_str = format!("{rtype:?}").to_uppercase();
    println!("; <<>> nameserver dig +trace <<>> {domain} {rtype_str}");
    println!();

    let wire = build_trace_query(domain, rtype)?;
    let mut servers: Vec<String> = ROOT_SERVERS.iter().map(|s| s.to_string()).collect();

    for _depth in 0..MAX_TRACE_DEPTH {
        // Try each server in the pool until one responds
        let mut response = None;
        let mut responder_ip = String::new();
        let mut elapsed = Duration::ZERO;

        for server_ip in &servers {
            match query_udp(server_ip, &wire).await {
                Ok((bytes, dur)) => {
                    if let Ok(msg) = Message::from_vec(&bytes) {
                        responder_ip = server_ip.clone();
                        elapsed = dur;
                        response = Some(msg);
                        break;
                    }
                }
                Err(_) => continue,
            }
        }

        let msg = match response {
            Some(m) => m,
            None => {
                println!(";; No response from any server in pool");
                break;
            }
        };

        let msg_size = msg.to_vec().map(|v| v.len()).unwrap_or(0);

        if msg.truncated() {
            println!(";; WARNING: response truncated (TC bit set)");
        }

        // Check for answer
        if !msg.answers().is_empty() {
            for r in msg.answers() {
                println!(
                    "{:<24} {}\tIN\t{:?}\t{}",
                    r.name(),
                    r.ttl(),
                    r.record_type(),
                    record_data_str(r),
                );
            }
            println!(
                ";; Received {msg_size} bytes from {responder_ip}#53 in {} ms",
                elapsed.as_millis()
            );
            println!();
            break;
        }

        // Check for referral (NS in authority section)
        let ns_records: Vec<_> = msg
            .name_servers()
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .collect();

        if ns_records.is_empty() {
            // No answer, no referral — show what we got
            for r in msg.name_servers() {
                println!(
                    "{:<24} {}\tIN\t{:?}\t{}",
                    r.name(),
                    r.ttl(),
                    r.record_type(),
                    record_data_str(r),
                );
            }
            println!(
                ";; Received {msg_size} bytes from {responder_ip}#53 in {} ms",
                elapsed.as_millis()
            );
            println!();
            break;
        }

        // Print the referral NS records
        for r in &ns_records {
            println!(
                "{:<24} {}\tIN\tNS\t{}",
                r.name(),
                r.ttl(),
                record_data_str(r),
            );
        }
        println!(
            ";; Received {msg_size} bytes from {responder_ip}#53 in {} ms",
            elapsed.as_millis()
        );
        println!();

        // Extract glue A records from additional section for the NS names
        let ns_names: Vec<String> = ns_records.iter().map(|r| record_data_str(r)).collect();

        let mut next_servers = Vec::new();
        for r in msg.additionals() {
            if r.record_type() == RecordType::A {
                let name_str = r.name().to_string();
                if ns_names.iter().any(|ns| ns == &name_str) {
                    next_servers.push(record_data_str(r));
                }
            }
        }

        if next_servers.is_empty() {
            // No glue — resolve first NS name via recursive query to last working server
            if let Some(ns_name) = ns_names.first() {
                let resolve_wire = build_trace_query(ns_name, RecordType::A)?;
                // Use a recursive query to the last working server to resolve the NS
                let mut resolve_msg = Message::from_vec(&resolve_wire)?;
                resolve_msg.set_recursion_desired(true);
                let resolve_bytes = resolve_msg.to_vec()?;

                if let Ok((resp_bytes, _)) = query_udp(&responder_ip, &resolve_bytes).await
                    && let Ok(resp) = Message::from_vec(&resp_bytes)
                {
                    for r in resp.answers() {
                        if r.record_type() == RecordType::A {
                            next_servers.push(record_data_str(r));
                        }
                    }
                }
            }
        }

        if next_servers.is_empty() {
            println!(";; Unable to resolve NS server addresses");
            break;
        }

        servers = next_servers;
    }

    Ok(())
}
