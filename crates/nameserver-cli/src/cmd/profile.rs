use anyhow::Result;
use clap::Args;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct ProfileArgs {
    /// DNS server hostname (e.g., dns.example.test). Falls back to config dns_server.
    #[arg(long)]
    server: Option<String>,

    /// Server IP addresses for failover (repeatable). Falls back to config dns_addrs.
    #[arg(long = "addr", short = 'a')]
    addrs: Vec<String>,

    /// DoH URL path (overridden by --profile-id)
    #[arg(long, default_value = "/dns-query")]
    doh_path: String,

    /// Nameserver profile ID — sets DoH path to /{profile_id}
    #[arg(long)]
    profile_id: Option<String>,

    /// Generate DoT (DNS over TLS) profile instead of DoH
    #[arg(long)]
    dot: bool,

    /// Display name shown in iOS/macOS Settings
    #[arg(long, default_value = "Nameserver DNS")]
    name: String,

    /// Profile description
    #[arg(long)]
    description: Option<String>,

    /// Output file path (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Generate unsigned profile locally (skip control plane signing)
    #[arg(long)]
    unsigned: bool,
}

/// Derive a deterministic UUID from an input string using SHA-256.
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
        // Set version nibble to 5 (name-based SHA) per RFC 4122
        (hash[6] & 0x0F) | 0x50,
        hash[7],
        // Set variant bits to 10xx per RFC 4122
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

pub async fn run(api: &Client, args: ProfileArgs) -> Result<()> {
    if args.unsigned {
        return run_local(args).await;
    }

    let body = serde_json::json!({
        "profile_id": args.profile_id,
        "dot": args.dot,
        "name": args.name,
        "description": args.description,
    });

    let data = api.post_bytes_json("/api/mobileconfig", &body).await?;

    let proto = if args.dot { "DoT" } else { "DoH" };

    if let Some(ref path) = args.output {
        std::fs::write(path, &data)?;
        println!("Signed profile written to {}", path.display());
        println!();
        println!("  Protocol:  {proto}");
        if let Some(ref pid) = args.profile_id {
            println!("  Profile:   {pid}");
        }
        println!("  Size:      {} bytes", data.len());
        println!();
        println!("Install: AirDrop to your device, or open directly on macOS.");
    } else {
        // Binary output to stdout.
        use std::io::Write;
        std::io::stdout().write_all(&data)?;
    }

    Ok(())
}

/// Generate unsigned mobileconfig locally (no API call).
async fn run_local(args: ProfileArgs) -> Result<()> {
    let config = crate::config::Config::load();

    let server_raw = args
        .server
        .or_else(|| {
            if config.dns_server.is_empty() {
                None
            } else {
                Some(config.dns_server.clone())
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!("--server is required (or set dns_server in config.toml)")
        })?;

    let addrs: Vec<String> = if args.addrs.is_empty() {
        config.dns_addrs.clone()
    } else {
        args.addrs.clone()
    };

    let desc = args
        .description
        .as_deref()
        .unwrap_or("Encrypted DNS settings for Nameserver");
    let desc = xml_escape(desc);
    let name = xml_escape(&args.name);
    let server = xml_escape(&server_raw);

    // If --profile-id is set, use /{profile_id} as the DoH path.
    let doh_path = match &args.profile_id {
        Some(pid) => format!("/{pid}"),
        None => args.doh_path.clone(),
    };

    let identifier = match &args.profile_id {
        Some(pid) => format!("io.nameserver.dns.{}.{pid}", server_raw.replace('.', "-")),
        None => format!("io.nameserver.dns.{}", server_raw.replace('.', "-")),
    };

    let uuid_seed = match &args.profile_id {
        Some(pid) => format!("nameserver-profile-{}-{pid}", server_raw),
        None => format!("nameserver-profile-{}", server_raw),
    };
    let profile_uuid = deterministic_uuid(&uuid_seed);

    // Build ServerAddresses XML fragment (for failover between ns1/ns2)
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

    let (dns_settings, payload_name, payload_id, payload_uuid) = if args.dot {
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
        let url = format!("https://{}{}", server, xml_escape(&doh_path));
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

    let xml = format!(
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
    );

    if output::is_json() {
        let mut data = serde_json::json!({
            "server": server_raw,
            "protocol": if args.dot { "DoT" } else { "DoH" },
            "profile_uuid": profile_uuid,
            "payload_uuid": payload_uuid,
        });
        if !args.dot {
            data["server_url"] =
                serde_json::Value::String(format!("https://{}{}", server_raw, doh_path));
        }
        if let Some(ref path) = args.output {
            data["output"] = serde_json::Value::String(path.display().to_string());
        }
        data["xml"] = serde_json::Value::String(xml.clone());
        if let Some(ref path) = args.output {
            std::fs::write(path, &xml)?;
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else if let Some(ref path) = args.output {
        std::fs::write(path, &xml)?;
        println!("Profile written to {}", path.display());
        println!();
        println!("  Server:    {}", server_raw);
        if args.dot {
            println!("  Protocol:  DoT (DNS over TLS)");
        } else {
            println!("  Protocol:  DoH (DNS over HTTPS)");
            println!("  URL:       https://{}{}", server_raw, doh_path);
        }
        println!("  Profile:   {profile_uuid}");
        println!();
        println!("Install: AirDrop to your device, or open directly on macOS.");
    } else {
        print!("{xml}");
    }

    Ok(())
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
    fn deterministic_uuid_differs_for_different_input() {
        let a = deterministic_uuid("input-a");
        let b = deterministic_uuid("input-b");
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_uuid_format() {
        let uuid = deterministic_uuid("test");
        // 8-4-4-4-12 format
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn xml_escape_special_chars() {
        assert_eq!(xml_escape("a<b>c&d"), "a&lt;b&gt;c&amp;d");
    }
}
