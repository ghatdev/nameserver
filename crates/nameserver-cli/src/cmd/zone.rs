use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct ZoneArgs {
    #[command(subcommand)]
    action: ZoneAction,
}

#[derive(Subcommand)]
enum ZoneAction {
    /// List all managed zones
    List,
    /// Show current zone config (deployed in NATS KV)
    Show {
        /// Zone origin (e.g., example.test)
        origin: String,
    },
    /// Compare a local TOML zone file against the deployed zone
    Diff {
        /// Path to the zone TOML file
        file: String,
    },
    /// Apply a local TOML zone file to the control plane
    Apply {
        /// Path to the zone TOML file
        file: String,
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
    /// DNSSEC key management
    Dnssec(DnssecArgs),
}

#[derive(Args)]
pub struct DnssecArgs {
    #[command(subcommand)]
    action: DnssecAction,
}

#[derive(Subcommand)]
enum DnssecAction {
    /// Show key status (whether keys exist in Object Store)
    Status,
    /// Generate KSK + ZSK key pair and store in NATS Object Store
    Keygen {
        /// Overwrite existing keys (DANGEROUS — invalidates DS at registrar)
        #[arg(long)]
        force: bool,
    },
    /// Print the DS record for the registrar (computed from KSK)
    Ds {
        /// Zone origin (e.g., example.test)
        origin: String,
    },
    /// Roll over the ZSK (generates new key, triggers zone rebuild)
    Rollover,
}

pub async fn run(api: &Client, args: ZoneArgs) -> Result<()> {
    match args.action {
        ZoneAction::List => list(api).await,
        ZoneAction::Show { origin } => show(api, &origin).await,
        ZoneAction::Diff { file } => diff(api, &file).await,
        ZoneAction::Apply { file, yes } => apply(api, &file, yes).await,
        ZoneAction::Dnssec(args) => run_dnssec(api, args).await,
    }
}

// ---------------------------------------------------------------------------
// Zone commands
// ---------------------------------------------------------------------------

async fn list(api: &Client) -> Result<()> {
    let data = api.get_json("/api/zones").await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let zones = data["zones"].as_array();
    if zones.is_none_or(|z| z.is_empty()) {
        println!("No zones found.");
        return Ok(());
    }

    println!("{:<25} {:>8} {:>8}  DNSSEC", "ORIGIN", "VERSION", "RECORDS");
    println!("{}", "-".repeat(55));
    for z in zones.unwrap() {
        let origin = z["origin"].as_str().unwrap_or("?");
        let version = z["version"].as_u64().unwrap_or(0);
        let records = z["record_count"].as_u64().unwrap_or(0);
        let dnssec = if z["dnssec_enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        println!("{:<25} {:>8} {:>8}  {}", origin, version, records, dnssec);
    }

    Ok(())
}

async fn show(api: &Client, origin: &str) -> Result<()> {
    let data = api.get_json(&format!("/api/zones/{origin}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let origin_str = data["origin"].as_str().unwrap_or("?");
    let version = data["version"].as_u64().unwrap_or(0);

    println!("Zone: {origin_str} (version {version})");

    // Nameservers
    if let Some(ns) = data["nameservers"].as_array() {
        println!("\nNameservers:");
        for n in ns {
            if let Some(s) = n.as_str() {
                println!("  {s}");
            }
        }
    }

    // SOA
    let soa = &data["soa"];
    if !soa.is_null() {
        println!("\nSOA:");
        println!(
            "  refresh={} retry={} expire={} minimum={}",
            soa["refresh"].as_u64().unwrap_or(0),
            soa["retry"].as_u64().unwrap_or(0),
            soa["expire"].as_u64().unwrap_or(0),
            soa["minimum"].as_u64().unwrap_or(0),
        );
    }

    // Records
    if let Some(records) = data["records"].as_array() {
        println!("\nRecords ({}):", records.len());
        for r in records {
            let name = r["name"].as_str().unwrap_or("?");
            let rtype = r["type"]
                .as_str()
                .or_else(|| r["rtype"].as_str())
                .unwrap_or("?");
            let value = r["value"].as_str().unwrap_or("?");
            let ttl = r["ttl"].as_u64().unwrap_or(3600);
            println!("  {name:<20} {ttl:>5}  {rtype:<6} {value}");
        }
    }

    // DNSSEC
    if let Some(dnssec) = data.get("dnssec")
        && !dnssec.is_null()
    {
        let enabled = dnssec["enabled"].as_bool().unwrap_or(false);
        let algo = dnssec["algorithm"].as_str().unwrap_or("?");
        let nsec = dnssec["nsec_mode"].as_str().unwrap_or("?");
        println!(
            "\nDNSSEC: {} ({}, {})",
            if enabled { "enabled" } else { "disabled" },
            algo,
            nsec
        );
    }

    Ok(())
}

/// Read and parse a zone TOML file from a user-provided CLI path.
fn read_zone_file(path: &str) -> Result<nameserver_common::zone::ZoneKvConfig> {
    use std::io::Read;
    let resolved = std::fs::canonicalize(path) // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        .map_err(|e| anyhow::anyhow!("cannot read '{path}': {e}"))?;
    let mut buf = String::new();
    std::fs::File::open(&resolved)?.read_to_string(&mut buf)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    let config: nameserver_common::zone::ZoneKvConfig = toml::from_str(&buf)?;
    Ok(config)
}

async fn diff(api: &Client, file: &str) -> Result<()> {
    let local = read_zone_file(file)?;

    // Fetch deployed zone.
    let resp = api.get_json(&format!("/api/zones/{}", local.origin)).await;
    let deployed: Option<nameserver_common::zone::ZoneKvConfig> = match resp {
        Ok(data) => serde_json::from_value(data).ok(),
        Err(_) => None,
    };

    match deployed {
        None => {
            eprintln!(
                "  + zone/{} (new zone, {} records)",
                local.origin,
                local.records.len()
            );
            for r in &local.records {
                eprintln!("    + {} {} {}", r.name, r.rtype, r.value);
            }
        }
        Some(remote) => {
            let mut changes = false;

            // Compare nameservers
            if local.nameservers != remote.nameservers {
                changes = true;
                eprintln!("  ~ nameservers:");
                for ns in &remote.nameservers {
                    if !local.nameservers.contains(ns) {
                        eprintln!("    - {ns}");
                    }
                }
                for ns in &local.nameservers {
                    if !remote.nameservers.contains(ns) {
                        eprintln!("    + {ns}");
                    }
                }
            }

            // Compare SOA
            if local.soa.refresh != remote.soa.refresh
                || local.soa.retry != remote.soa.retry
                || local.soa.expire != remote.soa.expire
                || local.soa.minimum != remote.soa.minimum
            {
                changes = true;
                eprintln!(
                    "  ~ soa: refresh={}->{} retry={}->{} expire={}->{} minimum={}->{}",
                    remote.soa.refresh,
                    local.soa.refresh,
                    remote.soa.retry,
                    local.soa.retry,
                    remote.soa.expire,
                    local.soa.expire,
                    remote.soa.minimum,
                    local.soa.minimum,
                );
            }

            // Compare records
            let remote_set: Vec<String> = remote
                .records
                .iter()
                .map(|r| format!("{} {} {} {}", r.name, r.rtype, r.value, r.ttl))
                .collect();
            let local_set: Vec<String> = local
                .records
                .iter()
                .map(|r| format!("{} {} {} {}", r.name, r.rtype, r.value, r.ttl))
                .collect();

            for (i, key) in remote_set.iter().enumerate() {
                if !local_set.contains(key) {
                    changes = true;
                    let r = &remote.records[i];
                    eprintln!("  - {} {} {} (TTL={})", r.name, r.rtype, r.value, r.ttl);
                }
            }
            for (i, key) in local_set.iter().enumerate() {
                if !remote_set.contains(key) {
                    changes = true;
                    let r = &local.records[i];
                    eprintln!("  + {} {} {} (TTL={})", r.name, r.rtype, r.value, r.ttl);
                }
            }

            // Compare DNSSEC
            let local_dnssec = local.dnssec.as_ref().map(|d| d.enabled).unwrap_or(false);
            let remote_dnssec = remote.dnssec.as_ref().map(|d| d.enabled).unwrap_or(false);
            if local_dnssec != remote_dnssec {
                changes = true;
                eprintln!("  ~ dnssec: {} -> {}", remote_dnssec, local_dnssec);
            }

            if !changes {
                eprintln!("  (no changes)");
            }
        }
    }

    Ok(())
}

async fn apply(api: &Client, file: &str, yes: bool) -> Result<()> {
    let local = read_zone_file(file)?;

    // Show diff first.
    diff(api, file).await?;

    // Confirm.
    if !yes {
        eprint!("\nApply zone config for '{}'? [y/N] ", local.origin);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    // PUT to API.
    let body = serde_json::to_value(&local)?;
    let resp = api
        .put_json(&format!("/api/zones/{}", local.origin), &body)
        .await?;

    if output::maybe_json(&resp) {
        return Ok(());
    }

    let revision = resp["revision"].as_u64().unwrap_or(0);
    eprintln!("Applied zone '{}' (revision {revision})", local.origin);

    Ok(())
}

// ---------------------------------------------------------------------------
// DNSSEC subcommands (moved from top-level dnssec command)
// ---------------------------------------------------------------------------

async fn run_dnssec(api: &Client, args: DnssecArgs) -> Result<()> {
    match args.action {
        DnssecAction::Status => dnssec_status(api).await,
        DnssecAction::Keygen { force } => dnssec_keygen(api, force).await,
        DnssecAction::Ds { origin } => dnssec_ds(api, &origin).await,
        DnssecAction::Rollover => dnssec_rollover(api).await,
    }
}

async fn dnssec_status(api: &Client) -> Result<()> {
    let resp = api.get_json("/api/dnssec/status").await?;
    if output::maybe_json(&resp) {
        return Ok(());
    }

    println!("DNSSEC Key Status:");
    let configured = resp["configured"].as_bool().unwrap_or(false);
    if !configured {
        println!("  Not configured (Object Store bucket not found)");
        return Ok(());
    }

    let ksk = resp["ksk_present"].as_bool().unwrap_or(false);
    let zsk = resp["zsk_present"].as_bool().unwrap_or(false);
    println!(
        "  KSK: {}",
        if ksk {
            format!("present ({} bytes)", resp["ksk_size"])
        } else {
            "missing".to_string()
        }
    );
    println!(
        "  ZSK: {}",
        if zsk {
            format!("present ({} bytes)", resp["zsk_size"])
        } else {
            "missing".to_string()
        }
    );

    Ok(())
}

async fn dnssec_keygen(api: &Client, force: bool) -> Result<()> {
    let body = serde_json::json!({ "force": force });
    let resp = api.post_json("/api/dnssec/keygen", &body).await?;

    if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
        anyhow::bail!("{error}");
    }

    let key_tag = resp["ksk_key_tag"].as_u64().unwrap_or(0);
    eprintln!("DNSSEC keys generated and stored:");
    eprintln!(
        "  Algorithm:   {} ({})",
        resp["algorithm"].as_str().unwrap_or("?"),
        resp["algorithm_number"]
    );
    eprintln!("  KSK key tag: {key_tag}");
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Set dnssec.enabled = true in zone config");
    eprintln!("  2. Run: nameserver zone dnssec ds <zone-origin>");
    eprintln!("  3. Add the DS record at your registrar");

    Ok(())
}

async fn dnssec_ds(api: &Client, origin: &str) -> Result<()> {
    let resp = api.get_json(&format!("/api/dnssec/ds/{origin}")).await?;

    if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
        anyhow::bail!("{error}");
    }

    if let Some(ds_record) = resp["ds_record"].as_str() {
        println!("{ds_record}");
    }

    eprintln!();
    eprintln!("Add this DS record at your registrar ({origin}).");
    if let Some(key_tag) = resp["key_tag"].as_u64() {
        eprintln!("  Key Tag:     {key_tag}");
    }
    eprintln!("  Algorithm:   {} (ECDSAP256SHA256)", resp["algorithm"]);
    eprintln!("  Digest Type: {} (SHA-256)", resp["digest_type"]);

    Ok(())
}

async fn dnssec_rollover(api: &Client) -> Result<()> {
    let resp = api
        .post_json("/api/dnssec/rollover/zsk", &serde_json::json!({}))
        .await?;

    if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
        anyhow::bail!("{error}");
    }

    let old_tag = resp["old_key_tag"].as_u64().unwrap_or(0);
    let new_tag = resp["new_key_tag"].as_u64().unwrap_or(0);
    let rebuilt = resp["zone_rebuild_triggered"].as_bool().unwrap_or(false);

    eprintln!("ZSK rolled over:");
    eprintln!("  Old key tag: {old_tag}");
    eprintln!("  New key tag: {new_tag}");
    eprintln!(
        "  Zone rebuild: {}",
        if rebuilt {
            "triggered"
        } else {
            "pending (manual restart needed)"
        }
    );
    eprintln!();
    eprintln!("No DS update needed (KSK unchanged).");

    Ok(())
}
