use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::cmd::apply;
use crate::output;

#[derive(Args)]
pub struct GeoipArgs {
    #[command(subcommand)]
    action: GeoipAction,
}

#[derive(Subcommand)]
enum GeoipAction {
    /// Compile GeoIP prefix table from fetched data
    Compile {
        /// Only show what would be built
        #[arg(long)]
        dry_run: bool,
    },
    /// Look up an IP address
    Lookup {
        /// IP address to look up
        ip: String,
        /// Use Team Cymru DNS for live lookup
        #[arg(long)]
        live: bool,
    },
    /// Show geo data status
    Status,
    /// Show pending geoip changes (desired DB state vs deployed NATS state)
    Diff,
    /// Compile and publish geoip to DNS servers
    Apply {
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
}

pub async fn run(client: &Client, args: GeoipArgs) -> Result<()> {
    match args.action {
        GeoipAction::Compile { dry_run } => compile(client, dry_run).await,
        GeoipAction::Lookup { ip, live } => lookup(client, &ip, live).await,
        GeoipAction::Status => status(client).await,
        GeoipAction::Diff => apply::scoped_diff(client, "geoip").await,
        GeoipAction::Apply { yes } => {
            apply::scoped_apply(client, "/api/geoip/apply", "geoip", yes).await
        }
    }
}

async fn compile(client: &Client, dry_run: bool) -> Result<()> {
    let query = if dry_run { "?dry_run=true" } else { "" };
    let data = client
        .post_empty(&format!("/api/geoip/compile{query}"))
        .await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    if let Some(msg) = data["message"].as_str() {
        println!("{msg}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    }

    Ok(())
}

async fn lookup(client: &Client, ip: &str, live: bool) -> Result<()> {
    let query = if live { "?live=true" } else { "" };
    let data = client
        .get_json(&format!("/api/geoip/lookup/{ip}{query}"))
        .await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    if data.get("error").is_some() {
        println!("{}", data["error"].as_str().unwrap_or("lookup failed"));
        return Ok(());
    }

    if let Some(country) = data["country"].as_str() {
        println!("Country: {country}");
    }
    if let Some(asn) = data["asn"].as_u64() {
        println!("ASN:     AS{asn}");
    }
    if let Some(prefix) = data["prefix"].as_str() {
        println!("Prefix:  {prefix}");
    }
    if let Some(rir) = data["rir"].as_str() {
        println!("RIR:     {rir}");
    }

    let is_cdn = data["is_cdn"].as_bool().unwrap_or(false);
    if is_cdn {
        let asn = data["asn"].as_u64().unwrap_or(0);
        println!("CDN:     yes  [AS{asn} in CDN list]");
    } else {
        println!("CDN:     no");
    }

    if let Some(source) = data["source"].as_str() {
        println!("Source:  {source}");
    }

    Ok(())
}

async fn status(client: &Client) -> Result<()> {
    let data = client.get_json("/api/geoip/status").await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    if let Some(entries) = data["entries"].as_array() {
        println!("{:<12} {:>6} {:>10}", "SOURCE", "TYPE", "ENTRIES");
        println!("{}", "-".repeat(30));
        for entry in entries {
            let source = entry["source"].as_str().unwrap_or("-");
            let vtype = entry["type"].as_str().unwrap_or("-");
            let count = entry["count"].as_u64().unwrap_or(0);
            println!("{:<12} {:>6} {:>10}", source, vtype, count);
        }
        let total = data["total"].as_u64().unwrap_or(0);
        println!("{}", "-".repeat(30));
        println!("{:<12} {:>6} {:>10}", "TOTAL", "", total);
    }

    if let Some(compiled) = data.get("compiled") {
        if compiled.is_null() {
            println!("\nCompiled:    (not found)");
        } else {
            let size = compiled["size"].as_u64().unwrap_or(0);
            println!("\nCompiled:    geoip.bin ({size} bytes)");
        }
    }

    Ok(())
}
