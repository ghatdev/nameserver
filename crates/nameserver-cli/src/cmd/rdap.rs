use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct RdapArgs {
    #[command(subcommand)]
    action: RdapAction,
}

#[derive(Subcommand)]
enum RdapAction {
    /// Pull RDAP/WHOIS data for a domain or retry failed entries
    Pull {
        /// Domain to look up (omit for batch)
        #[arg(long)]
        domain: Option<String>,
        /// Retry all failed entries (reset backoff, re-fetch)
        #[arg(long)]
        retry_failed: bool,
        /// Max domains to process in batch
        #[arg(long, default_value = "100")]
        limit: u32,
    },
    /// Show RDAP cache status
    Status,
    /// Look up cached RDAP data for a domain
    Lookup {
        /// Domain to look up
        domain: String,
        /// Force pull if not cached or stale
        #[arg(long)]
        pull: bool,
    },
}

pub async fn run(client: &Client, args: RdapArgs) -> Result<()> {
    match args.action {
        RdapAction::Pull {
            domain,
            retry_failed,
            limit,
        } => {
            if let Some(d) = domain {
                pull(client, &d).await
            } else {
                pull_batch(client, retry_failed, limit).await
            }
        }
        RdapAction::Status => status(client).await,
        RdapAction::Lookup {
            domain,
            pull: force_pull,
        } => {
            if force_pull {
                pull(client, &domain).await?;
            }
            lookup(client, &domain).await
        }
    }
}

async fn pull(client: &Client, domain: &str) -> Result<()> {
    let query = format!("?domain={domain}");

    let data = client.post_empty(&format!("/api/rdap/pull{query}")).await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    let fetched = data["fetched"].as_u64().unwrap_or(0);
    let failed = data["failed"].as_u64().unwrap_or(0);
    let skipped = data["skipped"].as_u64().unwrap_or(0);

    if let Some(d) = data["domain"].as_str() {
        let method = data["lookup_method"].as_str().unwrap_or("unknown");
        println!("Domain:  {d}");
        println!("Method:  {method}");
    }

    println!("Fetched: {fetched}");
    println!("Failed:  {failed}");
    println!("Skipped: {skipped}");

    if let Some(msg) = data["message"].as_str() {
        println!("{msg}");
    }

    Ok(())
}

async fn pull_batch(client: &Client, retry_failed: bool, limit: u32) -> Result<()> {
    let mut query = format!("?limit={limit}");
    if retry_failed {
        query.push_str("&retry_failed=true");
    }

    let data = client.post_empty(&format!("/api/rdap/pull{query}")).await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    let fetched = data["fetched"].as_u64().unwrap_or(0);
    let failed = data["failed"].as_u64().unwrap_or(0);
    let skipped = data["skipped"].as_u64().unwrap_or(0);
    let total = data["total_candidates"].as_u64().unwrap_or(0);

    println!("Candidates: {total}");
    println!("Fetched:    {fetched}");
    println!("Failed:     {failed}");
    println!("Skipped:    {skipped}");

    if let Some(msg) = data["message"].as_str() {
        println!("{msg}");
    }

    Ok(())
}

async fn status(client: &Client) -> Result<()> {
    let data = client.get_json("/api/rdap/status").await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    let total = data["total_domains"].as_u64().unwrap_or(0);
    let cached = data["cached"].as_u64().unwrap_or(0);
    let fresh = data["fresh"].as_u64().unwrap_or(0);
    let stale = data["stale"].as_u64().unwrap_or(0);
    let failed = data["failed"].as_u64().unwrap_or(0);

    println!("RDAP Cache Status");
    println!("{}", "-".repeat(30));
    println!("Total domains:  {total}");
    println!("Cached:         {cached}");
    println!("  Fresh:        {fresh}");
    println!("  Stale (>24h): {stale}");
    println!("  Failed:       {failed}");

    if total > 0 {
        let pct = (cached as f64 / total as f64) * 100.0;
        println!("Coverage:       {pct:.1}%");
    }

    Ok(())
}

async fn lookup(client: &Client, domain: &str) -> Result<()> {
    let data = client
        .get_json(&format!("/api/rdap/lookup/{domain}"))
        .await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    if data.get("error").is_some() {
        let msg = data["error"].as_str().unwrap_or("lookup failed");
        let reg = data["registrable_domain"].as_str().unwrap_or(domain);
        println!("{msg} (registrable: {reg})");
        return Ok(());
    }

    if let Some(reg) = data["registrable_domain"].as_str() {
        println!("Domain:      {reg}");
    }
    if let Some(method) = data["lookup_method"].as_str() {
        println!("Method:      {method}");
    }
    if let Some(created) = data["creation_date"].as_str() {
        println!("Created:     {created}");
    }
    if let Some(expires) = data["expiration_date"].as_str() {
        println!("Expires:     {expires}");
    }
    if let Some(registrar) = data["registrar"].as_str() {
        println!("Registrar:   {registrar}");
    }
    if let Some(privacy) = data["privacy_protected"].as_bool() {
        println!("Privacy:     {}", if privacy { "yes" } else { "no" });
    }
    if let Some(status) = data["status"].as_array()
        && !status.is_empty()
    {
        let flags: Vec<&str> = status.iter().filter_map(|v| v.as_str()).collect();
        println!("Status:      {}", flags.join(", "));
    }
    if let Some(ns) = data["nameservers"].as_array()
        && !ns.is_empty()
    {
        let servers: Vec<&str> = ns.iter().filter_map(|v| v.as_str()).collect();
        println!("Nameservers: {}", servers.join(", "));
    }
    if let Some(ts) = data["fetched_at"].as_i64() {
        println!("Fetched at:  {ts}");
    }

    Ok(())
}
