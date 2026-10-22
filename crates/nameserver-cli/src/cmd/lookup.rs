use anyhow::Result;
use clap::Args;

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct LookupArgs {
    /// Domain name to look up
    domain: String,
}

pub async fn run(client: &Client, args: LookupArgs) -> Result<()> {
    let data = client
        .get_json(&format!("/api/reputation/{}", args.domain))
        .await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    if let Some(err) = data["error"].as_str() {
        println!("Not found: {err}");
        return Ok(());
    }

    let domain = data["registrable_domain"].as_str().unwrap_or("-");
    let ns_trust = data["ns_trust"].as_str().unwrap_or("unknown");
    let tld = data["tld"].as_str().unwrap_or("-");
    let tld_type = data["tld_type"].as_str().unwrap_or("-");
    let flows = data["total_flow_count"].as_i64().unwrap_or(0);
    let ns_obs = data["ns_observation_count"].as_i64().unwrap_or(0);

    println!("{domain}  ({tld} / {tld_type})");
    println!();

    // NS trust with color hint
    let trust_marker = match ns_trust {
        "stable" => "+",
        "known_provider" => "+",
        "free_dns" => "!",
        "registrar_default" => "~",
        "changed" => "!",
        "new" => "~",
        _ => "?",
    };
    println!("  NS trust:    [{trust_marker}] {ns_trust}  ({ns_obs} observations)");

    // NS domains
    if let Some(ns) = data["ns_domains"].as_array() {
        let ns_strs: Vec<&str> = ns.iter().filter_map(|v| v.as_str()).take(5).collect();
        if !ns_strs.is_empty() {
            println!("  NS:          {}", ns_strs.join(", "));
        }
    }

    // Flags
    let mut flags = Vec::new();
    if data["is_well_known"].as_bool().unwrap_or(false) {
        flags.push("well-known");
    }
    if data["is_nrd"].as_bool().unwrap_or(false) {
        flags.push("NRD");
    }
    if data["is_trusted"].as_bool().unwrap_or(false) {
        flags.push("TRUSTED");
    }
    if data["has_dnssec"].as_bool().unwrap_or(false) {
        flags.push("DNSSEC");
    }
    if data["has_cname"].as_bool().unwrap_or(false) {
        flags.push("CNAME");
    }
    if data["is_cdn"].as_bool().unwrap_or(false) {
        flags.push("CDN");
    }
    if !flags.is_empty() {
        println!("  Flags:       {}", flags.join(", "));
    }

    // Stats
    if let Some(ttl) = data["avg_auth_ttl"].as_f64() {
        println!("  Auth TTL:    {:.0}s", ttl);
    }
    if let Some(ms) = data["avg_resolve_ms"].as_f64() {
        println!("  Resolve:     {:.0}ms", ms);
    }
    if let Some(depth) = data["avg_chain_depth"].as_f64() {
        println!("  Chain depth: {:.1}", depth);
    }
    println!("  Flows:       {flows}");

    // CNAME targets
    if let Some(cnames) = data["cname_targets"].as_array() {
        let targets: Vec<&str> = cnames.iter().filter_map(|v| v.as_str()).take(5).collect();
        if !targets.is_empty() {
            println!("  CNAMEs:      {}", targets.join(", "));
        }
    }

    // IP info
    if let Some(country) = data["primary_country"].as_str() {
        let asn = data["primary_asn"].as_i64().unwrap_or(0);
        println!("  IP:          {country} / AS{asn}");
    }

    // Trust info
    if data["is_trusted"].as_bool().unwrap_or(false) {
        let source = data["trust_source"].as_str().unwrap_or("unknown");
        println!("  Trust:       verified ({source})");
    }

    Ok(())
}
