use anyhow::Result;
use clap::Args;

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct InspectArgs {
    /// Domain name or IP address
    target: String,
}

pub async fn run(client: &Client, args: InspectArgs) -> Result<()> {
    let target = &args.target;

    // Detect if target looks like an IP address.
    let is_ip = target.contains(':') || target.parse::<std::net::Ipv4Addr>().is_ok();

    let path = if is_ip {
        format!("/api/ips/{target}")
    } else {
        format!("/api/domains/{target}")
    };

    let data = client.get_json(&path).await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    if is_ip {
        print_ip(&data);
    } else {
        print_domain(&data);
    }

    Ok(())
}

fn print_domain(data: &serde_json::Value) {
    // API wraps domain fields under "domain" key
    let d = &data["domain"];

    println!("Domain: {}", str_or(d, "domain", "-"));
    println!("First seen: {}", format_ts_field(d, "first_seen"));
    println!("Last seen:  {}", format_ts_field(d, "last_seen"));
    println!("Queries:    {}", d["query_count"].as_i64().unwrap_or(0));
    println!();

    // Reputation data
    if let Some(rep) = data["reputation"].as_object() {
        println!("--- Reputation ---");
        println!(
            "Registrable: {}  (TLD: {} / {})",
            rep.get("registrable_domain")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            rep.get("tld").and_then(|v| v.as_str()).unwrap_or("-"),
            rep.get("tld_type").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        println!(
            "NS trust:    {}  ({} observations, {} flows)",
            rep.get("ns_trust").and_then(|v| v.as_str()).unwrap_or("-"),
            rep.get("ns_observation_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
            rep.get("total_flow_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
        );

        // Authoritative NS domains
        if let Some(ns_arr) = rep.get("ns_domains").and_then(|v| v.as_array()) {
            let ns_strs: Vec<&str> = ns_arr.iter().filter_map(|v| v.as_str()).collect();
            if !ns_strs.is_empty() {
                println!("NS servers:  {}", ns_strs.join(", "));
            }
        }

        // Delegation NS chain
        if let Some(deleg) = rep.get("delegation_ns").and_then(|v| v.as_array()) {
            let deleg_strs: Vec<&str> = deleg.iter().filter_map(|v| v.as_str()).collect();
            if !deleg_strs.is_empty() {
                println!("Delegation:  {}", deleg_strs.join(" → "));
            }
        }

        // CNAME targets
        if let Some(cnames) = rep.get("cname_targets").and_then(|v| v.as_array()) {
            let cname_strs: Vec<&str> = cnames.iter().filter_map(|v| v.as_str()).take(5).collect();
            if !cname_strs.is_empty() {
                println!("CNAMEs:      {}", cname_strs.join(", "));
            }
        }

        // Flags
        let mut flags: Vec<String> = Vec::new();
        if rep
            .get("is_well_known")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            flags.push("well-known".to_string());
        }
        if rep.get("is_nrd").and_then(|v| v.as_bool()).unwrap_or(false) {
            let src = rep
                .get("nrd_source")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            flags.push(format!("NRD ({src})"));
        }
        if rep
            .get("is_trusted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let src = rep
                .get("trust_source")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            flags.push(format!("TRUSTED ({src})"));
        }
        if rep
            .get("has_dnssec")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            flags.push("DNSSEC".to_string());
        }
        if rep
            .get("has_cname")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            flags.push("CNAME".to_string());
        }
        if rep.get("has_mx").and_then(|v| v.as_bool()).unwrap_or(false) {
            flags.push("MX".to_string());
        }
        if rep.get("is_cdn").and_then(|v| v.as_bool()).unwrap_or(false) {
            flags.push("CDN".to_string());
        }
        if !flags.is_empty() {
            println!("Flags:       {}", flags.join(", "));
        }

        // Resolution stats
        let mut stats = Vec::new();
        if let Some(ttl) = rep.get("avg_auth_ttl").and_then(|v| v.as_f64()) {
            stats.push(format!("TTL={:.0}s", ttl));
        }
        if let Some(min_ttl) = rep.get("min_auth_ttl").and_then(|v| v.as_f64()) {
            stats.push(format!("min={:.0}s", min_ttl));
        }
        if let Some(ms) = rep.get("avg_resolve_ms").and_then(|v| v.as_f64()) {
            stats.push(format!("{:.0}ms", ms));
        }
        if let Some(depth) = rep.get("avg_chain_depth").and_then(|v| v.as_f64()) {
            stats.push(format!("depth={:.1}", depth));
        }
        let ips = rep
            .get("unique_ip_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let a_recs = rep
            .get("a_record_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        stats.push(format!("{ips} IPs"));
        stats.push(format!("{a_recs} A"));
        if !stats.is_empty() {
            println!("Resolution:  {}", stats.join(", "));
        }

        // IP summary
        if let Some(country) = rep.get("primary_country").and_then(|v| v.as_str()) {
            let asn = rep.get("primary_asn").and_then(|v| v.as_i64()).unwrap_or(0);
            if asn > 0 {
                println!("Primary IP:  {} / AS{}", country, asn);
            }
        }
        println!();
    }

    // Resolution history — at top level
    if let Some(history) = data["resolution_history"].as_array()
        && !history.is_empty()
    {
        println!("--- Resolution History (last {}) ---", history.len());
        for entry in history {
            let ts = format_ts_field(entry, "timestamp");
            let ttl = entry["ttl"].as_i64().unwrap_or(0);
            let dnssec = str_or(entry, "dnssec_status", "-");
            let ms = entry["resolve_ms"].as_i64().unwrap_or(0);
            let ips = str_or(entry, "ips", "-");
            println!("  {ts} | TTL={ttl:<5} | {dnssec} | {ms}ms | IPs: {ips}");
        }
        println!();
    }

    // Associated IPs — at top level
    if let Some(ips) = data["associated_ips"].as_array()
        && !ips.is_empty()
    {
        println!("--- Associated IPs ---");
        for entry in ips {
            let ip = str_or(entry, "ip", "-");
            let country = str_or(entry, "geo_country", "??");
            let asn = str_or(entry, "asn_org", "unknown");
            let dcount = entry["domain_count"].as_i64().unwrap_or(0);
            let cdn = entry["is_cdn"].as_bool().unwrap_or(false);
            let cdn_tag = if cdn { " [CDN]" } else { "" };
            println!("  {ip:<20} {country} | {asn} | {dcount} domains{cdn_tag}");
        }
    }
}

fn print_ip(data: &serde_json::Value) {
    // API wraps IP fields under "ip" key
    let ip = &data["ip"];

    println!("IP: {}", str_or(ip, "ip", "-"));
    println!("First seen: {}", format_ts_field(ip, "first_seen"));
    println!("Last seen:  {}", format_ts_field(ip, "last_seen"));
    println!(
        "GeoIP:      {} {}",
        str_or(ip, "geo_country", "??"),
        str_or(ip, "geo_city", ""),
    );
    if let Some(asn) = ip["asn_number"].as_i64() {
        println!(
            "ASN:        AS{} ({})",
            asn,
            str_or(ip, "asn_org", "unknown")
        );
    }
    if let Some(ptr) = ip["ptr_record"].as_str() {
        let ptr_match = ip["ptr_matches"].as_bool().unwrap_or(false);
        let match_tag = if ptr_match {
            " (matches)"
        } else {
            " (mismatch)"
        };
        println!("PTR:        {ptr}{match_tag}");
    }
    println!(
        "CDN:        {}",
        if ip["is_cdn"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Bulletproof: {}",
        if ip["is_bulletproof"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Domains:    {} (malicious: {})",
        ip["domain_count"].as_i64().unwrap_or(0),
        ip["malicious_count"].as_i64().unwrap_or(0),
    );

    // Blocklist — parse JSON string
    if let Some(bl_str) = ip["blocklist_json"].as_str()
        && let Ok(bl) = serde_json::from_str::<serde_json::Value>(bl_str)
        && let Some(arr) = bl.as_array()
    {
        if !arr.is_empty() {
            let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            println!("Blocklist:  {}", names.join(", "));
        } else {
            println!("Blocklist:  none");
        }
    }

    println!();

    // Associated domains — at top level
    if let Some(domains) = data["associated_domains"].as_array()
        && !domains.is_empty()
    {
        println!("--- Associated Domains ---");
        for entry in domains {
            let domain = str_or(entry, "domain", "-");
            println!("  {domain}");
        }
    }
}

fn str_or<'a>(v: &'a serde_json::Value, key: &str, default: &'a str) -> &'a str {
    v[key].as_str().unwrap_or(default)
}

fn format_ts_field(v: &serde_json::Value, key: &str) -> String {
    if let Some(ts) = v[key].as_i64() {
        format_ts(ts)
    } else if let Some(s) = v[key].as_str() {
        s.to_string()
    } else {
        "-".to_string()
    }
}

fn format_ts(ts: i64) -> String {
    let dt =
        time::OffsetDateTime::from_unix_timestamp(ts).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let format = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    dt.format(&format).unwrap_or_else(|_| ts.to_string())
}
