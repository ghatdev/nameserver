use anyhow::Result;

use crate::client::Client;
use crate::output;

pub async fn run(client: &Client) -> Result<()> {
    let data = client.get_json("/api/status").await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    println!("=== Nameserver Status ===\n");

    // Local database stats.
    if let Some(db) = data.get("local_database") {
        println!("Database:");
        println!("  Domains:      {}", db["domains"].as_u64().unwrap_or(0));
        println!("  IPs:          {}", db["ips"].as_u64().unwrap_or(0));
        println!(
            "  Ind. domains: {}",
            db["indicator_domains"].as_u64().unwrap_or(0)
        );
        println!(
            "  Ind. IPs:     {}",
            db["indicator_ips"].as_u64().unwrap_or(0)
        );
        println!("  Filters:      {}", db["filters"].as_u64().unwrap_or(0));
        println!(
            "  Geo entries:  {}",
            db["geo_entries"].as_u64().unwrap_or(0)
        );
        println!();
    }

    // Data plane health (via NATS request/reply).
    if let Some(dns) = data.get("dns_health") {
        println!("Data Plane:");
        if dns.is_null() {
            println!("  unreachable (NATS timeout)");
        } else if dns.get("error").is_some() {
            let err = dns["error"].as_str().unwrap_or("unreachable");
            println!("  {err}");
        } else {
            println!(
                "  Uptime:     {}s",
                dns["uptime_secs"].as_u64().unwrap_or(0)
            );
            println!(
                "  Queries:    {}",
                dns["total_queries"].as_u64().unwrap_or(0)
            );
            println!(
                "  Blocked:    {}",
                dns["blocked_queries"].as_u64().unwrap_or(0)
            );
            let nats = if dns["nats_connected"].as_bool().unwrap_or(false) {
                "connected"
            } else {
                "disconnected"
            };
            println!("  NATS:       {nats}");
        }
    }

    Ok(())
}
