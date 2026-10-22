use anyhow::Result;
use clap::Args;

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct DomainsArgs {
    /// Maximum results
    #[arg(long, default_value = "50")]
    limit: u32,
}

pub async fn run(client: &Client, args: DomainsArgs) -> Result<()> {
    let mut params = Vec::new();
    params.push(format!("limit={}", args.limit));

    let query = format!("?{}", params.join("&"));
    let data = client.get_json(&format!("/api/domains{query}")).await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    let domains = match data["domains"].as_array() {
        Some(arr) => arr,
        None => {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
            return Ok(());
        }
    };

    if domains.is_empty() {
        println!("No domains found.");
        return Ok(());
    }

    println!("{:<45} {:>7} {:>5}", "DOMAIN", "QUERIES", "DAYS");
    println!("{}", "-".repeat(60));

    for d in domains {
        let domain = d["domain"].as_str().unwrap_or("-");
        let queries = d["query_count"].as_u64().unwrap_or(0);
        let first_seen = d["first_seen"].as_i64().unwrap_or(0);
        let last_seen = d["last_seen"].as_i64().unwrap_or(0);
        let age_days = if first_seen > 0 {
            (last_seen - first_seen) / 86400
        } else {
            0
        };

        println!(
            "{:<45} {:>7} {:>5}",
            truncate(domain, 45),
            queries,
            age_days,
        );
    }

    println!("\n{} domains shown.", domains.len());
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
