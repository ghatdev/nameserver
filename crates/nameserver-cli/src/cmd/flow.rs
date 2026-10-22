use anyhow::Result;
use clap::Args;

use crate::client::Client;
use crate::cmd::format;
use crate::output;

#[derive(Args)]
pub struct FlowArgs {
    /// Filter by domain
    domain: Option<String>,
    /// Filter by query type (A, AAAA, CNAME, etc.)
    #[arg(long, short = 't')]
    r#type: Option<String>,
    /// Show N most recent flows
    #[arg(long, default_value = "20")]
    recent: u32,
    /// Show top N domains by query count
    #[arg(long)]
    top: Option<u32>,
    /// Show only NXDOMAIN responses
    #[arg(long)]
    nxdomain: bool,
    /// Show only blocked queries
    #[arg(long)]
    blocked: bool,
    /// Show full resolution path, all records, and DNSSEC details
    #[arg(long, short = 'v')]
    verbose: bool,
    /// Filter by profile (ID or display name)
    #[arg(long, short = 'p')]
    profile: Option<String>,
    /// Show per-profile aggregation (query/block counts)
    #[arg(long, conflicts_with = "top")]
    by_profile: bool,
}

pub async fn run(client: &Client, args: FlowArgs) -> Result<()> {
    let mut params = Vec::new();
    if let Some(ref domain) = args.domain {
        params.push(format!("domain={domain}"));
    }
    if let Some(ref qtype) = args.r#type {
        params.push(format!("type={qtype}"));
    }
    if let Some(top) = args.top {
        params.push(format!("top={top}"));
    }
    if args.nxdomain {
        params.push("nxdomain=true".to_string());
    }
    if args.blocked {
        params.push("action=BLOCK".to_string());
    }
    if let Some(ref profile) = args.profile {
        let resolved = resolve_profile_id(client, profile).await?;
        params.push(format!("profile={resolved}"));
    }
    if args.by_profile {
        params.push("by_profile=true".to_string());
    }
    params.push(format!("recent={}", args.recent));

    let query = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    let data = client.get_json(&format!("/api/flows{query}")).await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    // By-profile aggregation mode.
    if args.by_profile {
        let arr = data.get("by_profile").unwrap_or(&data);
        print_by_profile(arr);
        return Ok(());
    }

    // If "top" mode was requested, the response has "top_domains".
    if args.top.is_some() {
        let arr = data.get("top_domains").unwrap_or(&data);
        print_top_domains(arr);
        return Ok(());
    }

    // Recent flows are nested under "flows" key.
    let arr = data.get("flows").unwrap_or(&data);
    print_flows(arr, args.verbose);
    Ok(())
}

/// Resolve a profile argument to its ID.
///
/// If the input looks like an 8-char alphanumeric ID, use it directly.
/// Otherwise fetch the profile list and match by display name (case-insensitive).
async fn resolve_profile_id(client: &Client, input: &str) -> Result<String> {
    if input.len() == 8 && input.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok(input.to_string());
    }
    let data = client.get_json("/api/profiles").await?;
    if let Some(profiles) = data["profiles"].as_array() {
        for p in profiles {
            if p["display_name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(input))
                && let Some(id) = p["id"].as_str()
            {
                return Ok(id.to_string());
            }
        }
    }
    // Fallback: use as-is (might be a valid ID with different length).
    Ok(input.to_string())
}

fn print_top_domains(data: &serde_json::Value) {
    let entries = match data.as_array() {
        Some(arr) => arr,
        None => {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            return;
        }
    };

    println!("{:<50} {:>8}", "DOMAIN", "QUERIES");
    println!("{}", "-".repeat(60));
    for entry in entries {
        let domain = entry["domain"].as_str().unwrap_or("-");
        let count = entry["count"].as_u64().unwrap_or(0);
        println!("{:<50} {:>8}", truncate(domain, 50), count);
    }
}

fn print_by_profile(data: &serde_json::Value) {
    let entries = match data.as_array() {
        Some(arr) => arr,
        None => {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            return;
        }
    };

    println!(
        "{:<10} {:<20} {:>10} {:>10} {:>10}",
        "ID", "PROFILE", "QUERIES", "BLOCKED", "NXDOMAIN"
    );
    println!("{}", "-".repeat(64));
    for entry in entries {
        let id = entry["profile_id"].as_str().unwrap_or("-");
        let name = entry["profile_name"].as_str().unwrap_or("-");
        let queries = entry["total_queries"].as_u64().unwrap_or(0);
        let blocked = entry["blocked"].as_u64().unwrap_or(0);
        let nxdomain = entry["nxdomain"].as_u64().unwrap_or(0);
        let display_name = if name.is_empty() { id } else { name };
        println!(
            "{:<10} {:<20} {:>10} {:>10} {:>10}",
            truncate(id, 10),
            truncate(display_name, 20),
            queries,
            blocked,
            nxdomain,
        );
    }
}

fn print_flows(data: &serde_json::Value, verbose: bool) {
    let flows = match data.as_array() {
        Some(arr) => arr,
        None => {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            return;
        }
    };

    println!(
        "{:<40} {:<6} {:<14} {:<10} {:<2} {:<18} {:<12} {:>5} {:<8} {:>6}",
        "DOMAIN", "QTYPE", "ACTION", "RCODE", "CC", "ASN", "PROFILE", "TTL", "DNSSEC", "MS"
    );
    println!("{}", "-".repeat(125));

    for flow in flows {
        let domain = flow["domain"].as_str().unwrap_or("-");
        let qtype = flow["qtype"].as_str().unwrap_or("-");
        let list_action = flow["list_action"].as_str().unwrap_or("PASS");
        let list_filter = flow["list_filter"].as_str().unwrap_or("");
        let action = if list_filter.is_empty() {
            list_action.to_string()
        } else {
            format!("{list_action}({list_filter})")
        };
        let rcode = flow["rcode"].as_str().unwrap_or("-");
        let ttl = flow["response_ttl"].as_u64().unwrap_or(0);
        let dnssec = flow["dnssec_status"].as_str().unwrap_or("-");
        let total_ms = flow["total_ms"].as_u64().unwrap_or(0);

        let cc = flow["geo_country"].as_str().unwrap_or("");
        let cc_display = if cc.is_empty() { "-" } else { cc };

        let asn_num = flow["geo_asn"].as_u64().unwrap_or(0);
        let asn_org = flow["geo_asn_org"].as_str().unwrap_or("");
        let asn_display = if asn_num > 0 {
            if asn_org.is_empty() {
                format!("AS{asn_num}")
            } else {
                format!("AS{asn_num} {asn_org}")
            }
        } else {
            "-".to_string()
        };

        let profile_name = flow["profile_name"].as_str().unwrap_or("");
        let profile_id = flow["profile_id"].as_str().unwrap_or("");
        let profile_display = if !profile_name.is_empty() {
            profile_name
        } else if !profile_id.is_empty() {
            profile_id
        } else {
            "-"
        };

        println!(
            "{:<40} {:<6} {:<14} {:<10} {:<2} {:<18} {:<12} {:>5} {:<8} {:>6}",
            truncate(domain, 40),
            qtype,
            truncate(&action, 14),
            rcode,
            cc_display,
            truncate(&asn_display, 18),
            truncate(profile_display, 12),
            ttl,
            truncate(dnssec, 8),
            total_ms,
        );

        if let Some(reason) = flow["servfail_reason"].as_str()
            && !reason.is_empty()
        {
            println!("  SERVFAIL reason: {reason}");
        }

        if let Some(ips) = flow["response_ips"].as_array()
            && !ips.is_empty()
        {
            let ip_strs: Vec<&str> = ips.iter().filter_map(|v| v.as_str()).collect();
            println!("  IPs: {}", ip_strs.join(", "));
        }

        if verbose {
            print_flow_verbose(flow);
        }
    }
}

fn print_flow_verbose(flow: &serde_json::Value) {
    // CNAME chain
    if let Some(chain) = flow["cname_chain"].as_array()
        && !chain.is_empty()
    {
        let names: Vec<&str> = chain.iter().filter_map(|v| v.as_str()).collect();
        if !names.is_empty() {
            println!("  CNAME: {}", names.join(" -> "));
        }
    }

    // DNSSEC detail
    let status = flow["dnssec_status"].as_str().unwrap_or("");
    let algo = flow["dnssec_algorithm"].as_str().unwrap_or("");
    let fail = flow["dnssec_failure_reason"].as_str().unwrap_or("");
    if !status.is_empty() {
        let detail = format::dnssec_detail(status, algo, fail);
        println!("  DNSSEC: {detail}");
    }

    // Resolution path (parallel arrays)
    if let Some(rp) = flow.get("resolution_path") {
        let steps = rp["steps"].as_array();
        let asked = rp["asked"].as_array();
        let servers = rp["servers"].as_array();
        let server_names = rp["server_names"].as_array();
        let response_types = rp["response_types"].as_array();
        let ms_arr = rp["ms"].as_array();

        if let (Some(steps), Some(asked), Some(server_names), Some(response_types), Some(ms_arr)) =
            (steps, asked, server_names, response_types, ms_arr)
        {
            let len = steps
                .len()
                .min(asked.len())
                .min(server_names.len())
                .min(response_types.len())
                .min(ms_arr.len());

            if len > 0 {
                println!("  Resolution:");
                for i in 0..len {
                    let step_num = steps[i].as_u64().unwrap_or(0);
                    let server_name = server_names[i].as_str().unwrap_or("");
                    let server_ip = servers
                        .and_then(|s| s.get(i))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let server_display = if server_name.is_empty() {
                        server_ip
                    } else {
                        server_name
                    };
                    let ask = asked[i].as_str().unwrap_or("-");
                    let rtype = response_types[i].as_str().unwrap_or("-");
                    let ms = ms_arr[i].as_u64().unwrap_or(0);
                    println!("    #{step_num} {server_display} -> {ask} ({rtype}, {ms}ms)");
                }
            }
        }
    }

    // All records
    if let Some(records_str) = flow["all_records_json"].as_str()
        && !records_str.is_empty()
        && let Ok(records) = serde_json::from_str::<serde_json::Value>(records_str)
    {
        let formatted = format::format_all_records(&records, "    ");
        if !formatted.is_empty() {
            println!("  Records:");
            println!("{formatted}");
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
