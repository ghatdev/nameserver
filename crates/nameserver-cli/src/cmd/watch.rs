use anyhow::Result;
use clap::Args;
use nameserver_common::messages::flow::DnsFlow;

use crate::cmd::format;

#[derive(Args)]
pub struct WatchArgs {
    /// Filter by domain (substring match)
    #[arg(long, short)]
    domain: Option<String>,

    /// Show only blocked queries
    #[arg(long)]
    blocked: bool,

    /// Show full resolution path and records
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Use SSE via control plane API instead of direct NATS
    #[arg(long)]
    sse: bool,
}

pub async fn run(control_url: &str, args: WatchArgs) -> Result<()> {
    run_sse(control_url, &args).await
}

async fn run_sse(control_url: &str, args: &WatchArgs) -> Result<()> {
    let url = format!("{}/api/flows/live", control_url.trim_end_matches('/'));

    eprintln!(
        "\x1b[2m── watching live DNS flows via SSE {} (ctrl-c to stop) ──\x1b[0m",
        url
    );

    let client = reqwest::Client::new();
    let mut response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("SSE endpoint returned {}", response.status());
    }

    let mut buffer = String::new();

    while let Some(chunk) = response.chunk().await? {
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // SSE format: "data: {...}\n\n"
        while let Some(pos) = buffer.find("\n\n") {
            let event = buffer[..pos].to_string();
            buffer = buffer[pos + 2..].to_string();

            for line in event.lines() {
                if let Some(json_str) = line.strip_prefix("data:") {
                    let json_str = json_str.trim();
                    if let Ok(flow) = serde_json::from_str::<DnsFlow>(json_str)
                        && let Some(action) = filter_flow(&flow, args)
                    {
                        print_flow(&flow, &action, args.verbose);
                    }
                }
            }
        }
    }

    Ok(())
}

fn filter_flow(flow: &DnsFlow, args: &WatchArgs) -> Option<String> {
    if let Some(ref pat) = args.domain
        && !flow.query.domain.contains(pat.as_str())
    {
        return None;
    }
    let action = serde_json::to_value(&flow.list_action)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", flow.list_action));
    if args.blocked && action != "BLOCK" {
        return None;
    }
    Some(action)
}

fn enum_str<T: serde::Serialize + std::fmt::Debug>(val: &T) -> String {
    serde_json::to_value(val)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{val:?}"))
}

fn print_flow(flow: &DnsFlow, action: &str, verbose: bool) {
    let qtype = enum_str(&flow.query.qtype);
    let rcode = enum_str(&flow.response.rcode);

    // DNSSEC detail with algorithm/failure
    let dnssec_status = enum_str(&flow.dnssec.status);
    let dnssec = format::dnssec_detail(
        &dnssec_status,
        flow.dnssec.algorithm.as_deref().unwrap_or(""),
        flow.dnssec.failure_reason.as_deref().unwrap_or(""),
    );

    let action_colored = match action {
        "BLOCK" => format!("\x1b[31m{}\x1b[0m", action),
        "ALLOW" => format!("\x1b[32m{}\x1b[0m", action),
        _ => format!("\x1b[33m{}\x1b[0m", action),
    };

    let ips = if flow.response.ips.is_empty() {
        "—".to_string()
    } else {
        flow.response.ips.join(", ")
    };

    println!(
        "{action_colored:>15}  {qtype:<6} {domain:<50} {rcode:<10} {ms:>4}ms TTL={ttl:<5}  {ips}  [{dnssec}]",
        domain = flow.query.domain,
        ms = flow.total_ms,
        ttl = flow.response.min_ttl,
    );

    // CNAME chain (always shown if present)
    if let Some(ref chain) = flow.cname_chain
        && !chain.is_empty()
    {
        println!(
            "                  \x1b[36mCNAME: {}\x1b[0m",
            chain.join(" -> ")
        );
    }

    if verbose {
        // Resolution path with per-step records
        if !flow.resolution_path.is_empty() {
            for step in &flow.resolution_path {
                let stype = enum_str(&step.response_type);
                let server = step.server_name.as_deref().unwrap_or(&step.server);
                println!(
                    "                  \x1b[2m└─ #{} {} → {} ({}, {}ms)\x1b[0m",
                    step.step, server, step.asked, stype, step.ms,
                );

                // Step records from StepData.got
                let indent = "                       ";
                if let Some(ref ns) = step.got.ns
                    && !ns.is_empty()
                {
                    println!("\x1b[2m{indent}NS: {}\x1b[0m", ns.join(", "));
                }
                if let Some(ref a) = step.got.a
                    && !a.is_empty()
                {
                    let label = if step.got.ns.is_some() { "Glue A" } else { "A" };
                    let ttl_str = step
                        .got
                        .ttl
                        .map(|t| format!(" (TTL={t})"))
                        .unwrap_or_default();
                    println!("\x1b[2m{indent}{label}: {}{ttl_str}\x1b[0m", a.join(", "));
                }
                if let Some(ref aaaa) = step.got.aaaa
                    && !aaaa.is_empty()
                {
                    let label = if step.got.ns.is_some() {
                        "Glue AAAA"
                    } else {
                        "AAAA"
                    };
                    println!("\x1b[2m{indent}{label}: {}\x1b[0m", aaaa.join(", "));
                }
                if let Some(ref cname) = step.got.cname {
                    println!("\x1b[2m{indent}CNAME: {cname}\x1b[0m");
                }
                if let Some(ref error) = step.got.error {
                    println!("\x1b[31m{indent}Error: {error}\x1b[0m");
                }
            }
        }

        // All records summary (beyond A/AAAA already shown as IPs)
        let records = &flow.response.all_records;
        let detail = format::format_all_records_struct(records, "                  ");
        if !detail.is_empty() {
            println!("\x1b[2m{detail}\x1b[0m");
        }
    }
}
