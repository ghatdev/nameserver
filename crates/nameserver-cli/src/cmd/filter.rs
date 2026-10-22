use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::cmd::apply;
use crate::cmd::format::format_epoch;
use crate::output;

#[derive(Args)]
pub struct FilterArgs {
    #[command(subcommand)]
    action: FilterAction,
}

#[derive(Subcommand)]
enum FilterAction {
    /// List all compiled filters
    List,
    /// Show filter details
    Show {
        /// Filter slug
        slug: String,
    },
    /// Create a new filter (links a source to a compiled output)
    Create {
        /// Filter slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        slug: String,
        /// Display name
        #[arg(long)]
        name: String,
        /// Source slug (indicator source to compile from)
        #[arg(long)]
        source: String,
        /// Filter type: block or allow
        #[arg(long, name = "type", default_value = "block")]
        filter_type: String,
        /// Output format: xor, fst, or ipf
        #[arg(long, default_value = "xor")]
        format: String,
    },
    /// Delete a filter
    Delete {
        /// Filter slug
        slug: String,
    },
    /// Check if a domain appears in any threat feed
    Check {
        /// Domain to check
        domain: String,
    },
    /// Compile all filters and publish
    Compile,
    /// Show pending filter changes (desired DB state vs deployed NATS state)
    Diff,
    /// Compile and publish changed filters to DNS servers
    Apply {
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
}

pub async fn run(api: &Client, args: FilterArgs) -> Result<()> {
    match args.action {
        FilterAction::List => list(api).await,
        FilterAction::Show { slug } => show(api, &slug).await,
        FilterAction::Create {
            slug,
            name,
            source,
            filter_type,
            format,
        } => create(api, &slug, &name, &source, &filter_type, &format).await,
        FilterAction::Delete { slug } => delete(api, &slug).await,
        FilterAction::Check { domain } => check(api, &domain).await,
        FilterAction::Compile => compile(api).await,
        FilterAction::Diff => apply::scoped_diff(api, "filters").await,
        FilterAction::Apply { yes } => {
            apply::scoped_apply(api, "/api/filters/apply", "filters", yes).await
        }
    }
}

async fn list(api: &Client) -> Result<()> {
    let data = api.get_json("/api/filters").await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let empty = vec![];
    let filters = data["filters"].as_array().unwrap_or(&empty);

    if filters.is_empty() {
        println!("No filters found.");
        return Ok(());
    }

    println!(
        "{:<24} {:<6} {:<6} {:<20} {:>8}  COMPILED",
        "SLUG", "TYPE", "FMT", "SOURCE", "ENTRIES"
    );
    println!("{}", "-".repeat(80));
    for f in filters {
        let slug = f["slug"].as_str().unwrap_or("?");
        let ft = f["filter_type"].as_str().unwrap_or("?");
        let fmt = f["output_format"].as_str().unwrap_or("?");
        let source = f["source_slug"].as_str().unwrap_or("?");
        let count = f["compiled_entry_count"]
            .as_i64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string());
        let compiled = format_epoch(
            f["compiled_at"]
                .as_str()
                .and_then(|s| {
                    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .map(|dt| dt.unix_timestamp()),
        );
        println!(
            "{:<24} {:<6} {:<6} {:<20} {:>8}  {}",
            slug, ft, fmt, source, count, compiled
        );
    }

    Ok(())
}

async fn show(api: &Client, slug: &str) -> Result<()> {
    let data = api.get_json(&format!("/api/filters/{slug}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let name = data["display_name"].as_str().unwrap_or("-");
    let ft = data["filter_type"].as_str().unwrap_or("-");
    let fmt = data["output_format"].as_str().unwrap_or("-");
    let source = data["source_slug"].as_str().unwrap_or("-");
    let count = data["compiled_entry_count"]
        .as_i64()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".to_string());

    println!("Filter: {slug}");
    println!("  Name:       {name}");
    println!("  Type:       {ft}");
    println!("  Format:     {fmt}");
    println!("  Source:     {source}");
    println!("  Entries:    {count}");

    if let Some(checksum) = data["compiled_checksum"].as_str() {
        println!("  Checksum:   {}...", &checksum[..16.min(checksum.len())]);
    }

    let compiled = format_epoch(
        data["compiled_at"]
            .as_str()
            .and_then(|s| {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|dt| dt.unix_timestamp()),
    );
    println!("  Compiled:   {compiled}");

    Ok(())
}

async fn create(
    api: &Client,
    slug: &str,
    name: &str,
    source_slug: &str,
    filter_type: &str,
    output_format: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "slug": slug,
        "display_name": name,
        "source_slug": source_slug,
        "filter_type": filter_type,
        "output_format": output_format,
    });
    let data = api.post_json("/api/filters", &body).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Created filter '{slug}' (source: {source_slug})");
    Ok(())
}

async fn delete(api: &Client, slug: &str) -> Result<()> {
    let data = api.delete(&format!("/api/filters/{slug}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    if let Some(affected) = data["affected_profiles"].as_array()
        && !affected.is_empty()
    {
        let ids: Vec<&str> = affected.iter().filter_map(|v| v.as_str()).collect();
        println!("Warning: removed from profiles: {}", ids.join(", "));
    }
    println!("Deleted filter '{slug}'");
    Ok(())
}

async fn check(api: &Client, domain: &str) -> Result<()> {
    let resp = api
        .get_json(&format!("/api/threat-feed/check/{domain}"))
        .await?;
    if output::maybe_json(&resp) {
        return Ok(());
    }

    let in_feed = resp["in_threat_feed"].as_bool().unwrap_or(false);
    if in_feed {
        let sources = resp["sources"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        println!("{domain}: IN threat feed ({sources})");
    } else {
        println!("{domain}: not in any threat feed");
    }
    Ok(())
}

async fn compile(api: &Client) -> Result<()> {
    let resp = api.post_empty("/api/filters/compile").await?;
    if output::maybe_json(&resp) {
        return Ok(());
    }
    let published = resp["published"].as_u64().unwrap_or(0);
    println!("Compiled and published {published} filter(s)");
    Ok(())
}
