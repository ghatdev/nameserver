use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::cmd::format::format_epoch;
use crate::output;

#[derive(Args)]
pub struct IntelArgs {
    #[command(subcommand)]
    pub action: IntelAction,
}

#[derive(Subcommand)]
pub enum IntelAction {
    /// Overview of all intelligence data
    Status,

    /// NRD (Newly Registered Domains) operations
    Nrd {
        #[command(subcommand)]
        action: NrdAction,
    },

    /// NS reputation operations
    Ns {
        #[command(subcommand)]
        action: NsAction,
    },

    /// Well-known domains operations
    WellKnown {
        #[command(subcommand)]
        action: WellKnownAction,
    },
}

#[derive(Subcommand)]
pub enum NrdAction {
    /// Check if a domain is newly registered
    Check {
        /// Domain to check
        domain: String,
    },
    /// Show NRD source stats
    Status,
    /// Enable NRD source(s)
    Enable {
        /// Source slug(s) to enable
        slugs: Vec<String>,
    },
    /// Disable NRD source(s)
    Disable {
        /// Source slug(s) to disable
        slugs: Vec<String>,
    },
    /// Force pull NRD data
    Pull {
        /// Specific source slug
        slug: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum NsAction {
    /// Show domain_ns_map statistics
    Status,
    /// Import NS data from TSV file
    Import {
        /// Path to TSV file
        file: PathBuf,
        /// Lines per batch
        #[arg(long, default_value = "5000")]
        batch_size: usize,
    },
}

#[derive(Subcommand)]
pub enum WellKnownAction {
    /// Show well-known domain source stats
    Status,
    /// Enable well-known source(s)
    Enable {
        /// Source slug(s) to enable
        slugs: Vec<String>,
    },
    /// Disable well-known source(s)
    Disable {
        /// Source slug(s) to disable
        slugs: Vec<String>,
    },
    /// Force pull well-known data
    Pull {
        /// Specific source slug
        slug: Option<String>,
    },
}

pub async fn run(api: &Client, args: IntelArgs) -> Result<()> {
    match args.action {
        IntelAction::Status => intel_status(api).await,
        IntelAction::Nrd { action } => run_nrd(api, action).await,
        IntelAction::Ns { action } => run_ns(api, action).await,
        IntelAction::WellKnown { action } => run_well_known(api, action).await,
    }
}

/// Get all sources and filter by category.
async fn get_sources_by_category<'a>(
    sources: &'a [serde_json::Value],
    category: &str,
) -> Vec<&'a serde_json::Value> {
    sources
        .iter()
        .filter(|s| {
            s["categories"]
                .as_array()
                .is_some_and(|cats| cats.iter().any(|c| c.as_str() == Some(category)))
        })
        .collect()
}

async fn intel_status(api: &Client) -> Result<()> {
    // NS map stats.
    let ns = api.get_json("/api/ns-map/status").await?;
    println!("NS Reputation (domain_ns_map):");
    println!(
        "  Total entries:       {:>8}",
        ns["total_entries"].as_i64().unwrap_or(0)
    );
    println!(
        "  Unique domains:      {:>8}",
        ns["unique_domains"].as_i64().unwrap_or(0)
    );
    println!(
        "  Stable (obs>=10):    {:>8}",
        ns["stable_entries"].as_i64().unwrap_or(0)
    );

    // Sources by category.
    let data = api.get_json("/api/sources").await?;
    let empty = vec![];
    let sources = data["sources"].as_array().unwrap_or(&empty);

    println!("\nWell-known domains:");
    let wk = get_sources_by_category(sources, "well_known").await;
    if wk.is_empty() {
        println!("  (none)");
    }
    for s in &wk {
        let slug = s["slug"].as_str().unwrap_or("?");
        let enabled = if s["enabled"].as_bool() == Some(true) {
            "on"
        } else {
            "off"
        };
        let count = s["last_entry_count"]
            .as_i64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!("  {slug:<24} {enabled:<4} {count:>8} entries");
    }

    println!("\nNRD:");
    let nrd = get_sources_by_category(sources, "nrd").await;
    if nrd.is_empty() {
        println!("  (none)");
    }
    for s in &nrd {
        let slug = s["slug"].as_str().unwrap_or("?");
        let enabled = if s["enabled"].as_bool() == Some(true) {
            "on"
        } else {
            "off"
        };
        let count = s["last_entry_count"]
            .as_i64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!("  {slug:<24} {enabled:<4} {count:>8} entries");
    }

    Ok(())
}

async fn run_nrd(api: &Client, action: NrdAction) -> Result<()> {
    match action {
        NrdAction::Check { domain } => {
            let resp = api.get_json(&format!("/api/nrd/check/{domain}")).await?;
            if output::maybe_json(&resp) {
                return Ok(());
            }
            let is_nrd = resp["is_nrd"].as_bool().unwrap_or(false);
            if is_nrd {
                let age = resp["nrd_age_days"].as_u64().unwrap_or(0);
                let sources: Vec<&str> = resp["nrd_sources"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                println!(
                    "{domain}: NRD (registered within last {age} days, sources: {})",
                    sources.join(", "),
                );
            } else {
                println!("{domain}: not newly registered");
            }
            Ok(())
        }
        NrdAction::Status => print_sources_by_category(api, "nrd", "NRD sources").await,
        NrdAction::Enable { slugs } => set_source_enabled(api, &slugs, true).await,
        NrdAction::Disable { slugs } => set_source_enabled(api, &slugs, false).await,
        NrdAction::Pull { slug } => pull_sources_by_category(api, "nrd", slug.as_deref()).await,
    }
}

async fn run_ns(api: &Client, action: NsAction) -> Result<()> {
    match action {
        NsAction::Status => {
            let resp = api.get_json("/api/ns-map/status").await?;
            if output::maybe_json(&resp) {
                return Ok(());
            }
            println!("domain_ns_map:");
            println!(
                "  Total entries:       {:>8}",
                resp["total_entries"].as_i64().unwrap_or(0)
            );
            println!(
                "  Unique domains:      {:>8}",
                resp["unique_domains"].as_i64().unwrap_or(0)
            );
            println!(
                "  Stable (obs>=10):    {:>8}",
                resp["stable_entries"].as_i64().unwrap_or(0)
            );
            println!(
                "  Bootstrap (obs=100): {:>8}",
                resp["bootstrap_entries"].as_i64().unwrap_or(0)
            );
            Ok(())
        }
        NsAction::Import { file, batch_size } => {
            let content = std::fs::read_to_string(&file)?;
            import_ns(api, &content, batch_size).await
        }
    }
}

async fn import_ns(api: &Client, content: &str, batch_size: usize) -> Result<()> {
    let lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect();

    let total = lines.len();
    if total == 0 {
        println!("No entries to import.");
        return Ok(());
    }

    println!("Importing {total} NS mappings ...");

    let mut total_imported = 0u64;
    let mut total_skipped = 0u64;

    for (i, chunk) in lines.chunks(batch_size).enumerate() {
        let batch_text = chunk.join("\n");
        let resp = api.post_text("/api/ns-map/import", batch_text).await?;

        let imported = resp["imported"].as_u64().unwrap_or(0);
        let skipped = resp["skipped"].as_u64().unwrap_or(0);
        total_imported += imported;
        total_skipped += skipped;

        let progress = ((i + 1) * batch_size).min(total);
        println!(
            "  {progress}/{total} sent (imported: {total_imported}, skipped: {total_skipped})"
        );
    }

    println!("\nDone: {total_imported} imported, {total_skipped} skipped");
    Ok(())
}

async fn run_well_known(api: &Client, action: WellKnownAction) -> Result<()> {
    match action {
        WellKnownAction::Status => {
            print_sources_by_category(api, "well_known", "Well-known domain sources").await
        }
        WellKnownAction::Enable { slugs } => set_source_enabled(api, &slugs, true).await,
        WellKnownAction::Disable { slugs } => set_source_enabled(api, &slugs, false).await,
        WellKnownAction::Pull { slug } => {
            pull_sources_by_category(api, "well_known", slug.as_deref()).await
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for source-based intel commands
// ---------------------------------------------------------------------------

async fn print_sources_by_category(api: &Client, category: &str, title: &str) -> Result<()> {
    let data = api.get_json("/api/sources").await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    let empty = vec![];
    let sources = data["sources"].as_array().unwrap_or(&empty);
    let filtered = get_sources_by_category(sources, category).await;

    println!("{title}:");
    println!(
        "  {:<24} {:<7} {:>8}  {:<16}",
        "SLUG", "ENABLED", "ENTRIES", "LAST PULL"
    );
    println!("  {}", "-".repeat(60));

    if filtered.is_empty() {
        println!("  (none)");
        return Ok(());
    }

    for s in &filtered {
        let slug = s["slug"].as_str().unwrap_or("?");
        let enabled = if s["enabled"].as_bool() == Some(true) {
            "yes"
        } else {
            "no"
        };
        let count = s["last_entry_count"]
            .as_i64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string());
        let last_pull = format_epoch(
            s["last_pull_at"]
                .as_str()
                .and_then(|t| {
                    time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .map(|dt| dt.unix_timestamp()),
        );
        println!(
            "  {:<24} {:<7} {:>8}  {:<16}",
            slug, enabled, count, last_pull
        );
    }

    Ok(())
}

async fn set_source_enabled(api: &Client, slugs: &[String], enabled: bool) -> Result<()> {
    for slug in slugs {
        let body = serde_json::json!({ "enabled": enabled });
        api.put_json(&format!("/api/sources/{slug}"), &body).await?;
        let state = if enabled { "enabled" } else { "disabled" };
        println!("{slug}: {state}");
    }
    Ok(())
}

async fn pull_sources_by_category(api: &Client, category: &str, slug: Option<&str>) -> Result<()> {
    if let Some(slug) = slug {
        let resp = api.post_empty(&format!("/api/sources/{slug}/pull")).await?;
        print_pull_result(slug, &resp);
    } else {
        // Pull all enabled sources in this category.
        let data = api.get_json("/api/sources").await?;
        let empty = vec![];
        let sources = data["sources"].as_array().unwrap_or(&empty);
        let filtered = get_sources_by_category(sources, category).await;
        for s in filtered {
            if s["enabled"].as_bool() != Some(true) {
                continue;
            }
            let slug = s["slug"].as_str().unwrap_or("?");
            let resp = api.post_empty(&format!("/api/sources/{slug}/pull")).await?;
            print_pull_result(slug, &resp);
        }
    }
    Ok(())
}

fn print_pull_result(slug: &str, resp: &serde_json::Value) {
    if let Some(err) = resp["error"].as_str() {
        println!("{slug}: error — {err}");
    } else if resp["changed"].as_bool() == Some(true) {
        let count = resp["entry_count"].as_u64().unwrap_or(0);
        println!("{slug}: updated ({count} entries)");
    } else {
        println!("{slug}: unchanged");
    }
}
