use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::cmd::format::format_epoch;
use crate::cmd::source_def;
use crate::output;

#[derive(Args)]
pub struct SourceArgs {
    #[command(subcommand)]
    action: SourceAction,
}

#[derive(Subcommand)]
enum SourceAction {
    /// List all indicator sources
    List {
        /// Filter by category (e.g., nrd, well_known, threat_feed)
        #[arg(long, short = 'c')]
        category: Option<String>,
    },
    /// Show source details
    Show {
        /// Source slug
        slug: String,
    },
    /// Create a new indicator source
    Create {
        /// Source slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        slug: String,
        /// Source URL
        #[arg(long)]
        url: String,
        /// Indicator type: domain or ip
        #[arg(long, name = "type", default_value = "domain")]
        indicator_type: String,
        /// Categories (comma-separated, e.g., threat_feed,blocklist)
        #[arg(long)]
        categories: Option<String>,
        /// Refresh interval in seconds (default: 86400)
        #[arg(long, default_value = "86400")]
        refresh: i64,
    },
    /// Enable source(s)
    Enable {
        /// Source slug(s) to enable
        slugs: Vec<String>,
    },
    /// Disable source(s)
    Disable {
        /// Source slug(s) to disable
        slugs: Vec<String>,
    },
    /// Pull latest data for a source
    Pull {
        /// Source slug to pull
        slug: String,
    },
    /// Delete an indicator source
    Delete {
        /// Source slug
        slug: String,
    },
    /// Show diff between a TOML definition file and current DB state
    Diff {
        /// Path to sources TOML file
        file: PathBuf,
    },
    /// Reconcile DB to match a TOML definition file
    Apply {
        /// Path to sources TOML file
        file: PathBuf,
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
        /// Remove sources in DB but not in TOML
        #[arg(long)]
        prune: bool,
    },
}

pub async fn run(api: &Client, args: SourceArgs) -> Result<()> {
    match args.action {
        SourceAction::List { category } => list(api, category.as_deref()).await,
        SourceAction::Show { slug } => show(api, &slug).await,
        SourceAction::Create {
            slug,
            url,
            indicator_type,
            categories,
            refresh,
        } => {
            create(
                api,
                &slug,
                &url,
                &indicator_type,
                categories.as_deref(),
                refresh,
            )
            .await
        }
        SourceAction::Enable { slugs } => set_enabled(api, &slugs, true).await,
        SourceAction::Disable { slugs } => set_enabled(api, &slugs, false).await,
        SourceAction::Pull { slug } => pull(api, &slug).await,
        SourceAction::Delete { slug } => delete(api, &slug).await,
        SourceAction::Diff { file } => diff_sources(api, &file).await,
        SourceAction::Apply { file, yes, prune } => apply_sources(api, &file, yes, prune).await,
    }
}

async fn list(api: &Client, category: Option<&str>) -> Result<()> {
    let data = api.get_json("/api/sources").await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let empty = vec![];
    let all_sources = data["sources"].as_array().unwrap_or(&empty);

    let sources: Vec<&serde_json::Value> = if let Some(cat) = category {
        all_sources
            .iter()
            .filter(|s| {
                s["categories"]
                    .as_array()
                    .is_some_and(|cats| cats.iter().any(|c| c.as_str() == Some(cat)))
            })
            .collect()
    } else {
        all_sources.iter().collect()
    };

    if sources.is_empty() {
        let suffix = category.map_or(String::new(), |c| format!(" (category={c})"));
        println!("No sources found{suffix}.");
        return Ok(());
    }

    println!(
        "{:<24} {:<8} {:<7} {:>8}  {:<16} CATEGORIES",
        "SLUG", "TYPE", "ENABLED", "ENTRIES", "LAST PULL"
    );
    println!("{}", "-".repeat(90));
    for s in &sources {
        let slug = s["slug"].as_str().unwrap_or("?");
        let itype = s["indicator_type"].as_str().unwrap_or("?");
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
        let cats = s["categories"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        println!(
            "{:<24} {:<8} {:<7} {:>8}  {:<16} {}",
            slug, itype, enabled, count, last_pull, cats
        );
    }

    Ok(())
}

async fn show(api: &Client, slug: &str) -> Result<()> {
    let data = api.get_json(&format!("/api/sources/{slug}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let itype = data["indicator_type"].as_str().unwrap_or("-");
    let url = data["url"].as_str().unwrap_or("-");
    let enabled = data["enabled"].as_bool().unwrap_or(false);
    let count = data["last_entry_count"]
        .as_i64()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".to_string());
    let refresh = data["refresh_interval_secs"].as_i64().unwrap_or(0);
    let cats = data["categories"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    let last_pull = format_epoch(
        data["last_pull_at"]
            .as_str()
            .and_then(|t| {
                time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|dt| dt.unix_timestamp()),
    );

    println!("Source: {slug}");
    println!("  Type:       {itype}");
    println!("  URL:        {url}");
    println!("  Categories: {cats}");
    println!("  Enabled:    {enabled}");
    println!("  Entries:    {count}");
    println!("  Refresh:    {refresh}s");
    println!("  Last pull:  {last_pull}");

    if let Some(checksum) = data["last_checksum"].as_str() {
        println!("  Checksum:   {}...", &checksum[..16.min(checksum.len())]);
    }

    Ok(())
}

async fn create(
    api: &Client,
    slug: &str,
    url: &str,
    indicator_type: &str,
    categories: Option<&str>,
    refresh: i64,
) -> Result<()> {
    let cats: Vec<&str> = categories
        .map(|c| c.split(',').map(|s| s.trim()).collect())
        .unwrap_or_default();
    let body = serde_json::json!({
        "slug": slug,
        "url": url,
        "indicator_type": indicator_type,
        "categories": cats,
        "refresh_interval_secs": refresh,
    });
    let data = api.post_json("/api/sources", &body).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Created source '{slug}'");
    Ok(())
}

async fn set_enabled(api: &Client, slugs: &[String], enabled: bool) -> Result<()> {
    for slug in slugs {
        let body = serde_json::json!({ "enabled": enabled });
        api.put_json(&format!("/api/sources/{slug}"), &body).await?;
        let state = if enabled { "enabled" } else { "disabled" };
        println!("{slug}: {state}");
    }
    Ok(())
}

async fn pull(api: &Client, slug: &str) -> Result<()> {
    let resp = api.post_empty(&format!("/api/sources/{slug}/pull")).await?;
    if output::maybe_json(&resp) {
        return Ok(());
    }
    if let Some(err) = resp["error"].as_str() {
        println!("{slug}: error — {err}");
    } else if resp["changed"].as_bool() == Some(true) {
        let count = resp["entry_count"].as_u64().unwrap_or(0);
        println!("{slug}: updated ({count} entries)");
    } else {
        println!("{slug}: unchanged");
    }
    Ok(())
}

async fn delete(api: &Client, slug: &str) -> Result<()> {
    let data = api.delete(&format!("/api/sources/{slug}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    if let Some(affected) = data["affected_filters"].as_array()
        && !affected.is_empty()
    {
        let slugs: Vec<&str> = affected.iter().filter_map(|v| v.as_str()).collect();
        println!(
            "Warning: filters using this source will be orphaned: {}",
            slugs.join(", ")
        );
    }
    println!("Deleted source '{slug}'");
    Ok(())
}

async fn diff_sources(api: &Client, file: &std::path::Path) -> Result<()> {
    let desired = source_def::load(file)?;
    let data = api.get_json("/api/sources/full").await?;
    let actual = data["sources"].as_array().cloned().unwrap_or_default();
    let diff = source_def::compute_diff(&desired, &actual);
    source_def::print_diff(&diff, &desired);
    Ok(())
}

async fn apply_sources(api: &Client, file: &std::path::Path, yes: bool, prune: bool) -> Result<()> {
    let desired = source_def::load(file)?;
    let data = api.get_json("/api/sources/full").await?;
    let actual = data["sources"].as_array().cloned().unwrap_or_default();
    let diff = source_def::compute_diff(&desired, &actual);

    let total =
        diff.to_create.len() + diff.to_update.len() + if prune { diff.orphaned.len() } else { 0 };
    if total == 0 {
        println!("All {} sources up to date.", diff.unchanged.len());
        return Ok(());
    }

    source_def::print_diff(&diff, &desired);

    if !yes {
        print!("\nApply these changes? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    source_def::apply(api, &diff, &desired, prune).await?;
    Ok(())
}
