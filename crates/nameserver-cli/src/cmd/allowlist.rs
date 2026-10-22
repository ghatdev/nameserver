use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::output;

#[derive(Args)]
pub struct AllowlistArgs {
    #[command(subcommand)]
    pub action: AllowlistAction,
}

#[derive(Subcommand)]
pub enum AllowlistAction {
    /// Show all allowlist entries
    Show,
    /// Add a domain to the allowlist
    Add {
        /// Domain to allow
        domain: String,
    },
    /// Remove a domain from the allowlist
    Remove {
        /// Domain to remove
        domain: String,
    },
}

pub async fn run(api: &Client, args: AllowlistArgs) -> Result<()> {
    match args.action {
        AllowlistAction::Show => show(api).await,
        AllowlistAction::Add { domain } => modify(api, "add", &domain).await,
        AllowlistAction::Remove { domain } => modify(api, "remove", &domain).await,
    }
}

async fn show(api: &Client) -> Result<()> {
    let data = api.get_json("/api/lists/allowlist").await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let entries = data["entries"].as_array();
    match entries {
        Some(entries) if !entries.is_empty() => {
            println!("Allowlist ({} entries):", entries.len());
            for entry in entries {
                let domain = entry["domain"].as_str().unwrap_or("?");
                println!("  {domain}");
            }
        }
        _ => println!("Allowlist is empty."),
    }
    Ok(())
}

async fn modify(api: &Client, action: &str, domain: &str) -> Result<()> {
    let body = serde_json::json!({ "action": action, "domain": domain });
    let resp = api.post_json("/api/lists/allowlist", &body).await?;
    if output::maybe_json(&resp) {
        return Ok(());
    }
    println!("{}: {domain}", resp["status"].as_str().unwrap_or("done"));
    Ok(())
}
