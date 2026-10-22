use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::cmd::apply;
use crate::output;

#[derive(Args)]
pub struct ProfilesArgs {
    #[command(subcommand)]
    action: ProfilesAction,
}

#[derive(Subcommand)]
enum ProfilesAction {
    /// List all profiles
    List,
    /// Show profile details (filters + custom entries)
    Show {
        /// Profile ID
        id: String,
    },
    /// Create a new profile (ID is auto-generated)
    Create {
        /// Display name
        #[arg(long)]
        name: String,
        /// Block mode: nxdomain or redirect_ip
        #[arg(long, default_value = "nxdomain")]
        block_mode: String,
        /// Redirect IP (only if block_mode is redirect_ip)
        #[arg(long)]
        redirect_ip: Option<String>,
        /// Filter list IDs to subscribe on creation
        #[arg(long, short = 'f')]
        filter: Vec<String>,
    },
    /// Update a profile
    Update {
        /// Profile ID
        id: String,
        /// New display name
        #[arg(long)]
        name: Option<String>,
        /// New block mode
        #[arg(long)]
        block_mode: Option<String>,
        /// Enable or disable the profile
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a profile
    Delete {
        /// Profile ID
        id: String,
    },
    /// Subscribe a profile to a filter
    Subscribe {
        /// Profile ID
        id: String,
        /// Filter slug (e.g., hagezi-pro-block)
        filter_slug: String,
    },
    /// Unsubscribe a profile from a filter
    Unsubscribe {
        /// Profile ID
        id: String,
        /// Filter slug
        filter_slug: String,
    },
    /// Add a custom allowlist entry
    Allow {
        /// Profile ID
        id: String,
        /// Domain to allow
        domain: String,
    },
    /// Add a custom blocklist entry
    Block {
        /// Profile ID
        id: String,
        /// Domain to block
        domain: String,
    },
    /// Remove a custom entry (allow or block)
    Unblock {
        /// Profile ID
        id: String,
        /// Domain to remove
        domain: String,
    },
    /// Show pending profile changes (desired DB state vs deployed NATS state)
    Diff,
    /// Publish changed profile configs to DNS servers
    Apply {
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
}

pub async fn run(client: &Client, args: ProfilesArgs) -> Result<()> {
    match args.action {
        ProfilesAction::List => list(client).await,
        ProfilesAction::Show { id } => show(client, &id).await,
        ProfilesAction::Create {
            name,
            block_mode,
            redirect_ip,
            filter,
        } => create(client, &name, &block_mode, redirect_ip, &filter).await,
        ProfilesAction::Update {
            id,
            name,
            block_mode,
            enabled,
        } => update(client, &id, name, block_mode, enabled).await,
        ProfilesAction::Delete { id } => delete(client, &id).await,
        ProfilesAction::Subscribe { id, filter_slug } => subscribe(client, &id, &filter_slug).await,
        ProfilesAction::Unsubscribe { id, filter_slug } => {
            unsubscribe(client, &id, &filter_slug).await
        }
        ProfilesAction::Allow { id, domain } => custom(client, &id, &domain, "allowlist").await,
        ProfilesAction::Block { id, domain } => custom(client, &id, &domain, "blocklist").await,
        ProfilesAction::Unblock { id, domain } => remove_custom(client, &id, &domain).await,
        ProfilesAction::Diff => apply::scoped_diff(client, "profiles").await,
        ProfilesAction::Apply { yes } => {
            apply::scoped_apply(client, "/api/profiles/apply", "profiles", yes).await
        }
    }
}

async fn list(client: &Client) -> Result<()> {
    let data = client.get_json("/api/profiles").await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let profiles = data["profiles"].as_array();
    if profiles.is_none_or(|p| p.is_empty()) {
        println!("No profiles found.");
        return Ok(());
    }

    println!(
        "{:<15} {:<20} {:<12} {:<8} DEFAULT",
        "ID", "NAME", "BLOCK MODE", "ENABLED"
    );
    println!("{}", "-".repeat(65));
    for p in profiles.unwrap() {
        let id = p["id"].as_str().unwrap_or("-");
        let name = p["display_name"].as_str().unwrap_or("-");
        let mode = p["block_mode"].as_str().unwrap_or("-");
        let enabled = if p["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let default = if p["is_default"].as_bool().unwrap_or(false) {
            "*"
        } else {
            ""
        };
        println!(
            "{:<15} {:<20} {:<12} {:<8} {}",
            id, name, mode, enabled, default
        );
    }

    Ok(())
}

async fn show(client: &Client, id: &str) -> Result<()> {
    let data = client.get_json(&format!("/api/profiles/{id}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }

    let name = data["display_name"].as_str().unwrap_or("-");
    let mode = data["block_mode"].as_str().unwrap_or("-");
    let enabled = data["enabled"].as_bool().unwrap_or(false);
    let is_default = data["is_default"].as_bool().unwrap_or(false);

    println!("Profile: {id}");
    println!("  Name:       {name}");
    println!("  Block mode: {mode}");
    if let Some(ip) = data["redirect_ip"].as_str() {
        println!("  Redirect:   {ip}");
    }
    println!("  Enabled:    {enabled}");
    if is_default {
        println!("  Default:    yes");
    }

    // Filters.
    if let Some(filters) = data["filters"].as_array() {
        println!();
        if filters.is_empty() {
            println!("  Filters: (none)");
        } else {
            println!("  Filters:");
            for f in filters {
                let fid = f["slug"]
                    .as_str()
                    .or_else(|| f["id"].as_str())
                    .unwrap_or("-");
                let fname = f["display_name"].as_str().unwrap_or("");
                let ftype = f["filter_type"]
                    .as_str()
                    .or_else(|| f["list_type"].as_str())
                    .unwrap_or("");
                println!("    - {fid} ({fname}, {ftype})");
            }
        }
    }

    // Custom entries.
    if let Some(custom) = data.get("custom_entries") {
        let allow = custom["allowlist"].as_array();
        let block = custom["blocklist"].as_array();
        let has_allow = allow.is_some_and(|a| !a.is_empty());
        let has_block = block.is_some_and(|b| !b.is_empty());

        if has_allow || has_block {
            println!();
            println!("  Custom entries:");
            if let Some(domains) = allow {
                for d in domains {
                    if let Some(s) = d.as_str() {
                        println!("    + allow {s}");
                    }
                }
            }
            if let Some(domains) = block {
                for d in domains {
                    if let Some(s) = d.as_str() {
                        println!("    - block {s}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn create(
    client: &Client,
    name: &str,
    block_mode: &str,
    redirect_ip: Option<String>,
    filter_ids: &[String],
) -> Result<()> {
    let body = serde_json::json!({
        "display_name": name,
        "block_mode": block_mode,
        "redirect_ip": redirect_ip,
        "filter_ids": filter_ids,
    });
    let data = client.post_json("/api/profiles", &body).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    let id = data["id"].as_str().unwrap_or("?");
    println!("Created profile '{id}'");
    println!("  Name: {name}");
    println!("  DoH:  https://{{server}}/{id}");
    println!("  DoT:  tls://{id}.{{server}}:853");
    if !filter_ids.is_empty() {
        println!("  Subscribed to: {}", filter_ids.join(", "));
    }
    Ok(())
}

async fn update(
    client: &Client,
    id: &str,
    name: Option<String>,
    block_mode: Option<String>,
    enabled: Option<bool>,
) -> Result<()> {
    let body = serde_json::json!({
        "display_name": name,
        "block_mode": block_mode,
        "enabled": enabled,
    });
    let data = client
        .put_json(&format!("/api/profiles/{id}"), &body)
        .await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Updated profile '{id}'");
    Ok(())
}

async fn delete(client: &Client, id: &str) -> Result<()> {
    let data = client.delete(&format!("/api/profiles/{id}")).await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Deleted profile '{id}'");
    Ok(())
}

async fn subscribe(client: &Client, id: &str, filter_slug: &str) -> Result<()> {
    let body = serde_json::json!({ "filter_slug": filter_slug });
    let data = client
        .post_json(&format!("/api/profiles/{id}/filters"), &body)
        .await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Profile '{id}' subscribed to '{filter_slug}'");
    Ok(())
}

async fn unsubscribe(client: &Client, id: &str, filter_slug: &str) -> Result<()> {
    let data = client
        .delete(&format!("/api/profiles/{id}/filters/{filter_slug}"))
        .await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Profile '{id}' unsubscribed from '{filter_slug}'");
    Ok(())
}

async fn custom(client: &Client, id: &str, domain: &str, list_type: &str) -> Result<()> {
    let body = serde_json::json!({ "domain": domain, "list_type": list_type });
    let data = client
        .post_json(&format!("/api/profiles/{id}/custom"), &body)
        .await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Added {list_type} entry '{domain}' to profile '{id}'");
    Ok(())
}

async fn remove_custom(client: &Client, id: &str, domain: &str) -> Result<()> {
    let data = client
        .delete(&format!("/api/profiles/{id}/custom/{domain}"))
        .await?;
    if output::maybe_json(&data) {
        return Ok(());
    }
    println!("Removed custom entry '{domain}' from profile '{id}'");
    Ok(())
}
