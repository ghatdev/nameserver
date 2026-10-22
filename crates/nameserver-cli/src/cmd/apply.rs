use anyhow::Result;

use crate::client::Client;
use crate::output;

// ---------------------------------------------------------------------------
// Per-section diff printers
// ---------------------------------------------------------------------------

pub fn print_filter_diff(data: &serde_json::Value) {
    let filters = &data["filters"];

    if let Some(added) = filters["added"].as_array() {
        for f in added {
            let name = f["name"].as_str().unwrap_or("?");
            let entries = f["desired_entries"].as_u64().unwrap_or(0);
            let kind = f["kind"].as_str().unwrap_or("?");
            eprintln!("  + filter/{name} ({kind}, {entries} entries)");
        }
    }
    if let Some(changed) = filters["changed"].as_array() {
        for f in changed {
            let name = f["name"].as_str().unwrap_or("?");
            let desired = f["desired_entries"].as_u64().unwrap_or(0);
            let actual = f["actual_entries"].as_u64().unwrap_or(0);
            eprintln!("  ~ filter/{name} ({actual} -> {desired} entries)");
        }
    }
    if let Some(removed) = filters["removed"].as_array() {
        for f in removed {
            let name = f["name"].as_str().unwrap_or("?");
            eprintln!("  - filter/{name}");
        }
    }
}

pub fn print_profile_diff(data: &serde_json::Value) {
    let profiles = &data["profiles"];

    if let Some(added) = profiles["added"].as_array() {
        for p in added {
            let id = p["id"].as_str().unwrap_or("?");
            let name = p["desired"]["display_name"].as_str().unwrap_or("");
            let label = if name.is_empty() {
                id.to_string()
            } else {
                format!("{id} ({name})")
            };
            eprintln!("  + profile/{label}");
            print_profile_detail("    ", &p["desired"]);
        }
    }
    if let Some(changed) = profiles["changed"].as_array() {
        for p in changed {
            let id = p["id"].as_str().unwrap_or("?");
            let name = p["desired"]["display_name"].as_str().unwrap_or("");
            let label = if name.is_empty() {
                id.to_string()
            } else {
                format!("{id} ({name})")
            };
            eprintln!("  ~ profile/{label}");
            print_profile_changes(&p["actual"], &p["desired"]);
        }
    }
    if let Some(removed) = profiles["removed"].as_array() {
        for p in removed {
            let id = p["id"].as_str().unwrap_or("?");
            eprintln!("  - profile/{id}");
        }
    }
}

fn print_profile_detail(indent: &str, detail: &serde_json::Value) {
    if detail.is_null() {
        return;
    }
    let mode = detail["block_mode"].as_str().unwrap_or("?");
    eprintln!("{indent}block_mode: {mode}");
    if let Some(filters) = detail["filter_names"].as_array() {
        let names: Vec<&str> = filters.iter().filter_map(|v| v.as_str()).collect();
        if !names.is_empty() {
            eprintln!("{indent}filters: {}", names.join(", "));
        }
    }
}

fn print_profile_changes(actual: &serde_json::Value, desired: &serde_json::Value) {
    if actual.is_null() || desired.is_null() {
        // Can't compare — just show desired
        print_profile_detail("    ", desired);
        return;
    }

    // Block mode
    let act_mode = actual["block_mode"].as_str().unwrap_or("");
    let des_mode = desired["block_mode"].as_str().unwrap_or("");
    if act_mode != des_mode {
        eprintln!("    block_mode: {act_mode} -> {des_mode}");
    }

    // Filters
    let act_filters: Vec<&str> = actual["filter_names"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let des_filters: Vec<&str> = desired["filter_names"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let added: Vec<&&str> = des_filters
        .iter()
        .filter(|f| !act_filters.contains(f))
        .collect();
    let removed: Vec<&&str> = act_filters
        .iter()
        .filter(|f| !des_filters.contains(f))
        .collect();

    if !added.is_empty() || !removed.is_empty() {
        for f in &added {
            eprintln!("    + filter {}", f);
        }
        for f in &removed {
            eprintln!("    - filter {}", f);
        }
    } else if act_filters != des_filters {
        eprintln!("    filters: {}", des_filters.join(", "));
    }

    // Custom lists
    let act_cb = actual["has_custom_blocklist"].as_bool().unwrap_or(false);
    let des_cb = desired["has_custom_blocklist"].as_bool().unwrap_or(false);
    let act_ca = actual["has_custom_allowlist"].as_bool().unwrap_or(false);
    let des_ca = desired["has_custom_allowlist"].as_bool().unwrap_or(false);
    if act_cb != des_cb {
        let state = if des_cb { "added" } else { "removed" };
        eprintln!("    custom blocklist: {state}");
    }
    if act_ca != des_ca {
        let state = if des_ca { "added" } else { "removed" };
        eprintln!("    custom allowlist: {state}");
    }
}

pub fn print_geoip_diff(data: &serde_json::Value) {
    let geoip = &data["geoip"];
    let geo_status = geoip["status"].as_str().unwrap_or("no_data");
    let geo_entries = geoip["desired_entries"].as_u64().unwrap_or(0);
    match geo_status {
        "changed" => eprintln!("  ~ geoip ({geo_entries} entries, recompile needed)"),
        "not_published" => eprintln!("  + geoip ({geo_entries} entries, not yet published)"),
        "unchanged" => eprintln!("  = geoip ({geo_entries} entries)"),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Shared scoped diff / apply
// ---------------------------------------------------------------------------

/// Fetch the per-resource diff and display it.
/// `section` is the resource key in the diff response: "filters", "profiles", "geoip".
pub async fn scoped_diff(client: &Client, section: &str) -> Result<()> {
    let url = match section {
        "filters" => "/api/filters/diff",
        "profiles" => "/api/profiles/diff",
        "geoip" => "/api/geoip/diff",
        _ => anyhow::bail!("unknown section: {section}"),
    };

    let data = client.get_json(url).await?;

    if output::maybe_json(&data) {
        return Ok(());
    }

    match section {
        "filters" => print_filter_diff(&data),
        "profiles" => print_profile_diff(&data),
        "geoip" => print_geoip_diff(&data),
        _ => {}
    }

    let has_changes = data["has_changes"].as_bool().unwrap_or(false);
    if !has_changes {
        eprintln!("  (no changes)");
    }

    Ok(())
}

/// Apply a scoped resource change with confirmation.
pub async fn scoped_apply(
    client: &Client,
    apply_url: &str,
    section: &str,
    yes: bool,
) -> Result<()> {
    // Show diff first.
    let diff_url = match section {
        "filters" => "/api/filters/diff",
        "profiles" => "/api/profiles/diff",
        "geoip" => "/api/geoip/diff",
        _ => anyhow::bail!("unknown section: {section}"),
    };

    let diff_data = client.get_json(diff_url).await?;
    let has_changes = diff_data["has_changes"].as_bool().unwrap_or(false);
    if !has_changes {
        eprintln!("No changes to apply.");
        return Ok(());
    }

    match section {
        "filters" => print_filter_diff(&diff_data),
        "profiles" => print_profile_diff(&diff_data),
        "geoip" => print_geoip_diff(&diff_data),
        _ => {}
    }

    // Confirm unless --yes.
    if !yes {
        eprint!("\nApply these changes? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    // Apply.
    let result = client.post_empty(apply_url).await?;

    if output::maybe_json(&result) {
        return Ok(());
    }

    if result["status"] == "no_changes" {
        eprintln!("No changes to apply.");
    } else {
        eprintln!("Applied.");
    }

    Ok(())
}
