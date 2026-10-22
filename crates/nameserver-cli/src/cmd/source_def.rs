//! TOML-based declarative source management.
//!
//! Parses a `sources.toml` file and reconciles it against the control plane
//! API via `nameserver source diff` / `nameserver source apply`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::client::Client;

/// Top-level TOML structure: `[source.<slug>]`.
#[derive(Debug, Deserialize)]
pub struct SourcesFile {
    #[serde(rename = "source")]
    pub sources: BTreeMap<String, SourceDef>,
}

/// A single source definition from TOML.
#[derive(Debug, Deserialize, Serialize)]
pub struct SourceDef {
    pub url: String,
    pub indicator_type: String,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_parse_config")]
    pub parse_config: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub fetch_config: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub validate_config: serde_json::Value,
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: i64,
    #[serde(default)]
    pub filter: Option<FilterDef>,
    #[serde(default)]
    pub enrichment_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FilterDef {
    /// Defaults to source slug when omitted.
    #[serde(default)]
    pub slug: Option<String>,
    pub display_name: String,
    #[serde(default = "default_filter_type")]
    pub filter_type: String,
    #[serde(default = "default_output_format")]
    pub output_format: String,
}

fn default_parse_config() -> serde_json::Value {
    serde_json::json!({"type": "lines"})
}
fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}
fn default_refresh() -> i64 {
    86400
}
fn default_filter_type() -> String {
    "block".to_string()
}
fn default_output_format() -> String {
    "xor".to_string()
}

/// Validate a source slug (same rules as server-side).
fn validate_slug(slug: &str) -> Result<()> {
    anyhow::ensure!(
        !slug.is_empty() && slug.len() <= 64,
        "slug '{slug}' must be 1-64 characters"
    );
    anyhow::ensure!(
        slug.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'),
        "slug '{slug}' must be lowercase alphanumeric, hyphens, or underscores"
    );
    Ok(())
}

/// Load and parse a sources TOML file.
pub fn load(path: &Path) -> Result<SourcesFile> {
    // Canonicalize to resolve symlinks and relative components (defense-in-depth).
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve path {}", path.display()))?;
    let text = std::fs::read_to_string(&canonical) // nosemgrep
        .with_context(|| format!("failed to read {}", canonical.display()))?;
    let file: SourcesFile =
        toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?;
    // Validate all slugs before returning.
    for slug in file.sources.keys() {
        validate_slug(slug).with_context(|| "invalid source slug in TOML".to_string())?;
    }
    Ok(file)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

pub struct SourcesDiff {
    pub to_create: Vec<String>,
    pub to_update: Vec<(String, Vec<FieldChange>)>,
    pub orphaned: Vec<String>,
    pub unchanged: Vec<String>,
}

pub struct FieldChange {
    pub field: String,
    pub old: String,
    pub new: String,
}

/// Compute diff between desired (TOML) and actual (API response).
pub fn compute_diff(desired: &SourcesFile, actual: &[serde_json::Value]) -> SourcesDiff {
    let actual_map: BTreeMap<String, &serde_json::Value> = actual
        .iter()
        .filter_map(|s| s["slug"].as_str().map(|slug| (slug.to_string(), s)))
        .collect();

    let mut to_create = Vec::new();
    let mut to_update = Vec::new();
    let mut unchanged = Vec::new();

    for (slug, def) in &desired.sources {
        if let Some(actual_src) = actual_map.get(slug) {
            let changes = diff_source(slug, def, actual_src);
            if changes.is_empty() {
                unchanged.push(slug.clone());
            } else {
                to_update.push((slug.clone(), changes));
            }
        } else {
            to_create.push(slug.clone());
        }
    }

    let orphaned: Vec<String> = actual_map
        .keys()
        .filter(|slug| !desired.sources.contains_key(*slug))
        .cloned()
        .collect();

    SourcesDiff {
        to_create,
        to_update,
        orphaned,
        unchanged,
    }
}

fn diff_source(slug: &str, def: &SourceDef, actual: &serde_json::Value) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    // Compare simple fields.
    diff_str(
        &mut changes,
        "url",
        &def.url,
        actual["url"].as_str().unwrap_or(""),
    );
    diff_str(
        &mut changes,
        "indicator_type",
        &def.indicator_type,
        actual["indicator_type"].as_str().unwrap_or(""),
    );
    diff_i64(
        &mut changes,
        "refresh_interval_secs",
        def.refresh_interval_secs,
        actual["refresh_interval_secs"].as_i64().unwrap_or(0),
    );

    // Compare categories (sorted).
    let mut desired_cats = def.categories.clone();
    desired_cats.sort();
    let mut actual_cats: Vec<String> = actual["categories"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    actual_cats.sort();
    if desired_cats != actual_cats {
        changes.push(FieldChange {
            field: "categories".into(),
            old: actual_cats.join(","),
            new: desired_cats.join(","),
        });
    }

    // Compare JSON configs.
    diff_json(
        &mut changes,
        "parse_config",
        &def.parse_config,
        &actual["parse_config"],
    );
    diff_json(
        &mut changes,
        "fetch_config",
        &def.fetch_config,
        &actual["fetch_config"],
    );
    diff_json(
        &mut changes,
        "validate_config",
        &def.validate_config,
        &actual["validate_config"],
    );

    // Compare filter.
    let actual_filter = &actual["filter"];
    match (
        &def.filter,
        actual_filter.is_null() || actual_filter.is_object() && actual_filter.as_object().is_none(),
    ) {
        (Some(f), true) => {
            // Desired has filter, actual doesn't.
            changes.push(FieldChange {
                field: "filter".into(),
                old: "(none)".into(),
                new: f.slug.as_deref().unwrap_or(slug).to_string(),
            });
        }
        (None, false) if !actual_filter.is_null() => {
            changes.push(FieldChange {
                field: "filter".into(),
                old: actual_filter["slug"].as_str().unwrap_or("?").into(),
                new: "(none)".into(),
            });
        }
        (Some(f), false) if !actual_filter.is_null() => {
            let filter_slug = f.slug.as_deref().unwrap_or(slug);
            diff_str(
                &mut changes,
                "filter.display_name",
                &f.display_name,
                actual_filter["display_name"].as_str().unwrap_or(""),
            );
            diff_str(
                &mut changes,
                "filter.filter_type",
                &f.filter_type,
                actual_filter["filter_type"].as_str().unwrap_or(""),
            );
            diff_str(
                &mut changes,
                "filter.output_format",
                &f.output_format,
                actual_filter["output_format"].as_str().unwrap_or(""),
            );
            let actual_slug = actual_filter["slug"].as_str().unwrap_or("");
            if filter_slug != actual_slug {
                diff_str(&mut changes, "filter.slug", filter_slug, actual_slug);
            }
        }
        _ => {}
    }

    // Compare enrichment.
    let actual_enrichment = actual["enrichment_type"].as_str();
    match (&def.enrichment_type, actual_enrichment) {
        (Some(desired), Some(actual)) if desired != actual => {
            changes.push(FieldChange {
                field: "enrichment_type".into(),
                old: actual.into(),
                new: desired.clone(),
            });
        }
        (Some(desired), None) => {
            changes.push(FieldChange {
                field: "enrichment_type".into(),
                old: "(none)".into(),
                new: desired.clone(),
            });
        }
        (None, Some(actual)) => {
            changes.push(FieldChange {
                field: "enrichment_type".into(),
                old: actual.into(),
                new: "(none)".into(),
            });
        }
        _ => {}
    }

    changes
}

fn diff_str(changes: &mut Vec<FieldChange>, field: &str, desired: &str, actual: &str) {
    if desired != actual {
        changes.push(FieldChange {
            field: field.into(),
            old: actual.into(),
            new: desired.into(),
        });
    }
}

fn diff_i64(changes: &mut Vec<FieldChange>, field: &str, desired: i64, actual: i64) {
    if desired != actual {
        changes.push(FieldChange {
            field: field.into(),
            old: actual.to_string(),
            new: desired.to_string(),
        });
    }
}

fn diff_json(
    changes: &mut Vec<FieldChange>,
    field: &str,
    desired: &serde_json::Value,
    actual: &serde_json::Value,
) {
    // Normalize: treat null/missing as empty object for comparison.
    let d = if desired.is_null() {
        &serde_json::Value::Object(serde_json::Map::new())
    } else {
        desired
    };
    let a = if actual.is_null() {
        &serde_json::Value::Object(serde_json::Map::new())
    } else {
        actual
    };
    if d != a {
        changes.push(FieldChange {
            field: field.into(),
            old: serde_json::to_string(a).unwrap_or_default(),
            new: serde_json::to_string(d).unwrap_or_default(),
        });
    }
}

// ---------------------------------------------------------------------------
// Print
// ---------------------------------------------------------------------------

pub fn print_diff(diff: &SourcesDiff, desired: &SourcesFile) {
    for slug in &diff.to_create {
        let def = &desired.sources[slug];
        println!("+ source/{slug}");
        println!(
            "    type: {}, categories: {:?}",
            def.indicator_type, def.categories
        );
        if let Some(ref f) = def.filter {
            let fslug = f.slug.as_deref().unwrap_or(slug);
            println!(
                "    + filter: {fslug} ({}, {})",
                f.filter_type, f.output_format
            );
        }
        if let Some(ref e) = def.enrichment_type {
            println!("    + enrichment: {e}");
        }
    }

    for (slug, changes) in &diff.to_update {
        println!("~ source/{slug}");
        for c in changes {
            println!("    {}: {} -> {}", c.field, c.old, c.new);
        }
    }

    if !diff.orphaned.is_empty() {
        println!();
        for slug in &diff.orphaned {
            println!("? source/{slug} (in DB, not in TOML — use --prune to remove)");
        }
    }

    println!();
    let total = diff.to_create.len() + diff.to_update.len();
    if total == 0 && diff.orphaned.is_empty() {
        println!("All {} sources up to date.", diff.unchanged.len());
    } else {
        println!(
            "{} to create, {} to update, {} unchanged, {} orphaned",
            diff.to_create.len(),
            diff.to_update.len(),
            diff.unchanged.len(),
            diff.orphaned.len(),
        );
    }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

/// Build the JSON body for PUT /api/sources/{slug}/full from a SourceDef.
pub fn to_api_body(slug: &str, def: &SourceDef) -> serde_json::Value {
    let filter = def.filter.as_ref().map(|f| {
        serde_json::json!({
            "slug": f.slug.as_deref().unwrap_or(slug),
            "display_name": f.display_name,
            "filter_type": f.filter_type,
            "output_format": f.output_format,
        })
    });

    serde_json::json!({
        "url": def.url,
        "indicator_type": def.indicator_type,
        "categories": def.categories,
        "parse_config": def.parse_config,
        "fetch_config": def.fetch_config,
        "validate_config": def.validate_config,
        "refresh_interval_secs": def.refresh_interval_secs,
        "filter": filter,
        "enrichment_type": def.enrichment_type,
    })
}

pub async fn apply(
    api: &Client,
    diff: &SourcesDiff,
    desired: &SourcesFile,
    prune: bool,
) -> Result<()> {
    // Create new sources.
    for slug in &diff.to_create {
        let def = &desired.sources[slug];
        let body = to_api_body(slug, def);
        api.put_json(&format!("/api/sources/{slug}/full"), &body)
            .await?;
        println!("  + {slug}");
    }

    // Update changed sources.
    for (slug, _changes) in &diff.to_update {
        let def = &desired.sources[slug];
        let body = to_api_body(slug, def);
        api.put_json(&format!("/api/sources/{slug}/full"), &body)
            .await?;
        println!("  ~ {slug}");
    }

    // Prune orphaned sources.
    if prune {
        for slug in &diff.orphaned {
            api.delete(&format!("/api/sources/{slug}")).await?;
            println!("  - {slug}");
        }
    }

    let total =
        diff.to_create.len() + diff.to_update.len() + if prune { diff.orphaned.len() } else { 0 };
    if total == 0 {
        println!("Nothing to apply.");
    } else {
        println!("Applied {total} changes.");
    }

    Ok(())
}
