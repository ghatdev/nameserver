use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use tracing::info;

use nameserver_common::types::enums::{EnrichmentType, FilterType, IndicatorType, OutputFormat};

use super::AppState;

/// GET /api/sources — list all indicator sources.
pub async fn list_sources(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;
    let rows = sqlx::query!(
        r#"SELECT id, slug, indicator_type as "indicator_type: IndicatorType", url, categories,
                refresh_interval_secs, enabled, last_pull_at, last_checksum, last_entry_count,
                created_at, updated_at
         FROM sources ORDER BY slug"#,
    )
    .fetch_all(pool)
    .await;

    match rows {
        Ok(rows) => {
            let sources: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.id.to_string(),
                        "slug": row.slug,
                        "indicator_type": row.indicator_type,
                        "url": row.url,
                        "categories": row.categories,
                        "refresh_interval_secs": row.refresh_interval_secs,
                        "enabled": row.enabled,
                        "last_pull_at": super::rfc3339(row.last_pull_at),
                        "last_entry_count": row.last_entry_count,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "sources": sources })),
            )
                .into_response()
        }
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// GET /api/sources/{slug} — get source details.
pub async fn get_source(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let row = sqlx::query!(
        r#"SELECT id, slug, indicator_type as "indicator_type: IndicatorType", url, categories,
                fetch_config, parse_config, validate_config,
                refresh_interval_secs, enabled, last_pull_at, last_checksum, last_entry_count,
                created_at, updated_at
         FROM sources WHERE slug = $1"#,
        slug,
    )
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some(row)) => {
            let source = serde_json::json!({
                "id": row.id.to_string(),
                "slug": row.slug,
                "indicator_type": row.indicator_type,
                "url": row.url,
                "categories": row.categories,
                "fetch_config": row.fetch_config,
                "parse_config": row.parse_config,
                "validate_config": row.validate_config,
                "refresh_interval_secs": row.refresh_interval_secs,
                "enabled": row.enabled,
                "last_pull_at": super::rfc3339(row.last_pull_at),
                "last_checksum": row.last_checksum,
                "last_entry_count": row.last_entry_count,
            });
            (StatusCode::OK, Json(source)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "source not found" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateSourceBody {
    pub slug: String,
    pub url: String,
    pub indicator_type: IndicatorType,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_empty_object")]
    pub fetch_config: serde_json::Value,
    #[serde(default = "default_parse_config")]
    pub parse_config: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub validate_config: serde_json::Value,
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: i64,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

fn default_parse_config() -> serde_json::Value {
    serde_json::json!({"type": "lines"})
}

fn default_refresh() -> i64 {
    86400
}

/// POST /api/sources — create a new indicator source.
pub async fn create_source(
    State(state): State<AppState>,
    Json(body): Json<CreateSourceBody>,
) -> impl IntoResponse {
    if let Err(e) = validate_slug(&body.slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    // Validate parse_config is valid.
    if serde_json::from_value::<nameserver_common::parse_config::ParseConfig>(
        body.parse_config.clone(),
    )
    .is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid parse_config" })),
        )
            .into_response();
    }

    let pool = &state.db.pool;
    let result = sqlx::query!(
        "INSERT INTO sources (slug, url, indicator_type, categories, fetch_config, parse_config, validate_config, refresh_interval_secs)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (slug) DO NOTHING",
        body.slug,
        body.url,
        body.indicator_type as IndicatorType,
        &body.categories,
        body.fetch_config,
        body.parse_config,
        body.validate_config,
        body.refresh_interval_secs as i32,
    )
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(slug = %body.slug, "indicator source created");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "status": "created", "slug": body.slug })),
            )
                .into_response()
        }
        Ok(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "source already exists" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateSourceBody {
    pub url: Option<String>,
    pub categories: Option<Vec<String>>,
    pub fetch_config: Option<serde_json::Value>,
    pub parse_config: Option<serde_json::Value>,
    pub validate_config: Option<serde_json::Value>,
    pub refresh_interval_secs: Option<i64>,
    pub enabled: Option<bool>,
}

/// PUT /api/sources/{slug} — update an indicator source.
pub async fn update_source(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<UpdateSourceBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let now = time::OffsetDateTime::now_utc();

    let result = sqlx::query!(
        "UPDATE sources SET
            url = COALESCE($2, url),
            categories = COALESCE($3, categories),
            fetch_config = COALESCE($4, fetch_config),
            parse_config = COALESCE($5, parse_config),
            validate_config = COALESCE($6, validate_config),
            refresh_interval_secs = COALESCE($7, refresh_interval_secs),
            enabled = COALESCE($8, enabled),
            updated_at = $1
         WHERE slug = $9",
        now,
        body.url,
        body.categories.as_deref(),
        body.fetch_config,
        body.parse_config,
        body.validate_config,
        body.refresh_interval_secs.map(|v| v as i32),
        body.enabled,
        slug,
    )
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "updated" })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "source not found" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// DELETE /api/sources/{slug} — delete an indicator source (with cascade warning).
pub async fn delete_source(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Check for affected filters before deleting.
    let affected_filters: Vec<String> = sqlx::query_scalar!(
        "SELECT f.slug FROM filters f JOIN sources s ON f.source_id = s.id WHERE s.slug = $1",
        slug,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let result = sqlx::query!("DELETE FROM sources WHERE slug = $1", slug)
        .execute(pool)
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(slug = %slug, affected_filters = ?affected_filters, "indicator source deleted");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "deleted",
                    "affected_filters": affected_filters,
                })),
            )
                .into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "source not found" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// POST /api/sources/{slug}/pull — manually trigger pull for one source.
pub async fn pull_source(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Look up source ID by slug.
    let source_id = sqlx::query_scalar!(
        "SELECT id FROM sources WHERE slug = $1 AND enabled = true",
        slug,
    )
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let Some(source_id) = source_id else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "source not found or disabled" })),
        )
            .into_response();
    };

    match crate::autopull::pull_source_by_id(pool, &source_id).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => {
            tracing::warn!(slug = %slug, error = %e, "source pull failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("pull failed: {e}") })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Composite endpoints for declarative source management
// ---------------------------------------------------------------------------

/// GET /api/sources/full — list all sources with their linked filter and enrichment.
pub async fn list_sources_full(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    let rows = sqlx::query!(
        r#"SELECT s.slug, s.url,
                s.indicator_type as "indicator_type: IndicatorType",
                s.categories, s.fetch_config, s.parse_config, s.validate_config,
                s.refresh_interval_secs, s.enabled,
                s.last_pull_at, s.last_checksum, s.last_entry_count,
                f.slug AS "filter_slug?",
                f.display_name AS "filter_display_name?",
                f.filter_type as "filter_type?: FilterType",
                f.output_format as "output_format?: OutputFormat",
                eb.enrichment_type as "enrichment_type?: EnrichmentType"
         FROM sources s
         LEFT JOIN filters f ON f.source_id = s.id
         LEFT JOIN enrichment_bindings eb ON eb.source_id = s.id
         ORDER BY s.slug"#,
    )
    .fetch_all(pool)
    .await;

    match rows {
        Ok(rows) => {
            let sources: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    let filter = row.filter_slug.as_ref().map(|slug| {
                        serde_json::json!({
                            "slug": slug,
                            "display_name": row.filter_display_name,
                            "filter_type": row.filter_type,
                            "output_format": row.output_format,
                        })
                    });
                    serde_json::json!({
                        "slug": row.slug,
                        "url": row.url,
                        "indicator_type": row.indicator_type,
                        "categories": row.categories,
                        "parse_config": row.parse_config,
                        "fetch_config": row.fetch_config,
                        "validate_config": row.validate_config,
                        "refresh_interval_secs": row.refresh_interval_secs,
                        "enabled": row.enabled,
                        "last_pull_at": super::rfc3339(row.last_pull_at),
                        "last_entry_count": row.last_entry_count,
                        "filter": filter,
                        "enrichment_type": row.enrichment_type,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "sources": sources })),
            )
                .into_response()
        }
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpsertSourceFullBody {
    pub url: String,
    pub indicator_type: IndicatorType,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_empty_object")]
    pub fetch_config: serde_json::Value,
    #[serde(default = "default_parse_config")]
    pub parse_config: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub validate_config: serde_json::Value,
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: i64,
    pub filter: Option<UpsertFilterDef>,
    pub enrichment_type: Option<EnrichmentType>,
}

#[derive(Deserialize)]
pub struct UpsertFilterDef {
    pub slug: Option<String>,
    pub display_name: String,
    pub filter_type: FilterType,
    pub output_format: OutputFormat,
}

/// PUT /api/sources/{slug}/full — upsert source + filter + enrichment atomically.
pub async fn upsert_source_full(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<UpsertSourceFullBody>,
) -> impl IntoResponse {
    if let Err(e) = validate_slug(&slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    let pool = &state.db.pool;
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return super::internal_error(e).into_response(),
    };

    // Upsert sources (never touch enabled, last_pull_at, last_checksum, last_entry_count).
    let source_id = match sqlx::query_scalar!(
        r#"INSERT INTO sources
            (slug, url, indicator_type, categories, fetch_config, parse_config, validate_config, refresh_interval_secs)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (slug) DO UPDATE SET
            url = EXCLUDED.url,
            indicator_type = EXCLUDED.indicator_type,
            categories = EXCLUDED.categories,
            fetch_config = EXCLUDED.fetch_config,
            parse_config = EXCLUDED.parse_config,
            validate_config = EXCLUDED.validate_config,
            refresh_interval_secs = EXCLUDED.refresh_interval_secs,
            updated_at = now()
         RETURNING id"#,
        slug,
        body.url,
        body.indicator_type as IndicatorType,
        &body.categories,
        body.fetch_config,
        body.parse_config,
        body.validate_config,
        body.refresh_interval_secs as i32,
    )
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(e) => return super::internal_error(e).into_response(),
    };

    // Handle filter: create/update or delete.
    if let Some(ref filter) = body.filter {
        let filter_slug = filter.slug.as_deref().unwrap_or(&slug);
        if let Err(e) = sqlx::query!(
            "INSERT INTO filters (slug, display_name, source_id, filter_type, output_format)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (slug) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                source_id = EXCLUDED.source_id,
                filter_type = EXCLUDED.filter_type,
                output_format = EXCLUDED.output_format,
                updated_at = now()",
            filter_slug,
            filter.display_name,
            source_id,
            filter.filter_type as FilterType,
            filter.output_format as OutputFormat,
        )
        .execute(&mut *tx)
        .await
        {
            return super::internal_error(e).into_response();
        }
    } else {
        // No filter desired — delete any existing filter for this source.
        let _ = sqlx::query!("DELETE FROM filters WHERE source_id = $1", source_id,)
            .execute(&mut *tx)
            .await;
    }

    // Handle enrichment binding: create or delete.
    if let Some(enrichment_type) = body.enrichment_type {
        if let Err(e) = sqlx::query!(
            "INSERT INTO enrichment_bindings (source_id, enrichment_type)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            source_id,
            enrichment_type as EnrichmentType,
        )
        .execute(&mut *tx)
        .await
        {
            return super::internal_error(e).into_response();
        }
    } else {
        let _ = sqlx::query!(
            "DELETE FROM enrichment_bindings WHERE source_id = $1",
            source_id,
        )
        .execute(&mut *tx)
        .await;
    }

    if let Err(e) = tx.commit().await {
        return super::internal_error(e).into_response();
    }

    info!(slug = %slug, "source upserted (full)");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "ok", "slug": slug })),
    )
        .into_response()
}

fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.is_empty() || slug.len() > 64 {
        return Err("slug must be 1-64 characters".to_string());
    }
    if slug.starts_with('_') {
        return Err("slug cannot start with underscore (reserved)".to_string());
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("slug must be lowercase alphanumeric, hyphens, or underscores".to_string());
    }
    Ok(())
}
