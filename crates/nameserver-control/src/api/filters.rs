use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use tracing::info;

use nameserver_common::types::enums::{FilterType, OutputFormat};

use super::AppState;

/// GET /api/filters — list all compiled filters.
pub async fn list_filters(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    let rows = sqlx::query!(
        r#"SELECT f.id, f.slug, f.display_name,
                f.filter_type as "filter_type: FilterType",
                f.output_format as "output_format: OutputFormat",
                f.compiled_entry_count, f.compiled_at, s.slug AS source_slug
         FROM filters f
         JOIN sources s ON f.source_id = s.id
         ORDER BY f.slug"#,
    )
    .fetch_all(pool)
    .await;

    match rows {
        Ok(rows) => {
            let filters: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.id.to_string(),
                        "slug": row.slug,
                        "display_name": row.display_name,
                        "filter_type": row.filter_type,
                        "output_format": row.output_format,
                        "source_slug": row.source_slug,
                        "compiled_entry_count": row.compiled_entry_count,
                        "compiled_at": super::rfc3339(row.compiled_at),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "filters": filters })),
            )
                .into_response()
        }
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// GET /api/filters/{slug} — get filter details.
pub async fn get_filter(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let row = sqlx::query!(
        r#"SELECT f.id, f.slug, f.display_name,
                f.filter_type as "filter_type: FilterType",
                f.output_format as "output_format: OutputFormat",
                f.source_id, f.compiled_checksum, f.compiled_entry_count, f.compiled_at,
                s.slug AS source_slug
         FROM filters f
         JOIN sources s ON f.source_id = s.id
         WHERE f.slug = $1"#,
        slug,
    )
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some(row)) => {
            let filter = serde_json::json!({
                "id": row.id.to_string(),
                "slug": row.slug,
                "display_name": row.display_name,
                "filter_type": row.filter_type,
                "output_format": row.output_format,
                "source_slug": row.source_slug,
                "compiled_checksum": row.compiled_checksum,
                "compiled_entry_count": row.compiled_entry_count,
                "compiled_at": super::rfc3339(row.compiled_at),
            });
            (StatusCode::OK, Json(filter)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "filter not found" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateFilterBody {
    pub slug: String,
    pub display_name: String,
    pub source_slug: String,
    pub filter_type: FilterType,
    pub output_format: OutputFormat,
}

/// POST /api/filters — create a new filter.
pub async fn create_filter(
    State(state): State<AppState>,
    Json(body): Json<CreateFilterBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Resolve source_slug → source_id.
    let source_id =
        sqlx::query_scalar!("SELECT id FROM sources WHERE slug = $1", body.source_slug,)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let Some(source_id) = source_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "source not found" })),
        )
            .into_response();
    };

    let result = sqlx::query!(
        "INSERT INTO filters (slug, display_name, source_id, filter_type, output_format)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (slug) DO NOTHING",
        body.slug,
        body.display_name,
        source_id,
        body.filter_type as FilterType,
        body.output_format as OutputFormat,
    )
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(slug = %body.slug, source = %body.source_slug, "filter created");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "status": "created", "slug": body.slug })),
            )
                .into_response()
        }
        Ok(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "filter already exists" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateFilterBody {
    pub display_name: Option<String>,
    pub source_slug: Option<String>,
}

/// PUT /api/filters/{slug} — update a filter.
pub async fn update_filter(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<UpdateFilterBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Resolve source_slug if provided.
    let source_id: Option<sqlx::types::Uuid> = if let Some(ref source_slug) = body.source_slug {
        sqlx::query_scalar!("SELECT id FROM sources WHERE slug = $1", source_slug,)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
    } else {
        None
    };

    let result = sqlx::query!(
        "UPDATE filters SET
            display_name = COALESCE($2, display_name),
            source_id = COALESCE($3, source_id),
            updated_at = now()
         WHERE slug = $1",
        slug,
        body.display_name,
        source_id,
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
            Json(serde_json::json!({ "error": "filter not found" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// DELETE /api/filters/{slug} — delete a filter.
pub async fn delete_filter(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Check for affected profiles.
    let affected_profiles: Vec<String> = sqlx::query_scalar!(
        "SELECT pf.profile_id FROM profile_filters pf JOIN filters f ON pf.filter_id = f.id WHERE f.slug = $1",
        slug,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let result = sqlx::query!("DELETE FROM filters WHERE slug = $1", slug)
        .execute(pool)
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(slug = %slug, affected_profile_count = affected_profiles.len(), "filter deleted");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "deleted",
                    "affected_profiles": affected_profiles,
                })),
            )
                .into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "filter not found" })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// POST /api/filters/compile — compile all filters and publish.
pub async fn compile_all(State(state): State<AppState>) -> impl IntoResponse {
    match crate::compiler::compile_from_db(&state.db).await {
        Ok(result) => {
            match crate::compiler::publish_filters(&state.nats_client, &state.js, &result).await {
                Ok(published) => {
                    let source_checksums = crate::compiler::read_source_checksums(&state.db).await;
                    let _ = crate::compiler::publish_filter_manifest(
                        &state.js,
                        &result,
                        &source_checksums,
                    )
                    .await;
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "status": "compiled",
                            "published": published.len(),
                        })),
                    )
                        .into_response()
                }
                Err(e) => super::internal_error(e).into_response(),
            }
        }
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// GET /api/filters/diff — compare desired (DB) vs actual (NATS) filter state.
pub async fn filter_diff(State(state): State<AppState>) -> impl IntoResponse {
    let desired = match crate::state::read_desired_filters(&state.db).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };
    let actual = match crate::state::read_actual_filters(&state.js).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };

    let diff = crate::state::diff_filters(&actual, &desired);
    let has_changes =
        !diff.added.is_empty() || !diff.changed.is_empty() || !diff.removed.is_empty();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "filters": diff,
            "has_changes": has_changes,
        })),
    )
        .into_response()
}

/// POST /api/filters/apply — compile and publish changed filters only.
pub async fn filter_apply(State(state): State<AppState>) -> impl IntoResponse {
    let desired = match crate::state::read_desired_filters(&state.db).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };
    let actual = match crate::state::read_actual_filters(&state.js).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };

    let diff = crate::state::diff_filters(&actual, &desired);

    match crate::state::apply_filter_diff(&diff, &state.db, &state.nats_client, &state.js).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}
