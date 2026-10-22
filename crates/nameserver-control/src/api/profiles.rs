use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use time::OffsetDateTime;

use nameserver_common::filter::normalize_domain;
use nameserver_common::types::enums::{BlockMode, FilterType, ListType};

use super::AppState;

/// GET /api/profiles — list all profiles.
pub async fn list_profiles(State(state): State<AppState>) -> impl IntoResponse {
    let rows = match sqlx::query!(
        r#"SELECT id, display_name, block_mode as "block_mode: BlockMode", redirect_ip, is_default, enabled
         FROM profiles ORDER BY is_default DESC, id"#,
    )
    .fetch_all(&state.db.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let profiles: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "display_name": row.display_name,
                "block_mode": row.block_mode,
                "redirect_ip": row.redirect_ip.map(|ip| ip.to_string()),
                "is_default": row.is_default,
                "enabled": row.enabled,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "profiles": profiles })),
    )
        .into_response()
}

/// GET /api/profiles/{id} — get profile detail with subscribed filters and custom entries.
pub async fn get_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Profile metadata.
    let profile = match sqlx::query!(
        r#"SELECT id, display_name, block_mode as "block_mode: BlockMode", redirect_ip, is_default, enabled,
                created_at, updated_at
         FROM profiles WHERE id = $1"#,
        id,
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(row)) => serde_json::json!({
            "id": row.id,
            "display_name": row.display_name,
            "block_mode": row.block_mode,
            "redirect_ip": row.redirect_ip.map(|ip| ip.to_string()),
            "is_default": row.is_default,
            "enabled": row.enabled,
            "created_at": row.created_at.unix_timestamp(),
            "updated_at": row.updated_at.unix_timestamp(),
        }),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("profile '{id}' not found") })),
            )
                .into_response();
        }
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    // Subscribed filters.
    let filters: Vec<serde_json::Value> = sqlx::query!(
        r#"SELECT f.id, f.slug, f.display_name,
                f.filter_type as "filter_type: FilterType"
         FROM profile_filters pf
         JOIN filters f ON f.id = pf.filter_id
         WHERE pf.profile_id = $1
         ORDER BY f.slug"#,
        id,
    )
    .fetch_all(pool)
    .await
    .ok()
    .map(|rows| {
        rows.iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id.to_string(),
                    "slug": row.slug,
                    "display_name": row.display_name,
                    "filter_type": row.filter_type,
                })
            })
            .collect()
    })
    .unwrap_or_default();

    // Custom entries.
    let custom_allow: Vec<String> = sqlx::query_scalar!(
        "SELECT domain FROM profile_custom_entries WHERE profile_id = $1 AND list_type = 'allowlist' ORDER BY domain",
        id,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let custom_block: Vec<String> = sqlx::query_scalar!(
        "SELECT domain FROM profile_custom_entries WHERE profile_id = $1 AND list_type = 'blocklist' ORDER BY domain",
        id,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut result = profile;
    result["filters"] = serde_json::json!(filters);
    result["custom_entries"] = serde_json::json!({
        "allowlist": custom_allow,
        "blocklist": custom_block,
    });

    (StatusCode::OK, Json(result)).into_response()
}

#[derive(Deserialize)]
pub struct CreateProfileBody {
    pub display_name: String,
    #[serde(default = "default_block_mode")]
    pub block_mode: BlockMode,
    pub redirect_ip: Option<String>,
    /// Optional list of filter IDs to subscribe to on creation.
    #[serde(default)]
    pub filter_ids: Vec<String>,
}

fn default_block_mode() -> BlockMode {
    BlockMode::Nxdomain
}

/// Generate a random 8-char lowercase alphanumeric profile ID.
fn generate_profile_id() -> String {
    use rand::Rng;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
        .collect()
}

/// POST /api/profiles — create a new profile with auto-generated ID.
pub async fn create_profile(
    State(state): State<AppState>,
    Json(body): Json<CreateProfileBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let now = OffsetDateTime::now_utc();

    // Parse redirect_ip if provided.
    let redirect_ip: Option<IpNetwork> = match &body.redirect_ip {
        Some(s) => match s.parse() {
            Ok(ip) => Some(ip),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("invalid redirect_ip: '{s}'") })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    // Generate unique ID, retry on (unlikely) collision.
    let id = loop {
        let candidate = generate_profile_id();
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM profiles WHERE id = $1)",
            candidate,
        )
        .fetch_one(pool)
        .await
        .unwrap_or(Some(false))
        .unwrap_or(false);
        if !exists {
            break candidate;
        }
    };

    match sqlx::query!(
        "INSERT INTO profiles (id, display_name, block_mode, redirect_ip, is_default, enabled, created_at, updated_at)
         VALUES ($1, $2, $3, $4, false, true, $5, $5)",
        id,
        body.display_name,
        body.block_mode as BlockMode,
        redirect_ip,
        now,
    )
    .execute(pool)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    }

    // Subscribe to initial filters.
    for filter_id_str in &body.filter_ids {
        let Ok(filter_id) = sqlx::types::Uuid::parse_str(filter_id_str) else {
            continue;
        };
        let _ = sqlx::query!(
            "INSERT INTO profile_filters (profile_id, filter_id, added_at) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
            id,
            filter_id,
            now,
        )
        .execute(pool)
        .await;
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "created", "id": id })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateProfileBody {
    pub display_name: Option<String>,
    pub block_mode: Option<BlockMode>,
    pub redirect_ip: Option<String>,
    pub enabled: Option<bool>,
}

/// PUT /api/profiles/{id} — update a profile.
pub async fn update_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateProfileBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let now = OffsetDateTime::now_utc();

    // Parse redirect_ip if provided.
    let redirect_ip: Option<IpNetwork> = match &body.redirect_ip {
        Some(s) => match s.parse() {
            Ok(ip) => Some(ip),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("invalid redirect_ip: '{s}'") })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    let result = sqlx::query!(
        "UPDATE profiles SET
            display_name = COALESCE($2, display_name),
            block_mode = COALESCE($3, block_mode),
            redirect_ip = COALESCE($4, redirect_ip),
            enabled = COALESCE($5, enabled),
            updated_at = $1
         WHERE id = $6",
        now,
        body.display_name,
        body.block_mode as Option<BlockMode>,
        redirect_ip,
        body.enabled,
        id,
    )
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("profile '{id}' not found") })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "updated", "id": id })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// DELETE /api/profiles/{id} — delete a profile.
pub async fn delete_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    match sqlx::query!("DELETE FROM profiles WHERE id = $1", id)
        .execute(pool)
        .await
    {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("profile '{id}' not found") })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "deleted", "id": id })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SubscribeBody {
    pub filter_slug: String,
}

/// POST /api/profiles/{id}/filters — subscribe profile to a filter.
pub async fn subscribe_filter(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SubscribeBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Resolve filter slug → UUID.
    let filter_id =
        sqlx::query_scalar!("SELECT id FROM filters WHERE slug = $1", body.filter_slug,)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let Some(filter_id) = filter_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "filter not found" })),
        )
            .into_response();
    };

    match sqlx::query!(
        "INSERT INTO profile_filters (profile_id, filter_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
        id,
        filter_id,
    )
    .execute(pool)
    .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "subscribed", "profile_id": id, "filter_slug": body.filter_slug })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// DELETE /api/profiles/{id}/filters/{filter_slug} — unsubscribe.
pub async fn unsubscribe_filter(
    State(state): State<AppState>,
    Path((id, filter_slug)): Path<(String, String)>,
) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Resolve filter slug → UUID, then delete.
    match sqlx::query!(
        "DELETE FROM profile_filters WHERE profile_id = $1 AND filter_id = (SELECT id FROM filters WHERE slug = $2)",
        id,
        filter_slug,
    )
    .execute(pool)
    .await
    {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "subscription not found" })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "unsubscribed", "profile_id": id, "filter_slug": filter_slug })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CustomEntryBody {
    pub domain: String,
    pub list_type: ListType,
}

/// POST /api/profiles/{id}/custom — add a custom allowlist/blocklist entry.
pub async fn add_custom_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CustomEntryBody>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let now = OffsetDateTime::now_utc();
    let domain = normalize_domain(&body.domain);

    match sqlx::query!(
        "INSERT INTO profile_custom_entries (profile_id, domain, list_type, added_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING",
        id,
        domain,
        body.list_type as ListType,
        now,
    )
    .execute(pool)
    .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "status": "added", "profile_id": id, "domain": domain })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// DELETE /api/profiles/{id}/custom/{domain} — remove a custom entry.
pub async fn remove_custom_entry(
    State(state): State<AppState>,
    Path((id, domain)): Path<(String, String)>,
) -> impl IntoResponse {
    let pool = &state.db.pool;
    let domain = normalize_domain(&domain);

    match sqlx::query!(
        "DELETE FROM profile_custom_entries WHERE profile_id = $1 AND domain = $2",
        id,
        domain,
    )
    .execute(pool)
    .await
    {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "custom entry not found" })),
        )
            .into_response(),
        Ok(r) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "removed", "profile_id": id, "domain": domain, "deleted": r.rows_affected() })),
        )
            .into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Per-resource diff / apply
// ---------------------------------------------------------------------------

/// GET /api/profiles/diff — show pending profile changes.
pub async fn profile_diff(State(state): State<AppState>) -> impl IntoResponse {
    let desired = match crate::state::read_desired_profiles(&state.db).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };
    let actual = match crate::state::read_actual_profiles(&state.js).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };

    let diff = crate::state::diff_profiles(&actual, &desired);
    let has_changes =
        !diff.added.is_empty() || !diff.changed.is_empty() || !diff.removed.is_empty();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "profiles": diff,
            "has_changes": has_changes,
        })),
    )
        .into_response()
}

/// POST /api/profiles/apply — publish changed profile configs only.
pub async fn profile_apply(State(state): State<AppState>) -> impl IntoResponse {
    let desired = match crate::state::read_desired_profiles(&state.db).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };
    let actual = match crate::state::read_actual_profiles(&state.js).await {
        Ok(s) => s,
        Err(e) => return super::internal_error(e).into_response(),
    };

    let diff = crate::state::diff_profiles(&actual, &desired);

    match crate::state::apply_profile_diff(&diff, &state.db, &state.nats_client, &state.js).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}
