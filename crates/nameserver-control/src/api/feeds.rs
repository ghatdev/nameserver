use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use nameserver_common::types::IndicatorType;

use super::AppState;

/// GET /api/feeds — show indicator source statistics.
pub async fn get_feeds(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    // Per-source indicator counts (domains + IPs).
    let sources = match sqlx::query!(
        r#"SELECT s.slug, s.indicator_type as "indicator_type: IndicatorType", s.last_entry_count, s.last_pull_at, s.enabled
         FROM sources s
         ORDER BY s.slug"#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "slug": row.slug,
                    "indicator_type": row.indicator_type,
                    "entry_count": row.last_entry_count,
                    "last_pull_at": super::rfc3339(row.last_pull_at),
                    "enabled": row.enabled,
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "sources": sources,
        })),
    )
        .into_response()
}
