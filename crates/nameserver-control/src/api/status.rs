use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use nameserver_common::admin::HealthStatus;
use nameserver_common::nats_subjects::SUBJECT_HEALTH;

use super::AppState;

pub async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    let domain_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domains")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let indicator_domain_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM indicator_domains")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let indicator_ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM indicator_ips")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let filter_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM filters")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let geo_entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM geo_entries")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    // Query DNS health via NATS request/reply.
    let dns_health = match tokio::time::timeout(
        Duration::from_secs(3),
        state.nats_client.request(SUBJECT_HEALTH, Bytes::new()),
    )
    .await
    {
        Ok(Ok(msg)) => match serde_json::from_slice::<HealthStatus>(&msg.payload) {
            Ok(health) => Some(serde_json::json!({
                "uptime_secs": health.uptime_secs,
                "total_queries": health.total_queries,
                "blocked_queries": health.blocked_queries,
                "nats_connected": health.nats_connected,
            })),
            Err(e) => Some(serde_json::json!({
                "error": format!("failed to parse health response: {e}"),
            })),
        },
        Ok(Err(e)) => Some(serde_json::json!({
            "error": format!("NATS request failed: {e}"),
        })),
        Err(_) => Some(serde_json::json!({
            "error": "NATS health check timed out",
        })),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "local_database": {
                "domains": domain_count,
                "ips": ip_count,
                "indicator_domains": indicator_domain_count,
                "indicator_ips": indicator_ip_count,
                "filters": filter_count,
                "geo_entries": geo_entries,
            },
            "dns_health": dns_health,
        })),
    )
        .into_response()
}
