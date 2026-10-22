use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use sqlx::Row;
use time::OffsetDateTime;

use super::AppState;

use nameserver_common::filter::normalize_domain;

fn validate_kind(kind: &str) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    match kind {
        "allowlist" | "blocklist" => Ok(kind),
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("unknown list kind '{kind}'. Use 'allowlist' or 'blocklist'.")
            })),
        )),
    }
}

pub async fn get_list(
    State(state): State<AppState>,
    Path(kind): Path<String>,
) -> impl IntoResponse {
    let table = match validate_kind(&kind) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };

    let pool = &state.db.pool;

    // Get total count.
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    // Get entries grouped by source.
    let sources = match sqlx::query(&format!(
        "SELECT source, COUNT(*) AS cnt FROM {table} GROUP BY source ORDER BY source"
    ))
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "source": row.get::<String, _>("source"),
                    "count": row.get::<i64, _>("cnt"),
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    // If total is small enough, include individual entries.
    let entries = if total <= 500 {
        match sqlx::query(&format!(
            "SELECT domain, source, added_at FROM {table} ORDER BY domain"
        ))
        .fetch_all(pool)
        .await
        {
            Ok(rows) => Some(
                rows.iter()
                    .map(|row| {
                        let added_at: time::OffsetDateTime = row.get("added_at");
                        serde_json::json!({
                            "domain": row.get::<String, _>("domain"),
                            "source": row.get::<String, _>("source"),
                            "added_at": added_at.unix_timestamp(),
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            Err(e) => {
                return super::internal_error(e).into_response();
            }
        }
    } else {
        None
    };

    let mut result = serde_json::json!({
        "kind": kind,
        "total": total,
        "sources": sources,
    });

    if let Some(entries) = entries {
        result["entries"] = serde_json::json!(entries);
    }

    (StatusCode::OK, Json(result)).into_response()
}

#[derive(Deserialize)]
pub struct ListModifyBody {
    action: String,
    domain: String,
}

pub async fn modify_list(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    Json(body): Json<ListModifyBody>,
) -> impl IntoResponse {
    let table = match validate_kind(&kind) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };

    let pool = &state.db.pool;
    let fqdn = normalize_domain(&body.domain);

    match body.action.as_str() {
        "add" => {
            let now = OffsetDateTime::now_utc();
            let query = format!(
                "INSERT INTO {table} (domain, added_at, source) VALUES ($1, $2, 'manual') ON CONFLICT DO NOTHING"
            );
            match sqlx::query(&query)
                .bind(&fqdn)
                .bind(now)
                .execute(pool)
                .await
            {
                Ok(result) => {
                    if result.rows_affected() > 0 {
                        (
                            StatusCode::CREATED,
                            Json(serde_json::json!({
                                "status": "added",
                                "domain": fqdn,
                                "list": kind,
                            })),
                        )
                            .into_response()
                    } else {
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "status": "already_exists",
                                "domain": fqdn,
                                "list": kind,
                            })),
                        )
                            .into_response()
                    }
                }
                Err(e) => super::internal_error(e).into_response(),
            }
        }
        "remove" => {
            let query = format!("DELETE FROM {table} WHERE domain = $1");
            match sqlx::query(&query).bind(&fqdn).execute(pool).await {
                Ok(result) => {
                    if result.rows_affected() > 0 {
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "status": "removed",
                                "domain": fqdn,
                                "list": kind,
                            })),
                        )
                            .into_response()
                    } else {
                        (
                            StatusCode::NOT_FOUND,
                            Json(serde_json::json!({
                                "status": "not_found",
                                "domain": fqdn,
                                "list": kind,
                            })),
                        )
                            .into_response()
                    }
                }
                Err(e) => super::internal_error(e).into_response(),
            }
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("unknown action '{other}'. Use 'add' or 'remove'."),
            })),
        )
            .into_response(),
    }
}

pub async fn import_list(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let table = match validate_kind(&kind) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };

    let text = match String::from_utf8(body.to_vec()) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid UTF-8: {e}") })),
            )
                .into_response();
        }
    };

    let pool = &state.db.pool;
    let now = OffsetDateTime::now_utc();

    // Wrap bulk insert in a single transaction for performance.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let query = format!(
        "INSERT INTO {table} (domain, added_at, source) VALUES ($1, $2, 'import') ON CONFLICT DO NOTHING"
    );

    let mut count = 0u64;
    let mut skipped = 0u64;
    for line in text.lines() {
        let raw = line.trim();
        if raw.is_empty() || raw.starts_with('#') {
            skipped += 1;
            continue;
        }

        // Handle OISD wildcard format.
        let domain = raw.strip_prefix("*.").unwrap_or(raw);

        // Skip IP addresses and entries without a dot.
        if domain.parse::<std::net::IpAddr>().is_ok() || !domain.contains('.') {
            skipped += 1;
            continue;
        }

        let fqdn = normalize_domain(domain);
        match sqlx::query(&query)
            .bind(&fqdn)
            .bind(now)
            .execute(&mut *tx)
            .await
        {
            Ok(_) => count += 1,
            Err(_) => skipped += 1,
        }
    }

    if let Err(e) = tx.commit().await {
        return super::internal_error(e).into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "imported",
            "list": kind,
            "imported": count,
            "skipped": skipped,
        })),
    )
        .into_response()
}
