use std::convert::Infallible;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt;
use nameserver_common::messages::DetectorScore;
use nameserver_common::nats_subjects::SUBJECT_DETECTOR_SCORE;
use serde::Deserialize;

use super::AppState;
use crate::clickhouse::DetectorScoreRow;

#[derive(Deserialize)]
pub struct DetectorScoreQuery {
    /// Filter by domain (exact or substring with %).
    domain: Option<String>,
    /// Filter by ML class (malicious, suspicious, safe, unknown).
    class: Option<String>,
    /// Minimum ML probability.
    min_prob: Option<f32>,
    /// Maximum number of results.
    recent: Option<u32>,
    /// Time window in seconds (e.g., 3600 for last hour).
    since: Option<u64>,
}

pub async fn get_detector_scores(
    State(state): State<AppState>,
    Query(params): Query<DetectorScoreQuery>,
) -> impl IntoResponse {
    let db_name = &state.ch_config.database;
    let limit = params.recent.unwrap_or(50);

    let mut conditions = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ref domain) = params.domain {
        if domain.contains('%') {
            conditions.push("domain LIKE ?".to_string());
        } else {
            conditions.push("domain = ?".to_string());
        }
        bind_values.push(domain.clone());
    }

    if let Some(ref class) = params.class {
        conditions.push("ml_class = ?".to_string());
        bind_values.push(class.clone());
    }

    if let Some(min_prob) = params.min_prob {
        conditions.push(format!("final_probability >= {min_prob}"));
    }

    if let Some(secs) = params.since {
        conditions.push(format!("predicted_at >= now() - INTERVAL {secs} SECOND"));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT * FROM {db}.detector_scores {wc} ORDER BY predicted_at DESC LIMIT {n}",
        db = db_name,
        wc = where_clause,
        n = limit,
    );

    let mut query = state.ch.query(&sql);
    for val in &bind_values {
        query = query.bind(val.as_str());
    }

    let result: Result<Vec<DetectorScoreRow>, clickhouse::error::Error> = async {
        let mut cursor = query.fetch::<DetectorScoreRow>()?;
        let mut rows = Vec::new();
        while let Some(row) = cursor.next().await? {
            rows.push(row);
        }
        Ok(rows)
    }
    .await;

    match result {
        Ok(rows) => {
            let json_rows: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "predicted_at": r.predicted_at.unix_timestamp(),
                        "domain": r.domain,
                        "ml_probability": r.ml_probability,
                        "final_probability": r.final_probability,
                        "ml_class": r.ml_class,
                        "divergent": r.divergent != 0,
                        "override_rule": if r.override_rule.is_empty() { None } else { Some(&r.override_rule) },
                        "ns_trust": r.ns_trust,
                        "signals": {
                            "dnssec": r.dnssec_adj,
                            "ns": r.ns_adj,
                            "similarity": r.similarity_adj,
                            "hosting": r.hosting_adj,
                            "nrd": r.nrd_adj,
                            "temporal": r.temporal_adj,
                        },
                    })
                })
                .collect();
            Json(serde_json::json!({ "scores": json_rows, "count": json_rows.len() }))
                .into_response()
        }
        Err(e) => {
            let msg = format!("ClickHouse query failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
        }
    }
}

/// SSE endpoint: `GET /api/detector/scores/live`
///
/// Subscribes to `ns.detector.score` NATS subject and streams each score
/// as a JSON SSE event. Connection-scoped: subscription is dropped when the
/// client disconnects.
pub async fn live_scores(
    State(state): State<AppState>,
) -> Result<
    Sse<impl futures::Stream<Item = Result<Event, Infallible>>>,
    (StatusCode, Json<serde_json::Value>),
> {
    let sub = state
        .nats_client
        .subscribe(SUBJECT_DETECTOR_SCORE)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "live subscription unavailable"})),
            )
        })?;

    let stream = sub.filter_map(|msg| async move {
        let score: DetectorScore = serde_json::from_slice(&msg.payload).ok()?;
        let json = serde_json::to_string(&score).ok()?;
        Some(Ok(Event::default().data(json)))
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
