use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use super::AppState;
use crate::compiler;

// ---------------------------------------------------------------------------
// Legacy compile endpoint (used by autopull, force-recompile escape hatch)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CompileQuery {
    publish: Option<bool>,
}

/// POST /api/compile — compile all filters and optionally publish.
pub async fn compile_filters(
    State(state): State<AppState>,
    Query(params): Query<CompileQuery>,
) -> impl IntoResponse {
    let should_publish = params.publish.unwrap_or(false);

    let result = match compiler::compile_from_db(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let mut response = serde_json::json!({
        "filters": result.blocklists.len() + result.allowlist.iter().count(),
    });

    if should_publish {
        match compiler::publish_filters(&state.nats_client, &state.js, &result).await {
            Ok(published) => {
                response["published"] = serde_json::json!(published);
            }
            Err(e) => {
                return super::internal_error(e).into_response();
            }
        }

        let source_checksums = compiler::read_source_checksums(&state.db).await;
        if let Err(e) =
            compiler::publish_filter_manifest(&state.js, &result, &source_checksums).await
        {
            response["manifest_error"] = serde_json::json!(e.to_string());
        }
    }

    (StatusCode::OK, Json(response)).into_response()
}
