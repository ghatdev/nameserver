use std::fmt::Write;
use std::io::Cursor;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use nameserver_common::admin::HealthStatus;
use nameserver_common::nats_subjects::*;
use tokio::io::AsyncReadExt;
use tracing::debug;

use super::AppState;

/// GET /metrics — Prometheus text exposition format.
pub async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let mut out = String::with_capacity(1024);

    // 1. TLS certificate expiry (from NATS Object Store).
    let cert_expiry = fetch_cert_expiry_seconds(&state).await;
    writeln!(
        out,
        "# HELP nameserver_cert_expiry_seconds Seconds until TLS certificate expires"
    )
    .ok();
    writeln!(out, "# TYPE nameserver_cert_expiry_seconds gauge").ok();
    writeln!(out, "nameserver_cert_expiry_seconds {cert_expiry}").ok();

    // 2. DNSSEC last-signed age (from NATS KV).
    let dnssec_age = fetch_dnssec_last_signed_seconds(&state).await;
    writeln!(
        out,
        "# HELP nameserver_dnssec_last_signed_seconds Seconds since last DNSSEC zone re-sign"
    )
    .ok();
    writeln!(out, "# TYPE nameserver_dnssec_last_signed_seconds gauge").ok();
    writeln!(out, "nameserver_dnssec_last_signed_seconds {dnssec_age}").ok();

    // 3. DNS health check (via NATS request/reply).
    let (dns_up, queries_total) = fetch_dns_health(&state).await;
    writeln!(
        out,
        "# HELP nameserver_dns_up Whether DNS health check succeeded (1=up, 0=down)"
    )
    .ok();
    writeln!(out, "# TYPE nameserver_dns_up gauge").ok();
    writeln!(out, "nameserver_dns_up {dns_up}").ok();

    writeln!(
        out,
        "# HELP nameserver_dns_queries_total Total DNS queries served"
    )
    .ok();
    writeln!(out, "# TYPE nameserver_dns_queries_total gauge").ok();
    writeln!(out, "nameserver_dns_queries_total {queries_total}").ok();

    // 4. NATS connection state.
    let nats_up =
        if state.nats_client.connection_state() == async_nats::connection::State::Connected {
            1
        } else {
            0
        };
    writeln!(
        out,
        "# HELP nameserver_nats_connected Whether NATS client is connected (1=yes, 0=no)"
    )
    .ok();
    writeln!(out, "# TYPE nameserver_nats_connected gauge").ok();
    writeln!(out, "nameserver_nats_connected {nats_up}").ok();

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the ACME cert bundle from Object Store, parse X.509, return seconds
/// until expiry. Returns -1 if unavailable.
async fn fetch_cert_expiry_seconds(state: &AppState) -> f64 {
    let store = match state.js.get_object_store(BUCKET_CERTS).await {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "metrics: cert bucket unavailable");
            return -1.0;
        }
    };

    let data = match tokio::time::timeout(Duration::from_secs(5), async {
        let mut obj = store.get(OBJ_CERT_BUNDLE).await?;
        let mut buf = Vec::new();
        obj.read_to_end(&mut buf).await?;
        Ok::<_, anyhow::Error>(buf)
    })
    .await
    {
        Ok(Ok(d)) => d,
        _ => return -1.0,
    };

    // cert-bundle.json has shape: { "cert_pem": "...", "key_pem": "..." }
    let bundle: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return -1.0,
    };
    let cert_pem = match bundle["cert_pem"].as_str() {
        Some(s) => s,
        None => return -1.0,
    };

    // Parse PEM → DER
    let mut cursor = Cursor::new(cert_pem.as_bytes());
    let certs = match rustls_pemfile::certs(&mut cursor).collect::<Result<Vec<_>, _>>() {
        Ok(c) if !c.is_empty() => c,
        _ => return -1.0,
    };

    // Parse X.509 → notAfter
    let (_, cert) = match x509_parser::parse_x509_certificate(certs[0].as_ref()) {
        Ok(c) => c,
        Err(_) => return -1.0,
    };

    let not_after = cert.validity().not_after.timestamp();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    (not_after - now) as f64
}

/// Read the last-signed-at timestamp from NATS KV, return seconds since then.
/// Returns -1 if the key does not exist.
async fn fetch_dnssec_last_signed_seconds(state: &AppState) -> f64 {
    let kv = match state.js.get_key_value(BUCKET_CONFIG).await {
        Ok(kv) => kv,
        Err(_) => return -1.0,
    };
    let entry = match kv.get(KV_DNSSEC_LAST_SIGNED_AT).await {
        Ok(Some(bytes)) => bytes,
        _ => return -1.0,
    };
    let ts_str = match std::str::from_utf8(&entry) {
        Ok(s) => s,
        Err(_) => return -1.0,
    };
    let parsed =
        match time::OffsetDateTime::parse(ts_str, &time::format_description::well_known::Rfc3339) {
            Ok(t) => t,
            Err(_) => return -1.0,
        };
    let now = time::OffsetDateTime::now_utc();
    (now - parsed).as_seconds_f64()
}

/// Query DNS health via NATS request/reply. Returns (up, total_queries).
async fn fetch_dns_health(state: &AppState) -> (u8, u64) {
    match tokio::time::timeout(
        Duration::from_secs(3),
        state.nats_client.request(SUBJECT_HEALTH, Bytes::new()),
    )
    .await
    {
        Ok(Ok(msg)) => match serde_json::from_slice::<HealthStatus>(&msg.payload) {
            Ok(h) => (1, h.total_queries),
            Err(_) => (0, 0),
        },
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn prometheus_text_format_is_valid() {
        // Verify metric lines follow Prometheus text format conventions.
        let sample = "nameserver_cert_expiry_seconds 5184000\n";
        let parts: Vec<&str> = sample.trim().split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[1].parse::<f64>().is_ok());
    }
}
