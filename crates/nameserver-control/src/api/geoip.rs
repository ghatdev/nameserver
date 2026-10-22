use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ipnetwork::IpNetwork;
use nameserver_common::geo::{CDN_ASNS, GeoEntry4, GeoEntry6, GeoTable};
use nameserver_common::nats_subjects::{BUCKET_GEO, OBJ_GEOIP_BIN};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use super::AppState;

pub async fn geoip_status(State(state): State<AppState>) -> impl IntoResponse {
    let pool = &state.db.pool;

    let rows = match sqlx::query!(
        r#"SELECT rir, ip_version, COUNT(*) as "count!" FROM geo_entries GROUP BY rir, ip_version ORDER BY rir, ip_version"#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let mut entries = Vec::new();
    let mut total: i64 = 0;
    for row in &rows {
        let vtype = if row.ip_version == 4 { "ipv4" } else { "ipv6" };
        total += row.count;
        entries.push(serde_json::json!({
            "source": row.rir,
            "type": vtype,
            "count": row.count,
        }));
    }

    // Check NATS Object Store for compiled geoip.bin.
    let compiled = match state.js.get_object_store(BUCKET_GEO).await {
        Ok(bucket) => match bucket.info(OBJ_GEOIP_BIN).await {
            Ok(info) => serde_json::json!({ "size": info.size }),
            Err(_) => serde_json::Value::Null,
        },
        Err(_) => serde_json::Value::Null,
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "entries": entries,
            "total": total,
            "compiled": compiled,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CompileGeoQuery {
    /// If true, only compile without publishing (default: false → always publish).
    dry_run: Option<bool>,
}

pub async fn compile_geoip(
    State(state): State<AppState>,
    Query(params): Query<CompileGeoQuery>,
) -> impl IntoResponse {
    let should_publish = !params.dry_run.unwrap_or(false);
    let pool = &state.db.pool;

    let v4_entries = match read_v4_entries(pool).await {
        Ok(v) => v,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let v6_entries = match read_v6_entries(pool).await {
        Ok(v) => v,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let mut v4_sorted = v4_entries;
    let mut v6_sorted = v6_entries;
    v4_sorted.sort_by_key(|e| e.start);
    v6_sorted.sort_by(|a, b| {
        a.start_hi
            .cmp(&b.start_hi)
            .then(a.start_lo.cmp(&b.start_lo))
    });

    if v4_sorted.is_empty() && v6_sorted.is_empty() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "empty",
                "message": "No geo entries found. Pull geo data first.",
            })),
        )
            .into_response();
    }

    let table = GeoTable {
        v4: v4_sorted,
        v6: v6_sorted,
    };

    let bytes = match bincode::serialize(&table) {
        Ok(b) => b,
        Err(e) => {
            return super::internal_error(e).into_response();
        }
    };

    let checksum = hex::encode(Sha256::digest(&bytes));
    info!(
        v4 = table.v4.len(),
        v6 = table.v6.len(),
        bytes = bytes.len(),
        checksum = %checksum,
        "compiled GeoIP table"
    );

    let mut response = serde_json::json!({
        "ipv4_entries": table.v4.len(),
        "ipv6_entries": table.v6.len(),
        "bytes": bytes.len(),
        "checksum": checksum,
    });

    if should_publish {
        match publish_geo_to_object_store(&state, &bytes).await {
            Ok(()) => {
                response["published"] = serde_json::json!(true);
                info!("published geoip.bin to Object Store");

                // Notify DNS server to hot-reload the geo table.
                crate::compiler::send_reload(
                    &state.nats_client,
                    nameserver_common::admin::ReloadSignal::Geoip,
                )
                .await;
            }
            Err(e) => {
                return super::internal_error(e).into_response();
            }
        }
    }

    (StatusCode::OK, Json(response)).into_response()
}

async fn publish_geo_to_object_store(state: &AppState, bytes: &[u8]) -> anyhow::Result<()> {
    let bucket = state.js.get_object_store(BUCKET_GEO).await?;
    let mut data: &[u8] = bytes;
    bucket.put(OBJ_GEOIP_BIN, &mut data).await?;
    Ok(())
}

pub async fn lookup_geoip(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> impl IntoResponse {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": format!("'{ip_str}' is not a valid IP address") }),
                ),
            )
                .into_response();
        }
    };

    let pool = &state.db.pool;
    let ip_net = IpNetwork::from(ip);
    let result = match ip {
        IpAddr::V4(_) => lookup_v4_from_db(pool, ip_net).await,
        IpAddr::V6(_) => lookup_v6_from_db(pool, ip_net).await,
    };

    match result {
        Ok(Some(info)) => (StatusCode::OK, Json(info)).into_response(),
        Ok(None) => {
            // Fall back to Team Cymru DNS lookup.
            match lookup_cymru(ip).await {
                Ok(info) => (StatusCode::OK, Json(info)).into_response(),
                Err(_) => (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "ip": ip_str,
                        "error": "no geo data found",
                    })),
                )
                    .into_response(),
            }
        }
        Err(e) => super::internal_error(e).into_response(),
    }
}

async fn lookup_v4_from_db(
    pool: &PgPool,
    ip_net: IpNetwork,
) -> anyhow::Result<Option<serde_json::Value>> {
    let row = sqlx::query!(
        "SELECT country, asn, asn_desc FROM geo_entries
         WHERE ip_version = 4
           AND start_ip <= $1 AND end_ip >= $1
         ORDER BY start_ip DESC LIMIT 1",
        ip_net,
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => {
            let is_cdn = CDN_ASNS.contains(&(row.asn as u32));
            Ok(Some(serde_json::json!({
                "ip": ip_net.ip().to_string(),
                "country": row.country,
                "asn": row.asn,
                "asn_desc": row.asn_desc,
                "is_cdn": is_cdn,
                "source": "local",
            })))
        }
        None => Ok(None),
    }
}

async fn lookup_v6_from_db(
    pool: &PgPool,
    ip_net: IpNetwork,
) -> anyhow::Result<Option<serde_json::Value>> {
    let row = sqlx::query!(
        "SELECT country, asn, asn_desc FROM geo_entries
         WHERE ip_version = 6
           AND start_ip <= $1 AND end_ip >= $1
         ORDER BY start_ip DESC LIMIT 1",
        ip_net,
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => {
            let is_cdn = CDN_ASNS.contains(&(row.asn as u32));
            Ok(Some(serde_json::json!({
                "ip": ip_net.ip().to_string(),
                "country": row.country,
                "asn": row.asn,
                "asn_desc": row.asn_desc,
                "is_cdn": is_cdn,
                "source": "local",
            })))
        }
        None => Ok(None),
    }
}

/// Team Cymru DNS lookup via Google DoH.
async fn lookup_cymru(ip: IpAddr) -> anyhow::Result<serde_json::Value> {
    let reversed = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.origin.asn.cymru.com",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let segments = v6.octets();
            let nibbles: String = segments
                .iter()
                .rev()
                .flat_map(|b| [b & 0x0f, b >> 4])
                .map(|n| format!("{:x}", n))
                .collect::<Vec<_>>()
                .join(".");
            format!("{nibbles}.origin6.asn.cymru.com")
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let url = format!("https://dns.google/resolve?name={reversed}&type=TXT");
    let resp = client.get(&url).send().await?;
    let json: serde_json::Value = resp.json().await?;

    let answers = json["Answer"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no answer from Team Cymru for {ip}"))?;

    for answer in answers {
        let data = answer["data"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"')
            .trim();
        let parts: Vec<&str> = data.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            let asn: u32 = parts[0].parse().unwrap_or(0);
            let prefix = parts[1];
            let country = parts[2];
            let rir = parts.get(3).unwrap_or(&"");
            let is_cdn = CDN_ASNS.contains(&asn);

            return Ok(serde_json::json!({
                "ip": ip.to_string(),
                "country": country,
                "asn": asn,
                "prefix": prefix,
                "rir": rir,
                "is_cdn": is_cdn,
                "source": "cymru",
            }));
        }
    }

    anyhow::bail!("no valid Team Cymru response for {ip}")
}

// ---------------------------------------------------------------------------
// Per-resource diff / apply
// ---------------------------------------------------------------------------

/// GET /api/geoip/diff — show pending geoip changes.
pub async fn geoip_diff(State(state): State<AppState>) -> impl IntoResponse {
    let desired = crate::state::read_geoip_state(&state.db.pool).await;
    let actual = crate::state::read_actual_geoip(&state.js).await;
    let diff = crate::state::diff_geoip(&actual, &desired);

    let has_changes = diff.status == crate::state::GeoipDiffStatus::Changed
        || diff.status == crate::state::GeoipDiffStatus::NotPublished;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "geoip": diff,
            "has_changes": has_changes,
        })),
    )
        .into_response()
}

/// POST /api/geoip/apply — compile and publish geoip only.
pub async fn geoip_apply(State(state): State<AppState>) -> impl IntoResponse {
    let desired = crate::state::read_geoip_state(&state.db.pool).await;
    let actual = crate::state::read_actual_geoip(&state.js).await;
    let diff = crate::state::diff_geoip(&actual, &desired);

    match crate::state::apply_geoip_diff(&diff, &state.db, &state.nats_client, &state.js).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => super::internal_error(e).into_response(),
    }
}

/// Compile GeoTable from PostgreSQL and publish to NATS Object Store.
/// Used by both the API handler and the autopull task.
pub(crate) async fn compile_and_publish_geoip(
    pool: &PgPool,
    js: &async_nats::jetstream::Context,
) -> anyhow::Result<()> {
    let v4_entries = read_v4_entries(pool).await?;
    let v6_entries = read_v6_entries(pool).await?;

    let mut v4_sorted = v4_entries;
    let mut v6_sorted = v6_entries;
    v4_sorted.sort_by_key(|e| e.start);
    v6_sorted.sort_by(|a, b| {
        a.start_hi
            .cmp(&b.start_hi)
            .then(a.start_lo.cmp(&b.start_lo))
    });

    if v4_sorted.is_empty() && v6_sorted.is_empty() {
        return Ok(());
    }

    let table = GeoTable {
        v4: v4_sorted,
        v6: v6_sorted,
    };

    let bytes = bincode::serialize(&table)?;
    let checksum = hex::encode(Sha256::digest(&bytes));
    info!(
        v4 = table.v4.len(),
        v6 = table.v6.len(),
        bytes = bytes.len(),
        checksum = %checksum,
        "compiled GeoIP table"
    );

    let bucket = js.get_object_store(BUCKET_GEO).await?;
    let mut data: &[u8] = &bytes;
    bucket.put(OBJ_GEOIP_BIN, &mut data).await?;
    info!("published geoip.bin to Object Store");

    Ok(())
}

async fn read_v4_entries(pool: &PgPool) -> anyhow::Result<Vec<GeoEntry4>> {
    let rows = sqlx::query!(
        "SELECT start_ip, end_ip, country, asn FROM geo_entries WHERE ip_version = 4",
    )
    .fetch_all(pool)
    .await?;

    let mut entries = Vec::new();
    for row in &rows {
        let IpAddr::V4(start) = row.start_ip.ip() else {
            continue;
        };
        let IpAddr::V4(end) = row.end_ip.ip() else {
            continue;
        };
        let cb = row.country.as_bytes();
        if cb.len() < 2 {
            continue;
        }
        entries.push(GeoEntry4 {
            start: u32::from(start),
            end: u32::from(end),
            country: [cb[0], cb[1]],
            asn: row.asn as u32,
        });
    }
    Ok(entries)
}

async fn read_v6_entries(pool: &PgPool) -> anyhow::Result<Vec<GeoEntry6>> {
    let rows = sqlx::query!(
        "SELECT start_ip, end_ip, country, asn FROM geo_entries WHERE ip_version = 6",
    )
    .fetch_all(pool)
    .await?;

    let mut entries = Vec::new();
    for row in &rows {
        let IpAddr::V6(start) = row.start_ip.ip() else {
            continue;
        };
        let IpAddr::V6(end) = row.end_ip.ip() else {
            continue;
        };
        let cb = row.country.as_bytes();
        if cb.len() < 2 {
            continue;
        }
        let s = u128::from(start);
        let e = u128::from(end);
        entries.push(GeoEntry6 {
            start_hi: (s >> 64) as u64,
            start_lo: s as u64,
            end_hi: (e >> 64) as u64,
            end_lo: e as u64,
            country: [cb[0], cb[1]],
            asn: row.asn as u32,
        });
    }
    Ok(entries)
}
