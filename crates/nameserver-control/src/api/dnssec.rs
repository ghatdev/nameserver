use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures::StreamExt;
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::{DNSKEY, DS};
use hickory_proto::dnssec::{Algorithm, DigestType, SigningKey};
use hickory_proto::rr::Name;
use nameserver_common::nats_subjects::*;
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

use super::AppState;

// ---------------------------------------------------------------------------
// DNSSEC key management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct KeygenBody {
    #[serde(default)]
    pub force: bool,
}

/// POST /api/dnssec/keygen — generate KSK + ZSK, store in NATS Object Store.
pub async fn keygen(
    State(state): State<AppState>,
    Json(body): Json<KeygenBody>,
) -> impl IntoResponse {
    let store = match provision_dnssec_bucket(&state).await {
        Ok(s) => s,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    // Check for existing keys.
    if !body.force {
        let ksk_exists = store.info(OBJ_DNSSEC_KSK).await.is_ok();
        let zsk_exists = store.info(OBJ_DNSSEC_ZSK).await.is_ok();
        if ksk_exists || zsk_exists {
            return error_response(
                StatusCode::CONFLICT,
                "DNSSEC keys already exist. Set force=true to overwrite (invalidates DS at registrar).",
            );
        }
    }

    let algorithm = Algorithm::ECDSAP256SHA256;

    let ksk_pkcs8 = match EcdsaSigningKey::generate_pkcs8(algorithm) {
        Ok(k) => k,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("KSK keygen failed: {e}"),
            );
        }
    };
    let zsk_pkcs8 = match EcdsaSigningKey::generate_pkcs8(algorithm) {
        Ok(k) => k,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("ZSK keygen failed: {e}"),
            );
        }
    };

    let ksk_bytes = ksk_pkcs8.secret_pkcs8_der().to_vec();
    let zsk_bytes = zsk_pkcs8.secret_pkcs8_der().to_vec();

    // Store in Object Store.
    let mut ksk_data: &[u8] = &ksk_bytes;
    if let Err(e) = store.put(OBJ_DNSSEC_KSK, &mut ksk_data).await {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to store KSK: {e}"),
        );
    }
    let mut zsk_data: &[u8] = &zsk_bytes;
    if let Err(e) = store.put(OBJ_DNSSEC_ZSK, &mut zsk_data).await {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to store ZSK: {e}"),
        );
    }

    // Compute key tag for response.
    let key_tag = load_ksk_key_tag(&ksk_bytes).unwrap_or_default();

    info!(key_tag, "DNSSEC keys generated and stored");

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "created",
            "algorithm": "ECDSAP256SHA256",
            "algorithm_number": 13,
            "ksk_key_tag": key_tag,
        })),
    )
        .into_response()
}

/// GET /api/dnssec/status — check if keys exist.
pub async fn dnssec_status(State(state): State<AppState>) -> impl IntoResponse {
    let store = match state.js.get_object_store(BUCKET_DNSSEC).await {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "configured": false,
                    "ksk_present": false,
                    "zsk_present": false,
                })),
            )
                .into_response();
        }
    };

    let ksk = store.info(OBJ_DNSSEC_KSK).await;
    let zsk = store.info(OBJ_DNSSEC_ZSK).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "configured": true,
            "ksk_present": ksk.is_ok(),
            "ksk_size": ksk.as_ref().map(|i| i.size).unwrap_or(0),
            "zsk_present": zsk.is_ok(),
            "zsk_size": zsk.as_ref().map(|i| i.size).unwrap_or(0),
        })),
    )
        .into_response()
}

/// GET /api/dnssec/ds/{origin} — compute DS record from KSK.
pub async fn ds_record(
    State(state): State<AppState>,
    Path(origin): Path<String>,
) -> impl IntoResponse {
    let store = match state.js.get_object_store(BUCKET_DNSSEC).await {
        Ok(s) => s,
        Err(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "DNSSEC keys not found (run keygen first)",
            );
        }
    };

    // Load KSK.
    let ksk_bytes = match read_object_bytes(&store, OBJ_DNSSEC_KSK).await {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode::NOT_FOUND, &format!("KSK not found: {e}")),
    };

    let algorithm = Algorithm::ECDSAP256SHA256;
    let ksk_signing =
        match EcdsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(ksk_bytes), algorithm) {
            Ok(k) => k,
            Err(e) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to load KSK: {e}"),
                );
            }
        };

    let ksk_pub = match ksk_signing.to_public_key() {
        Ok(k) => k,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("KSK public key: {e}"),
            );
        }
    };
    let ksk_dnskey = DNSKEY::new(true, true, false, ksk_pub);

    let origin_fqdn = if origin.ends_with('.') {
        origin.clone()
    } else {
        format!("{origin}.")
    };
    let origin_name = match Name::from_str_relaxed(&origin_fqdn) {
        Ok(n) => n,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid origin: {e}")),
    };

    let key_tag = match ksk_dnskey.calculate_key_tag() {
        Ok(t) => t,
        Err(e) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("key tag: {e}"));
        }
    };

    let digest = match ksk_dnskey.to_digest(&origin_name, DigestType::SHA256) {
        Ok(d) => d,
        Err(e) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("digest: {e}"));
        }
    };

    let ds = DS::new(
        key_tag,
        algorithm,
        DigestType::SHA256,
        digest.as_ref().to_owned(),
    );
    let digest_hex: String = ds.digest().iter().map(|b| format!("{b:02X}")).collect();
    let ds_record = format!("{origin_name} IN DS {key_tag} 13 2 {digest_hex}");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ds_record": ds_record,
            "key_tag": key_tag,
            "algorithm": 13,
            "digest_type": 2,
            "digest": digest_hex,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Key rollover
// ---------------------------------------------------------------------------

/// POST /api/dnssec/rollover/zsk — generate a new ZSK, store it, and trigger zone rebuild.
/// KSK is unchanged — no DS update at registrar needed.
pub async fn rollover_zsk(State(state): State<AppState>) -> impl IntoResponse {
    let store = match provision_dnssec_bucket(&state).await {
        Ok(s) => s,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    // Verify KSK exists (rollover only makes sense with an existing key pair).
    if store.info(OBJ_DNSSEC_KSK).await.is_err() {
        return error_response(
            StatusCode::PRECONDITION_FAILED,
            "KSK not found — run `nameserver dnssec keygen` first",
        );
    }

    // Generate new ZSK.
    let algorithm = Algorithm::ECDSAP256SHA256;
    let zsk_pkcs8 = match EcdsaSigningKey::generate_pkcs8(algorithm) {
        Ok(k) => k,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("ZSK keygen failed: {e}"),
            );
        }
    };

    // Compute old ZSK key tag for the response.
    let old_tag = match read_object_bytes(&store, OBJ_DNSSEC_ZSK).await {
        Ok(bytes) => load_zsk_key_tag(&bytes).unwrap_or(0),
        Err(_) => 0,
    };

    // Store new ZSK (overwrites old).
    let zsk_bytes = zsk_pkcs8.secret_pkcs8_der().to_vec();
    let mut zsk_data: &[u8] = &zsk_bytes;
    if let Err(e) = store.put(OBJ_DNSSEC_ZSK, &mut zsk_data).await {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to store ZSK: {e}"),
        );
    }

    let new_tag = load_zsk_key_tag(&zsk_bytes).unwrap_or(0);
    info!(old_tag, new_tag, "ZSK rolled over");

    // Bump zone config version to trigger zone watcher rebuild.
    // The watcher loads fresh keys from Object Store automatically.
    let kv_bumped = match bump_zone_config_version(&state).await {
        Ok(true) => true,
        Ok(false) => {
            warn!(
                "no zone config found in KV to bump — authority will pick up new ZSK on next restart"
            );
            false
        }
        Err(e) => {
            warn!(error = %e, "failed to bump zone config version (non-fatal)");
            false
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "rolled_over",
            "key_type": "ZSK",
            "old_key_tag": old_tag,
            "new_key_tag": new_tag,
            "zone_rebuild_triggered": kv_bumped,
        })),
    )
        .into_response()
}

/// Bump the version field in the zone config KV entry to trigger a zone watcher rebuild.
async fn bump_zone_config_version(state: &AppState) -> anyhow::Result<bool> {
    let kv = state.js.get_key_value(BUCKET_CONFIG).await?;

    let mut keys = kv.keys().await?;
    let mut bumped = false;
    while let Some(key) = keys.next().await {
        let key = key?;
        if !key.starts_with(KV_ZONE_PREFIX) {
            continue;
        }
        let Some(entry) = kv.get(&key).await? else {
            continue;
        };
        let mut config: serde_json::Value = rmp_serde::from_slice(&entry)?;
        let version = config["version"]
            .as_u64()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("zone revision exhausted"))?;
        config["version"] = serde_json::json!(version);
        kv.put(&key, rmp_serde::to_vec_named(&config)?.into())
            .await?;
        bumped = true;
    }
    Ok(bumped)
}

// ---------------------------------------------------------------------------
// Zone configuration
// ---------------------------------------------------------------------------

/// GET /api/zones — list all zone configs from NATS KV.
pub async fn list_zones(State(state): State<AppState>) -> impl IntoResponse {
    let kv = match state.js.get_key_value(BUCKET_CONFIG).await {
        Ok(kv) => kv,
        Err(e) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("KV store: {e}"));
        }
    };

    let mut zones = Vec::new();
    let Ok(mut keys) = kv.keys().await else {
        let empty: Vec<serde_json::Value> = Vec::new();
        return (StatusCode::OK, Json(serde_json::json!({ "zones": empty }))).into_response();
    };
    while let Some(key) = keys.next().await {
        if let Ok(k) = key
            && let Some(origin) = k.strip_prefix(KV_ZONE_PREFIX)
        {
            let mut entry = serde_json::json!({ "origin": origin });
            // Try to decode config for summary info.
            if let Ok(Some(bytes)) = kv.get(&k).await
                && let Ok(config) = rmp_serde::from_slice::<serde_json::Value>(&bytes)
            {
                entry["version"] = config["version"].clone();
                entry["record_count"] =
                    serde_json::json!(config["records"].as_array().map(|a| a.len()).unwrap_or(0));
                entry["dnssec_enabled"] =
                    serde_json::json!(config["dnssec"]["enabled"].as_bool().unwrap_or(false));
            }
            zones.push(entry);
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "zones": zones }))).into_response()
}

/// GET /api/zone/{origin} — get current zone config from NATS KV.
pub async fn get_zone(
    State(state): State<AppState>,
    Path(origin): Path<String>,
) -> impl IntoResponse {
    let kv = match state.js.get_key_value(BUCKET_CONFIG).await {
        Ok(kv) => kv,
        Err(e) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("KV store: {e}"));
        }
    };

    let key = zone_kv_key(&origin);
    match kv.get(&key).await {
        Ok(Some(bytes)) => match rmp_serde::from_slice::<serde_json::Value>(&bytes) {
            Ok(config) => (StatusCode::OK, Json(config)).into_response(),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("parse zone: {e}"),
            ),
        },
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &format!("zone '{origin}' not found in KV"),
        ),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("KV get: {e}")),
    }
}

/// PUT /api/zone/{origin} — update zone config in NATS KV.
pub async fn update_zone(
    State(state): State<AppState>,
    Path(origin): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let kv = match state.js.get_key_value(BUCKET_CONFIG).await {
        Ok(kv) => kv,
        Err(e) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("KV store: {e}"));
        }
    };

    // Validate: must have "origin" field matching the path.
    if let Some(body_origin) = body.get("origin").and_then(|v| v.as_str()) {
        let clean = origin.strip_suffix('.').unwrap_or(&origin);
        let body_clean = body_origin.strip_suffix('.').unwrap_or(body_origin);
        if clean != body_clean {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("origin mismatch: path={clean}, body={body_clean}"),
            );
        }
    }

    let bytes = match rmp_serde::to_vec_named(&body) {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("serialize: {e}")),
    };

    let key = zone_kv_key(&origin);
    match kv.put(&key, bytes.into()).await {
        Ok(revision) => {
            info!(revision, "zone config updated via API");
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "updated", "origin": origin, "revision": revision })),
            )
                .into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("KV put: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use nameserver_common::nats_subjects::zone_kv_key;

async fn provision_dnssec_bucket(
    state: &AppState,
) -> anyhow::Result<async_nats::jetstream::object_store::ObjectStore> {
    match state
        .js
        .create_object_store(async_nats::jetstream::object_store::Config {
            bucket: BUCKET_DNSSEC.to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(s) => Ok(s),
        Err(_) => Ok(state.js.get_object_store(BUCKET_DNSSEC).await?),
    }
}

async fn read_object_bytes(
    store: &async_nats::jetstream::object_store::ObjectStore,
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut obj = store.get(name).await?;
    let mut bytes = Vec::new();
    obj.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

fn load_zsk_key_tag(zsk_pkcs8: &[u8]) -> anyhow::Result<u16> {
    let algorithm = Algorithm::ECDSAP256SHA256;
    let signing =
        EcdsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(zsk_pkcs8.to_vec()), algorithm)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pub_key = signing
        .to_public_key()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let dnskey = DNSKEY::new(true, false, false, pub_key); // ZSK: no SEP
    dnskey
        .calculate_key_tag()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn load_ksk_key_tag(ksk_pkcs8: &[u8]) -> anyhow::Result<u16> {
    let algorithm = Algorithm::ECDSAP256SHA256;
    let signing =
        EcdsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(ksk_pkcs8.to_vec()), algorithm)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pub_key = signing
        .to_public_key()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let dnskey = DNSKEY::new(true, true, false, pub_key);
    dnskey
        .calculate_key_tag()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn error_response(status: StatusCode, message: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}
