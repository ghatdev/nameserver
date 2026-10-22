mod compile;
mod detector;
mod dnssec;
mod domains;
mod feeds;
pub mod filters;
mod flows;
pub(crate) mod geoip;
mod ips;
mod lists;
mod metrics;
mod mobileconfig;
mod ns_map;
mod profiles;
pub mod rdap;
mod reputation;
pub mod sources;
mod status;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use time::OffsetDateTime;

use crate::config::{ClickHouseConfig, DnsConfig};
use crate::db::Database;

/// Format an `OffsetDateTime` as an RFC 3339 string for JSON responses.
/// The default `time` serde serializes as a tuple, which breaks CLI parsing.
pub fn rfc3339(dt: Option<OffsetDateTime>) -> serde_json::Value {
    match dt.and_then(|dt| {
        dt.format(&time::format_description::well_known::Rfc3339)
            .ok()
    }) {
        Some(s) => serde_json::Value::String(s),
        None => serde_json::Value::Null,
    }
}

/// Return a generic error to the client while logging the detail server-side.
/// Prevents leaking internal schema, query text, or PostgreSQL version info.
pub fn internal_error(e: impl std::fmt::Display) -> impl IntoResponse {
    tracing::debug!(error = %e, "request failed");
    tracing::warn!("request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "internal server error" })),
    )
}

/// Shared application state for all API handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub ch: clickhouse::Client,
    pub nats_client: async_nats::Client,
    pub js: async_nats::jetstream::Context,
    pub ch_config: ClickHouseConfig,
    pub dns_config: DnsConfig,
    pub suffix_set: std::sync::Arc<arc_swap::ArcSwap<nameserver_common::suffix::SuffixSet>>,
}

/// Build the axum Router with all API routes.
pub fn router() -> Router<AppState> {
    Router::new()
        // Flows
        .route("/api/flows", get(flows::get_flows))
        .route("/api/flows/live", get(flows::live_flows))
        // Domains
        .route("/api/domains", get(domains::list_domains))
        .route("/api/domains/{domain}", get(domains::get_domain))
        // IPs
        .route("/api/ips/{ip}", get(ips::get_ip))
        // Lists
        .route(
            "/api/lists/{kind}",
            get(lists::get_list).post(lists::modify_list),
        )
        .route("/api/lists/{kind}/import", post(lists::import_list))
        // Feeds (threat intel only)
        .route("/api/feeds", get(feeds::get_feeds))
        // Indicator sources (data origin management)
        .route(
            "/api/sources",
            get(sources::list_sources).post(sources::create_source),
        )
        // Static "full" routes BEFORE parameterized {slug} to avoid capture.
        .route("/api/sources/full", get(sources::list_sources_full))
        .route(
            "/api/sources/{slug}",
            get(sources::get_source)
                .put(sources::update_source)
                .delete(sources::delete_source),
        )
        .route("/api/sources/{slug}/full", put(sources::upsert_source_full))
        .route("/api/sources/{slug}/pull", post(sources::pull_source))
        // Filters (compiled artifacts)
        .route(
            "/api/filters",
            get(filters::list_filters).post(filters::create_filter),
        )
        .route(
            "/api/filters/{slug}",
            get(filters::get_filter)
                .put(filters::update_filter)
                .delete(filters::delete_filter),
        )
        .route("/api/filters/compile", post(filters::compile_all))
        // Profiles
        .route(
            "/api/profiles",
            get(profiles::list_profiles).post(profiles::create_profile),
        )
        .route(
            "/api/profiles/{id}",
            get(profiles::get_profile)
                .put(profiles::update_profile)
                .delete(profiles::delete_profile),
        )
        .route(
            "/api/profiles/{id}/filters",
            post(profiles::subscribe_filter),
        )
        .route(
            "/api/profiles/{id}/filters/{filter_id}",
            axum::routing::delete(profiles::unsubscribe_filter),
        )
        .route(
            "/api/profiles/{id}/custom",
            post(profiles::add_custom_entry),
        )
        .route(
            "/api/profiles/{id}/custom/{domain}",
            axum::routing::delete(profiles::remove_custom_entry),
        )
        // Profile diff/apply (per-resource reconciliation)
        .route("/api/profiles/diff", get(profiles::profile_diff))
        .route("/api/profiles/apply", post(profiles::profile_apply))
        // Filter diff/apply (per-resource reconciliation)
        .route("/api/filters/diff", get(filters::filter_diff))
        .route("/api/filters/apply", post(filters::filter_apply))
        // Compile (legacy: used by autopull)
        .route("/api/compile", post(compile::compile_filters))
        // GeoIP
        .route("/api/geoip/status", get(geoip::geoip_status))
        .route("/api/geoip/compile", post(geoip::compile_geoip))
        .route("/api/geoip/lookup/{ip}", get(geoip::lookup_geoip))
        .route("/api/geoip/diff", get(geoip::geoip_diff))
        .route("/api/geoip/apply", post(geoip::geoip_apply))
        // RDAP
        .route("/api/rdap/pull", post(rdap::pull_rdap))
        .route("/api/rdap/status", get(rdap::rdap_status))
        .route("/api/rdap/lookup/{domain}", get(rdap::rdap_lookup))
        // ML-based detector scores
        .route("/api/detector/scores", get(detector::get_detector_scores))
        .route("/api/detector/scores/live", get(detector::live_scores))
        // Domain reputation
        .route("/api/reputation/{domain}", get(reputation::get_reputation))
        // NS map (domain_ns_map bootstrap)
        .route("/api/ns-map/import", post(ns_map::import_ns_map))
        .route("/api/ns-map/status", get(ns_map::ns_map_status))
        // Well-known domains (Tranco, Majestic — reference data)
        .route("/api/well-known/domains", get(ns_map::well_known_domains))
        // NRD (Newly Registered Domains)
        .route("/api/nrd/check/{domain}", get(ns_map::nrd_check))
        // Threat feeds (domain + IP intelligence)
        .route("/api/threat-feed/domains", get(ns_map::threat_feed_domains))
        .route("/api/threat-feed/ips", get(ns_map::threat_feed_ips))
        .route(
            "/api/threat-feed/check/{domain}",
            get(ns_map::threat_feed_check),
        )
        // DNSSEC
        .route("/api/dnssec/keygen", post(dnssec::keygen))
        .route("/api/dnssec/status", get(dnssec::dnssec_status))
        .route("/api/dnssec/ds/{origin}", get(dnssec::ds_record))
        .route("/api/dnssec/rollover/zsk", post(dnssec::rollover_zsk))
        // Zone config
        .route("/api/zones", get(dnssec::list_zones))
        .route(
            "/api/zones/{origin}",
            get(dnssec::get_zone).put(dnssec::update_zone),
        )
        // Mobileconfig (signed Apple configuration profiles)
        .route("/api/mobileconfig", post(mobileconfig::post_mobileconfig))
        // Metrics (Prometheus text format)
        .route("/metrics", get(metrics::get_metrics))
        // Status
        .route("/api/status", get(status::get_status))
}
