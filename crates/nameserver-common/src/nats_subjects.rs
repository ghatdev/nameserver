//! NATS subject and resource name constants shared across all crates.

// --- JetStream Streams ---

/// Stream for DNS flow documents.
pub const STREAM_FLOWS: &str = "NAMESERVER_FLOWS";
/// Subject for flow messages within the NAMESERVER_FLOWS stream.
pub const SUBJECT_FLOW: &str = "ns.dns.flow";

/// Stream for DNS debug events (short retention).
pub const STREAM_EVENTS: &str = "NAMESERVER_EVENTS";
/// Subject prefix for event messages.
pub const SUBJECT_EVENT_PREFIX: &str = "ns.dns.event.>";

// --- Object Store Buckets ---

/// Object Store bucket for compiled FST/XOR filter files.
pub const BUCKET_FILTERS: &str = "nameserver-filters";
/// Object Store bucket for compiled GeoIP table.
pub const BUCKET_GEO: &str = "nameserver-geo";
/// Object Store bucket for ACME certificate distribution.
pub const BUCKET_CERTS: &str = "nameserver-certs";
/// Object key for the cert+key JSON bundle.
pub const OBJ_CERT_BUNDLE: &str = "cert-bundle.json";
/// Object Store bucket for DNSSEC key material.
pub const BUCKET_DNSSEC: &str = "nameserver-dnssec";
/// Object key for the KSK PKCS#8 DER.
pub const OBJ_DNSSEC_KSK: &str = "ksk.p8";
/// Object key for the ZSK PKCS#8 DER.
pub const OBJ_DNSSEC_ZSK: &str = "zsk.p8";

/// Object key for the compiled GeoIP binary file.
pub const OBJ_GEOIP_BIN: &str = "geoip.bin";
/// Object key for the compiled public suffix set.
pub const OBJ_SUFFIX_SET: &str = "suffix-set.bin";

// --- KV Store ---

/// KV bucket for configuration (profile configs, filter manifest, etc.).
pub const BUCKET_CONFIG: &str = "nameserver-config";
/// KV bucket for ACME leader election (short TTL for auto-expiry).
pub const BUCKET_ACME: &str = "nameserver-acme";
/// KV key for the ACME leader lock.
pub const KV_ACME_LEADER: &str = "leader";
/// KV key for the filter manifest listing all shared filters.
pub const KV_FILTER_MANIFEST: &str = "filters.manifest";
/// KV key prefix for authoritative zone configurations.
pub const KV_ZONE_PREFIX: &str = "zone.";
/// KV key prefix for per-profile configuration.
pub const KV_PROFILE_PREFIX: &str = "profiles.";
/// KV key for geoip compile metadata (entry count + checksum).
pub const KV_GEOIP_META: &str = "geoip.meta";
/// KV key for the DNSSEC last-signed-at timestamp (RFC 3339 UTC).
pub const KV_DNSSEC_LAST_SIGNED_AT: &str = "dnssec.last_signed_at";

// --- ACME TXT Sync ---

/// Subject for ACME DNS-01 TXT record set (published by ACME leader, consumed by followers).
pub const SUBJECT_ACME_TXT_SET: &str = "ns.dns.acme-txt.set";
/// Subject for ACME DNS-01 TXT record clear.
pub const SUBJECT_ACME_TXT_CLEAR: &str = "ns.dns.acme-txt.clear";

// --- Reload Signal ---

/// Subject for reload signals from control plane → DNS server.
/// Payload: MessagePack-encoded `ReloadSignal`.
pub const SUBJECT_RELOAD: &str = "ns.ctrl.reload";

// --- Request/Reply Subjects ---

/// Request/reply subject for DNS health checks.
pub const SUBJECT_HEALTH: &str = "ns.ctrl.health";
/// Request/reply subject for DNS list status.
pub const SUBJECT_LIST_STATUS: &str = "ns.ctrl.list.status";

// --- Durable Consumer Names ---

/// Durable consumer for PostgreSQL flow processing (domains, IPs, ML, RDAP).
pub const CONSUMER_CONTROL_PG: &str = "nameserver-control-pg";
/// Durable consumer for ClickHouse flow insertion (time-series analytics).
pub const CONSUMER_CONTROL_CH: &str = "nameserver-control-ch";
/// Durable consumer for the resolution injector's reconciliation path.
/// Matches returning flows back to `injection_queue` rows by domain.
/// Independent cursor so injector failures don't back-pressure CH/PG.
pub const CONSUMER_CONTROL_INJECTOR: &str = "nameserver-control-injector";

// --- Retention ---

/// Maximum age for flow stream messages (7 days).
pub const FLOWS_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum bytes for flow stream (10 GB).
pub const FLOWS_MAX_BYTES: i64 = 10 * 1024 * 1024 * 1024;

/// Maximum age for event stream messages (1 hour).
pub const EVENTS_MAX_AGE_SECS: u64 = 60 * 60;

// --- ML-based detector ---

/// Subject for detector scores (published by the control plane after every
/// scored flow).
pub const SUBJECT_DETECTOR_SCORE: &str = "ns.detector.score";

// --- Helpers ---

/// Build a valid NATS KV key for a zone (strip trailing dot from FQDN).
pub fn zone_kv_key(origin: &str) -> String {
    let clean = origin.strip_suffix('.').unwrap_or(origin);
    format!("{KV_ZONE_PREFIX}{clean}")
}
