//! Resolution injector — continuous label acquisition for the detector.
//!
//! # Why this exists
//!
//! Prior to 2026-04-20 the detector's malicious training flows were 99.9%
//! from a single one-shot bulk resolution session. That created a detectable
//! per-flow signature (one profile_id, two-day window, mostly post-cleanup
//! NODATA responses) which the model ended up memorizing instead of real
//! malicious patterns. See memory `project_bulk_resolution_contamination.md`.
//!
//! This module replaces that approach with a continuous, diff-driven,
//! anti-signature injection pipeline:
//!
//! 1. **Autopull diff hook** (future PR): when `indicator_domains` gets a
//!    new entry (identified by `added_at > prior_pull_time`), the injector
//!    enqueues a row in `injection_queue`.
//! 2. **Scheduler**: a background task dequeues pending rows at an
//!    organic-looking rate, sends a DoH query to our own nameserver-resolver.
//!    The resolver treats it identically to a real user query; a DnsFlow
//!    is published to NATS as usual.
//! 3. **NATS reconciliation** (future PR): a separate durable JetStream
//!    consumer (`CONSUMER_CONTROL_INJECTOR`) on `ns.dns.flow` matches
//!    returning flows to queue rows by domain.
//!
//! # Independence from flow processing
//!
//! Runs on its own async task and owns only its PG state. Failure here
//! (DoH timeouts, queue stuck, runaway scheduler) cannot back-pressure
//! flow ingestion or analytics. The only blast radius is stalled label
//! acquisition.
//!
//! # Status — PR-2 (2026-04-20)
//!
//! Scheduler loop + DoH client landed. NATS reconciliation + autopull
//! Source reconciliation feeds the injection queue through the control-plane API.
//! `project_resolution_injector.md` for the full design.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use nameserver_common::messages::flow::DnsFlow;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::{DohResolver, InjectorConfig};

/// Channel capacity for NATS → reconciler. Oversized to avoid
/// back-pressure from reconciler onto the NATS consumer; drops on
/// full are fine (reconciliation is best-effort).
const RECONCILE_CHANNEL_CAPACITY: usize = 4096;

const DOH_CONTENT_TYPE: &str = "application/dns-message";

/// Lifecycle of a single `injection_queue` row. Mirrors the PG enum
/// `injection_status` defined in
/// `atlas/migrations/postgres/20260420000000_add_injection_queue.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "injection_status", rename_all = "snake_case")]
pub enum InjectionStatus {
    /// Not yet attempted.
    Pending,
    /// DoH query sent, awaiting flow reconciliation.
    InFlight,
    /// Reconciled to a flow_id; resolution recorded.
    Resolved,
    /// Attempt ended in error; eligible for retry.
    Failed,
    /// Exceeded retry budget; will not be attempted again.
    Abandoned,
}

/// The label semantics we want to associate with the domain we're
/// resolving. Kept as a typed enum to avoid raw-string comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelVerdict {
    Malicious,
    Benign,
}

impl LabelVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            LabelVerdict::Malicious => "malicious",
            LabelVerdict::Benign => "benign",
        }
    }
}

/// A row in the injection_queue.
#[derive(Debug, Clone)]
pub struct InjectionQueueRow {
    pub id: i64,
    pub domain: String,
    pub source_slug: String,
    pub label_verdict: LabelVerdict,
    pub enqueued_at: OffsetDateTime,
    pub scheduled_for: OffsetDateTime,
    pub attempt_count: i32,
    pub last_attempt_at: Option<OffsetDateTime>,
    pub status: InjectionStatus,
    pub resolved_flow_id: Option<Uuid>,
    pub resolved_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}

/// Drain priority for an `injection_queue` row — lower value is served
/// first by the scheduler. Mirrors the values backfilled in migration
/// `20260423000000_iq_priority.sql`.
pub mod priority {
    /// Direct malicious-label signal (TIF, DGA). Detector training
    /// depends on these being fresh, so they cut the line.
    pub const MALICIOUS_HIGH: i32 = 10;
    /// Benign-injected rows (tranco/majestic sampler). Between the
    /// malicious feeds and general blocklists so we keep a healthy
    /// label balance without starving either.
    pub const BENIGN: i32 = 50;
    /// Default — any source not otherwise classified.
    pub const DEFAULT: i32 = 100;
}

/// Enqueue a (domain, source, verdict) triple for injection. Upsert-style:
/// if an active row already exists for this (domain, source_slug), the
/// call is a no-op (the unique index enforces this). Returns true iff a
/// new row was inserted.
pub async fn enqueue(
    pool: &PgPool,
    domain: &str,
    source_slug: &str,
    verdict: LabelVerdict,
    priority: i32,
    scheduled_for: OffsetDateTime,
) -> anyhow::Result<bool> {
    let res = sqlx::query(
        "INSERT INTO injection_queue \
           (domain, source_slug, label_verdict, priority, scheduled_for) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT DO NOTHING",
    )
    .bind(domain)
    .bind(source_slug)
    .bind(verdict.as_str())
    .bind(priority)
    .bind(scheduled_for)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ---------------------------------------------------------------------------
// Scheduler + DoH dispatch
// ---------------------------------------------------------------------------

/// One resolver the injector can dispatch through. Built once at
/// startup from config: the `http` client has its DNS pre-resolved so
/// every request hits the intended `ip:port`, and `url_prefix` is the
/// final `https://{host}[:port]` string reused per dispatch.
struct ResolverClient {
    name: String,
    http: reqwest::Client,
    url_prefix: String,
}

/// Shared context for the injector background task.
struct InjectorCtx {
    pool: PgPool,
    resolvers: Arc<Vec<ResolverClient>>,
    resolver_rr: Arc<AtomicUsize>,
    profile_pool: Arc<Vec<String>>,
    profile_rr: Arc<AtomicUsize>,
    batch_size: i64,
    tick_interval: Duration,
    max_attempts: i32,
    retry_backoff: Duration,
}

impl InjectorCtx {
    /// Pick the next profile_id to use. Round-robin within the pool so no
    /// single profile ends up on a disproportionate share of queries —
    /// that was the signature of the prior bulk session.
    fn pick_profile(&self) -> &str {
        pick_profile_rr(&self.profile_pool, &self.profile_rr)
    }

    /// Pick the next resolver. Round-robin independent of profile so the
    /// (profile × resolver) cross product is exhausted every
    /// lcm(len(profile_pool), len(resolvers)) queries — which, for
    /// coprime counts, is their product.
    fn pick_resolver(&self) -> &ResolverClient {
        let i = self.resolver_rr.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
        &self.resolvers[i]
    }
}

fn pick_profile_rr<'a>(pool: &'a [String], rr: &AtomicUsize) -> &'a str {
    let i = rr.fetch_add(1, Ordering::Relaxed) % pool.len();
    pool[i].as_str()
}

fn build_resolver_client(
    r: &DohResolver,
    timeout: Duration,
    verify_tls: bool,
) -> anyhow::Result<ResolverClient> {
    let addr = SocketAddr::new(r.ip, r.port);
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(!verify_tls)
        .resolve(&r.host, addr)
        .build()?;
    // Omit :443 from URL so it stays canonical and the cert SNI check is
    // unambiguous; any other port is reflected explicitly.
    let url_prefix = if r.port == 443 {
        format!("https://{}", r.host)
    } else {
        format!("https://{}:{}", r.host, r.port)
    };
    Ok(ResolverClient {
        name: r.name.clone(),
        http,
        url_prefix,
    })
}

/// Spawn the injector scheduler task. Returns a JoinHandle the caller can
/// store but typically doesn't need to await. No-op (and returns a dummy
/// handle) when `config.enabled` is false.
pub fn spawn_injector(
    config: InjectorConfig,
    pool: PgPool,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    if !config.enabled {
        info!("injector: disabled in config; not spawning");
        return Ok(None);
    }
    if config.profile_pool.is_empty() {
        anyhow::bail!(
            "injector.profile_pool is empty — anti-signature requires at least a \
             few rotating profile_ids; refusing to start"
        );
    }
    if config.doh_resolvers.is_empty() {
        anyhow::bail!(
            "injector.doh_resolvers is empty — need at least one resolver to \
             dispatch through; refusing to start"
        );
    }

    let timeout = Duration::from_secs(config.doh_timeout_secs);
    let mut resolvers = Vec::with_capacity(config.doh_resolvers.len());
    for r in &config.doh_resolvers {
        resolvers.push(build_resolver_client(r, timeout, config.verify_tls)?);
    }
    let resolver_names: Vec<String> = resolvers.iter().map(|r| r.name.clone()).collect();

    let ctx = InjectorCtx {
        pool,
        resolvers: Arc::new(resolvers),
        resolver_rr: Arc::new(AtomicUsize::new(0)),
        profile_pool: Arc::new(config.profile_pool.clone()),
        profile_rr: Arc::new(AtomicUsize::new(0)),
        batch_size: config.batch_size,
        tick_interval: Duration::from_secs(config.tick_secs),
        max_attempts: config.max_attempts,
        retry_backoff: Duration::from_secs(config.retry_backoff_secs),
    };

    info!(
        resolvers = ?resolver_names,
        pool_size = config.profile_pool.len(),
        batch = config.batch_size,
        tick_secs = config.tick_secs,
        "injector: starting scheduler",
    );

    let handle = tokio::spawn(scheduler_loop(ctx));
    Ok(Some(handle))
}

async fn scheduler_loop(ctx: InjectorCtx) {
    let mut ticker = tokio::time::interval(ctx.tick_interval);
    // On startup, skip the immediate tick so the service isn't hammered
    // right after boot.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match drain_batch(&ctx).await {
            Ok(0) => debug!("injector: tick produced no rows"),
            Ok(n) => debug!(dispatched = n, "injector: tick dispatched"),
            Err(e) => warn!(error = %e, "injector: tick failed"),
        }
    }
}

/// Claim up to `batch_size` pending rows in a single UPDATE … FOR UPDATE
/// SKIP LOCKED … RETURNING transaction, then dispatch all of them
/// concurrently. Concurrency keeps a slow row (DoH timeout on a dead
/// malicious domain) from serialising the rest of the batch — under
/// sequential dispatch the worst-case batch ran in `batch * timeout`.
async fn drain_batch(ctx: &InjectorCtx) -> anyhow::Result<usize> {
    let claimed: Vec<(i64, String)> = sqlx::query_as(
        "UPDATE injection_queue \
            SET status = 'in_flight'::injection_status, \
                attempt_count = attempt_count + 1, \
                last_attempt_at = NOW() \
          WHERE id IN ( \
              SELECT id FROM injection_queue \
               WHERE status = 'pending'::injection_status \
                 AND scheduled_for <= NOW() \
               ORDER BY priority, scheduled_for \
               FOR UPDATE SKIP LOCKED \
               LIMIT $1 \
          ) \
         RETURNING id, domain",
    )
    .bind(ctx.batch_size)
    .fetch_all(&ctx.pool)
    .await?;

    let n = claimed.len();
    let mut tasks: FuturesUnordered<_> = claimed
        .into_iter()
        .map(|(id, domain)| async move {
            if let Err(e) = dispatch(ctx, id, &domain).await {
                warn!(
                    error = %e,
                    id,
                    "injector: DoH dispatch failed; recording failure",
                );
                if let Err(e2) = mark_failed(ctx, id, &format!("{e:#}")).await {
                    warn!(error = %e2, id, "injector: failed to mark row failed");
                }
            }
        })
        .collect();
    while tasks.next().await.is_some() {}
    Ok(n)
}

async fn dispatch(ctx: &InjectorCtx, id: i64, domain: &str) -> anyhow::Result<()> {
    let profile = ctx.pick_profile();
    let resolver = ctx.pick_resolver();
    let wire = build_dns_query(domain)?;
    let url = format!("{}/{}", resolver.url_prefix, profile);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(DOH_CONTENT_TYPE));
    headers.insert(ACCEPT, HeaderValue::from_static(DOH_CONTENT_TYPE));

    let resp = resolver
        .http
        .post(&url)
        .headers(headers)
        .body(wire)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("DoH resolver {} returned HTTP {status}", resolver.name);
    }
    // We intentionally discard the response body — the returning flow
    // will arrive via NATS and be reconciled by the consumer in PR-3.
    // Until then, the row stays in_flight (and will eventually retry if
    // reconciliation doesn't happen).
    debug!(id, resolver = %resolver.name, "injector: DoH dispatched");
    Ok(())
}

/// Build a standard A-record DNS query for the given domain. Uses a
/// random transaction ID + recursion-desired; signed DNSSEC querying is
/// handled by the resolver itself, not by us.
fn build_dns_query(domain: &str) -> anyhow::Result<Vec<u8>> {
    let name = Name::from_ascii(domain)?;
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, RecordType::A));
    Ok(msg.to_bytes()?)
}

// ---------------------------------------------------------------------------
// NATS reconciliation
// ---------------------------------------------------------------------------

/// Create the channel the NATS consumer pushes flows into.
pub fn reconcile_channel() -> (mpsc::Sender<DnsFlow>, mpsc::Receiver<DnsFlow>) {
    mpsc::channel(RECONCILE_CHANNEL_CAPACITY)
}

/// Spawn the reconciler loop. Reads flows from the NATS injector
/// consumer, strips the trailing dot from domain, atomically updates
/// any matching `in_flight` queue row to `resolved` with the flow_id.
/// Non-match → drop (real user flows share this stream and should not
/// affect queue state).
pub fn spawn_reconciler(pool: PgPool, mut rx: mpsc::Receiver<DnsFlow>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(flow) = rx.recv().await {
            let domain = flow.query.domain.trim_end_matches('.').to_string();
            if domain.is_empty() {
                continue;
            }
            match reconcile_flow(&pool, &domain, flow.flow_id).await {
                Ok(matched) if matched > 0 => {
                    debug!(domain = %domain, flow_id = %flow.flow_id, matched, "injector: reconciled");
                }
                Ok(_) => {} // no matching in_flight row — typical for real user traffic
                Err(e) => warn!(
                    error = %e,
                    flow_id = %flow.flow_id,
                    "injector: reconciler PG update failed",
                ),
            }
        }
        info!("injector: reconcile channel closed");
    })
}

async fn reconcile_flow(pool: &PgPool, domain: &str, flow_id: Uuid) -> anyhow::Result<u64> {
    // Atomically transition exactly the in-flight row(s) for this domain
    // (usually 0 or 1) into 'resolved', stamping flow_id + resolved_at.
    // A partial unique index (idx_iq_active_uniq) guarantees at most one
    // active row per (domain, source_slug), so in practice this is
    // bounded by the number of sources that enqueued the same domain.
    let res = sqlx::query(
        "UPDATE injection_queue \
            SET status = 'resolved'::injection_status, \
                resolved_flow_id = $2, \
                resolved_at = NOW() \
          WHERE domain = $1 \
            AND status = 'in_flight'::injection_status",
    )
    .bind(domain)
    .bind(flow_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

async fn mark_failed(ctx: &InjectorCtx, id: i64, err: &str) -> anyhow::Result<()> {
    // If we've exhausted retries, mark abandoned; otherwise schedule the
    // next attempt after a backoff and put the row back in pending state.
    //
    // Computing the retry decision in SQL lets this run in one round-trip
    // and keeps the state machine visible to operators running ad-hoc
    // queries against the queue.
    let backoff_secs = ctx.retry_backoff.as_secs() as i64;
    sqlx::query(
        "UPDATE injection_queue \
            SET status = CASE \
                    WHEN attempt_count >= $2 THEN 'abandoned'::injection_status \
                    ELSE 'pending'::injection_status END, \
                scheduled_for = CASE \
                    WHEN attempt_count >= $2 THEN scheduled_for \
                    ELSE NOW() + make_interval(secs => $3) END, \
                last_error = $4 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(ctx.max_attempts)
    .bind(backoff_secs)
    .bind(err)
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_is_valid_wire_format() {
        // A query for "example.com" must encode without error and start
        // with a 12-byte header.
        let wire = build_dns_query("example.com").unwrap();
        assert!(wire.len() > 12, "encoded query too short: {}", wire.len());
        // qdcount in the header is the 5th/6th byte (big-endian u16).
        let qd = u16::from_be_bytes([wire[4], wire[5]]);
        assert_eq!(qd, 1, "expected qdcount=1, got {qd}");
    }

    #[test]
    fn round_robin_cycles_pool() {
        let pool = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let rr = AtomicUsize::new(0);
        let seq: Vec<&str> = (0..7).map(|_| pick_profile_rr(&pool, &rr)).collect();
        assert_eq!(seq, vec!["a", "b", "c", "a", "b", "c", "a"]);
    }
}
