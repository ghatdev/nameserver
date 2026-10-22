//! Benign-label sampler — the PR-C half of the anti-contamination
//! design. The detector can only avoid learning "injected == malicious"
//! if benign domains flow through the same injection path (same profile
//! pool, same resolvers, same cadence) as the malicious ones. This task
//! is the benign producer: it samples domains from a well-known list
//! (tranco / majestic) and enqueues them into `injection_queue` with
//! `label_verdict = benign`. The existing scheduler drains them through
//! the same DoH path as TIF rows, so the per-flow features a detector
//! sees are indistinguishable between labels.
//!
//! This module is intentionally minimal and stateless: each tick is
//! one SQL statement that samples N rows from `indicator_domains` and
//! INSERTs them into `injection_queue` with `ON CONFLICT DO NOTHING`.
//! No in-memory cursor, no retry queue, no special failure path. If a
//! tick errors, it's logged and the next tick moves on.

use std::time::Duration;

use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::BenignSamplerConfig;
use crate::injector::priority;

pub fn spawn_benign_sampler(config: BenignSamplerConfig, pool: PgPool) -> Option<JoinHandle<()>> {
    if !config.enabled {
        info!("benign sampler: disabled in config; not spawning");
        return None;
    }
    info!(
        source = %config.source_slug,
        batch = config.batch_size,
        interval_secs = config.interval_secs,
        "benign sampler: starting"
    );
    Some(tokio::spawn(sampler_loop(config, pool)))
}

async fn sampler_loop(config: BenignSamplerConfig, pool: PgPool) {
    let mut ticker = tokio::time::interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match sample_and_enqueue(&pool, &config).await {
            Ok(0) => debug!("benign sampler: tick produced no new rows"),
            Ok(n) => debug!(enqueued = n, "benign sampler: tick done"),
            Err(e) => warn!(error = %e, "benign sampler: tick failed"),
        }
    }
}

/// Single-statement sample-and-enqueue. Picks N random rows from the
/// configured source's domain list and bulk-inserts them into the
/// injection queue. `ON CONFLICT DO NOTHING` handles the case where a
/// sampled domain already has an active row for this source (re-sampled
/// before its previous copy drained) — those rows are just skipped.
///
/// We sort by `random()` rather than using `TABLESAMPLE` so the query
/// works on any PG table regardless of storage params; at 1M-row tranco
/// and the sampler's modest batch sizes this is sub-100ms in practice.
async fn sample_and_enqueue(pool: &PgPool, config: &BenignSamplerConfig) -> anyhow::Result<u64> {
    let res = sqlx::query(
        "INSERT INTO injection_queue \
           (domain, source_slug, label_verdict, priority, scheduled_for) \
         SELECT d.domain, $1, 'benign', $2, NOW() \
           FROM indicator_domains d \
           JOIN sources s ON s.id = d.source \
          WHERE s.slug = $1 \
          ORDER BY random() \
          LIMIT $3 \
         ON CONFLICT DO NOTHING",
    )
    .bind(&config.source_slug)
    .bind(priority::BENIGN)
    .bind(config.batch_size)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
