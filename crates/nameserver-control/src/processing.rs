use ipnetwork::IpNetwork;
use nameserver_common::messages::flow::DnsFlow;
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::api::rdap::extract_registrable_domain;
use crate::clickhouse::FlowNoveltyRow;
use crate::db::Database;
use crate::detector::{MlRequest, NoveltyContext};

/// Channel capacity for flow processing pipeline.
const PROCESSING_CHANNEL_CAPACITY: usize = 4096;

/// Channel capacity for the novelty → ClickHouse writer.
const NOVELTY_CHANNEL_CAPACITY: usize = 4096;

/// ClickHouse inserter batch ceiling for flow_novelty.
const NOVELTY_CH_MAX_ROWS: u64 = 10_000;
/// ClickHouse inserter commit period for flow_novelty.
const NOVELTY_CH_COMMIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);

/// Create the processing channel and return the sender (for NATS consumer).
pub fn channel() -> (mpsc::Sender<DnsFlow>, mpsc::Receiver<DnsFlow>) {
    mpsc::channel(PROCESSING_CHANNEL_CAPACITY)
}

/// Spawn the PostgreSQL flow processing pipeline.
///
/// Consumes flows from the MPSC channel and upserts into PostgreSQL
/// (domains, IPs, resolution_history), then routes to ML + RDAP workers.
///
/// ClickHouse insertion is handled by a separate NATS consumer
/// (`nameserver-control-ch`) — see `nats::spawn_ch_consumer`.
pub fn spawn_pipeline(
    db: Database,
    mut rx: mpsc::Receiver<DnsFlow>,
    ml_tx: mpsc::Sender<MlRequest>,
    rdap_tx: mpsc::Sender<String>,
    novelty_tx: mpsc::Sender<FlowNoveltyRow>,
    suffix_set: std::sync::Arc<arc_swap::ArcSwap<nameserver_common::suffix::SuffixSet>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!("flow processing pipeline started");
        let mut count: u64 = 0;

        while let Some(flow) = rx.recv().await {
            let domain = flow.query.domain.clone();

            // PostgreSQL upserts.
            let ss = suffix_set.load();
            match upsert_flow(&db.pool, &flow, &ss).await {
                Ok(novelty) => {
                    // Snapshot the bits the ML detector needs before novelty
                    // is moved into the CH inserter channel.
                    let novelty_ctx = NoveltyContext {
                        is_first_contact: novelty.is_first_contact != 0,
                        age_minutes_at_flow: novelty.age_minutes_at_flow,
                    };

                    if novelty_tx.try_send(novelty).is_err() {
                        // Dropping novelty rows on backpressure is acceptable —
                        // this is experimental observability, not on the hot path.
                        debug!("novelty channel full, dropping row");
                    }

                    // Only enqueue resolved flows for ML — blocked flows have no
                    // resolution data (empty path, no IPs) and would produce noise.
                    if !matches!(
                        flow.list_action,
                        nameserver_common::types::ListAction::Block
                    ) {
                        let _ = ml_tx.try_send(MlRequest::FromFlow {
                            flow: flow.clone(),
                            novelty: novelty_ctx,
                        });
                    }

                    // Enqueue RDAP fetch for the registrable domain
                    // (skip non-registrable TLDs: .arpa, .local, .invalid, etc.)
                    if !crate::api::rdap::should_skip_rdap(&domain) {
                        let registrable = extract_registrable_domain(&domain, &ss);
                        let _ = rdap_tx.try_send(registrable);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to upsert flow into PostgreSQL");
                }
            }

            count += 1;
            // (milestone logging removed for privacy)
        }

        info!(total = count, "flow processing pipeline stopped");
    })
}

/// Spawn the ClickHouse inserter for per-flow novelty rows.
///
/// Mirrors the pattern used by `ml_worker::spawn_ml_inserter`: owns its own
/// `clickhouse::Client` + `Inserter`, reconnects on transient failures.
pub fn spawn_novelty_inserter(
    ch_client: ::clickhouse::Client,
    mut rx: mpsc::Receiver<FlowNoveltyRow>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match run_novelty_inserter(&ch_client, &mut rx).await {
                Ok(()) => {
                    info!("flow_novelty inserter stream ended");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "flow_novelty inserter failed, retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    })
}

async fn run_novelty_inserter(
    client: &::clickhouse::Client,
    rx: &mut mpsc::Receiver<FlowNoveltyRow>,
) -> ::clickhouse::error::Result<()> {
    let mut inserter = client
        .inserter::<FlowNoveltyRow>("flow_novelty")
        .with_max_rows(NOVELTY_CH_MAX_ROWS)
        .with_period(Some(NOVELTY_CH_COMMIT_PERIOD));

    loop {
        let time_left = inserter.time_left().unwrap_or(NOVELTY_CH_COMMIT_PERIOD);
        tokio::select! {
            maybe_row = rx.recv() => {
                match maybe_row {
                    Some(row) => {
                        inserter.write(&row).await?;
                        let stats = inserter.commit().await?;
                        if stats.rows > 0 {
                            debug!(rows = stats.rows, "flow_novelty batch committed");
                        }
                    }
                    None => {
                        inserter.end().await?;
                        return Ok(());
                    }
                }
            }
            _ = tokio::time::sleep(time_left) => {
                let stats = inserter.commit().await?;
                if stats.rows > 0 {
                    debug!(rows = stats.rows, "flow_novelty periodic commit");
                }
            }
        }
    }
}

/// Separate channel constructor for the novelty pipeline so main.rs can wire
/// producer + consumer independently.
pub fn novelty_channel() -> (mpsc::Sender<FlowNoveltyRow>, mpsc::Receiver<FlowNoveltyRow>) {
    mpsc::channel(NOVELTY_CHANNEL_CAPACITY)
}

async fn upsert_flow(
    pool: &PgPool,
    flow: &DnsFlow,
    suffix_set: &nameserver_common::suffix::SuffixSet,
) -> anyhow::Result<FlowNoveltyRow> {
    let now = OffsetDateTime::now_utc();

    // Upsert domain. RETURNING tells us whether this was a fresh insert
    // (query_count == 1 → first contact) and gives us the earliest first_seen.
    let domain_row = sqlx::query!(
        "INSERT INTO domains (domain, first_seen, last_seen, query_count, updated_at)
         VALUES ($1, $2, $2, 1, $2)
         ON CONFLICT(domain) DO UPDATE SET
           last_seen = GREATEST(domains.last_seen, $2),
           query_count = domains.query_count + 1,
           updated_at = $2
         RETURNING first_seen, query_count",
        flow.query.domain,
        now,
    )
    .fetch_one(pool)
    .await?;

    // Insert resolution history.
    let ips_json = serde_json::to_value(&flow.response.ips)?;
    let cname_json: Option<serde_json::Value> = flow
        .cname_chain
        .as_ref()
        .filter(|c| !c.is_empty())
        .map(serde_json::to_value)
        .transpose()?;

    let dnssec_status = serde_json::to_value(&flow.dnssec.status)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", flow.dnssec.status));

    // Extract record data from all_records.
    let ns_json: serde_json::Value = flow
        .response
        .all_records
        .ns
        .as_ref()
        .filter(|v| !v.is_empty())
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(serde_json::Value::Array(vec![]));

    let mx_json: serde_json::Value = flow
        .response
        .all_records
        .mx
        .as_ref()
        .filter(|v| !v.is_empty())
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(serde_json::Value::Array(vec![]));

    let a_record_count: i16 = flow
        .response
        .all_records
        .a
        .as_ref()
        .map(|v| v.len() as i16)
        .unwrap_or(0);

    let has_txt: bool = flow
        .response
        .all_records
        .txt
        .as_ref()
        .is_some_and(|v| !v.is_empty());

    let referral_hop_count: i16 = flow.resolution_path.len() as i16;

    let soa_json: Option<serde_json::Value> = flow
        .response
        .all_records
        .soa
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;

    let resolved_at = OffsetDateTime::from_unix_timestamp(flow.started_at / 1000)?;
    let ttl = flow.response.auth_ttl as i32;
    let resolve_ms = flow.total_ms as i32;

    sqlx::query!(
        "INSERT INTO resolution_history (domain, resolved_at, ips, ttl, cname_chain, ns_servers, mx_records, dnssec_status, resolve_ms, a_record_count, has_txt, referral_hop_count, soa_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        flow.query.domain,
        resolved_at,
        ips_json,
        ttl,
        cname_json,
        ns_json,
        mx_json,
        dnssec_status,
        resolve_ms,
        a_record_count,
        has_txt,
        referral_hop_count,
        soa_json,
    )
    .execute(pool)
    .await?;

    // Upsert IPs and domain_ips — parse string to IpNetwork, no SQL cast needed.
    for ip_str in &flow.response.ips {
        let Ok(ip_net) = ip_str.parse::<IpNetwork>() else {
            continue;
        };

        // Upsert (domain, ip). RETURNING (xmax = 0) is true iff this row
        // was freshly inserted; we use that as the domain_count delta on
        // the ips upsert below, replacing the per-flow COUNT(DISTINCT)
        // recomputation that dominated PG CPU on the control plane.
        let inserted: bool = sqlx::query_scalar!(
            r#"INSERT INTO domain_ips (domain, ip, first_seen, last_seen)
               VALUES ($1, $2, $3, $3)
               ON CONFLICT(domain, ip) DO UPDATE SET
                 last_seen = GREATEST(domain_ips.last_seen, $3)
               RETURNING (xmax = 0) AS "inserted!""#,
            flow.query.domain,
            ip_net,
            now,
        )
        .fetch_one(pool)
        .await?;

        sqlx::query!(
            "INSERT INTO ips (ip, first_seen, last_seen, domain_count, updated_at)
             VALUES ($1, $2, $2, 1, $2)
             ON CONFLICT(ip) DO UPDATE SET
               last_seen = GREATEST(ips.last_seen, $2),
               domain_count = ips.domain_count + CASE WHEN $3 THEN 1 ELSE 0 END,
               updated_at = $2",
            ip_net,
            now,
            inserted,
        )
        .execute(pool)
        .await?;
    }

    // NS handling: (1) compute change detection against the pre-upsert domain_ns_map
    // snapshot, (2) upsert the map, (3) pass the change signal to reputation.
    let registrable = crate::scoring_chain::extract_registrable(
        flow.query.domain.trim_end_matches('.'),
        suffix_set,
    );
    let auth_ns = nameserver_common::messages::flow::extract_auth_ns(flow);
    let ns_names: Vec<String> = auth_ns
        .as_ref()
        .map(|a| a.all_ns().into_iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let ns_changed =
        crate::reputation::detect_ns_change(pool, &registrable, &auth_ns, suffix_set).await;

    for ns_clean in &ns_names {
        sqlx::query!(
            "INSERT INTO domain_ns_map (registrable_domain, ns_domain, first_seen, last_seen, observation_count)
             VALUES ($1, $2, $3, $3, 1)
             ON CONFLICT(registrable_domain, ns_domain) DO UPDATE SET
               last_seen = GREATEST(domain_ns_map.last_seen, $3),
               observation_count = domain_ns_map.observation_count + 1",
            registrable,
            ns_clean as &str,
            now,
        )
        .execute(pool)
        .await?;
    }

    // Update domain reputation (infrastructure fingerprint + trust).
    crate::reputation::upsert_reputation(pool, flow, ns_changed, suffix_set).await;

    // Build novelty row. `first_seen` comes from the RETURNING clause above —
    // for a first insert it equals `now`, otherwise it's the preserved original.
    let started_at = OffsetDateTime::from_unix_timestamp_nanos(flow.started_at as i128 * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let age_minutes = (started_at - domain_row.first_seen).whole_minutes().max(0) as u32;
    let novelty = FlowNoveltyRow {
        flow_id: flow.flow_id,
        started_at,
        domain: flow.query.domain.clone(),
        registrable: registrable.clone(),
        profile_id: flow.profile_id.clone().unwrap_or_default(),
        geo_asn: flow.geo_asn,
        is_first_contact: u8::from(domain_row.query_count == 1),
        first_seen_in_network: domain_row.first_seen,
        age_minutes_at_flow: age_minutes,
    };

    Ok(novelty)
}
