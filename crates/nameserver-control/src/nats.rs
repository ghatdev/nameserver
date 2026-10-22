use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::consumer::pull;
use futures::TryStreamExt;
use nameserver_common::messages::flow::DnsFlow;
use nameserver_common::nats_subjects::*;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::clickhouse::FlowRow;
use nameserver_common::nats_config::NatsConfig;

/// ClickHouse inserter batch size.
const CH_MAX_ROWS: u64 = 10_000;
/// ClickHouse inserter commit period.
const CH_COMMIT_PERIOD: Duration = Duration::from_secs(30);
/// Reconnect delay for consumer errors.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);

/// Connect to NATS and return client + JetStream context.
pub async fn connect(
    config: &NatsConfig,
) -> anyhow::Result<(async_nats::Client, jetstream::Context)> {
    let client = async_nats::connect(&config.url).await?;
    let js = jetstream::new(client.clone());
    nameserver_common::broker::provision(&js, config).await?;
    info!("connected to NATS");
    Ok((client, js))
}

// ---------------------------------------------------------------------------
// PostgreSQL consumer
// ---------------------------------------------------------------------------

/// Spawn a durable consumer that forwards flows to the PG processing pipeline.
pub fn spawn_pg_consumer(js: jetstream::Context, tx: mpsc::Sender<DnsFlow>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match consume_pg(&js, &tx).await {
                Ok(()) => info!("PG consumer stream ended, restarting"),
                Err(e) => {
                    warn!(error = %e, "PG consumer error, retrying in 5s");
                    tokio::time::sleep(RECONNECT_INTERVAL).await;
                }
            }
        }
    })
}

async fn consume_pg(js: &jetstream::Context, tx: &mpsc::Sender<DnsFlow>) -> anyhow::Result<()> {
    let stream = js.get_stream(STREAM_FLOWS).await?;

    let consumer = stream
        .get_or_create_consumer(
            CONSUMER_CONTROL_PG,
            pull::Config {
                durable_name: Some(CONSUMER_CONTROL_PG.to_string()),
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
                ..Default::default()
            },
        )
        .await?;

    info!(consumer = CONSUMER_CONTROL_PG, "PG consumer ready");

    let mut messages = consumer.messages().await?;

    while let Some(msg) = messages.try_next().await? {
        match rmp_serde::from_slice::<DnsFlow>(&msg.payload) {
            Ok(flow) => {
                if tx.send(flow).await.is_err() {
                    warn!("PG processing channel closed");
                    return Ok(());
                }
                if let Err(e) = msg.ack().await {
                    warn!(error = %e, "PG consumer: failed to ack");
                }
            }
            Err(e) => {
                warn!(error = %e, "PG consumer: failed to deserialize, skipping");
                if let Err(e) = msg.ack().await {
                    warn!(error = %e, "PG consumer: failed to ack malformed message");
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ClickHouse consumer
// ---------------------------------------------------------------------------

/// Spawn a durable consumer that inserts flows directly into ClickHouse.
///
/// The consumer owns the inserter loop — no intermediate MPSC channel.
/// Messages are acked only after the batch commits successfully.
pub fn spawn_ch_consumer(js: jetstream::Context, ch_client: clickhouse::Client) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match consume_ch(&js, &ch_client).await {
                Ok(()) => info!("CH consumer stream ended, restarting"),
                Err(e) => {
                    warn!(error = %e, "CH consumer error, retrying in 5s");
                    tokio::time::sleep(RECONNECT_INTERVAL).await;
                }
            }
        }
    })
}

async fn consume_ch(js: &jetstream::Context, ch_client: &clickhouse::Client) -> anyhow::Result<()> {
    let stream = js.get_stream(STREAM_FLOWS).await?;

    let consumer = stream
        .get_or_create_consumer(
            CONSUMER_CONTROL_CH,
            pull::Config {
                durable_name: Some(CONSUMER_CONTROL_CH.to_string()),
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
                ..Default::default()
            },
        )
        .await?;

    info!(consumer = CONSUMER_CONTROL_CH, "CH consumer ready");

    let mut inserter = ch_client
        .inserter::<FlowRow>("flows")
        .with_max_rows(CH_MAX_ROWS)
        .with_period(Some(CH_COMMIT_PERIOD));

    info!("ClickHouse flow inserter ready");

    let mut pending_acks: Vec<async_nats::jetstream::Message> = Vec::new();
    let mut messages = consumer.messages().await?;

    loop {
        let time_left = inserter.time_left().unwrap_or(CH_COMMIT_PERIOD);

        tokio::select! {
            maybe_msg = messages.try_next() => {
                let msg = match maybe_msg? {
                    Some(m) => m,
                    None => return Ok(()), // Stream ended.
                };

                match rmp_serde::from_slice::<DnsFlow>(&msg.payload) {
                    Ok(flow) => {
                        let row = FlowRow::from(flow);
                        inserter.write(&row).await?;
                        pending_acks.push(msg);

                        // Check if auto-commit threshold reached.
                        let stats = inserter.commit().await?;
                        if stats.rows > 0 {
                            ack_all(&mut pending_acks).await;
                            debug!(rows = stats.rows, "CH batch committed + acked");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "CH consumer: failed to deserialize, skipping");
                        // Ack malformed messages to prevent infinite redelivery.
                        let _ = msg.ack().await;
                    }
                }
            }
            // Periodic flush.
            _ = tokio::time::sleep(time_left) => {
                let stats = inserter.commit().await?;
                if stats.rows > 0 {
                    ack_all(&mut pending_acks).await;
                    debug!(rows = stats.rows, "CH periodic commit + acked");
                }
            }
        }
    }
}

/// Ack all pending messages and clear the buffer.
async fn ack_all(pending: &mut Vec<async_nats::jetstream::Message>) {
    for msg in pending.drain(..) {
        if let Err(e) = msg.ack().await {
            warn!(error = %e, "CH consumer: failed to ack message after commit");
        }
    }
}

// ---------------------------------------------------------------------------
// Injector reconciliation consumer
// ---------------------------------------------------------------------------

/// Spawn a durable consumer that forwards flows to the resolution
/// injector's reconciler. The reconciler matches a returning flow back
/// to an `injection_queue` row (by domain) and transitions it to
/// `resolved`, recording the flow_id.
///
/// Fully independent of the PG and CH consumers — own durable name,
/// own cursor. A slow reconciler or wedged PG update cannot
/// back-pressure flow ingestion. On backpressure we drop (reconciliation
/// is best-effort; an orphan in_flight row will either be retried or
/// abandoned by the scheduler).
pub fn spawn_injector_consumer(
    js: jetstream::Context,
    tx: mpsc::Sender<DnsFlow>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match consume_injector(&js, &tx).await {
                Ok(()) => info!("injector consumer stream ended, restarting"),
                Err(e) => {
                    warn!(error = %e, "injector consumer error, retrying in 5s");
                    tokio::time::sleep(RECONNECT_INTERVAL).await;
                }
            }
        }
    })
}

async fn consume_injector(
    js: &jetstream::Context,
    tx: &mpsc::Sender<DnsFlow>,
) -> anyhow::Result<()> {
    let stream = js.get_stream(STREAM_FLOWS).await?;

    let consumer = stream
        .get_or_create_consumer(
            CONSUMER_CONTROL_INJECTOR,
            pull::Config {
                durable_name: Some(CONSUMER_CONTROL_INJECTOR.to_string()),
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
                ..Default::default()
            },
        )
        .await?;

    info!(
        consumer = CONSUMER_CONTROL_INJECTOR,
        "injector consumer ready"
    );

    let mut messages = consumer.messages().await?;

    while let Some(msg) = messages.try_next().await? {
        match rmp_serde::from_slice::<DnsFlow>(&msg.payload) {
            Ok(flow) => {
                if tx.try_send(flow).is_err() {
                    debug!("injector channel full, dropping flow");
                }
                if let Err(e) = msg.ack().await {
                    warn!(error = %e, "injector consumer: failed to ack");
                }
            }
            Err(e) => {
                warn!(error = %e, "injector consumer: failed to deserialize, skipping");
                if let Err(e) = msg.ack().await {
                    warn!(error = %e, "injector consumer: failed to ack malformed message");
                }
            }
        }
    }

    Ok(())
}
