use crate::{nats_config::NatsConfig, nats_subjects::*};
use async_nats::jetstream::{self, object_store};
use std::time::Duration;

/// Idempotently create JetStream streams, Object Store buckets, and KV store.
pub async fn provision(js: &jetstream::Context, config: &NatsConfig) -> anyhow::Result<()> {
    // Flow stream.
    js.get_or_create_stream(jetstream::stream::Config {
        name: STREAM_FLOWS.to_string(),
        subjects: vec![SUBJECT_FLOW.to_string()],
        max_age: Duration::from_secs(FLOWS_MAX_AGE_SECS),
        max_bytes: FLOWS_MAX_BYTES,
        num_replicas: config.stream_replicas,
        ..Default::default()
    })
    .await?;
    tracing::info!(
        stream = STREAM_FLOWS,
        replicas = config.stream_replicas,
        "flow stream ready"
    );

    // Event stream.
    js.get_or_create_stream(jetstream::stream::Config {
        name: STREAM_EVENTS.to_string(),
        subjects: vec![SUBJECT_EVENT_PREFIX.to_string()],
        max_age: Duration::from_secs(EVENTS_MAX_AGE_SECS),
        num_replicas: config.stream_replicas,
        ..Default::default()
    })
    .await?;
    tracing::info!(
        stream = STREAM_EVENTS,
        replicas = config.stream_replicas,
        "event stream ready"
    );

    // Object Store buckets.
    match js
        .create_object_store(object_store::Config {
            bucket: BUCKET_FILTERS.to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(_) => {}
        Err(_) => {
            js.get_object_store(BUCKET_FILTERS).await?;
        }
    }
    tracing::info!(bucket = BUCKET_FILTERS, "filter object store ready");

    match js
        .create_object_store(object_store::Config {
            bucket: BUCKET_GEO.to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(_) => {}
        Err(_) => {
            js.get_object_store(BUCKET_GEO).await?;
        }
    }
    tracing::info!(bucket = BUCKET_GEO, "geo object store ready");

    // KV store.
    match js
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: BUCKET_CONFIG.to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(_) => {}
        Err(_) => {
            js.get_key_value(BUCKET_CONFIG).await?;
        }
    }
    tracing::info!(bucket = BUCKET_CONFIG, "config KV store ready");

    Ok(())
}
