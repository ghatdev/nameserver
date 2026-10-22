use tokio::sync::mpsc;

use nameserver_common::messages::flow::DnsFlow;

/// Per-flow novelty context computed by `processing::upsert_flow` and
/// shipped alongside the flow to the ML detector. Avoids a redundant
/// PG/CH read on the detector path.
#[derive(Debug, Clone, Copy)]
pub struct NoveltyContext {
    pub is_first_contact: bool,
    pub age_minutes_at_flow: u32,
}

/// Requests processed by the ML worker.
pub enum MlRequest {
    FromFlow {
        flow: DnsFlow,
        novelty: NoveltyContext,
    },
}

/// Create the ML request channel.
pub fn channel() -> (mpsc::Sender<MlRequest>, mpsc::Receiver<MlRequest>) {
    mpsc::channel(1024)
}

#[cfg(feature = "ml")]
mod worker {
    use time::OffsetDateTime;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{debug, info, warn};

    use nameserver_common::messages::flow::DnsFlow;

    use crate::analysis::ml::MlScorer;
    use crate::clickhouse::DetectorScoreRow;
    use crate::config::MlConfig;
    use crate::db::Database;
    use crate::scoring_chain;
    use crate::similarity;

    use super::MlRequest;

    const ML_INSERT_CHANNEL_CAPACITY: usize = 1024;
    const ML_CH_MAX_ROWS: u64 = 500;
    const ML_CH_COMMIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(10);
    const METRICS_LOG_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);
    const EMBEDDING_WRITER_CHANNEL_CAPACITY: usize = 1024;

    /// Per-flow input to the embedding writer task. Carries everything
    /// `similarity::upsert_label_embedding` needs without referencing
    /// `Features` (which is `MlScorer`-private).
    struct EmbeddingUpsert {
        label: String,
        embedding: Vec<f32>,
        sim_embedding: Vec<f32>,
        domain: String,
        ns_domains: Vec<String>,
    }

    /// Sibling task that consumes `EmbeddingUpsert` requests and writes
    /// them to PG `domain_label_embeddings`. Decouples feature persistence
    /// from the scoring path: a slow PG write or a transient error here
    /// degrades the HNSW similarity index for FUTURE flows but cannot
    /// stall scoring of the current flow. Mirrors the fanout pattern
    /// already used for the CH inserter and NATS publish.
    fn spawn_embedding_writer(pool: sqlx::PgPool, mut rx: mpsc::Receiver<EmbeddingUpsert>) {
        tokio::spawn(async move {
            info!("embedding writer started");
            let mut count: u64 = 0;
            while let Some(req) = rx.recv().await {
                similarity::upsert_label_embedding(
                    &pool,
                    &req.label,
                    &req.embedding,
                    &req.sim_embedding,
                    &req.domain,
                    &req.ns_domains,
                )
                .await;
                count += 1;
            }
            info!(total = count, "embedding writer stopping (channel closed)");
        });
    }

    /// Per-step throughput + latency aggregates for the ML detector
    /// pipeline. Per the failure-isolation rule the detector runs in its
    /// own task and shouldn't add observability dependencies; atomics +
    /// periodic info! summary is enough to answer "is the worker keeping
    /// up with NATS flow rate?" — the only question PR#3f gating cares
    /// about. No client_ip / domain / profile_id ever appears here.
    #[derive(Default)]
    struct PipelineMetrics {
        flow_count: std::sync::atomic::AtomicU64,
        extract_us_sum: std::sync::atomic::AtomicU64,
        score_us_sum: std::sync::atomic::AtomicU64,
        chain_us_sum: std::sync::atomic::AtomicU64,
        nats_publish_us_sum: std::sync::atomic::AtomicU64,
        ch_inserter_drops: std::sync::atomic::AtomicU64,
        embedding_writer_drops: std::sync::atomic::AtomicU64,
    }

    fn spawn_metrics_logger(metrics: std::sync::Arc<PipelineMetrics>) {
        use std::sync::atomic::Ordering;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(METRICS_LOG_PERIOD);
            ticker.tick().await; // skip immediate fire
            let mut prev_flows: u64 = 0;
            loop {
                ticker.tick().await;
                let flows = metrics.flow_count.load(Ordering::Relaxed);
                let delta = flows.saturating_sub(prev_flows);
                if flows == 0 {
                    continue;
                }
                info!(
                    flows_total = flows,
                    flows_window = delta,
                    extract_mean_us = metrics.extract_us_sum.load(Ordering::Relaxed) / flows.max(1),
                    score_mean_us = metrics.score_us_sum.load(Ordering::Relaxed) / flows.max(1),
                    chain_mean_us = metrics.chain_us_sum.load(Ordering::Relaxed) / flows.max(1),
                    nats_publish_mean_us =
                        metrics.nats_publish_us_sum.load(Ordering::Relaxed) / flows.max(1),
                    ch_inserter_drops = metrics.ch_inserter_drops.load(Ordering::Relaxed),
                    embedding_writer_drops = metrics.embedding_writer_drops.load(Ordering::Relaxed),
                    "ML detector pipeline metrics"
                );
                prev_flows = flows;
            }
        });
    }

    pub fn spawn_ml_worker(
        db: Database,
        nats_client: async_nats::Client,
        ch_client: clickhouse::Client,
        ml_config: MlConfig,
        mut rx: mpsc::Receiver<MlRequest>,
        suffix_set: std::sync::Arc<arc_swap::ArcSwap<nameserver_common::suffix::SuffixSet>>,
    ) -> JoinHandle<()> {
        let (ml_ch_tx, ml_ch_rx) = mpsc::channel::<DetectorScoreRow>(ML_INSERT_CHANNEL_CAPACITY);
        spawn_ml_inserter(ch_client.clone(), ml_ch_rx);

        let (emb_tx, emb_rx) = mpsc::channel::<EmbeddingUpsert>(EMBEDDING_WRITER_CHANNEL_CAPACITY);
        spawn_embedding_writer(db.pool.clone(), emb_rx);

        let metrics = std::sync::Arc::new(PipelineMetrics::default());
        spawn_metrics_logger(metrics.clone());

        let mut ml_scorer: Option<MlScorer> = if ml_config.enabled {
            match MlScorer::load(
                &ml_config.model_path,
                ml_config.threshold_malicious,
                ml_config.threshold_suspicious,
            ) {
                Ok(scorer) => Some(scorer),
                Err(e) => {
                    warn!(error = %e, "failed to load ML model, ML worker disabled");
                    None
                }
            }
        } else {
            info!("ML scoring disabled");
            None
        };

        let own_zones = ml_config.own_zones.clone();

        tokio::spawn(async move {
            info!(ml_enabled = ml_scorer.is_some(), "ML worker started");
            let mut predict_count: u64 = 0;

            while let Some(req) = rx.recv().await {
                match req {
                    MlRequest::FromFlow { flow, novelty } => {
                        if let Some(ref mut scorer) = ml_scorer {
                            let ss = suffix_set.load();
                            ml_predict(
                                scorer,
                                PredictionServices {
                                    db: &db,
                                    ch_client: &ch_client,
                                    nats_client: &nats_client,
                                    ml_ch_tx: &ml_ch_tx,
                                    emb_tx: &emb_tx,
                                    metrics: &metrics,
                                },
                                &flow,
                                novelty,
                                &own_zones,
                                &ss,
                            )
                            .await;
                            predict_count += 1;
                        }
                    }
                }
            }

            info!(
                total_predictions = predict_count,
                "ML worker stopping (channel closed)"
            );
        })
    }

    struct PredictionServices<'a> {
        db: &'a Database,
        ch_client: &'a clickhouse::Client,
        nats_client: &'a async_nats::Client,
        ml_ch_tx: &'a mpsc::Sender<DetectorScoreRow>,
        emb_tx: &'a mpsc::Sender<EmbeddingUpsert>,
        metrics: &'a std::sync::Arc<PipelineMetrics>,
    }

    async fn ml_predict(
        scorer: &mut MlScorer,
        services: PredictionServices<'_>,
        flow: &DnsFlow,
        novelty: super::NoveltyContext,
        own_zones: &[String],
        suffix_set: &nameserver_common::suffix::SuffixSet,
    ) {
        let PredictionServices {
            db,
            ch_client,
            nats_client,
            ml_ch_tx,
            emb_tx,
            metrics,
        } = services;
        use std::sync::atomic::Ordering;
        use std::time::Instant;

        let domain = &flow.query.domain;

        if scoring_chain::should_skip(domain) || scoring_chain::is_own_zone(domain, own_zones) {
            return;
        }

        // ── extract ──
        let t0 = Instant::now();
        let features = scorer
            .extract(db, ch_client, domain, flow, novelty, suffix_set)
            .await;
        metrics
            .extract_us_sum
            .fetch_add(t0.elapsed().as_micros() as u64, Ordering::Relaxed);

        // ── score (LightGBM ONNX inference) ──
        let t1 = Instant::now();
        let score = match scorer.score(&features) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "ML inference failed");
                return;
            }
        };
        metrics
            .score_us_sum
            .fetch_add(t1.elapsed().as_micros() as u64, Ordering::Relaxed);

        // ── scoring chain ──
        let t2 = Instant::now();
        let chain = scoring_chain::evaluate(
            domain,
            score.ml_probability,
            flow,
            &db.pool,
            features.label_embedding.as_ref().map(|(l, _)| l.as_str()),
            features.sim_embedding.as_deref(),
            suffix_set,
        )
        .await;
        metrics
            .chain_us_sum
            .fetch_add(t2.elapsed().as_micros() as u64, Ordering::Relaxed);

        debug!(
            ml = score.ml_probability,
            final_score = chain.final_score,
            dnssec = chain.signals.dnssec_adj,
            ns = chain.signals.ns_adj,
            similarity = chain.signals.similarity_adj,
            hosting = chain.signals.hosting_adj,
            nrd = chain.signals.nrd_adj,
            ns_trust = %chain.ns_trust,
            "scoring chain signals"
        );

        // ── embedding upsert handoff (PG, async sibling task) ──
        // Feature persistence: this flow's contrastive embedding goes
        // into pgvector so the NEXT flow's similarity ANN can see it.
        // Off the scoring path — fanout via spawn_embedding_writer.
        // try_send so a slow PG write can't stall scoring; on overflow
        // we lose ONE flow's embedding from the future-similarity index,
        // which is a small index-quality cost, not a correctness one.
        if let (Some((label, embedding)), Some(sim_embedding)) = (
            features.label_embedding.as_ref(),
            features.sim_embedding.as_deref(),
        ) {
            let auth_ns = nameserver_common::messages::flow::extract_auth_ns(flow);
            let ns_domains: Vec<String> = auth_ns
                .as_ref()
                .map(|a| a.all_ns().into_iter().map(|s| s.to_string()).collect())
                .unwrap_or_default();
            let req = EmbeddingUpsert {
                label: label.clone(),
                embedding: embedding.clone(),
                sim_embedding: sim_embedding.to_vec(),
                domain: domain.to_string(),
                ns_domains,
            };
            if emb_tx.try_send(req).is_err() {
                metrics
                    .embedding_writer_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let prediction = nameserver_common::messages::DetectorScore {
            domain: domain.to_string(),
            ml_probability: score.ml_probability,
            final_probability: chain.final_score,
            classification: chain.verdict.clone(),
            divergent: false,
            override_rule: score.override_rule.clone(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
            ns_trust: chain.ns_trust.to_string(),
            dnssec_adj: chain.signals.dnssec_adj,
            ns_adj: chain.signals.ns_adj,
            similarity_adj: chain.signals.similarity_adj,
            hosting_adj: chain.signals.hosting_adj,
            nrd_adj: chain.signals.nrd_adj,
            temporal_adj: 0.0,
        };

        // ── NATS publish ──
        let t4 = Instant::now();
        if let Ok(payload) = serde_json::to_vec(&prediction) {
            let client = nats_client.clone();
            let subject: async_nats::Subject =
                nameserver_common::nats_subjects::SUBJECT_DETECTOR_SCORE.into();
            tokio::spawn(async move {
                let _ = client.publish(subject, payload.into()).await;
            });
        }
        metrics
            .nats_publish_us_sum
            .fetch_add(t4.elapsed().as_micros() as u64, Ordering::Relaxed);

        // ── CH inserter handoff ──
        let row = DetectorScoreRow::from(prediction);
        if ml_ch_tx.try_send(row).is_err() {
            metrics.ch_inserter_drops.fetch_add(1, Ordering::Relaxed);
        }

        metrics.flow_count.fetch_add(1, Ordering::Relaxed);
    }

    fn spawn_ml_inserter(ch_client: clickhouse::Client, mut rx: mpsc::Receiver<DetectorScoreRow>) {
        tokio::spawn(async move {
            loop {
                match run_ml_inserter(&ch_client, &mut rx).await {
                    Ok(()) => break,
                    Err(e) => {
                        warn!(error = %e, "detector_scores inserter failed, reconnecting in 5s");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    async fn run_ml_inserter(
        client: &clickhouse::Client,
        rx: &mut mpsc::Receiver<DetectorScoreRow>,
    ) -> clickhouse::error::Result<()> {
        let mut inserter = client
            .inserter::<DetectorScoreRow>("detector_scores")
            .with_max_rows(ML_CH_MAX_ROWS)
            .with_period(Some(ML_CH_COMMIT_PERIOD));

        loop {
            let time_left = inserter.time_left().unwrap_or(ML_CH_COMMIT_PERIOD);
            tokio::select! {
                maybe_row = rx.recv() => {
                    match maybe_row {
                        Some(row) => {
                            inserter.write(&row).await?;
                            let stats = inserter.commit().await?;
                            if stats.rows > 0 {
                                debug!(rows = stats.rows, "committed detector_scores batch");
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
                        debug!(rows = stats.rows, "periodic detector_scores commit");
                    }
                }
            }
        }
    }
}

// Re-export spawn_ml_worker only when ml feature is enabled.
#[cfg(feature = "ml")]
pub use worker::spawn_ml_worker;
