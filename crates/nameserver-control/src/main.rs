use nameserver_control::{
    api, autopull, benign_sampler, config, db, detector, injector, nats, processing,
};

use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("nameserver_control=info".parse().unwrap()),
        )
        .init();

    use clap::Parser;
    #[derive(Parser)]
    #[command(version, about = "Nameserver management API and analytics service")]
    struct Args {
        #[arg(short, long, default_value = "nameserver-control.toml")]
        config: std::path::PathBuf,
        #[arg(long)]
        check: bool,
    }
    let args = Args::parse();
    let config = config::Config::load(&args.config)?;
    if args.check {
        info!("control-plane configuration is valid");
        return Ok(());
    }

    // Init PostgreSQL.
    let db = db::Database::connect(&config.postgres_url).await?;
    info!("PostgreSQL connected");

    // Init ClickHouse client.
    let ch_client = config.clickhouse_client();
    info!(url = %config.clickhouse.url, "ClickHouse client ready");

    // Connect to NATS.
    let (nats_client, js) = nats::connect(&config.nats).await?;

    // Build initial suffix set from DB (may be empty on first run).
    // Must be created before workers that need it.
    let suffix_set = {
        use nameserver_common::suffix::SuffixSet;
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT suffix, rule_type FROM indicator_suffixes",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap_or_default();

        let mut psl_text = String::new();
        for (suffix, rule_type) in &rows {
            match rule_type.as_str() {
                "wildcard" => {
                    psl_text.push_str("*.");
                    psl_text.push_str(suffix);
                }
                "exception" => {
                    psl_text.push('!');
                    psl_text.push_str(suffix);
                }
                _ => {
                    psl_text.push_str(suffix);
                }
            }
            psl_text.push('\n');
        }
        let set = SuffixSet::from_psl_text(&psl_text);
        info!(entries = set.entry_count(), "loaded suffix set from DB");
        std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(set))
    };

    // Create ML channel + spawn ML worker.
    // Similarity search (Step 3.5) uses PostgreSQL + pgvector directly.
    let (ml_tx, ml_rx) = detector::channel();
    #[cfg(feature = "ml")]
    if config.ml.enabled {
        detector::spawn_ml_worker(
            db.clone(),
            nats_client.clone(),
            config.clickhouse_client(),
            config.ml.clone(),
            ml_rx,
            suffix_set.clone(),
        );
        info!("ML worker spawned");
    }

    #[cfg(not(feature = "ml"))]
    drop(ml_rx);

    // RDAP lookup APIs remain available; automatic external enrichment is opt-in.
    let (rdap_tx, rdap_rx) = tokio::sync::mpsc::channel::<String>(1024);
    if config.auto_rdap {
        api::rdap::spawn_rdap_worker(db.clone(), rdap_rx);
    } else {
        drop(rdap_rx);
    }
    info!("RDAP worker spawned");

    // Create flow processing channel.
    let (flow_tx, flow_rx) = processing::channel();

    // Novelty pipeline: PG processing computes per-flow novelty features and
    // ships them to ClickHouse via a dedicated inserter.
    let (novelty_tx, novelty_rx) = processing::novelty_channel();
    processing::spawn_novelty_inserter(ch_client.clone(), novelty_rx);
    info!("flow_novelty inserter spawned");

    // Resolution injector: continuous label acquisition via synthetic DoH
    // queries to our own resolver, plus its own NATS durable consumer
    // that reconciles returning flows against injection_queue. Fully
    // independent failure domain — a wedged injector cannot affect core
    // flow ingestion or analytics.
    match injector::spawn_injector(config.injector.clone(), db.pool.clone()) {
        Ok(Some(_handle)) => {
            info!("injector scheduler spawned");
            let (inj_tx, inj_rx) = injector::reconcile_channel();
            injector::spawn_reconciler(db.pool.clone(), inj_rx);
            nats::spawn_injector_consumer(js.clone(), inj_tx);
            info!("injector reconciler + NATS consumer spawned");
        }
        Ok(None) => info!("injector disabled"),
        Err(e) => {
            tracing::error!(error = %e, "failed to start injector");
            anyhow::bail!(e);
        }
    }

    // Benign-label sampler — feeds the same injection queue with
    // tranco/majestic domains so the per-flow features of injected
    // traffic don't correlate with the malicious label (PR-C of the
    // anti-contamination design).
    match benign_sampler::spawn_benign_sampler(config.benign_sampler.clone(), db.pool.clone()) {
        Some(_handle) => info!("benign sampler spawned"),
        None => info!("benign sampler disabled"),
    }

    // Spawn dual NATS consumers — each with independent durability.
    nats::spawn_pg_consumer(js.clone(), flow_tx);
    info!("NATS PG consumer spawned");
    nats::spawn_ch_consumer(js.clone(), ch_client.clone());
    info!("NATS CH consumer spawned");

    // Spawn PG flow processing pipeline (-> PostgreSQL + ML + RDAP + novelty).
    processing::spawn_pipeline(
        db.clone(),
        flow_rx,
        ml_tx,
        rdap_tx,
        novelty_tx,
        suffix_set.clone(),
    );
    info!("flow processing pipeline spawned");

    // Spawn auto-pull background task.
    if config.auto_pull {
        autopull::spawn_autopull(
            db.clone(),
            nats_client.clone(),
            js.clone(),
            suffix_set.clone(),
        );
        info!("automatic feed pulls enabled");
    }

    // Build API state.
    let app_state = api::AppState {
        db,
        ch: ch_client,
        nats_client,
        js,
        ch_config: config.clickhouse.clone(),
        dns_config: config.dns.clone(),
        suffix_set,
    };

    // Start API server.
    let app = api::router().with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&config.api.listen).await?;
    info!("management API listening");

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }

    info!("shutdown signal received");
}
