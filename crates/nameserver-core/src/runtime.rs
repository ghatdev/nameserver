use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::{Args, Handler, ServerSettings, Snapshot, doh, dot, tls};

pub struct Prepared {
    pub server: ServerSettings,
    pub certificate: Option<Arc<dyn rustls::server::ResolvesServerCert>>,
    pub snapshot: Snapshot,
    /// Rebuild signed authoritative data before its signatures expire.
    pub refresh_after: Option<Duration>,
}

pub async fn run<F, Fut>(args: Args, build: F) -> Result<()>
where
    F: Fn(PathBuf) -> Fut,
    Fut: Future<Output = Result<Prepared>>,
{
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "off,nameserver_core=info,nameserver_resolver=info,nameserver_authority=info",
        )
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let path = std::fs::canonicalize(&args.config).context("configuration file does not exist")?;
    let prepared = build(path.clone()).await?;
    prepared.server.validate()?;
    let override_certificate = prepared.certificate.clone();
    let certificate = prepared
        .server
        .tls
        .as_ref()
        .filter(|_| override_certificate.is_none())
        .map(|settings| tls::load(settings, &path))
        .transpose()?;
    if args.check {
        info!("configuration and data files are valid");
        return Ok(());
    }

    let settings = prepared.server;
    let mut refresh_after = prepared.refresh_after;
    let handler = Handler::new(prepared.snapshot, settings.clone());
    let snapshots = handler.snapshot.clone();
    let mut server = Server::new(handler.clone());
    let native_active = !settings.listen.is_empty();
    let timeout = Duration::from_secs(settings.tcp_idle_timeout_secs);
    // Bind every socket before registering any listener, so startup is all-or-nothing.
    let mut plain = Vec::new();
    for address in &settings.listen {
        plain.push((
            UdpSocket::bind(address)
                .await
                .context("cannot bind DNS UDP listener")?,
            TcpListener::bind(address)
                .await
                .context("cannot bind DNS TCP listener")?,
        ));
    }
    let mut dot = Vec::new();
    for address in &settings.listen_dot {
        dot.push(
            TcpListener::bind(address)
                .await
                .context("cannot bind DoT listener")?,
        );
    }
    let mut doh = Vec::new();
    for address in &settings.listen_doh {
        doh.push(
            TcpListener::bind(address)
                .await
                .context("cannot bind DoH listener")?,
        );
    }
    let file_certificate = certificate.map(|key| {
        Arc::new(tls::CertificateResolver(ArcSwap::from_pointee(key)))
            as Arc<dyn rustls::server::ResolvesServerCert>
    });
    let certificate = override_certificate
        .or(file_certificate)
        .map(|provider| Arc::new(tls::CertificateSource::new(provider)));
    for (udp, tcp) in plain {
        server.register_socket(udp);
        server.register_listener(tcp, timeout, 16);
    }
    let mut doh_handles = Vec::new();
    let mut doh_jobs = tokio::task::JoinSet::new();
    let (dot_shutdown, dot_receiver) = tokio::sync::watch::channel(false);
    if let Some(resolver) = &certificate {
        for listener in dot {
            let job = dot::start(
                listener,
                resolver.clone(),
                handler.clone(),
                settings.tls.as_ref().and_then(|tls| tls.dns_name.clone()),
                timeout,
                dot_receiver.clone(),
            )?;
            doh_jobs.spawn(job);
        }
        for listener in doh {
            let (handle, job) = doh::start(
                listener,
                resolver.clone(),
                handler.clone(),
                settings.tls.as_ref().and_then(|tls| tls.dns_name.clone()),
            )?;
            doh_handles.push(handle);
            doh_jobs.spawn(job);
        }
    }
    info!(
        dns_listeners = settings.listen.len(),
        dot_listeners = settings.listen_dot.len(),
        doh_listeners = settings.listen_doh.len(),
        "DNS service ready"
    );

    #[cfg(unix)]
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let timer = tokio::time::sleep(refresh_after.unwrap_or(Duration::from_secs(86_400)));
    tokio::pin!(timer);
    loop {
        let reload_requested = async {
            #[cfg(unix)]
            {
                reload.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            result = server.block_until_done(), if native_active => {
                result?;
                bail!("all DNS listeners stopped unexpectedly");
            }
            result = &mut shutdown => {
                result?;
                info!("shutdown requested; draining DNS service");
                let _ = dot_shutdown.send(true);
                for handle in &doh_handles { handle.graceful_shutdown(Some(Duration::from_secs(10))); }
                let drain = async {
                    server.shutdown_gracefully().await?;
                    while let Some(result) = doh_jobs.join_next().await { result???; }
                    Ok::<_, anyhow::Error>(())
                };
                tokio::time::timeout(Duration::from_secs(12), drain).await.context("DNS shutdown timed out")??;
                return Ok(());
            }
            result = doh_jobs.join_next(), if !doh_jobs.is_empty() => {
                if let Some(result) = result { result???; }
                bail!("a DoH listener stopped unexpectedly");
            }
            _ = reload_requested => {}
            _ = &mut timer, if refresh_after.is_some() => {}
        }
        // Build the whole replacement before swapping. Existing requests retain their snapshot.
        let replacement = async {
            let next = build(path.clone()).await?;
            next.server.validate()?;
            if next.server != settings {
                bail!("listener and access settings require a restart");
            }
            let key = next
                .server
                .tls
                .as_ref()
                .filter(|_| next.certificate.is_none())
                .map(|tls| tls::load(tls, &path))
                .transpose()?;
            Ok::<_, anyhow::Error>((next, key))
        }
        .await;
        match replacement {
            Ok((next, key)) => {
                let provider = next.certificate.clone().or_else(|| {
                    key.map(|key| {
                        Arc::new(tls::CertificateResolver(ArcSwap::from_pointee(key)))
                            as Arc<dyn rustls::server::ResolvesServerCert>
                    })
                });
                if let (Some(resolver), Some(provider)) = (&certificate, provider) {
                    resolver.swap(provider);
                }
                snapshots.store(Arc::new(next.snapshot));
                refresh_after = next.refresh_after;
                info!("configuration and data reloaded");
            }
            Err(error) => {
                warn!(error = %error, "reload rejected; keeping the current configuration")
            }
        }
        timer.as_mut().reset(
            tokio::time::Instant::now() + refresh_after.unwrap_or(Duration::from_secs(86_400)),
        );
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
