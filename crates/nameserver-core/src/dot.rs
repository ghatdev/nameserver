use crate::{CapturedResponse, Handler};
use hickory_server::{
    net::{runtime::TokioTime, xfer::Protocol},
    server::{Request, RequestHandler},
};
use rustls::server::ResolvesServerCert;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

pub fn start(
    listener: TcpListener,
    certificate: Arc<dyn ResolvesServerCert>,
    handler: Handler,
    base_name: Option<String>,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<JoinHandle<io::Result<()>>> {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certificate);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    Ok(tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(1024));
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, source) = result?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                    let acceptor = acceptor.clone(); let handler = handler.clone(); let base = base_name.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await else { return; };
                        let handler = match route_profile(handler, tls.get_ref().1.server_name(), base.as_deref()).await { Some(handler) => handler, None => return };
                        if let Err(error) = serve(tls, source, handler, idle_timeout).await { tracing::debug!(error = %error, "DoT connection ended"); }
                    });
                }
                _ = shutdown.changed() => { connections.abort_all(); break; }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        while connections.join_next().await.is_some() {}
        Ok(())
    }))
}

async fn route_profile(handler: Handler, sni: Option<&str>, base: Option<&str>) -> Option<Handler> {
    let (Some(sni), Some(base)) = (sni, base) else {
        return Some(handler);
    };
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    let base = base.trim_end_matches('.').to_ascii_lowercase();
    if sni == base {
        return Some(handler);
    }
    let profile = sni.strip_suffix(&format!(".{base}"))?;
    if handler.profile_exists(profile).await {
        Some(handler.with_profile(profile.to_owned()))
    } else {
        None
    }
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    source: SocketAddr,
    handler: Handler,
    timeout: Duration,
) -> io::Result<()> {
    loop {
        let length = match tokio::time::timeout(timeout, stream.read_u16()).await {
            Ok(Ok(length)) if length >= 12 => length,
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid or idle DoT frame",
                ));
            }
        };
        let mut wire = vec![0; length as usize];
        tokio::time::timeout(timeout, stream.read_exact(&mut wire))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoT body timeout"))??;
        let request = Request::from_bytes(wire, source, Protocol::Tls).map_err(io::Error::other)?;
        let response = CapturedResponse::default();
        handler
            .handle_request::<_, TokioTime>(&request, response.clone())
            .await;
        let wire = response
            .take()
            .ok_or_else(|| io::Error::other("no DNS response"))?;
        let write = async {
            stream.write_u16(wire.len() as u16).await?;
            stream.write_all(&wire).await?;
            stream.flush().await
        };
        tokio::time::timeout(timeout, write)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoT write timeout"))??;
    }
}
