use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_server::{
    net::{runtime::TokioTime, xfer::Protocol},
    server::{Request, RequestHandler},
};
use serde::Deserialize;
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{CapturedResponse, Handler};

#[derive(Clone)]
struct App {
    handler: Handler,
    dns_name: Option<String>,
}

pub fn start(
    listener: TcpListener,
    certificate: Arc<dyn rustls::server::ResolvesServerCert>,
    handler: Handler,
    dns_name: Option<String>,
) -> Result<(Handle<SocketAddr>, JoinHandle<std::io::Result<()>>)> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certificate);
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let app = Router::new()
        .route("/dns-query", get(get_query).post(post_query))
        .route("/{profile}", get(get_query).post(post_query))
        .layer(DefaultBodyLimit::max(65535))
        .with_state(App { handler, dns_name });
    let handle = Handle::new();
    let server = axum_server::from_tcp_rustls(
        listener.into_std()?,
        RustlsConfig::from_config(Arc::new(tls)),
    )?
    .handle(handle.clone())
    .serve(app.into_make_service_with_connect_info::<SocketAddr>());
    Ok((handle, tokio::spawn(server)))
}

#[derive(Deserialize)]
struct Parameters {
    dns: String,
}

async fn get_query(
    State(app): State<App>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Query(parameters): Query<Parameters>,
) -> Response {
    let Ok(wire) = URL_SAFE_NO_PAD.decode(parameters.dns) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    process(app, source, &headers, &uri, wire).await
}

async fn post_query(
    State(app): State<App>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/dns-message")) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    process(app, source, &headers, &uri, body.to_vec()).await
}

async fn process(
    app: App,
    source: SocketAddr,
    headers: &HeaderMap,
    uri: &Uri,
    wire: Vec<u8>,
) -> Response {
    if let Some(expected) = &app.dns_name {
        let authority = uri.authority().cloned().or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|host| host.to_str().ok())
                .and_then(|host| host.parse::<axum::http::uri::Authority>().ok())
        });
        if !authority.is_some_and(|authority| authority.host().eq_ignore_ascii_case(expected)) {
            return StatusCode::MISDIRECTED_REQUEST.into_response();
        }
    }
    if !(12..=65535).contains(&wire.len()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let profile = uri.path().trim_start_matches('/');
    let handler = if profile == "dns-query" {
        app.handler
    } else {
        if !app.handler.profile_exists(profile).await {
            return StatusCode::NOT_FOUND.into_response();
        }
        app.handler.with_profile(profile.to_owned())
    };
    let request = match Request::from_bytes(wire, source, Protocol::Https) {
        Ok(request) => request,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let response = CapturedResponse::default();
    handler
        .handle_request::<_, TokioTime>(&request, response.clone())
        .await;
    let wire = response.take();
    match wire {
        Some(wire) => (
            [
                (header::CONTENT_TYPE, "application/dns-message"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            wire,
        )
            .into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
