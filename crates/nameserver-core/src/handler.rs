use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use hickory_server::{
    net::runtime::Time,
    proto::{
        op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode},
        rr::{Name, RData, Record, rdata::SOA},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::{Catalog, MessageResponseBuilder},
};
use tokio::sync::Semaphore;

use crate::{Filter, ServerSettings};

pub struct Snapshot {
    pub catalog: Catalog,
    /// Kept separate so unchecked data cannot enter the validating resolver's cache.
    pub unchecked_catalog: Option<Catalog>,
    pub filter: Filter,
    pub recursive: bool,
}

#[derive(Clone)]
pub struct Handler {
    pub snapshot: Arc<ArcSwap<Snapshot>>,
    settings: ServerSettings,
    semaphore: Arc<Semaphore>,
}

impl Handler {
    pub fn new(snapshot: Snapshot, settings: ServerSettings) -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
            semaphore: Arc::new(Semaphore::new(settings.max_in_flight)),
            settings,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let snapshot = self.snapshot.load_full();
        let catalog = if request.metadata.checking_disabled {
            snapshot
                .unchecked_catalog
                .as_ref()
                .unwrap_or(&snapshot.catalog)
        } else {
            &snapshot.catalog
        };
        if !self.settings.permits(request.src().ip()) {
            return respond(
                request,
                response_handle,
                ResponseCode::Refused,
                snapshot.recursive,
                false,
            )
            .await;
        }
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return catalog
                .handle_request::<R, T>(request, response_handle)
                .await;
        }
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => {
                return respond(
                    request,
                    response_handle,
                    ResponseCode::FormErr,
                    snapshot.recursive,
                    false,
                )
                .await;
            }
        };
        // Let Hickory negotiate unsupported EDNS versions before applying local policy.
        if request.edns.as_ref().is_none_or(|edns| edns.version() == 0)
            && snapshot.filter.is_blocked(&Name::from(info.query.name()))
        {
            return respond(
                request,
                response_handle,
                ResponseCode::NXDomain,
                snapshot.recursive,
                true,
            )
            .await;
        }
        let Ok(_permit) = self.semaphore.try_acquire() else {
            return respond(
                request,
                response_handle,
                ResponseCode::ServFail,
                snapshot.recursive,
                false,
            )
            .await;
        };
        let fallback = response_handle.clone();
        match tokio::time::timeout(
            Duration::from_secs(self.settings.query_timeout_secs),
            catalog.handle_request::<R, T>(request, response_handle),
        )
        .await
        {
            Ok(info) => info,
            Err(_) => {
                respond(
                    request,
                    fallback,
                    ResponseCode::ServFail,
                    snapshot.recursive,
                    false,
                )
                .await
            }
        }
    }
}

async fn respond(
    request: &Request,
    mut response_handle: impl ResponseHandler,
    code: ResponseCode,
    recursive: bool,
    blocked: bool,
) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = code;
    metadata.recursion_available = recursive;
    let mut builder = MessageResponseBuilder::from_message_request(request);
    let edns = request.edns.as_ref().map(|original| {
        let mut edns = hickory_server::proto::op::Edns::new();
        edns.set_max_payload(original.max_payload().clamp(512, 1232));
        edns.set_dnssec_ok(original.flags().dnssec_ok);
        edns
    });
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let soa = if blocked {
        request.request_info().ok().map(|info| {
            Record::from_rdata(
                Name::from(info.query.name()),
                60,
                RData::SOA(SOA::new(Name::root(), Name::root(), 1, 60, 60, 60, 60)),
            )
        })
    } else {
        None
    };
    let response = builder.build(metadata, &[], &[], soa.iter(), &[]);
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| {
            ResponseInfo::from(Header {
                metadata,
                counts: HeaderCounts::default(),
            })
        })
}
