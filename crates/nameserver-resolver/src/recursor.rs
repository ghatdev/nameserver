//! Management wire adapter; recursion and DNSSEC are performed by Hickory 0.26.
use crate::dnssec::DnssecInfo;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, Record, RecordType},
};
use hickory_server::{
    net::{runtime::TokioTime, xfer::Protocol},
    server::{Request, RequestHandler},
};
use nameserver_common::{
    messages::flow::ResolveStep,
    types::enums::{DnssecStatus, ServfailReason},
};
use nameserver_core::{CapturedResponse, Snapshot};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

pub struct ResolveResult {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub rcode: ResponseCode,
    pub steps: Vec<ResolveStep>,
    pub cname_chain: Vec<String>,
    pub dnssec: DnssecInfo,
    pub original_ttl: u32,
    pub servfail_reason: Option<ServfailReason>,
}

pub async fn resolve(
    snapshot: &Arc<Snapshot>,
    name: &Name,
    qtype: RecordType,
    checking_disabled: bool,
) -> ResolveResult {
    match resolve_inner(snapshot, name, qtype, checking_disabled).await {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(error = %error, "managed DNS request failed");
            ResolveResult {
                answers: vec![],
                authority: vec![],
                additional: vec![],
                rcode: ResponseCode::ServFail,
                steps: vec![],
                cname_chain: vec![],
                dnssec: DnssecInfo::indeterminate(),
                original_ttl: 0,
                servfail_reason: None,
            }
        }
    }
}

async fn resolve_inner(
    snapshot: &Arc<Snapshot>,
    name: &Name,
    qtype: RecordType,
    checking_disabled: bool,
) -> anyhow::Result<ResolveResult> {
    let mut query = Message::new();
    query.add_query(Query::query(name.clone(), qtype));
    query
        .set_recursion_desired(true)
        .set_checking_disabled(checking_disabled);
    query
        .extensions_mut()
        .get_or_insert_with(Default::default)
        .set_dnssec_ok(true);
    let wire = query.to_vec()?;
    let request = Request::from_bytes(
        wire,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Protocol::Tcp,
    )?;
    let capture = CapturedResponse::default();
    let current = snapshot.catalog.load_full();
    let catalog = if checking_disabled {
        snapshot
            .unchecked_catalog
            .as_ref()
            .unwrap_or(current.as_ref())
    } else {
        current.as_ref()
    };
    let (_, steps) =
        crate::trace::collect(catalog.handle_request::<_, TokioTime>(&request, capture.clone()))
            .await;
    let wire = capture
        .take()
        .ok_or_else(|| anyhow::anyhow!("recursive engine produced no response"))?;
    let response = Message::from_vec(&wire)?;
    let mut dnssec = DnssecInfo::indeterminate();
    if !checking_disabled && snapshot.unchecked_catalog.is_some() {
        dnssec.status = if response.authentic_data() {
            DnssecStatus::Secure
        } else if response.response_code() == ResponseCode::NoError
            || response.response_code() == ResponseCode::NXDomain
        {
            DnssecStatus::Insecure
        } else {
            DnssecStatus::Indeterminate
        };
    }
    for record in response.answers().iter().chain(response.name_servers()) {
        if let hickory_proto::rr::RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::RRSIG(
            sig,
        )) = record.data()
        {
            dnssec.algorithm = Some(sig.algorithm().as_str().to_owned());
            dnssec.rrsig_expiry = Some(sig.sig_expiration().get() as i64);
            dnssec.ds_present = response.authentic_data();
            break;
        }
    }
    let cname_chain = response
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            hickory_proto::rr::RData::CNAME(name) => Some(name.0.to_ascii()),
            _ => None,
        })
        .collect();
    let original_ttl = steps
        .iter()
        .rev()
        .filter_map(|step| step.got.ttl)
        .next()
        .unwrap_or_else(|| {
            response
                .answers()
                .iter()
                .map(|record| record.ttl())
                .min()
                .unwrap_or(0)
        });
    Ok(ResolveResult {
        answers: response.answers().to_vec(),
        authority: response.name_servers().to_vec(),
        additional: response.additionals().to_vec(),
        rcode: response.response_code(),
        steps,
        cname_chain,
        dnssec,
        original_ttl,
        servfail_reason: None,
    })
}
