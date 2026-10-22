//! Per-request observations of the recursive engine's real upstream exchanges.
use futures::{StreamExt, stream::BoxStream};
use hickory_server::{
    net::{
        NetError,
        runtime::TokioRuntimeProvider,
        xfer::{DnsExchange, DnsHandle},
    },
    proto::{
        op::{DnsRequest, DnsResponse, ResponseCode},
        rr::{RData, RecordType},
    },
    resolver::{ConnectionProvider, PoolContext, config::ConnectionConfig},
};
use nameserver_common::{
    messages::flow::{ResolveStep, StepData},
    types::enums::StepResponseType,
};
use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};

tokio::task_local! { static ACTIVE: Arc<Mutex<Vec<ResolveStep>>>; }

pub async fn collect<F: Future>(future: F) -> (F::Output, Vec<ResolveStep>) {
    let steps = Arc::new(Mutex::new(Vec::new()));
    let result = ACTIVE.scope(steps.clone(), future).await;
    let mut steps = steps.lock().unwrap_or_else(|e| e.into_inner()).clone();
    // Completion order can differ from query order when NS addresses are resolved concurrently.
    steps.sort_by_key(|step| step.step);
    (result, steps)
}

#[derive(Clone, Default)]
pub struct Provider(TokioRuntimeProvider);
impl ConnectionProvider for Provider {
    type Conn = Observed;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Observed, NetError>> + Send>>;
    type RuntimeProvider = TokioRuntimeProvider;
    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.0
    }
    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let future = self.0.new_connection(ip, config, cx)?;
        Ok(Box::pin(async move {
            Ok(Observed {
                inner: future.await?,
                server: ip,
            })
        }))
    }
}

#[derive(Clone)]
pub struct Observed {
    inner: DnsExchange<TokioRuntimeProvider>,
    server: IpAddr,
}
impl DnsHandle for Observed {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;
    fn send(&self, request: DnsRequest) -> Self::Response {
        let collector = ACTIVE.try_with(Clone::clone).ok();
        let question = request.queries.first().cloned();
        let server = self.server;
        let started = Instant::now();
        let slot = collector.as_ref().and_then(|collector| {
            let mut steps = collector.lock().ok()?;
            if steps.len() >= 255 {
                return None;
            }
            let position = steps.len();
            steps.push(ResolveStep {
                step: position as u8,
                asked: question
                    .as_ref()
                    .map(|q| q.name().to_ascii())
                    .unwrap_or_default(),
                server: server.to_string(),
                server_name: None,
                response_type: StepResponseType::Error,
                got: StepData::default(),
                ms: 0,
            });
            Some(position)
        });
        self.inner
            .send(request)
            .map(move |result| {
                if let (Some(collector), Some(slot)) = (&collector, slot) {
                    let mut steps = collector.lock().unwrap_or_else(|e| e.into_inner());
                    let step = &mut steps[slot];
                    step.ms = started.elapsed().as_millis().min(u16::MAX as u128) as u16;
                    match &result {
                        Ok(response) => {
                            let ns: Vec<_> = response
                                .authorities
                                .iter()
                                .filter_map(|r| match &r.data {
                                    RData::NS(ns) => Some(ns.0.to_ascii()),
                                    _ => None,
                                })
                                .collect();
                            let a: Vec<_> = response
                                .answers
                                .iter()
                                .chain(&response.additionals)
                                .filter_map(|r| match &r.data {
                                    RData::A(a) => Some(a.0.to_string()),
                                    _ => None,
                                })
                                .collect();
                            let aaaa: Vec<_> = response
                                .answers
                                .iter()
                                .chain(&response.additionals)
                                .filter_map(|r| match &r.data {
                                    RData::AAAA(a) => Some(a.0.to_string()),
                                    _ => None,
                                })
                                .collect();
                            let cname = response.answers.iter().find_map(|r| match &r.data {
                                RData::CNAME(cname) => Some(cname.0.to_ascii()),
                                _ => None,
                            });
                            let referral = !ns.is_empty() && response.answers.is_empty();
                            step.response_type =
                                if response.metadata.response_code == ResponseCode::NXDomain {
                                    StepResponseType::Nxdomain
                                } else if referral {
                                    StepResponseType::Referral
                                } else if cname.is_some() {
                                    StepResponseType::Cname
                                } else if response.metadata.response_code == ResponseCode::NoError {
                                    StepResponseType::Answer
                                } else {
                                    StepResponseType::Error
                                };
                            if referral
                                && let Some(record) = response
                                    .authorities
                                    .iter()
                                    .find(|r| r.record_type() == RecordType::NS)
                            {
                                step.asked = record.name.to_ascii();
                            }
                            step.got = StepData {
                                ns: (!ns.is_empty()).then_some(ns),
                                a: (!a.is_empty()).then_some(a),
                                aaaa: (!aaaa.is_empty()).then_some(aaaa),
                                cname,
                                ttl: response
                                    .answers
                                    .iter()
                                    .filter(|r| r.record_type() != RecordType::RRSIG)
                                    .map(|r| r.ttl)
                                    .min(),
                                error: (response.metadata.response_code != ResponseCode::NoError
                                    && response.metadata.response_code != ResponseCode::NXDomain)
                                    .then(|| response.metadata.response_code.to_string()),
                            };
                            // Glue and NS-address answers provide exact hostname/IP associations.
                            let mappings: Vec<_> = response
                                .answers
                                .iter()
                                .chain(&response.additionals)
                                .filter_map(|record| {
                                    record
                                        .data
                                        .ip_addr()
                                        .map(|ip| (ip.to_string(), record.name.to_ascii()))
                                })
                                .collect();
                            for observed in steps.iter_mut() {
                                if let Some((_, name)) =
                                    mappings.iter().find(|(ip, _)| ip == &observed.server)
                                {
                                    observed.server_name = Some(name.clone());
                                }
                            }
                        }
                        Err(error) => step.got.error = Some(error.to_string()),
                    }
                }
                result
            })
            .boxed()
    }
}
