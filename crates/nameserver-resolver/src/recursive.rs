//! Catalog adapter for Hickory's recursive engine with observed upstream exchanges.
use crate::trace::Provider;
use hickory_server::{
    dnssec::NxProofKind,
    proto::{
        op::{Query, ResponseCode},
        rr::{LowerName, Name, RecordType, TSigResponseContext},
    },
    resolver::recursor::{RecursiveConfig, Recursor},
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, Nsec3QueryInfo,
        ZoneHandler, ZoneType,
    },
};
use std::{path::Path, time::Instant};

pub struct TracedRecursor {
    origin: LowerName,
    recursor: Recursor<Provider>,
}
impl TracedRecursor {
    pub async fn from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: RecursiveConfig,
        root_dir: Option<&Path>,
        provider: Provider,
    ) -> Result<Self, String> {
        let recursor =
            Recursor::from_config(config, root_dir, provider).map_err(|e| e.to_string())?;
        Ok(Self {
            origin: origin.into(),
            recursor,
        })
    }
}
#[async_trait::async_trait]
impl ZoneHandler for TracedRecursor {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }
    fn can_validate_dnssec(&self) -> bool {
        self.recursor.is_validating()
    }
    fn origin(&self) -> &LowerName {
        &self.origin
    }
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _request: Option<&RequestInfo<'_>>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let result = self
            .recursor
            .resolve(
                Query::query(name.into(), rtype),
                Instant::now(),
                options.dnssec_ok,
            )
            .await;
        LookupControlFlow::Continue(result.map(AuthLookup::Response).map_err(LookupError::from))
    }
    async fn search(
        &self,
        request: &Request,
        options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(error) => return (LookupControlFlow::Break(Err(error)), None),
        };
        (
            self.lookup(
                info.query.name(),
                info.query.query_type(),
                Some(&info),
                options,
            )
            .await,
            None,
        )
    }
    // Recursive responses carry authenticated denial from the validating engine.
    // Generating local authoritative proofs is forbidden for an external zone.
    async fn nsec_records(
        &self,
        _name: &LowerName,
        _options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)))
    }
    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)))
    }
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}
