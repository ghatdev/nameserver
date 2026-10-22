//! Keep denial proofs attached to negative and wildcard answers only.
//!
//! Hickory's Catalog requests NSEC3 for every successful non-SOA lookup. An exact
//! positive answer needs no denial proof; returning its type bitmap can cause a
//! validator to interpret that bitmap as an invalid NODATA proof.
use hickory_server::{
    dnssec::NxProofKind,
    proto::rr::{LowerName, RecordType, TSigResponseContext},
    server::{Request, RequestInfo},
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupOptions, Nsec3QueryInfo, ZoneHandler,
        ZoneType,
    },
};

pub struct ManagedZone(pub InMemoryZoneHandler);

#[async_trait::async_trait]
impl ZoneHandler for ManagedZone {
    fn zone_type(&self) -> ZoneType {
        self.0.zone_type()
    }
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }
    fn origin(&self) -> &LowerName {
        self.0.origin()
    }
    async fn lookup(
        &self,
        name: &LowerName,
        kind: RecordType,
        request: Option<&RequestInfo<'_>>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.0.lookup(name, kind, request, options).await
    }
    async fn search(
        &self,
        request: &Request,
        options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.0.search(request, options).await
    }
    async fn nsec_records(
        &self,
        name: &LowerName,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.0.nsec_records(name, options).await
    }
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        if !info.has_wildcard_match
            && self
                .0
                .lookup(info.qname, info.qtype, None, options)
                .await
                .map_result()
                .is_some_and(|result| result.is_ok_and(|lookup| !lookup.is_empty()))
        {
            return LookupControlFlow::Continue(Ok(AuthLookup::default()));
        }
        self.0.nsec3_records(info, options).await
    }
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.0.nx_proof_kind()
    }
}
