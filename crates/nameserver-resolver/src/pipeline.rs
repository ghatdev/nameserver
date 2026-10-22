use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Edns, Message, MessageType, ResponseCode as HickoryResponseCode};
use hickory_proto::rr::{RData, RecordType};
use nameserver_common::messages::flow::{DnsFlow, DnsQuery, DnsResponse, DnssecResult};
use nameserver_common::types::enums::{FlowType, ListAction, QueryType, ResponseCode};
use nameserver_common::types::records::{
    ARecord, AaaaRecord, AllRecords, CaaRecord, CnameRecord, MxRecord, SoaRecord,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use nameserver_common::filter::FilterId;

use crate::config::BlockMode;
use crate::filter_set::{FilterHolder, FilterResult};
use crate::geo::GeoHolder;
use crate::profiles::ProfileHolder;
use nameserver_core::Snapshot;

/// Minimum interval between drop-warning logs (milliseconds).
const DROP_WARN_INTERVAL_MS: i64 = 5_000;

/// Bundled state for flow publishing.
struct FlowPublishState {
    tx: mpsc::Sender<DnsFlow>,
    last_drop_warn_ms: AtomicI64,
    drops_since_warn: AtomicU64,
}

impl FlowPublishState {
    fn try_send(&self, flow: DnsFlow) {
        if self.tx.try_send(flow).is_err() {
            let count = self.drops_since_warn.fetch_add(1, Ordering::Relaxed) + 1;
            let now = now_ms();
            let last = self.last_drop_warn_ms.load(Ordering::Relaxed);
            if now - last >= DROP_WARN_INTERVAL_MS
                && self
                    .last_drop_warn_ms
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                warn!(
                    dropped = count,
                    "flow channel full or closed, flows dropped"
                );
                self.drops_since_warn.store(0, Ordering::Relaxed);
            }
        }
    }
}

/// Shared application state passed to axum handlers via `State`.
pub struct AppState {
    pub filters: Arc<FilterHolder>,
    pub profiles: Arc<ProfileHolder>,
    pub geo: Arc<GeoHolder>,
    pub suffix: Arc<crate::suffix::SuffixHolder>,
    pub block_mode: BlockMode,
    pub redirect_ip: Option<String>,
    pub max_domain_depth: usize,
    pub node_name: String,
    /// Canary domains (normalized trailing-dot FQDNs) that trigger synthetic responses.
    pub canary_domains: Vec<String>,
    publish: Option<Arc<FlowPublishState>>,
    queries: Arc<AtomicU64>,
    blocks: Arc<AtomicU64>,
}

pub struct Policy {
    pub block_mode: BlockMode,
    pub redirect_ip: Option<String>,
    pub max_domain_depth: usize,
    pub node_name: String,
    pub canary_domains: Vec<String>,
}

impl AppState {
    pub fn new(
        filters: Arc<FilterHolder>,
        profiles: Arc<ProfileHolder>,
        geo: Arc<GeoHolder>,
        suffix: Arc<crate::suffix::SuffixHolder>,
        policy: Policy,
        flow_tx: Option<mpsc::Sender<DnsFlow>>,
    ) -> Self {
        let publish = flow_tx.map(|tx| {
            Arc::new(FlowPublishState {
                tx,
                last_drop_warn_ms: AtomicI64::new(0),
                drops_since_warn: AtomicU64::new(0),
            })
        });
        Self {
            filters,
            profiles,
            geo,
            suffix,
            block_mode: policy.block_mode,
            redirect_ip: policy.redirect_ip,
            max_domain_depth: policy.max_domain_depth,
            node_name: policy.node_name,
            canary_domains: policy.canary_domains,
            publish,
            queries: Arc::new(AtomicU64::new(0)),
            blocks: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn query_counter(&self) -> Arc<AtomicU64> {
        self.queries.clone()
    }

    pub fn block_counter(&self) -> Arc<AtomicU64> {
        self.blocks.clone()
    }
}

/// Result of process_dns_query: wire bytes + min TTL for Cache-Control.
pub struct DnsQueryResult {
    pub wire: Vec<u8>,
    /// None = error (Cache-Control: no-store), Some(ttl) = max-age=ttl.
    pub min_ttl: Option<u32>,
}

/// Process a DNS query. Profile filtering applied when `profile` is `Some`.
/// Non-profile queries are pure resolution with no filtering.
pub async fn process_dns_query(
    state: &AppState,
    snapshot: Arc<Snapshot>,
    request: Message,
    profile: Option<&crate::profiles::ProfileConfig>,
) -> DnsQueryResult {
    let block_mode = profile.map(|p| &p.block_mode).unwrap_or(&state.block_mode);
    let redirect_ip = profile
        .and_then(|p| p.redirect_ip.as_deref())
        .or(state.redirect_ip.as_deref());
    let profile_id: Option<&str> = profile.map(|p| p.profile_id.as_str());
    let started = Instant::now();
    let started_at = now_ms();

    let request_id = request.id();
    let request_edns = request.extensions().clone();
    let checking_disabled = request.checking_disabled();

    // RFC 6891 §6.1.3: If client sends EDNS version > 0, respond BADVERS.
    if let Some(edns) = request_edns.as_ref()
        && edns.version() > 0
    {
        debug!(
            version = edns.version(),
            "EDNS version > 0, returning BADVERS"
        );
        return DnsQueryResult {
            wire: build_error_response(request_id, HickoryResponseCode::BADVERS, Some(edns)),
            min_ttl: None,
        };
    }

    // Extract the first query, or return FORMERR.
    let (qname, qtype_hickory) = match request.queries().first() {
        Some(q) => (q.name().clone(), q.query_type()),
        None => {
            debug!("DNS request with no queries");
            return DnsQueryResult {
                wire: build_error_response(
                    request_id,
                    HickoryResponseCode::FormErr,
                    request_edns.as_ref(),
                ),
                min_ttl: None,
            };
        }
    };

    // RFC 8484 §4.1: DoH limits to exactly one question.
    if request.queries().len() > 1 {
        debug!(
            qdcount = request.queries().len(),
            "QDCOUNT > 1, returning FORMERR"
        );
        return DnsQueryResult {
            wire: build_error_response(
                request_id,
                HickoryResponseCode::FormErr,
                request_edns.as_ref(),
            ),
            min_ttl: None,
        };
    }

    // Normalize domain for list matching: lowercase FQDN (trailing dot preserved).
    let domain_str = qname.to_ascii().to_lowercase();
    let domain_normalized = &domain_str;

    // RFC 7686: .onion is a special-use domain — never send upstream.
    if domain_normalized.ends_with(".onion.") || domain_normalized == "onion." {
        debug!("RFC 7686: .onion query blocked");
        return DnsQueryResult {
            wire: build_block_response(
                request_id,
                &request,
                request_edns.as_ref(),
                &BlockMode::Nxdomain,
                None,
            ),
            min_ttl: Some(60),
        };
    }

    // Canary domain: synthetic response proving client uses nameserver-resolver.
    if state.canary_domains.contains(&domain_str) {
        return DnsQueryResult {
            wire: build_canary_response(
                request_id,
                &request,
                request_edns.as_ref(),
                qtype_hickory,
                &state.node_name,
                profile_id,
            ),
            min_ttl: Some(300),
        };
    }

    state.queries.fetch_add(1, Ordering::Relaxed);

    // Load suffix set once per query for filter decomposition (zero-copy Arc guard).
    let suffix_guard = state.suffix.load();
    let suffix_ref = suffix_guard.as_ref().as_ref();

    // Domain filtering — only for profile traffic.
    // Non-profile = pure resolver, no filtering.
    let mut domain_allowed = false;
    let domain_blocked: Option<(FilterId, String)> = if let Some(pc) = profile {
        // Domain allowlists take precedence over domain and IP blocklists.
        domain_allowed = pc.custom_filters.as_ref().is_some_and(|custom| {
            matches!(
                custom.check(domain_normalized, state.max_domain_depth, suffix_ref),
                FilterResult::AllowlistHit { .. }
            )
        }) || state
            .filters
            .check_dn_allowlists(
                &pc.dn_allowlists,
                domain_normalized,
                state.max_domain_depth,
                suffix_ref,
            )
            .is_some();
        // 3. Custom blocklist.
        let custom_hit = if let Some(ref custom) = pc.custom_filters {
            if let FilterResult::BlocklistHit { filter_id, matched } =
                custom.check(domain_normalized, state.max_domain_depth, suffix_ref)
            {
                Some((filter_id, matched))
            } else {
                None
            }
        } else {
            None
        };
        // 4. Shared domain blocklist subset.
        if domain_allowed {
            None
        } else {
            custom_hit.or_else(|| {
                state
                    .filters
                    .check_dn_blocklists(
                        &pc.dn_blocklists,
                        domain_normalized,
                        state.max_domain_depth,
                        suffix_ref,
                    )
                    .map(|hit| (hit.filter_id, hit.matched))
            })
        }
    } else {
        None // Non-profile: no domain filtering.
    };

    if let Some((ref filter_id, ref matched)) = domain_blocked {
        state.blocks.fetch_add(1, Ordering::Relaxed);
        let wire = build_block_response(
            request_id,
            &request,
            request_edns.as_ref(),
            block_mode,
            redirect_ip,
        );

        let elapsed = started.elapsed();
        if let Some(publish) = &state.publish {
            let flow = DnsFlow {
                flow_id: Uuid::now_v7(),
                r#type: FlowType::DnsResolution,
                started_at,
                completed_at: started_at + elapsed.as_millis() as i64,
                total_ms: elapsed.as_millis() as u32,
                query: DnsQuery {
                    domain: domain_str,
                    qtype: map_record_type(qtype_hickory),
                },
                list_action: ListAction::Block,
                list_filter: Some(format!("{filter_id}:{matched}")),
                profile_id: profile_id.map(str::to_string),
                geo_country: None,
                geo_asn: 0,
                resolution_path: vec![],
                cname_chain: None,
                response: policy_response(&wire),
                dnssec: DnssecResult {
                    status: nameserver_common::types::enums::DnssecStatus::Indeterminate,
                    algorithm: None,
                    ds_present: false,
                    rrsig_expiry: None,
                    failure_reason: None,
                },
                servfail_reason: None,
            };
            publish.try_send(flow);
        }

        return DnsQueryResult {
            wire,
            min_ttl: Some(60),
        };
    }

    // Resolve iteratively via our recursor.
    let result = resolve_with_cd(&snapshot, &qname, qtype_hickory, checking_disabled).await;

    let elapsed = started.elapsed();

    // Post-resolution IP check: block if any response IP is in an IP blocklist.
    {
        let (ips_for_check, _, _) = extract_records(&result.answers);
        let parsed_ips: Vec<std::net::IpAddr> = ips_for_check
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        // IP filtering — only for profile traffic.
        let ip_blocked = if let Some(pc) = profile.filter(|_| !domain_allowed) {
            if state
                .filters
                .check_ip_allowlists(&pc.ip_allowlists, &parsed_ips)
            {
                None
            } else {
                state
                    .filters
                    .check_ip_blocklists(&pc.ip_blocklists, &parsed_ips)
            }
        } else {
            None // Non-profile: no IP filtering.
        };

        if let Some((filter_id, blocked_ip)) = ip_blocked {
            state.blocks.fetch_add(1, Ordering::Relaxed);
            let wire = build_block_response(
                request_id,
                &request,
                request_edns.as_ref(),
                block_mode,
                redirect_ip,
            );

            if let Some(publish) = &state.publish {
                let flow = DnsFlow {
                    flow_id: Uuid::now_v7(),
                    r#type: FlowType::DnsResolution,
                    started_at,
                    completed_at: started_at + elapsed.as_millis() as i64,
                    total_ms: elapsed.as_millis() as u32,
                    query: DnsQuery {
                        domain: domain_str.clone(),
                        qtype: map_record_type(qtype_hickory),
                    },
                    list_action: ListAction::Block,
                    list_filter: Some(format!("{filter_id}:{blocked_ip}")),
                    profile_id: profile_id.map(str::to_string),
                    geo_country: None,
                    geo_asn: 0,
                    resolution_path: vec![],
                    cname_chain: None,
                    response: policy_response(&wire),
                    dnssec: DnssecResult {
                        status: nameserver_common::types::enums::DnssecStatus::Indeterminate,
                        algorithm: None,
                        ds_present: false,
                        rrsig_expiry: None,
                        failure_reason: None,
                    },
                    servfail_reason: None,
                };
                publish.try_send(flow);
            }

            return DnsQueryResult {
                wire,
                min_ttl: Some(60),
            };
        }
    }

    let wire = build_dns_response(
        request_id,
        &request,
        &request_edns,
        &result,
        checking_disabled,
    );

    let is_error = result.rcode != HickoryResponseCode::NoError
        && result.rcode != HickoryResponseCode::NXDomain;

    // Fire-and-forget flow publishing.
    let (ips, min_ttl, all_records) = extract_records(&result.answers);
    if let Some(publish) = &state.publish {
        let rcode = map_response_code(result.rcode);
        let qtype = map_record_type(qtype_hickory);

        let cname_chain = if result.cname_chain.is_empty() {
            None
        } else {
            Some(result.cname_chain)
        };

        let dnssec = DnssecResult {
            status: result.dnssec.status,
            algorithm: result.dnssec.algorithm,
            ds_present: result.dnssec.ds_present,
            rrsig_expiry: result.dnssec.rrsig_expiry,
            failure_reason: result.dnssec.failure_reason,
        };

        // GeoIP lookup on the first resolved IP.
        let (geo_country, geo_asn) = ips
            .first()
            .and_then(|ip_str| ip_str.parse::<std::net::IpAddr>().ok())
            .and_then(|ip| state.geo.lookup(ip))
            .map(|g| (Some(g.country_str().to_string()), g.asn))
            .unwrap_or((None, 0));

        let flow = DnsFlow {
            flow_id: Uuid::now_v7(),
            r#type: FlowType::DnsResolution,
            started_at,
            completed_at: started_at + elapsed.as_millis() as i64,
            total_ms: elapsed.as_millis() as u32,
            query: DnsQuery {
                domain: domain_str,
                qtype,
            },
            list_action: if domain_allowed {
                ListAction::Allow
            } else {
                ListAction::Pass
            },
            list_filter: None,
            profile_id: profile_id.map(str::to_string),
            geo_country,
            geo_asn,
            resolution_path: result.steps,
            cname_chain,
            response: DnsResponse {
                rcode,
                ips: ips.clone(),
                min_ttl,
                auth_ttl: result.original_ttl,
                all_records,
            },
            dnssec,
            servfail_reason: result.servfail_reason,
        };
        publish.try_send(flow);
    }

    DnsQueryResult {
        wire,
        min_ttl: if is_error { None } else { Some(min_ttl) },
    }
}

fn policy_response(wire: &[u8]) -> DnsResponse {
    match Message::from_vec(wire) {
        Ok(message) => {
            let (ips, min_ttl, all_records) = extract_records(message.answers());
            DnsResponse {
                rcode: map_response_code(message.response_code()),
                ips,
                min_ttl,
                auth_ttl: min_ttl,
                all_records,
            }
        }
        Err(_) => DnsResponse {
            rcode: ResponseCode::Servfail,
            ips: vec![],
            min_ttl: 0,
            auth_ttl: 0,
            all_records: AllRecords::default(),
        },
    }
}

/// Resolve with CD (Checking Disabled) flag support.
/// RFC 4035 §3.2.2: If CD=1, skip DNSSEC validation.
async fn resolve_with_cd(
    snapshot: &Arc<Snapshot>,
    name: &hickory_proto::rr::Name,
    qtype: RecordType,
    checking_disabled: bool,
) -> crate::recursor::ResolveResult {
    crate::recursor::resolve(snapshot, name, qtype, checking_disabled).await
}

// ---------------------------------------------------------------------------
// (dns_wire_response moved to doh.rs)

fn build_error_response(id: u16, rcode: HickoryResponseCode, edns: Option<&Edns>) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(id);
    resp.set_message_type(MessageType::Response);
    resp.set_response_code(rcode);
    resp.set_recursion_available(true);

    if let Some(req_edns) = edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        // RFC 6891 §6.1.2: Advertise SERVER's buffer size.
        resp_edns.set_max_payload(1232);
        resp_edns.set_version(0);
        resp.set_edns(resp_edns);
    }

    resp.to_vec().unwrap_or_else(|_| static_servfail(id))
}

/// Minimal valid DNS response with RCODE=SERVFAIL. Used as an absolute
/// last-resort fallback when `Message::to_vec()` itself fails.
fn static_servfail(id: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2] = 0x80; // QR=1, OPCODE=0
    buf[3] = 0x02; // RCODE=SERVFAIL
    buf
}

/// Build a DNS wire response from a resolve result.
fn build_dns_response(
    id: u16,
    request: &Message,
    request_edns: &Option<Edns>,
    result: &crate::recursor::ResolveResult,
    checking_disabled: bool,
) -> Vec<u8> {
    use nameserver_common::types::enums::DnssecStatus;

    let mut resp = Message::new();
    resp.set_id(id);
    resp.set_message_type(MessageType::Response);
    resp.set_response_code(result.rcode);
    resp.set_recursion_desired(true);
    resp.set_recursion_available(true);

    // RFC 4035 §3.2.3: Set AD=1 when DNSSEC validation succeeds (Secure).
    // Only set AD if CD was not set by client.
    let ad = !checking_disabled && result.dnssec.status == DnssecStatus::Secure;
    resp.set_authentic_data(ad);

    // RFC 4035 §3.2.2: Echo CD bit from request.
    resp.set_checking_disabled(checking_disabled);

    for q in request.queries() {
        resp.add_query(q.clone());
    }

    let dnssec_ok = request_edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);
    let wanted = request.queries().first().map(|query| query.query_type());
    let keep = |record: &&hickory_proto::rr::Record| {
        dnssec_ok
            || !matches!(
                record.record_type(),
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
            )
            || wanted == Some(record.record_type())
    };
    resp.insert_answers(result.answers.iter().filter(keep).cloned().collect());
    resp.insert_name_servers(result.authority.iter().filter(keep).cloned().collect());
    resp.insert_additionals(result.additional.iter().filter(keep).cloned().collect());

    if let Some(req_edns) = request_edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        // RFC 6891 §6.1.2: Advertise SERVER's buffer size, not echo client's.
        resp_edns.set_max_payload(1232);
        resp_edns.set_version(0);
        resp.set_edns(resp_edns);
    }

    match resp.to_vec() {
        Ok(w) => w,
        Err(e) => {
            debug!(error = %e, "failed to serialize DNS response");
            build_error_response(id, HickoryResponseCode::ServFail, request_edns.as_ref())
        }
    }
}

/// Build a block response (NXDOMAIN or redirect IP).
/// RFC 2308 §2.1: Includes synthesized SOA for negative caching.
fn build_block_response(
    id: u16,
    request: &Message,
    edns: Option<&Edns>,
    block_mode: &BlockMode,
    redirect_ip: Option<&str>,
) -> Vec<u8> {
    use hickory_proto::rr::{Name, Record, rdata};
    use std::str::FromStr;

    let mut resp = Message::new();
    resp.set_id(id);
    resp.set_message_type(MessageType::Response);
    resp.set_recursion_desired(true);
    resp.set_recursion_available(true);

    for q in request.queries() {
        resp.add_query(q.clone());
    }

    match block_mode {
        BlockMode::Nxdomain => {
            resp.set_response_code(HickoryResponseCode::NXDomain);
            // RFC 2308 §2.1: Synthesize minimal SOA so clients can negative-cache.
            if let Some(q) = request.queries().first() {
                let soa = rdata::SOA::new(
                    Name::from_ascii("blocked.invalid.").expect("valid name"),
                    Name::from_ascii("admin.blocked.invalid.").expect("valid name"),
                    1,     // serial
                    3600,  // refresh
                    600,   // retry
                    86400, // expire
                    60,    // minimum (negative cache TTL)
                );
                let soa_record = Record::from_rdata(q.name().clone(), 60, RData::SOA(soa));
                resp.insert_name_servers(vec![soa_record]);
            }
        }
        BlockMode::RedirectIp => {
            resp.set_response_code(HickoryResponseCode::NoError);
            if let Some(ip_str) = redirect_ip
                && let Some(q) = request.queries().first()
                && let Ok(ipv4) = std::net::Ipv4Addr::from_str(ip_str)
            {
                let record = Record::from_rdata(q.name().clone(), 60, RData::A(rdata::A(ipv4)));
                resp.insert_answers(vec![record]);
            }
        }
    }

    if let Some(req_edns) = edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        // RFC 6891 §6.1.2: Advertise SERVER's buffer size.
        resp_edns.set_max_payload(1232);
        resp_edns.set_version(0);
        resp.set_edns(resp_edns);
    }

    resp.to_vec().unwrap_or_default()
}

/// Build a canary response: synthetic answer proving client uses nameserver-resolver.
/// TXT returns node name + profile; A returns 100.64.0.1 (CGNAT sentinel).
fn build_canary_response(
    id: u16,
    request: &Message,
    edns: Option<&Edns>,
    qtype: RecordType,
    node_name: &str,
    profile_id: Option<&str>,
) -> Vec<u8> {
    use hickory_proto::rr::{Record, rdata};

    let mut resp = Message::new();
    resp.set_id(id);
    resp.set_message_type(MessageType::Response);
    resp.set_response_code(HickoryResponseCode::NoError);
    resp.set_recursion_desired(true);
    resp.set_recursion_available(true);
    resp.set_authoritative(true);

    for q in request.queries() {
        resp.add_query(q.clone());
    }

    let qname = request
        .queries()
        .first()
        .expect("canary handler called after query validation")
        .name()
        .clone();

    match qtype {
        RecordType::TXT => {
            let profile = profile_id.unwrap_or("none");
            let txt = format!("nameserver v=1 node={node_name} profile={profile}");
            let txt_rdata = rdata::TXT::new(vec![txt]);
            let record = Record::from_rdata(qname, 300, RData::TXT(txt_rdata));
            resp.insert_answers(vec![record]);
        }
        RecordType::A => {
            // 100.64.0.1 — CGNAT range (RFC 6598), never routable on the public internet.
            let ip = std::net::Ipv4Addr::new(100, 64, 0, 1);
            let record = Record::from_rdata(qname, 300, RData::A(rdata::A(ip)));
            resp.insert_answers(vec![record]);
        }
        RecordType::AAAA => {
            // NODATA: valid domain but no AAAA record.
            // Empty answer with NOERROR is correct per RFC 2308.
        }
        _ => {
            // NODATA for unsupported types.
        }
    }

    if let Some(req_edns) = edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        resp_edns.set_max_payload(1232);
        resp_edns.set_version(0);
        resp.set_edns(resp_edns);
    }

    resp.to_vec().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Record extraction from answer section
// ---------------------------------------------------------------------------

fn extract_records(answers: &[hickory_proto::rr::Record]) -> (Vec<String>, u32, AllRecords) {
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    let mut all_records = AllRecords::default();

    for record in answers {
        let ttl = record.ttl();
        if ttl < min_ttl {
            min_ttl = ttl;
        }

        match record.data() {
            RData::A(a) => {
                let ip = a.0.to_string();
                ips.push(ip.clone());
                all_records
                    .a
                    .get_or_insert_with(Vec::new)
                    .push(ARecord { ip, ttl });
            }
            RData::AAAA(aaaa) => {
                let ip = aaaa.0.to_string();
                ips.push(ip.clone());
                all_records
                    .aaaa
                    .get_or_insert_with(Vec::new)
                    .push(AaaaRecord { ip, ttl });
            }
            RData::CNAME(cname) => {
                let target = cname.0.to_string();
                all_records
                    .cname
                    .get_or_insert_with(Vec::new)
                    .push(CnameRecord { target, ttl });
            }
            RData::NS(ns) => {
                all_records.ns.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::NsRecord {
                        name: ns.0.to_string(),
                        ttl,
                    },
                );
            }
            RData::MX(mx) => {
                all_records.mx.get_or_insert_with(Vec::new).push(MxRecord {
                    preference: mx.preference(),
                    exchange: mx.exchange().to_string(),
                    ttl,
                });
            }
            RData::SOA(soa) => {
                all_records.soa = Some(SoaRecord {
                    mname: soa.mname().to_string(),
                    rname: soa.rname().to_string(),
                    serial: soa.serial(),
                    refresh: soa.refresh() as u32,
                    retry: soa.retry() as u32,
                    expire: soa.expire() as u32,
                    minimum: soa.minimum(),
                    ttl,
                });
            }
            RData::TXT(txt) => {
                let text = txt
                    .txt_data()
                    .iter()
                    .filter_map(|b| std::str::from_utf8(b).ok())
                    .collect::<Vec<_>>()
                    .join("");
                all_records
                    .txt
                    .get_or_insert_with(Vec::new)
                    .push(nameserver_common::types::TxtRecord { value: text, ttl });
            }
            RData::CAA(caa) => {
                all_records
                    .caa
                    .get_or_insert_with(Vec::new)
                    .push(CaaRecord {
                        flags: caa.flags(),
                        tag: caa.tag().as_str().to_string(),
                        value: String::from_utf8_lossy(caa.raw_value()).into_owned(),
                        ttl,
                    });
            }
            RData::SRV(srv) => {
                all_records.srv.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::SrvRecord {
                        priority: srv.priority(),
                        weight: srv.weight(),
                        port: srv.port(),
                        target: srv.target().to_string(),
                        ttl,
                    },
                );
            }
            RData::PTR(ptr) => {
                all_records.ptr.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::PtrRecord {
                        name: ptr.0.to_string(),
                        ttl,
                    },
                );
            }
            RData::NAPTR(naptr) => {
                all_records.naptr.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::NaptrRecord {
                        order: naptr.order(),
                        preference: naptr.preference(),
                        flags: String::from_utf8_lossy(naptr.flags()).into_owned(),
                        services: String::from_utf8_lossy(naptr.services()).into_owned(),
                        regexp: String::from_utf8_lossy(naptr.regexp()).into_owned(),
                        replacement: naptr.replacement().to_string(),
                        ttl,
                    },
                );
            }
            RData::HTTPS(svcb) => {
                all_records.https.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::HttpsRecord {
                        priority: svcb.svc_priority(),
                        target: svcb.target_name().to_string(),
                        params: format!("{:?}", svcb.svc_params()),
                        ttl,
                    },
                );
            }
            RData::SVCB(svcb) => {
                all_records.svcb.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::SvcbRecord {
                        priority: svcb.svc_priority(),
                        target: svcb.target_name().to_string(),
                        params: format!("{:?}", svcb.svc_params()),
                        ttl,
                    },
                );
            }
            RData::DNSSEC(dnssec_rdata) => {
                use hickory_proto::dnssec::Verifier;
                use hickory_proto::dnssec::rdata::DNSSECRData;
                match dnssec_rdata {
                    DNSSECRData::DS(ds) => {
                        all_records.ds.get_or_insert_with(Vec::new).push(
                            nameserver_common::types::DsRecord {
                                key_tag: ds.key_tag(),
                                algorithm: ds.algorithm().as_str().to_string(),
                                digest_type: format!("{:?}", ds.digest_type()),
                                digest: hex::encode(ds.digest()),
                                ttl,
                            },
                        );
                    }
                    DNSSECRData::DNSKEY(key) => {
                        all_records.dnskey.get_or_insert_with(Vec::new).push(
                            nameserver_common::types::DnskeyRecord {
                                flags: key.flags(),
                                algorithm: key.algorithm().as_str().to_string(),
                                key_tag: key.calculate_key_tag().unwrap_or(0),
                                ttl,
                            },
                        );
                    }
                    DNSSECRData::RRSIG(sig) => {
                        all_records.rrsig.get_or_insert_with(Vec::new).push(
                            nameserver_common::types::RrsigRecord {
                                type_covered: format!("{:?}", sig.type_covered()),
                                algorithm: sig.algorithm().as_str().to_string(),
                                labels: sig.num_labels(),
                                original_ttl: sig.original_ttl(),
                                expiration: sig.sig_expiration().get(),
                                inception: sig.sig_inception().get(),
                                key_tag: sig.key_tag(),
                                signer: sig.signer_name().to_string(),
                                ttl,
                            },
                        );
                    }
                    DNSSECRData::NSEC(nsec) => {
                        all_records.nsec.get_or_insert_with(Vec::new).push(
                            nameserver_common::types::NsecRecord {
                                next_domain: nsec.next_domain_name().to_string(),
                                types: nsec.type_bit_maps().map(|t| format!("{t:?}")).collect(),
                                ttl,
                            },
                        );
                    }
                    DNSSECRData::NSEC3(nsec3) => {
                        all_records.nsec3.get_or_insert_with(Vec::new).push(
                            nameserver_common::types::Nsec3Record {
                                algorithm: format!("{:?}", nsec3.hash_algorithm()),
                                flags: nsec3.flags(),
                                iterations: nsec3.iterations(),
                                salt: hex::encode(nsec3.salt()),
                                next_hashed: hex::encode(nsec3.next_hashed_owner_name()),
                                types: nsec3.type_bit_maps().map(|t| format!("{t:?}")).collect(),
                                ttl,
                            },
                        );
                    }
                    _ => {
                        all_records.other.get_or_insert_with(Vec::new).push(
                            nameserver_common::types::OtherRecord {
                                rtype: format!("{:?}", record.record_type()),
                                ttl,
                                rdata: format!("{dnssec_rdata}"),
                            },
                        );
                    }
                }
            }
            other => {
                all_records.other.get_or_insert_with(Vec::new).push(
                    nameserver_common::types::OtherRecord {
                        rtype: format!("{:?}", other.record_type()),
                        ttl,
                        rdata: format!("{other}"),
                    },
                );
            }
        }
    }

    if min_ttl == u32::MAX {
        min_ttl = 0;
    }

    (ips, min_ttl, all_records)
}

// ---------------------------------------------------------------------------
// Type mapping helpers
// ---------------------------------------------------------------------------

fn map_record_type(rt: RecordType) -> QueryType {
    match rt {
        RecordType::A => QueryType::A,
        RecordType::AAAA => QueryType::Aaaa,
        RecordType::CNAME => QueryType::Cname,
        RecordType::MX => QueryType::Mx,
        RecordType::NS => QueryType::Ns,
        RecordType::TXT => QueryType::Txt,
        RecordType::SOA => QueryType::Soa,
        RecordType::PTR => QueryType::Ptr,
        RecordType::SRV => QueryType::Srv,
        RecordType::CAA => QueryType::Caa,
        RecordType::HTTPS => QueryType::Https,
        other => QueryType::Other(u16::from(other)),
    }
}

fn map_response_code(rc: HickoryResponseCode) -> ResponseCode {
    match rc {
        HickoryResponseCode::NoError => ResponseCode::Noerror,
        HickoryResponseCode::NXDomain => ResponseCode::Nxdomain,
        HickoryResponseCode::ServFail => ResponseCode::Servfail,
        HickoryResponseCode::Refused => ResponseCode::Refused,
        other => ResponseCode::Other(u16::from(other)),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as i64
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Message, MessageType, Query};
    use hickory_proto::rr::rdata;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use nameserver_common::types::enums::DnssecStatus;
    use std::net::Ipv4Addr;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn a_record(owner: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(rdata::A(ip)))
    }

    fn soa_record(owner: &str, ttl: u32, minimum: u32) -> Record {
        let soa = rdata::SOA::new(
            name("ns1.example.com."),
            name("admin.example.com."),
            2024010100,
            3600,
            600,
            86400,
            minimum,
        );
        Record::from_rdata(name(owner), ttl, RData::SOA(soa))
    }

    fn make_dns_query(qname: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        let query = Query::query(name(qname), qtype);
        msg.add_query(query);
        msg
    }

    fn make_dns_query_with_edns(qname: &str, qtype: RecordType, edns_version: u8) -> Message {
        let mut msg = make_dns_query(qname, qtype);
        let mut edns = Edns::new();
        edns.set_version(edns_version);
        edns.set_max_payload(4096);
        msg.set_edns(edns);
        msg
    }

    // -----------------------------------------------------------------------
    // 3c. Response construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_dns_response_correct_sections() {
        let request = make_dns_query("example.com.", RecordType::A);
        let request_edns = request.extensions().clone();
        let result = crate::recursor::ResolveResult {
            answers: vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            authority: vec![],
            additional: vec![],
            rcode: HickoryResponseCode::NoError,
            steps: vec![],
            cname_chain: vec![],
            dnssec: crate::dnssec::DnssecInfo::indeterminate(),
            original_ttl: 0,
            servfail_reason: None,
        };

        let wire = build_dns_response(0x1234, &request, &request_edns, &result, false);
        let resp = Message::from_vec(&wire).unwrap();

        assert_eq!(resp.id(), 0x1234);
        assert_eq!(resp.response_code(), HickoryResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert!(resp.recursion_available());
    }

    #[test]
    fn build_dns_response_edns_max_payload_is_server_value() {
        let request = make_dns_query_with_edns("example.com.", RecordType::A, 0);
        let request_edns = request.extensions().clone();
        let result = crate::recursor::ResolveResult {
            answers: vec![],
            authority: vec![],
            additional: vec![],
            rcode: HickoryResponseCode::NoError,
            steps: vec![],
            cname_chain: vec![],
            dnssec: crate::dnssec::DnssecInfo::indeterminate(),
            original_ttl: 0,
            servfail_reason: None,
        };

        let wire = build_dns_response(0x1234, &request, &request_edns, &result, false);
        let resp = Message::from_vec(&wire).unwrap();

        // Server should advertise its own buffer size (1232), not echo client's (4096).
        let resp_edns = resp
            .extensions()
            .as_ref()
            .expect("response should have EDNS");
        assert_eq!(resp_edns.max_payload(), 1232);
    }

    #[test]
    fn build_dns_response_ad_bit_set_on_secure() {
        let request = make_dns_query("example.com.", RecordType::A);
        let request_edns = request.extensions().clone();
        let result = crate::recursor::ResolveResult {
            answers: vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            authority: vec![],
            additional: vec![],
            rcode: HickoryResponseCode::NoError,
            steps: vec![],
            cname_chain: vec![],
            dnssec: crate::dnssec::DnssecInfo {
                status: DnssecStatus::Secure,
                algorithm: Some("RSASHA256".to_string()),
                ds_present: true,
                rrsig_expiry: None,
                failure_reason: None,
            },
            original_ttl: 0,
            servfail_reason: None,
        };

        let wire = build_dns_response(0x1234, &request, &request_edns, &result, false);
        let resp = Message::from_vec(&wire).unwrap();
        assert!(resp.authentic_data(), "AD bit should be set for Secure");
    }

    #[test]
    fn build_dns_response_ad_not_set_when_cd() {
        let request = make_dns_query("example.com.", RecordType::A);
        let request_edns = request.extensions().clone();
        let result = crate::recursor::ResolveResult {
            answers: vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            authority: vec![],
            additional: vec![],
            rcode: HickoryResponseCode::NoError,
            steps: vec![],
            cname_chain: vec![],
            dnssec: crate::dnssec::DnssecInfo {
                status: DnssecStatus::Secure,
                algorithm: None,
                ds_present: true,
                rrsig_expiry: None,
                failure_reason: None,
            },
            original_ttl: 0,
            servfail_reason: None,
        };

        // CD=true: AD should NOT be set even if validation is Secure.
        let wire = build_dns_response(0x1234, &request, &request_edns, &result, true);
        let resp = Message::from_vec(&wire).unwrap();
        assert!(!resp.authentic_data(), "AD should not be set when CD=1");
        assert!(resp.checking_disabled(), "CD bit should be echoed");
    }

    #[test]
    fn build_block_response_nxdomain_has_soa() {
        let request = make_dns_query("evil.com.", RecordType::A);
        let wire = build_block_response(0x1234, &request, None, &BlockMode::Nxdomain, None);
        let resp = Message::from_vec(&wire).unwrap();

        assert_eq!(resp.response_code(), HickoryResponseCode::NXDomain);
        // RFC 2308: SOA must be present for negative caching.
        assert!(
            resp.name_servers()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA),
            "block NXDOMAIN should include SOA"
        );
    }

    #[test]
    fn build_block_response_redirect_mode() {
        let request = make_dns_query("evil.com.", RecordType::A);
        let wire = build_block_response(
            0x1234,
            &request,
            None,
            &BlockMode::RedirectIp,
            Some("10.0.0.1"),
        );
        let resp = Message::from_vec(&wire).unwrap();

        assert_eq!(resp.response_code(), HickoryResponseCode::NoError);
        assert!(
            !resp.answers().is_empty(),
            "redirect should have answer records"
        );
    }

    #[test]
    fn build_error_response_formerr() {
        let wire = build_error_response(0x1234, HickoryResponseCode::FormErr, None);
        let resp = Message::from_vec(&wire).unwrap();
        assert_eq!(resp.id(), 0x1234);
        assert_eq!(resp.response_code(), HickoryResponseCode::FormErr);
    }

    #[test]
    fn build_error_response_servfail() {
        let wire = build_error_response(0x1234, HickoryResponseCode::ServFail, None);
        let resp = Message::from_vec(&wire).unwrap();
        assert_eq!(resp.response_code(), HickoryResponseCode::ServFail);
    }

    #[test]
    fn badvers_for_edns_version_gt_0() {
        let edns = {
            let mut e = Edns::new();
            e.set_version(1);
            e.set_max_payload(4096);
            e
        };
        let wire = build_error_response(0x1234, HickoryResponseCode::BADVERS, Some(&edns));
        let resp = Message::from_vec(&wire).unwrap();
        // BADVERS is RCODE 16 (extended), verify the response has EDNS.
        assert!(resp.extensions().is_some());
    }

    // -----------------------------------------------------------------------
    // Canary domain response tests
    // -----------------------------------------------------------------------

    #[test]
    fn canary_txt_response_contains_node_and_profile() {
        let request = make_dns_query("canary.example.test.", RecordType::TXT);
        let wire = build_canary_response(
            0x1234,
            &request,
            None,
            RecordType::TXT,
            "ns1",
            Some("default"),
        );
        let resp = Message::from_vec(&wire).unwrap();

        assert_eq!(resp.response_code(), HickoryResponseCode::NoError);
        assert!(resp.authoritative(), "canary should set AA bit");
        assert_eq!(resp.answers().len(), 1);

        let txt = match resp.answers()[0].data() {
            RData::TXT(txt) => txt.to_string(),
            other => panic!("expected TXT, got {other:?}"),
        };
        assert!(
            txt.contains("nameserver"),
            "TXT should contain 'nameserver'"
        );
        assert!(txt.contains("node=ns1"), "TXT should contain node name");
        assert!(
            txt.contains("profile=default"),
            "TXT should contain profile"
        );
    }

    #[test]
    fn canary_txt_no_profile_shows_none() {
        let request = make_dns_query("canary.example.test.", RecordType::TXT);
        let wire = build_canary_response(0x1234, &request, None, RecordType::TXT, "ns2", None);
        let resp = Message::from_vec(&wire).unwrap();
        let txt = match resp.answers()[0].data() {
            RData::TXT(txt) => txt.to_string(),
            other => panic!("expected TXT, got {other:?}"),
        };
        assert!(
            txt.contains("profile=none"),
            "no-profile should show 'none'"
        );
    }

    #[test]
    fn canary_a_response_returns_cgnat_sentinel() {
        let request = make_dns_query("canary.example.test.", RecordType::A);
        let wire = build_canary_response(0x1234, &request, None, RecordType::A, "ns1", None);
        let resp = Message::from_vec(&wire).unwrap();

        assert_eq!(resp.response_code(), HickoryResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(100, 64, 0, 1)),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn canary_aaaa_returns_nodata() {
        let request = make_dns_query("canary.example.test.", RecordType::AAAA);
        let wire = build_canary_response(0x1234, &request, None, RecordType::AAAA, "ns1", None);
        let resp = Message::from_vec(&wire).unwrap();

        assert_eq!(resp.response_code(), HickoryResponseCode::NoError);
        assert!(
            resp.answers().is_empty(),
            "AAAA should return NODATA (empty answers)"
        );
    }

    #[test]
    fn extract_records_all_types() {
        use hickory_proto::rr::rdata;

        let answers = vec![
            a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300),
            Record::from_rdata(
                name("example.com."),
                300,
                RData::AAAA(rdata::AAAA(std::net::Ipv6Addr::LOCALHOST)),
            ),
            Record::from_rdata(
                name("example.com."),
                300,
                RData::CNAME(rdata::CNAME(name("cdn.example.com."))),
            ),
            Record::from_rdata(
                name("example.com."),
                300,
                RData::MX(rdata::MX::new(10, name("mail.example.com."))),
            ),
            soa_record("example.com.", 300, 60),
            Record::from_rdata(
                name("example.com."),
                300,
                RData::TXT(rdata::TXT::new(vec![
                    "v=spf1 include:example.com".to_string(),
                ])),
            ),
        ];

        let (ips, min_ttl, all_records) = extract_records(&answers);

        assert_eq!(ips.len(), 2); // A + AAAA
        assert_eq!(min_ttl, 300);
        assert!(all_records.a.is_some());
        assert!(all_records.aaaa.is_some());
        assert!(all_records.cname.is_some());
        assert!(all_records.mx.is_some());
        assert!(all_records.soa.is_some());
        assert!(all_records.txt.is_some());
    }

    #[test]
    fn static_servfail_is_valid_dns() {
        let buf = static_servfail(0x1234);
        assert_eq!(buf.len(), 12);
        // Transaction ID
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x1234);
        // QR=1 (response)
        assert_eq!(buf[2] & 0x80, 0x80);
        // RCODE=2 (SERVFAIL)
        assert_eq!(buf[3] & 0x0F, 2);
        // Parseable by hickory
        let msg = Message::from_vec(&buf).expect("should parse as valid DNS");
        assert_eq!(msg.id(), 0x1234);
        assert_eq!(
            msg.response_code(),
            hickory_proto::op::ResponseCode::ServFail
        );
    }
    #[test]
    fn redirect_flow_matches_the_actual_dns_response() {
        let request = make_dns_query("blocked.example.", RecordType::A);
        let wire = build_block_response(
            10,
            &request,
            None,
            &BlockMode::RedirectIp,
            Some("192.0.2.99"),
        );
        let summary = policy_response(&wire);
        assert_eq!(summary.rcode, ResponseCode::Noerror);
        assert_eq!(summary.ips, ["192.0.2.99"]);
        assert_eq!(summary.min_ttl, 60);
    }
}
