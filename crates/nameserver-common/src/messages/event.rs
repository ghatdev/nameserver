use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{DnsEventType, DnssecStatus, ListAction, QueryType};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsEvent {
    pub flow_id: Uuid,
    pub seq: u16,
    pub event_type: DnsEventType,
    pub ts: i64,
    pub data: DnsEventData,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsEventData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qtype: Option<QueryType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ListAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnssec_status: Option<DnssecStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<u32>,
}
