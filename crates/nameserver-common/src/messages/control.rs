use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ConfigChange, HealthDirection, ListType, ListUpdateType};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ListUpdate {
    pub cmd_id: Uuid,
    pub issued_at: i64,
    pub list_type: ListType,
    pub update_type: ListUpdateType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ListReload {
    pub cmd_id: Uuid,
    pub issued_at: i64,
    pub list_type: ListType,
    pub file_path: String,
    pub expected_checksum: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigUpdate {
    pub cmd_id: Uuid,
    pub issued_at: i64,
    pub changes: Vec<ConfigChange>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HealthCheck {
    pub node_id: String,
    pub ts: i64,
    pub direction: HealthDirection,
    pub status: NodeStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NodeStatus {
    pub uptime_secs: u64,
    pub total_queries: u64,
    pub queries_per_sec: f32,
    pub allowlist_count: u32,
    pub blocklist_count: u32,
    pub nats_connected: bool,
    pub memory_bytes: u64,
}
