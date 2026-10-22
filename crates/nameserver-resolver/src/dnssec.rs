use nameserver_common::types::enums::DnssecStatus;

pub struct DnssecInfo {
    pub status: DnssecStatus,
    pub algorithm: Option<String>,
    pub ds_present: bool,
    pub rrsig_expiry: Option<i64>,
    pub failure_reason: Option<String>,
}
impl DnssecInfo {
    pub fn indeterminate() -> Self {
        Self {
            status: DnssecStatus::Indeterminate,
            algorithm: None,
            ds_present: false,
            rrsig_expiry: None,
            failure_reason: None,
        }
    }
}
