use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    DnsResolution,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
    Ptr,
    Srv,
    Caa,
    Https,
    #[serde(rename = "OTHER")]
    Other(u16),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ListAction {
    Allow,
    Block,
    Pass,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepResponseType {
    Referral,
    Answer,
    Cname,
    Nxdomain,
    Error,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseCode {
    Noerror,
    Nxdomain,
    Servfail,
    Refused,
    #[serde(rename = "OTHER")]
    Other(u16),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsEventType {
    QueryReceived,
    ListMatched,
    ResolveStep,
    DnssecCheck,
    FlowComplete,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "list_type", rename_all = "snake_case")
)]
#[serde(rename_all = "snake_case")]
pub enum ListType {
    Allowlist,
    Blocklist,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ListUpdateType {
    FullReplace {
        filter_data: Vec<u8>,
        entry_count: u32,
        built_at: i64,
        checksum: String,
    },
    IncrementalAdd {
        domains: Vec<String>,
        reason: String,
    },
    IncrementalRemove {
        domains: Vec<String>,
        reason: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "key", content = "value")]
pub enum ConfigChange {
    #[serde(rename = "event_stream_enabled")]
    EventStreamEnabled(bool),
    #[serde(rename = "include_all_records")]
    IncludeAllRecords(bool),
    #[serde(rename = "dnssec_validation")]
    DnssecValidation(bool),
    #[serde(rename = "log_level")]
    LogLevel(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthDirection {
    Request,
    Response,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
}

/// The `indicator_type` column in the `sources` table.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "indicator_type", rename_all = "snake_case")
)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Domain,
    Ip,
    Asn,
    Geo,
    Suffix,
    #[cfg_attr(feature = "postgres", sqlx(skip))]
    #[serde(other)]
    Unknown,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Asn => "asn",
            Self::Geo => "geo",
            Self::Suffix => "suffix",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IndicatorType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "domain" => Self::Domain,
            "ip" => Self::Ip,
            "asn" => Self::Asn,
            "geo" => Self::Geo,
            "suffix" => Self::Suffix,
            _ => Self::Unknown,
        })
    }
}

/// The `enrichment_type` column in the `enrichment_bindings` table.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "enrichment_type", rename_all = "snake_case")
)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentType {
    Nrd,
    WellKnown,
    Bulletproof,
    #[cfg_attr(feature = "postgres", sqlx(skip))]
    #[serde(other)]
    Unknown,
}

impl EnrichmentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nrd => "nrd",
            Self::WellKnown => "well_known",
            Self::Bulletproof => "bulletproof",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for EnrichmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EnrichmentType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "nrd" => Self::Nrd,
            "well_known" => Self::WellKnown,
            "bulletproof" => Self::Bulletproof,
            _ => Self::Unknown,
        })
    }
}

/// The `filter_type` column in the `filters` table.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "filter_type", rename_all = "snake_case")
)]
#[serde(rename_all = "snake_case")]
pub enum FilterType {
    Block,
    Allow,
}

impl fmt::Display for FilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => f.write_str("block"),
            Self::Allow => f.write_str("allow"),
        }
    }
}

/// The `output_format` column in the `filters` table.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "output_format", rename_all = "snake_case")
)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Xor,
    Fst,
    Ipf,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xor => f.write_str("xor"),
            Self::Fst => f.write_str("fst"),
            Self::Ipf => f.write_str("ipf"),
        }
    }
}

/// The `block_mode` column in the `profiles` table.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "block_mode", rename_all = "snake_case")
)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    Nxdomain,
    RedirectIp,
}

impl BlockMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nxdomain => "nxdomain",
            Self::RedirectIp => "redirect_ip",
        }
    }
}

/// Reason a query resulted in SERVFAIL.
///
/// Stored in the flow for diagnostics — visible in Grafana and CLI.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServfailReason {
    /// Wall-clock timeout exceeded for the entire resolution.
    Timeout,
    /// CNAME loop detected (A -> B -> A).
    CnameLoop,
    /// Exceeded maximum CNAME hops.
    CnameLimit,
    /// Query budget exhausted (too many upstream queries).
    BudgetExhausted,
    /// All authoritative servers failed at a delegation level.
    AllServersFailed,
    /// Failed to resolve NS names for a glueless referral.
    GluelessResolutionFailed,
    /// Exceeded maximum recursion depth.
    MaxDepthExceeded,
    /// Upstream server returned SERVFAIL.
    UpstreamServfail,
    /// Catch-all for future reasons.
    #[serde(other)]
    Other,
}

impl ServfailReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::CnameLoop => "cname_loop",
            Self::CnameLimit => "cname_limit",
            Self::BudgetExhausted => "budget_exhausted",
            Self::AllServersFailed => "all_servers_failed",
            Self::GluelessResolutionFailed => "glueless_resolution_failed",
            Self::MaxDepthExceeded => "max_depth_exceeded",
            Self::UpstreamServfail => "upstream_servfail",
            Self::Other => "other",
        }
    }

    /// Whether this failure represents a transient local condition (network
    /// error, timeout, budget) vs a persistent data/upstream state. Used to
    /// pick SERVFAIL cache TTL — short for transient (so a blip doesn't keep
    /// a healthy domain failing), longer for persistent (so upstream isn't
    /// hammered when the domain really is broken).
    pub fn kind(&self) -> ServfailKind {
        match self {
            Self::Timeout
            | Self::BudgetExhausted
            | Self::AllServersFailed
            | Self::GluelessResolutionFailed
            | Self::Other => ServfailKind::Transient,
            Self::CnameLoop
            | Self::CnameLimit
            | Self::MaxDepthExceeded
            | Self::UpstreamServfail => ServfailKind::Persistent,
        }
    }
}

/// Classification of a SERVFAIL for caching policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServfailKind {
    /// Likely a local transient issue (network error, timeout, budget).
    /// Cache briefly so a single dropped packet doesn't black-hole a zone.
    Transient,
    /// Persistent data or upstream state (CNAME loop, broken delegation,
    /// authoritative SERVFAIL). Cache longer to avoid amplification when
    /// attackers flood queries for broken names.
    Persistent,
}

impl fmt::Display for ServfailReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for BlockMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for BlockMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "nxdomain" => Ok(Self::Nxdomain),
            "redirect_ip" => Ok(Self::RedirectIp),
            other => anyhow::bail!("unknown block_mode: {other}"),
        }
    }
}
