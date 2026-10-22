use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct AllRecords {
    // --- Answer records ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<Vec<ARecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaaa: Option<Vec<AaaaRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<Vec<CnameRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dname: Option<Vec<DnameRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mx: Option<Vec<MxRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txt: Option<Vec<TxtRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srv: Option<Vec<SrvRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<Vec<PtrRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa: Option<Vec<CaaRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub naptr: Option<Vec<NaptrRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<Vec<HttpsRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svcb: Option<Vec<SvcbRecord>>,

    // --- Authority records ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<Vec<NsRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soa: Option<SoaRecord>,

    // --- DNSSEC records ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ds: Option<Vec<DsRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnskey: Option<Vec<DnskeyRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrsig: Option<Vec<RrsigRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<Vec<NsecRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec3: Option<Vec<Nsec3Record>>,

    // --- Security records ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsa: Option<Vec<TlsaRecord>>,

    // --- Catch-all ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<Vec<OtherRecord>>,
}

// ---------------------------------------------------------------------------
// Answer record types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ARecord {
    pub ip: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AaaaRecord {
    pub ip: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CnameRecord {
    pub target: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnameRecord {
    pub target: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NsRecord {
    pub name: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    pub value: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PtrRecord {
    pub name: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NaptrRecord {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub services: String,
    pub regexp: String,
    pub replacement: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    pub target: String,
    pub params: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SvcbRecord {
    pub priority: u16,
    pub target: String,
    pub params: String,
    pub ttl: u32,
}

// ---------------------------------------------------------------------------
// DNSSEC record types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: String,
    pub digest_type: String,
    pub digest: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub algorithm: String,
    pub key_tag: u16,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RrsigRecord {
    pub type_covered: String,
    pub algorithm: String,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: String,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NsecRecord {
    pub next_domain: String,
    pub types: Vec<String>,
    pub ttl: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Record {
    pub algorithm: String,
    pub flags: u8,
    pub iterations: u16,
    pub salt: String,
    pub next_hashed: String,
    pub types: Vec<String>,
    pub ttl: u32,
}

// ---------------------------------------------------------------------------
// Security record types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    pub usage: String,
    pub selector: String,
    pub matching_type: String,
    pub cert_data: String,
    pub ttl: u32,
}

// ---------------------------------------------------------------------------
// Catch-all
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OtherRecord {
    pub rtype: String,
    pub ttl: u32,
    pub rdata: String,
}
