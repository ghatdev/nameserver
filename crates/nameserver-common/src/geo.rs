use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// CDN ASN numbers — skip GeoIP mismatch rules for these.
pub const CDN_ASNS: &[u32] = &[
    13335, 209242, // Cloudflare
    16509,  // AWS CloudFront
    20940, 16625, // Akamai
    54113, // Fastly
    15169, // Google
    8075,  // Azure
];

/// A single IPv4 geo entry: IP range → country + ASN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoEntry4 {
    pub start: u32,
    pub end: u32,
    pub country: [u8; 2],
    pub asn: u32,
}

/// A single IPv6 geo entry: IP range → country + ASN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoEntry6 {
    pub start_hi: u64,
    pub start_lo: u64,
    pub end_hi: u64,
    pub end_lo: u64,
    pub country: [u8; 2],
    pub asn: u32,
}

impl GeoEntry6 {
    fn start_u128(&self) -> u128 {
        ((self.start_hi as u128) << 64) | (self.start_lo as u128)
    }

    fn end_u128(&self) -> u128 {
        ((self.end_hi as u128) << 64) | (self.end_lo as u128)
    }
}

/// Compiled geo lookup table. Sorted arrays with binary search.
///
/// Serialized with bincode. Both nameserver-resolver (runtime) and
/// nameserver-control (compile) use this format.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GeoTable {
    pub v4: Vec<GeoEntry4>,
    pub v6: Vec<GeoEntry6>,
}

/// Result of a geo lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoLookup {
    pub country: [u8; 2],
    pub asn: u32,
}

impl GeoLookup {
    /// Country code as a string (e.g., "KR").
    pub fn country_str(&self) -> &str {
        std::str::from_utf8(&self.country).unwrap_or("??")
    }

    /// Whether this ASN is a known CDN.
    pub fn is_cdn(&self) -> bool {
        CDN_ASNS.contains(&self.asn)
    }
}

impl GeoTable {
    /// Look up an IP address → country + ASN.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLookup> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(u32::from(v4)),
            IpAddr::V6(v6) => self.lookup_v6(u128::from(v6)),
        }
    }

    fn lookup_v4(&self, ip: u32) -> Option<GeoLookup> {
        let idx = self.v4.partition_point(|e| e.start <= ip);
        if idx == 0 {
            return None;
        }
        let entry = &self.v4[idx - 1];
        if ip <= entry.end {
            Some(GeoLookup {
                country: entry.country,
                asn: entry.asn,
            })
        } else {
            None
        }
    }

    fn lookup_v6(&self, ip: u128) -> Option<GeoLookup> {
        let idx = self.v6.partition_point(|e| e.start_u128() <= ip);
        if idx == 0 {
            return None;
        }
        let entry = &self.v6[idx - 1];
        if ip <= entry.end_u128() {
            Some(GeoLookup {
                country: entry.country,
                asn: entry.asn,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_v4_hit() {
        let table = GeoTable {
            v4: vec![
                GeoEntry4 {
                    start: u32::from(std::net::Ipv4Addr::new(1, 0, 0, 0)),
                    end: u32::from(std::net::Ipv4Addr::new(1, 0, 0, 255)),
                    country: *b"US",
                    asn: 13335,
                },
                GeoEntry4 {
                    start: u32::from(std::net::Ipv4Addr::new(1, 11, 0, 0)),
                    end: u32::from(std::net::Ipv4Addr::new(1, 11, 255, 255)),
                    country: *b"KR",
                    asn: 9318,
                },
            ],
            v6: vec![],
        };

        let result = table.lookup("1.11.100.5".parse().unwrap()).unwrap();
        assert_eq!(result.country, *b"KR");
        assert_eq!(result.asn, 9318);
        assert!(!result.is_cdn());

        let result = table.lookup("1.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(result.country, *b"US");
        assert_eq!(result.asn, 13335);
        assert!(result.is_cdn());

        assert!(table.lookup("2.2.2.2".parse().unwrap()).is_none());
    }

    #[test]
    fn test_lookup_v4_boundary() {
        let table = GeoTable {
            v4: vec![GeoEntry4 {
                start: u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)),
                end: u32::from(std::net::Ipv4Addr::new(10, 0, 0, 255)),
                country: *b"DE",
                asn: 12345,
            }],
            v6: vec![],
        };

        assert!(table.lookup("10.0.0.0".parse().unwrap()).is_some());
        assert!(table.lookup("10.0.0.255".parse().unwrap()).is_some());
        assert!(table.lookup("9.255.255.255".parse().unwrap()).is_none());
        assert!(table.lookup("10.0.1.0".parse().unwrap()).is_none());
    }

    #[test]
    fn test_lookup_v6() {
        let start: u128 = u128::from(std::net::Ipv6Addr::new(0x2001, 0x220, 0, 0, 0, 0, 0, 0));
        let end = start | ((1u128 << 93) - 1);

        let table = GeoTable {
            v4: vec![],
            v6: vec![GeoEntry6 {
                start_hi: (start >> 64) as u64,
                start_lo: start as u64,
                end_hi: (end >> 64) as u64,
                end_lo: end as u64,
                country: *b"KR",
                asn: 4766,
            }],
        };

        let result = table.lookup("2001:220::1".parse().unwrap()).unwrap();
        assert_eq!(result.country, *b"KR");
        assert_eq!(result.asn, 4766);

        assert!(table.lookup("2001:221::1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_bincode_roundtrip() {
        let table = GeoTable {
            v4: vec![GeoEntry4 {
                start: 0x0A000000,
                end: 0x0AFFFFFF,
                country: *b"JP",
                asn: 2516,
            }],
            v6: vec![],
        };

        let bytes = bincode::serialize(&table).unwrap();
        let restored: GeoTable = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.v4.len(), 1);
        assert_eq!(restored.v4[0].country, *b"JP");
        assert_eq!(restored.v4[0].asn, 2516);
    }
}
