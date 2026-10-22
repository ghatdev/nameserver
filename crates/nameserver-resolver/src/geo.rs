use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use nameserver_common::geo::{GeoLookup, GeoTable};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Thread-safe, hot-swappable GeoIP lookup table.
///
/// Same pattern as `FilterHolder`: uses `ArcSwap` for lock-free reads.
/// New GeoTable versions are built atomically and swapped in.
pub struct GeoHolder {
    inner: ArcSwap<Option<GeoTable>>,
}

impl GeoHolder {
    /// Create a new holder with no geo data loaded.
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(None),
        }
    }

    /// Look up an IP address → country + ASN.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLookup> {
        let guard = self.inner.load();
        guard.as_ref().as_ref()?.lookup(ip)
    }

    /// Replace the geo table from raw bincode bytes.
    /// Returns (ipv4_count, ipv6_count) on success.
    pub fn swap(&self, data: &[u8]) -> anyhow::Result<(usize, usize)> {
        let table: GeoTable =
            bincode::deserialize(data).map_err(|e| anyhow::anyhow!("invalid geoip.bin: {e}"))?;
        let v4 = table.v4.len();
        let v6 = table.v6.len();
        self.inner.store(Arc::new(Some(table)));
        info!(v4_entries = v4, v6_entries = v6, "geo table swapped");
        Ok((v4, v6))
    }

    /// Load geo table from disk. Fail-open: errors are logged, not propagated.
    pub fn load_from_disk(&self, path: Option<&Path>) {
        let Some(path) = path else { return };
        match std::fs::read(path) {
            Ok(data) => match self.swap(&data) {
                Ok((v4, v6)) => {
                    info!(path = %path.display(), v4, v6, "loaded geo table from disk")
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to parse geo table")
                }
            },
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read geo table file")
            }
        }
    }

    /// Return status info: entry counts and checksum.
    #[allow(dead_code)]
    pub fn status(&self) -> GeoStatus {
        let guard = self.inner.load();
        match guard.as_ref() {
            Some(table) => {
                let v4 = table.v4.len();
                let v6 = table.v6.len();
                // Compute checksum from current serialized state.
                let checksum = bincode::serialize(table)
                    .ok()
                    .map(|bytes| hex::encode(Sha256::digest(&bytes)));
                GeoStatus {
                    loaded: true,
                    v4_entries: v4,
                    v6_entries: v6,
                    checksum,
                }
            }
            None => GeoStatus {
                loaded: false,
                v4_entries: 0,
                v6_entries: 0,
                checksum: None,
            },
        }
    }
}

/// Status of the loaded geo table.
#[derive(serde::Serialize)]
pub struct GeoStatus {
    pub loaded: bool,
    pub v4_entries: usize,
    pub v6_entries: usize,
    pub checksum: Option<String>,
}

impl Default for GeoHolder {
    fn default() -> Self {
        Self::new()
    }
}
