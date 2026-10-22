use std::sync::Arc;

use arc_swap::ArcSwap;
use nameserver_common::suffix::SuffixSet;
use tracing::{info, warn};

/// Thread-safe, hot-swappable public suffix set.
///
/// Same pattern as `GeoHolder`: uses `ArcSwap` for lock-free reads.
/// `None` means no suffix data loaded yet — callers fall back to
/// walking all suffixes (current behavior, safe default).
pub struct SuffixHolder {
    inner: ArcSwap<Option<SuffixSet>>,
}

impl SuffixHolder {
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(None),
        }
    }

    /// Replace the suffix set from MessagePack bytes. Returns entry count.
    pub fn swap(&self, data: &[u8]) -> anyhow::Result<usize> {
        let set: SuffixSet =
            rmp_serde::from_slice(data).map_err(|e| anyhow::anyhow!("invalid suffix set: {e}"))?;
        let count = set.entry_count();
        self.inner.store(Arc::new(Some(set)));
        info!(entries = count, "suffix set swapped");
        Ok(count)
    }

    /// Load the current suffix set for use in filter matching.
    ///
    /// Returns the shared `Arc` directly — no cloning. The `Arc<Option<SuffixSet>>`
    /// remains valid even if a swap occurs concurrently (ArcSwap RCU semantics).
    pub fn load(&self) -> arc_swap::Guard<Arc<Option<SuffixSet>>> {
        self.inner.load()
    }

    /// Load from disk (fail-open: errors are logged, not propagated).
    pub fn load_from_disk(&self, path: Option<&std::path::Path>) {
        let Some(path) = path else { return };
        match std::fs::read(path) {
            Ok(data) => match self.swap(&data) {
                Ok(count) => {
                    info!(path = %path.display(), entries = count, "loaded suffix set from disk")
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to parse suffix set file")
                }
            },
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read suffix set file")
            }
        }
    }
}

impl Default for SuffixHolder {
    fn default() -> Self {
        Self::new()
    }
}
