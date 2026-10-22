//! Level-Compressed Trie (LC-Trie) for fast prefix matching.
//!
//! Compresses a binary prefix trie with path compression:
//! single-child chains are collapsed, storing the expected bit path
//! for verification during lookup.
//!
//! Build: `prefix_trie::TrieBuilder` → `lc_trie::compress()` → flat array
//! Lookup: `lc_trie::lookup()` — fewer memory accesses than plain trie
//!
//! The compressed trie is a flat array of [`LCNode`]s, zero-copy serializable.

use crate::prefix_trie::{self, TrieNode};

// ---------------------------------------------------------------------------
// LC-Trie node
// ---------------------------------------------------------------------------

/// A node in the level-compressed trie.
///
/// 12 bytes, `#[repr(C)]` for zero-copy serialization.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct LCNode {
    /// Bits to skip (path compression). 0 = no skip.
    /// Max 32 — if path is longer, chain multiple nodes.
    pub skip: u8,
    /// Number of branch bits. 0 = leaf node.
    /// branch=1 → 2 children, branch=2 → 4 children, etc.
    pub branch: u8,
    /// 1 if this node is a prefix terminal.
    pub is_prefix: u8,
    _pad: u8,
    /// Index of first child in the node array.
    pub child_idx: u32,
    /// Expected bit values during skip (path verification).
    /// During lookup, the query's bits at the skip positions must match
    /// these bits, otherwise the path diverges and we stop.
    pub skip_path: u32,
}

const _: () = assert!(std::mem::size_of::<LCNode>() == 12);

// ---------------------------------------------------------------------------
// Compress
// ---------------------------------------------------------------------------

/// Compress a finalized binary trie into an LC-Trie.
pub fn compress(bin_nodes: &[TrieNode]) -> Vec<LCNode> {
    if bin_nodes.len() < 2 {
        return vec![];
    }

    let mut lc = Vec::new();
    let mut queue: std::collections::VecDeque<CompressJob> = std::collections::VecDeque::new();

    lc.push(LCNode::default());
    queue.push_back(CompressJob {
        bin_idx: 1,
        lc_idx: 0,
        depth: 0,
    });

    while let Some(job) = queue.pop_front() {
        let (final_idx, skip, skip_path) = follow_chain(bin_nodes, job.bin_idx);
        let node = &bin_nodes[final_idx];

        let is_prefix = (node.left & prefix_trie::PREFIX_FLAG) != 0;
        let left = node.left & !prefix_trie::PREFIX_FLAG;
        let right = node.right;
        let has_left = left != 0;
        let has_right = right != 0;

        if !has_left && !has_right {
            // Leaf
            lc[job.lc_idx] = LCNode {
                skip,
                branch: 0,
                is_prefix: is_prefix as u8,
                _pad: 0,
                child_idx: 0,
                skip_path,
            };
        } else {
            // Branch: 1-bit (2 children)
            let child_start = lc.len();
            lc.push(LCNode::default());
            lc.push(LCNode::default());

            lc[job.lc_idx] = LCNode {
                skip,
                branch: 1,
                is_prefix: is_prefix as u8,
                _pad: 0,
                child_idx: child_start as u32,
                skip_path,
            };

            let new_depth = job.depth + skip as u32 + 1;
            if has_left {
                queue.push_back(CompressJob {
                    bin_idx: left as usize,
                    lc_idx: child_start,
                    depth: new_depth,
                });
            }
            if has_right {
                queue.push_back(CompressJob {
                    bin_idx: right as usize,
                    lc_idx: child_start + 1,
                    depth: new_depth,
                });
            }
        }
    }

    lc
}

struct CompressJob {
    bin_idx: usize,
    lc_idx: usize,
    depth: u32,
}

/// Follow single-child chains. Returns (final_node_idx, skip_count, skip_path).
///
/// `skip_path` records the bit direction taken at each skip:
/// bit 0 of skip_path = first skipped bit direction (0=left, 1=right).
fn follow_chain(nodes: &[TrieNode], start: usize) -> (usize, u8, u32) {
    let mut cur = start;
    let mut skip: u8 = 0;
    let mut path: u32 = 0;

    loop {
        if skip >= 32 {
            break; // max skip per node
        }

        let node = &nodes[cur];
        let is_prefix = (node.left & prefix_trie::PREFIX_FLAG) != 0;
        let left = node.left & !prefix_trie::PREFIX_FLAG;
        let right = node.right;
        let has_left = left != 0;
        let has_right = right != 0;

        // Stop at: branch point, prefix node, or dead end
        if is_prefix || (has_left && has_right) || (!has_left && !has_right) {
            break;
        }

        // Single child — record direction and skip
        if has_left {
            // went left = bit 0
            cur = left as usize;
        } else {
            // went right = bit 1
            path |= 1 << skip;
            cur = right as usize;
        }
        skip += 1;
    }

    (cur, skip, path)
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Check if `bits` matches any prefix in the LC-Trie.
pub fn lookup(nodes: &[LCNode], bits: u128, max_bits: u8) -> bool {
    if nodes.is_empty() {
        return false;
    }

    let mut idx = 0usize;
    let mut bit_pos: u32 = 0;
    let mut matched = false;

    loop {
        if idx >= nodes.len() {
            break;
        }
        let node = &nodes[idx];

        // Path compression: verify skipped bits match expected path
        if node.skip > 0 {
            let skip = node.skip as u32;
            if bit_pos + skip > max_bits as u32 {
                break;
            }
            // Extract `skip` bits from query and compare with skip_path
            for s in 0..skip {
                let query_bit = ((bits >> (max_bits as u32 - 1 - bit_pos - s)) & 1) as u32;
                let expected_bit = (node.skip_path >> s) & 1;
                if query_bit != expected_bit {
                    return matched; // path diverges — return last match
                }
            }
            bit_pos += skip;
        }

        // Check prefix match at this node
        if node.is_prefix != 0 {
            matched = true;
        }

        // Leaf — done
        if node.branch == 0 {
            break;
        }

        // Branch: extract bits to determine child
        if bit_pos >= max_bits as u32 {
            break;
        }
        let branch = node.branch as u32;
        if bit_pos + branch > max_bits as u32 {
            break;
        }

        let mut child_offset: u32 = 0;
        for i in 0..branch {
            let b = (bits >> (max_bits as u32 - 1 - bit_pos - i)) & 1;
            child_offset = (child_offset << 1) | (b as u32);
        }
        bit_pos += branch;

        let child = node.child_idx + child_offset;
        if (child as usize) >= nodes.len() {
            break;
        }
        idx = child as usize;
    }

    matched
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Cast `&[LCNode]` to `&[u8]`.
pub fn nodes_as_bytes(nodes: &[LCNode]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(nodes.as_ptr() as *const u8, std::mem::size_of_val(nodes)) }
}

/// Read `&[u8]` into `Vec<LCNode>`.
pub fn nodes_from_bytes(data: &[u8]) -> Vec<LCNode> {
    let node_size = std::mem::size_of::<LCNode>();
    let count = data.len() / node_size;
    let mut nodes = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * node_size;
        let node = unsafe { std::ptr::read(data[offset..].as_ptr() as *const LCNode) };
        nodes.push(node);
    }
    nodes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix_trie::TrieBuilder;

    fn build_and_compress(prefixes: &[(u128, u8)], max_bits: u8) -> Vec<LCNode> {
        let mut builder = TrieBuilder::new();
        for &(bits, len) in prefixes {
            builder.insert(bits, len, max_bits);
        }
        compress(&builder.finalize())
    }

    #[test]
    fn empty() {
        let lc = build_and_compress(&[], 32);
        assert!(!lookup(&lc, 0x0A010203, 32));
    }

    #[test]
    fn single_cidr_8() {
        let lc = build_and_compress(&[(0x0A000000, 8)], 32);
        assert!(lookup(&lc, 0x0A010203, 32)); // 10.1.2.3 ✓
        assert!(lookup(&lc, 0x0AFFFFFF, 32)); // 10.255.255.255 ✓
        assert!(!lookup(&lc, 0x0B000001, 32)); // 11.0.0.1 ✗
        assert!(!lookup(&lc, 0x09FFFFFF, 32)); // 9.255.255.255 ✗
    }

    #[test]
    fn exact_match_32() {
        let lc = build_and_compress(&[(0xC0A80101, 32)], 32);
        assert!(lookup(&lc, 0xC0A80101, 32)); // exact ✓
        assert!(!lookup(&lc, 0xC0A80102, 32)); // .2 ✗
        assert!(!lookup(&lc, 0xC0A80100, 32)); // .0 ✗
    }

    #[test]
    fn cidr_24() {
        let lc = build_and_compress(&[(0xC0A80100, 24)], 32);
        assert!(lookup(&lc, 0xC0A80100, 32)); // 192.168.1.0 ✓
        assert!(lookup(&lc, 0xC0A801FF, 32)); // 192.168.1.255 ✓
        assert!(!lookup(&lc, 0xC0A80200, 32)); // 192.168.2.0 ✗
        assert!(!lookup(&lc, 0xC0A800FF, 32)); // 192.168.0.255 ✗
    }

    #[test]
    fn multiple_prefixes() {
        let lc = build_and_compress(
            &[
                (0x0A000000, 8),  // 10.0.0.0/8
                (0xC0A80000, 16), // 192.168.0.0/16
                (0xAC100000, 12), // 172.16.0.0/12
                (0x08080808, 32), // 8.8.8.8/32
            ],
            32,
        );
        assert!(lookup(&lc, 0x0A010203, 32)); // 10.1.2.3 ✓
        assert!(lookup(&lc, 0xC0A80101, 32)); // 192.168.1.1 ✓
        assert!(lookup(&lc, 0xAC140001, 32)); // 172.20.0.1 ✓
        assert!(lookup(&lc, 0x08080808, 32)); // 8.8.8.8 ✓
        assert!(!lookup(&lc, 0x08080809, 32)); // 8.8.8.9 ✗
        assert!(!lookup(&lc, 0x01010101, 32)); // 1.1.1.1 ✗
    }

    #[test]
    fn nested_prefixes() {
        let lc = build_and_compress(
            &[
                (0x0A000000, 8),  // 10.0.0.0/8
                (0x0A010000, 16), // 10.1.0.0/16
                (0x0A010100, 24), // 10.1.1.0/24
            ],
            32,
        );
        assert!(lookup(&lc, 0x0A000001, 32)); // 10.0.0.1 → /8
        assert!(lookup(&lc, 0x0A010001, 32)); // 10.1.0.1 → /16
        assert!(lookup(&lc, 0x0A010101, 32)); // 10.1.1.1 → /24
        assert!(!lookup(&lc, 0x0B000001, 32)); // 11.0.0.1 ✗
    }

    #[test]
    fn path_compression_reduces_nodes() {
        let mut builder = TrieBuilder::new();
        builder.insert(0x0A000000, 8, 32);
        let bin = builder.finalize();
        let lc = compress(&bin);

        assert!(
            lc.len() < bin.len(),
            "LC-Trie ({}) should have fewer nodes than binary trie ({})",
            lc.len(),
            bin.len()
        );
    }

    #[test]
    fn serialize_roundtrip() {
        let lc = build_and_compress(&[(0x0A000000, 8), (0xC0A80100, 24)], 32);
        let bytes = nodes_as_bytes(&lc);
        let lc2 = nodes_from_bytes(bytes);

        assert!(lookup(&lc2, 0x0A010203, 32));
        assert!(lookup(&lc2, 0xC0A80164, 32));
        assert!(!lookup(&lc2, 0x0B000001, 32));
    }

    #[test]
    fn ipv6_prefix() {
        // 2001:db8::/32 = 0x20010db8... with prefix_len=32
        let prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let lc = build_and_compress(&[(prefix, 32)], 128);

        let match_ip: u128 = 0x20010db8_00000000_00000000_00000001;
        let no_match: u128 = 0x20010db9_00000000_00000000_00000001;
        assert!(lookup(&lc, match_ip, 128));
        assert!(!lookup(&lc, no_match, 128));
    }
}
