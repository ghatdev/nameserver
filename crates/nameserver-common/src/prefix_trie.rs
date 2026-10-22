//! Binary prefix trie: flat array, zero-copy serializable.
//!
//! A binary trie where each bit of the key determines left (0) or right (1).
//! Prefixes of any length are supported (CIDR-native).
//!
//! Node layout is `#[repr(C)]` for zero-copy: the serialized form is just
//! a contiguous `[TrieNode]` array that can be cast from `&[u8]`.
//!
//! Future: add LC-Trie path/level compression on top of this for
//! faster lookups (5-8 steps instead of 32/128).

/// A node in the flat binary trie.
///
/// 8 bytes, `#[repr(C)]` for zero-copy serialization.
/// Node 0 is the null sentinel. Node 1 is the root.
///
/// The high bit of `left` is used as a prefix flag: if set, this node
/// is a terminal (a prefix was inserted ending here).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct TrieNode {
    /// Index of left child (bit=0). High bit = prefix flag. 0 = no child.
    pub left: u32,
    /// Index of right child (bit=1). 0 = no child.
    pub right: u32,
}

const _: () = assert!(std::mem::size_of::<TrieNode>() == 8);

const NONE: u32 = 0;
/// Flag in `left` field indicating this node is a prefix terminal.
pub const PREFIX_FLAG: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builds a flat binary prefix trie from inserted prefixes.
///
/// Node 0 is reserved as the null sentinel. Node 1 is the root.
pub struct TrieBuilder {
    nodes: Vec<TrieNode>,
    is_prefix: Vec<bool>,
}

impl TrieBuilder {
    /// Create a new builder with null sentinel + root.
    pub fn new() -> Self {
        Self {
            nodes: vec![TrieNode::default(), TrieNode::default()],
            is_prefix: vec![false, false],
        }
    }

    /// Insert a prefix. `bits` is the key, `prefix_len` is how many
    /// leading bits are significant, `max_bits` is the key width (32 or 128).
    pub fn insert(&mut self, bits: u128, prefix_len: u8, max_bits: u8) {
        let mut cur: u32 = 1; // root
        for i in 0..prefix_len {
            let bit = ((bits >> (max_bits - 1 - i)) & 1) as u32;
            let next = if bit == 0 {
                self.nodes[cur as usize].left
            } else {
                self.nodes[cur as usize].right
            };
            if next == NONE {
                let new = self.alloc();
                if bit == 0 {
                    self.nodes[cur as usize].left = new;
                } else {
                    self.nodes[cur as usize].right = new;
                }
                cur = new;
            } else {
                cur = next;
            }
        }
        self.is_prefix[cur as usize] = true;
    }

    /// Finalize into a flat node array with prefix flags encoded.
    pub fn finalize(self) -> Vec<TrieNode> {
        let mut nodes = self.nodes;
        for (i, &is_pfx) in self.is_prefix.iter().enumerate() {
            if is_pfx {
                nodes[i].left |= PREFIX_FLAG;
            }
        }
        nodes
    }

    fn alloc(&mut self) -> u32 {
        let idx = self.nodes.len() as u32;
        self.nodes.push(TrieNode::default());
        self.is_prefix.push(false);
        idx
    }
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Check if `bits` matches any prefix in the flat trie.
///
/// Walks bit-by-bit from MSB. Returns true if any prefix along the
/// path was marked as terminal.
pub fn lookup(nodes: &[TrieNode], bits: u128, max_bits: u8) -> bool {
    if nodes.len() < 2 {
        return false;
    }

    let mut cur: u32 = 1;
    let mut matched = false;

    for i in 0..max_bits {
        let node = &nodes[cur as usize];

        if (node.left & PREFIX_FLAG) != 0 {
            matched = true;
        }

        let bit = ((bits >> (max_bits - 1 - i)) & 1) as u32;
        let left_idx = node.left & !PREFIX_FLAG;
        let next = if bit == 0 { left_idx } else { node.right };

        if next == NONE {
            break;
        }
        cur = next;
    }

    // Check final node
    if (nodes[cur as usize].left & PREFIX_FLAG) != 0 {
        matched = true;
    }

    matched
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Cast `&[TrieNode]` to `&[u8]`.
pub fn nodes_as_bytes(nodes: &[TrieNode]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(nodes.as_ptr() as *const u8, std::mem::size_of_val(nodes)) }
}

/// Read `&[u8]` into `Vec<TrieNode>`.
pub fn nodes_from_bytes(data: &[u8]) -> Vec<TrieNode> {
    let node_size = std::mem::size_of::<TrieNode>();
    let count = data.len() / node_size;
    let mut nodes = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * node_size;
        let node = unsafe { std::ptr::read(data[offset..].as_ptr() as *const TrieNode) };
        nodes.push(node);
    }
    nodes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

impl Default for TrieBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie() {
        let b = TrieBuilder::new();
        let nodes = b.finalize();
        assert!(!lookup(&nodes, 0xC0A80101, 32)); // 192.168.1.1
    }

    #[test]
    fn single_prefix() {
        let mut b = TrieBuilder::new();
        b.insert(0x0A000000, 8, 32); // 10.0.0.0/8
        let nodes = b.finalize();

        assert!(lookup(&nodes, 0x0A010203, 32)); // 10.1.2.3 ✓
        assert!(lookup(&nodes, 0x0AFFFFFF, 32)); // 10.255.255.255 ✓
        assert!(!lookup(&nodes, 0x0B000001, 32)); // 11.0.0.1 ✗
    }

    #[test]
    fn exact_match() {
        let mut b = TrieBuilder::new();
        b.insert(0xC0A80101, 32, 32); // 192.168.1.1/32
        let nodes = b.finalize();

        assert!(lookup(&nodes, 0xC0A80101, 32)); // exact ✓
        assert!(!lookup(&nodes, 0xC0A80102, 32)); // .2 ✗
    }

    #[test]
    fn serialize_roundtrip() {
        let mut b = TrieBuilder::new();
        b.insert(0x0A000000, 8, 32);
        let nodes = b.finalize();

        let bytes = nodes_as_bytes(&nodes);
        let nodes2 = nodes_from_bytes(bytes);

        assert!(lookup(&nodes2, 0x0A010203, 32));
        assert!(!lookup(&nodes2, 0x0B000001, 32));
    }
}
