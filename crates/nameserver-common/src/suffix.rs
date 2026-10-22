use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A compiled set of public suffix rules for determining registrable domain boundaries.
///
/// Supports the three PSL rule types:
/// - **Exact**: `co.kr` — this exact string is a public suffix
/// - **Wildcard**: `*.ck` — any label followed by `.ck` is a public suffix
/// - **Exception**: `!www.ck` — overrides a wildcard match
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuffixSet {
    exact: HashSet<String>,
    wildcards: HashSet<String>,
    exceptions: HashSet<String>,
}

impl SuffixSet {
    /// Parse the Mozilla PSL text format.
    ///
    /// Lines starting with `//` are comments. Blank lines are skipped.
    /// `*.foo` → wildcard rule (parent `foo` stored in wildcards).
    /// `!bar.foo` → exception rule (`bar.foo` stored in exceptions).
    /// Everything else → exact rule.
    pub fn from_psl_text(text: &str) -> Self {
        let mut set = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let normalized = line.to_ascii_lowercase().trim_end_matches('.').to_string();
            if normalized.is_empty() {
                continue;
            }
            if let Some(rest) = normalized.strip_prefix("*.") {
                if !rest.is_empty() {
                    set.wildcards.insert(rest.to_string());
                }
            } else if let Some(rest) = normalized.strip_prefix('!') {
                if !rest.is_empty() {
                    set.exceptions.insert(rest.to_string());
                }
            } else {
                set.exact.insert(normalized);
            }
        }
        set
    }

    /// Parse a plain suffix list (one suffix per line, `#` comments).
    /// All entries become exact rules.
    pub fn from_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Self {
        let mut set = Self::default();
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let normalized = line.to_ascii_lowercase().trim_end_matches('.').to_string();
            if !normalized.is_empty() {
                set.exact.insert(normalized);
            }
        }
        set
    }

    /// Merge another SuffixSet into this one (union of all rule sets).
    pub fn merge(&mut self, other: &SuffixSet) {
        self.exact.extend(other.exact.iter().cloned());
        self.wildcards.extend(other.wildcards.iter().cloned());
        self.exceptions.extend(other.exceptions.iter().cloned());
    }

    /// Check whether the given domain is itself a public suffix.
    ///
    /// Algorithm (per publicsuffix.org):
    /// 1. Exception rules override everything → not a suffix
    /// 2. Exact match → is a suffix
    /// 3. Wildcard match (parent in wildcards set) → is a suffix
    /// 4. Default rule: single labels (no dots) are implicitly TLDs
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        let d = domain
            .to_ascii_lowercase()
            .trim_end_matches('.')
            .to_string();
        if d.is_empty() {
            return false;
        }
        self.is_suffix_normalized(&d)
    }

    /// Find the registrable domain (eTLD+1) for a given FQDN.
    ///
    /// Returns `None` if the domain is itself a public suffix (e.g., `co.kr`)
    /// or a bare TLD (e.g., `com`).
    ///
    /// The returned string is a slice of the input (zero-copy).
    pub fn registrable_domain<'a>(&self, domain: &'a str) -> Option<&'a str> {
        let d = domain.trim_end_matches('.');
        if d.is_empty() {
            return None;
        }

        let d_lower = d.to_ascii_lowercase();

        // If the entire domain is a public suffix, there's no registrable domain.
        if self.is_suffix_normalized(&d_lower) {
            return None;
        }

        // Collect dot positions to iterate suffixes from shortest to longest.
        let dot_positions: Vec<usize> = d_lower
            .bytes()
            .enumerate()
            .filter_map(|(i, b)| if b == b'.' { Some(i) } else { None })
            .collect();

        if dot_positions.is_empty() {
            // Single label, not a known suffix — no registrable domain.
            return None;
        }

        // Walk suffixes from shortest (rightmost) to longest, tracking where
        // the longest public suffix starts in the string.
        let mut suffix_start: Option<usize> = None;

        for &dot_pos in dot_positions.iter().rev() {
            let suffix = &d_lower[dot_pos + 1..];
            if self.is_suffix_normalized(suffix) {
                suffix_start = Some(dot_pos + 1);
            } else {
                break;
            }
        }

        // The registrable domain is one label before the suffix boundary.
        let start = suffix_start.expect("at least the TLD matches via default rule");
        let before_suffix = &d[..start - 1]; // strip the dot before suffix
        match before_suffix.rfind('.') {
            Some(dot) => Some(&d[dot + 1..]),
            None => Some(d), // No more dots — the whole domain is registrable.
        }
    }

    /// Total number of rules in this set.
    pub fn entry_count(&self) -> usize {
        self.exact.len() + self.wildcards.len() + self.exceptions.len()
    }

    /// Check if this set has any rules loaded.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty() && self.exceptions.is_empty()
    }

    /// Internal: check if a normalized (lowercase, no trailing dot) string is a suffix.
    ///
    /// Implements the PSL default rule: "if no rules match, the prevailing rule
    /// is `*`" — meaning every bare label (no dots) is implicitly a TLD.
    fn is_suffix_normalized(&self, s: &str) -> bool {
        if self.exceptions.contains(s) {
            return false;
        }
        if self.exact.contains(s) {
            return true;
        }
        if let Some(parent) = s.split_once('.').map(|(_, p)| p)
            && self.wildcards.contains(parent)
        {
            return true;
        }
        // Default rule: single labels (no dots) are implicitly TLDs.
        !s.contains('.')
    }
}

/// Extract the registrable domain using a suffix set.
///
/// Convenience wrapper: strips trailing dot from input, delegates to
/// `SuffixSet::registrable_domain`, returns the input unchanged if the
/// suffix set yields no result.
pub fn extract_registrable<'a>(domain: &'a str, suffix_set: &SuffixSet) -> &'a str {
    let stripped = domain.strip_suffix('.').unwrap_or(domain);
    suffix_set.registrable_domain(stripped).unwrap_or(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psl() -> SuffixSet {
        SuffixSet::from_psl_text(
            "// Test PSL
com
co.kr
or.kr
go.kr
ac.kr
co.uk
com.au

// Wildcard
*.ck

// Exception
!www.ck

// Private
github.io
vercel.app
blogspot.com
",
        )
    }

    #[test]
    fn parse_psl_basic() {
        let set = test_psl();
        assert!(set.exact.contains("com"));
        assert!(set.exact.contains("co.kr"));
        assert!(set.exact.contains("github.io"));
        assert!(set.wildcards.contains("ck"));
        assert!(set.exceptions.contains("www.ck"));
    }

    #[test]
    fn parse_psl_comments_and_blanks() {
        let set = SuffixSet::from_psl_text("// comment\n\n  \ncom\n");
        assert_eq!(set.exact.len(), 1);
        assert!(set.exact.contains("com"));
    }

    #[test]
    fn parse_psl_normalization() {
        let set = SuffixSet::from_psl_text("COM\nCo.KR.\n");
        assert!(set.exact.contains("com"));
        assert!(set.exact.contains("co.kr"));
    }

    #[test]
    fn from_lines_basic() {
        let set =
            SuffixSet::from_lines(["# comment", "", "cafe24.com", "modoo.at"].iter().copied());
        assert_eq!(set.exact.len(), 2);
        assert!(set.exact.contains("cafe24.com"));
        assert!(set.exact.contains("modoo.at"));
        assert!(set.wildcards.is_empty());
        assert!(set.exceptions.is_empty());
    }

    #[test]
    fn is_public_suffix_exact() {
        let set = test_psl();
        assert!(set.is_public_suffix("com"));
        assert!(set.is_public_suffix("co.kr"));
        assert!(set.is_public_suffix("COM")); // case insensitive
        assert!(set.is_public_suffix("co.kr.")); // trailing dot
        assert!(set.is_public_suffix("github.io"));
        assert!(!set.is_public_suffix("example.com"));
        assert!(!set.is_public_suffix("ibk.co.kr"));
    }

    #[test]
    fn is_public_suffix_wildcard() {
        let set = test_psl();
        assert!(set.is_public_suffix("anything.ck"));
        assert!(set.is_public_suffix("foo.ck"));
        assert!(set.is_public_suffix("ck")); // bare label → implicit TLD (PSL default rule)
    }

    #[test]
    fn is_public_suffix_exception() {
        let set = test_psl();
        // www.ck is an exception to *.ck — it is NOT a public suffix.
        assert!(!set.is_public_suffix("www.ck"));
        // But other.ck IS a public suffix via wildcard.
        assert!(set.is_public_suffix("other.ck"));
    }

    #[test]
    fn registrable_domain_simple() {
        let set = test_psl();
        assert_eq!(set.registrable_domain("example.com"), Some("example.com"));
        assert_eq!(
            set.registrable_domain("sub.example.com"),
            Some("example.com")
        );
        assert_eq!(
            set.registrable_domain("a.b.c.example.com"),
            Some("example.com")
        );
    }

    #[test]
    fn registrable_domain_multi_part() {
        let set = test_psl();
        assert_eq!(set.registrable_domain("ibk.co.kr"), Some("ibk.co.kr"));
        assert_eq!(set.registrable_domain("shop.ibk.co.kr"), Some("ibk.co.kr"));
        assert_eq!(
            set.registrable_domain("example.co.uk"),
            Some("example.co.uk")
        );
    }

    #[test]
    fn registrable_domain_is_suffix() {
        let set = test_psl();
        assert_eq!(set.registrable_domain("com"), None);
        assert_eq!(set.registrable_domain("co.kr"), None);
        assert_eq!(set.registrable_domain("github.io"), None);
    }

    #[test]
    fn registrable_domain_wildcard() {
        let set = test_psl();
        // *.ck means bar.ck is a suffix, so foo.bar.ck is registrable.
        assert_eq!(set.registrable_domain("foo.bar.ck"), Some("foo.bar.ck"));
        assert_eq!(set.registrable_domain("bar.ck"), None); // bar.ck IS a suffix
    }

    #[test]
    fn registrable_domain_exception() {
        let set = test_psl();
        // !www.ck means www.ck is NOT a suffix, so www.ck itself is registrable.
        assert_eq!(set.registrable_domain("www.ck"), Some("www.ck"));
        assert_eq!(set.registrable_domain("sub.www.ck"), Some("www.ck"));
    }

    #[test]
    fn registrable_domain_trailing_dot() {
        let set = test_psl();
        assert_eq!(set.registrable_domain("example.com."), Some("example.com"));
        assert_eq!(set.registrable_domain("ibk.co.kr."), Some("ibk.co.kr"));
    }

    #[test]
    fn registrable_domain_private_suffix() {
        let set = test_psl();
        // github.io is a private suffix — each subdomain is independent.
        assert_eq!(
            set.registrable_domain("user.github.io"),
            Some("user.github.io")
        );
        assert_eq!(set.registrable_domain("github.io"), None);
    }

    #[test]
    fn merge_sets() {
        let mut a = SuffixSet::from_psl_text("com\n*.ck\n");
        let b = SuffixSet::from_psl_text("co.kr\n!www.ck\n");
        a.merge(&b);
        assert!(a.exact.contains("com"));
        assert!(a.exact.contains("co.kr"));
        assert!(a.wildcards.contains("ck"));
        assert!(a.exceptions.contains("www.ck"));
    }

    #[test]
    fn entry_count() {
        let set = test_psl();
        assert!(set.entry_count() > 0);
        assert_eq!(
            set.entry_count(),
            set.exact.len() + set.wildcards.len() + set.exceptions.len()
        );
    }

    #[test]
    fn extract_registrable_convenience() {
        let set = test_psl();
        assert_eq!(extract_registrable("sub.example.com", &set), "example.com");
        assert_eq!(extract_registrable("shop.ibk.co.kr.", &set), "ibk.co.kr");
        // Bare suffix returns itself (no panic).
        assert_eq!(extract_registrable("com", &set), "com");
    }

    #[test]
    fn msgpack_roundtrip() {
        let original = test_psl();
        let bytes = rmp_serde::to_vec_named(&original).expect("serialize");
        let restored: SuffixSet = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(original.exact, restored.exact);
        assert_eq!(original.wildcards, restored.wildcards);
        assert_eq!(original.exceptions, restored.exceptions);
    }
}
