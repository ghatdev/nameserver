use std::{
    collections::HashSet,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use hickory_server::proto::rr::Name;
use serde::Deserialize;

use crate::relative_to;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterSettings {
    pub blocklists: Vec<PathBuf>,
    pub allowlists: Vec<PathBuf>,
}

#[derive(Default)]
pub struct Filter {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
}

impl Filter {
    pub fn load(settings: &FilterSettings, config: &Path) -> Result<Self> {
        Ok(Self {
            blocked: load_lists(&settings.blocklists, config)?,
            allowed: load_lists(&settings.allowlists, config)?,
        })
    }

    pub fn is_blocked(&self, name: &Name) -> bool {
        let ascii = name.to_ascii().to_ascii_lowercase();
        let mut suffix = ascii.trim_end_matches('.');
        let mut blocked = false;
        loop {
            if self.allowed.contains(suffix) {
                return false;
            }
            blocked |= self.blocked.contains(suffix);
            match suffix.split_once('.') {
                Some((_, parent)) => suffix = parent,
                None => return blocked,
            }
        }
    }
}

fn load_lists(files: &[PathBuf], config: &Path) -> Result<HashSet<String>> {
    let mut entries = HashSet::new();
    for file in files {
        let path = relative_to(config, file);
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("cannot read list {}", path.display()))?;
        parse_list(&contents, &mut entries)
            .with_context(|| format!("invalid list {}", path.display()))?;
    }
    Ok(entries)
}

fn parse_list(contents: &str, entries: &mut HashSet<String>) -> Result<()> {
    for (line_number, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        if fields.is_empty() {
            continue;
        }
        let domains = if fields[0].parse::<IpAddr>().is_ok() {
            ensure!(
                fields.len() > 1,
                "hosts entry has no domain on line {}",
                line_number + 1
            );
            &fields[1..]
        } else {
            ensure!(
                fields.len() == 1,
                "expected one domain per line on line {}",
                line_number + 1
            );
            &fields[..]
        };
        for domain in domains {
            if domain.contains(['*', '/', '|', '^', ':']) {
                bail!("unsupported domain syntax on line {}", line_number + 1);
            }
            let name = Name::from_utf8(domain)
                .with_context(|| format!("invalid domain on line {}", line_number + 1))?;
            ensure!(!name.is_root(), "the root domain cannot be a list entry");
            entries.insert(name.to_ascii().trim_end_matches('.').to_ascii_lowercase());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching_respects_labels_and_allowlist_exceptions() {
        let mut filter = Filter::default();
        parse_list(
            "0.0.0.0 bad.example bad2.example\nBAD3.EXAMPLE. # comment\n",
            &mut filter.blocked,
        )
        .unwrap();
        parse_list("safe.bad.example", &mut filter.allowed).unwrap();
        for domain in [
            "bad.example.",
            "sub.bad.example.",
            "bad2.example.",
            "bad3.example.",
        ] {
            assert!(filter.is_blocked(&Name::from_ascii(domain).unwrap()));
        }
        for domain in [
            "notbad.example.",
            "safe.bad.example.",
            "sub.safe.bad.example.",
        ] {
            assert!(!filter.is_blocked(&Name::from_ascii(domain).unwrap()));
        }
    }

    #[test]
    fn malformed_lists_are_rejected_instead_of_silently_disabling_rules() {
        for text in [
            "https://bad.example/",
            "||bad.example^",
            "bad.example extra",
            ".",
            "0.0.0.0",
        ] {
            assert!(
                parse_list(text, &mut HashSet::new()).is_err(),
                "accepted {text}"
            );
        }
    }
}
