//! Configuration types for the indicator source pull pipeline.
//!
//! Stored as JSONB in the `sources` table. Each pipeline stage
//! reads only its own config: fetch → parse → validate.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Parse configuration — how to extract indicators from fetched content
// ---------------------------------------------------------------------------

/// Describes how to parse a fetched body into indicator values.
///
/// Stored as `parse_config JSONB` on `sources`.
/// Default: `{"type": "lines"}` (one indicator per line, skip `#` comments).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ParseConfig {
    /// One indicator per line. Skip empty lines and `#` comments.
    #[serde(rename = "lines")]
    Lines {
        /// Optional prefix to strip from each line (e.g., `"*."` for OISD wildcard format).
        #[serde(default)]
        strip_prefix: Option<String>,
    },

    /// CSV/TSV: split on delimiter, extract column by index (0-based).
    #[serde(rename = "csv")]
    Csv {
        /// 0-based column index for the primary indicator value.
        column: usize,
        /// Field delimiter. Default: `","`.
        #[serde(default)]
        delimiter: Option<String>,
        /// Skip the first row (header). Default: false.
        #[serde(default)]
        skip_header: Option<bool>,
        /// Maps extra JSONB field names to column indices.
        /// E.g., `{"rank": 0}` stores column 0 as `extra.rank`.
        #[serde(default)]
        extra_columns: Option<HashMap<String, usize>>,
    },

    /// JSONL: one JSON object per line, extract a field by name.
    #[serde(rename = "jsonl")]
    Jsonl {
        /// Field name to extract from each JSON object.
        field: String,
        /// Skip records where a field matches a value.
        /// E.g., `{"type": "metadata"}` skips Spamhaus metadata records.
        #[serde(default)]
        skip_when: Option<HashMap<String, String>>,
        /// Maps extra JSONB field names to source JSON field names.
        /// E.g., `{"sbl_id": "sblid"}` stores JSON field "sblid" as `extra.sbl_id`.
        #[serde(default)]
        extra_fields: Option<HashMap<String, String>>,
    },

    /// Mozilla PSL format: `//` comments, `*.foo` wildcards, `!bar.foo` exceptions.
    /// Each non-comment, non-blank line becomes a single-element row.
    #[serde(rename = "psl")]
    Psl,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self::Lines { strip_prefix: None }
    }
}

// ---------------------------------------------------------------------------
// Fetch configuration — how to retrieve content from the source URL
// ---------------------------------------------------------------------------

/// Describes how to fetch content from a source URL.
///
/// Stored as `fetch_config JSONB` on `sources`.
/// Default: `{}` (plain HTTP GET, no special handling).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FetchConfig {
    /// Archive type to extract before parsing. Supported: `"zip"`, `"gzip"`.
    #[serde(default)]
    pub archive: Option<String>,

    /// Custom HTTP headers to include in the request.
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Fallback URLs to try if the primary URL fails.
    #[serde(default)]
    pub fallback_urls: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Validate configuration — data quality checks after parsing
// ---------------------------------------------------------------------------

/// Describes post-parse validation rules.
///
/// Stored as `validate_config JSONB` on `sources`.
/// Default: `{}` (no validation).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidateConfig {
    /// Minimum expected entry count. Pull is rejected if fewer entries parsed.
    /// Guards against empty/truncated responses.
    #[serde(default)]
    pub min_entries: Option<u32>,

    /// Skip bogon/non-routable IP addresses (0.0.0.0/8, RFC 1918, etc.).
    /// Only meaningful for `indicator_type = ip`.
    #[serde(default)]
    pub skip_bogons: Option<bool>,
}

// ---------------------------------------------------------------------------
// Parse engine — execute ParseConfig against a body
// ---------------------------------------------------------------------------

/// Return the 0-based column index of the primary indicator value.
pub fn primary_column_index(config: &ParseConfig) -> usize {
    match config {
        ParseConfig::Csv { column, .. } => *column,
        _ => 0,
    }
}

/// Parse a fetched body into rows, preserving all columns/fields per row.
///
/// - `Lines`: each row is `vec![line]`
/// - `Csv`: each row is all split columns `vec![col0, col1, ...]`
/// - `Jsonl`: each row is `vec![extracted_field_value]`
pub fn parse_rows(body: &str, config: &ParseConfig) -> Vec<Vec<String>> {
    match config {
        ParseConfig::Lines { strip_prefix } => parse_lines_rows(body, strip_prefix.as_deref()),
        ParseConfig::Csv {
            delimiter,
            skip_header,
            ..
        } => parse_csv_rows(body, delimiter.as_deref(), *skip_header),
        ParseConfig::Jsonl {
            field,
            skip_when,
            extra_fields,
        } => parse_jsonl_rows(body, field, skip_when.as_ref(), extra_fields.as_ref()),
        ParseConfig::Psl => parse_psl_rows(body),
    }
}

/// Parse a fetched body into indicator values using the given config.
///
/// Thin wrapper over [`parse_rows`] that extracts only the primary column.
/// Returns raw strings — normalization (lowercase, trailing dot, IP validation)
/// is handled by the caller based on `indicator_type`.
pub fn parse_indicators(body: &str, config: &ParseConfig) -> Vec<String> {
    let col = primary_column_index(config);
    parse_rows(body, config)
        .into_iter()
        .filter_map(|row| row.into_iter().nth(col))
        .filter(|v| !v.is_empty())
        .collect()
}

/// Build an `extra` JSONB value from a parsed row using the config's column mapping.
///
/// - `Csv` with `extra_columns`: maps JSONB key → column index
/// - `Jsonl` with `extra_fields`: maps JSONB key → row position (extras at index 1+, sorted by key)
/// - All other configs: returns `{}`
///
/// Values are type-coerced: integer → float → string.
pub fn build_extra(row: &[String], config: &ParseConfig) -> serde_json::Value {
    match config {
        ParseConfig::Csv {
            extra_columns: Some(mapping),
            ..
        } => build_extra_by_index(row, mapping),
        ParseConfig::Jsonl {
            extra_fields: Some(mapping),
            ..
        } => {
            // Extra fields are stored at row positions 1+ in sorted key order.
            let mut sorted_keys: Vec<&String> = mapping.keys().collect();
            sorted_keys.sort();
            let index_map: HashMap<String, usize> = sorted_keys
                .into_iter()
                .enumerate()
                .map(|(i, k)| (k.clone(), i + 1))
                .collect();
            build_extra_by_index(row, &index_map)
        }
        _ => serde_json::json!({}),
    }
}

fn build_extra_by_index(row: &[String], mapping: &HashMap<String, usize>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (key, &col_idx) in mapping {
        if let Some(val) = row.get(col_idx) {
            let val = val.trim();
            if val.is_empty() {
                continue;
            }
            if let Ok(n) = val.parse::<i64>() {
                obj.insert(key.clone(), serde_json::Value::Number(n.into()));
            } else if let Ok(f) = val.parse::<f64>() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    obj.insert(key.clone(), serde_json::Value::Number(n));
                }
            } else {
                obj.insert(key.clone(), serde_json::Value::String(val.to_string()));
            }
        }
    }
    serde_json::Value::Object(obj)
}

fn parse_psl_rows(body: &str) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        results.push(vec![line.to_string()]);
    }
    results
}

fn parse_lines_rows(body: &str, strip_prefix: Option<&str>) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = if let Some(prefix) = strip_prefix {
            line.strip_prefix(prefix).unwrap_or(line)
        } else {
            line
        };
        if !value.is_empty() {
            results.push(vec![value.to_string()]);
        }
    }
    results
}

fn parse_csv_rows(
    body: &str,
    delimiter: Option<&str>,
    skip_header: Option<bool>,
) -> Vec<Vec<String>> {
    let delim = delimiter.unwrap_or(",");
    let skip = skip_header.unwrap_or(false);
    let mut results = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if skip && i == 0 {
            continue;
        }
        let fields: Vec<String> = line.split(delim).map(|f| f.trim().to_string()).collect();
        if !fields.is_empty() {
            results.push(fields);
        }
    }
    results
}

fn parse_jsonl_rows(
    body: &str,
    field: &str,
    skip_when: Option<&HashMap<String, String>>,
    extra_fields: Option<&HashMap<String, String>>,
) -> Vec<Vec<String>> {
    // Pre-compute sorted extra field keys for deterministic row positions.
    let sorted_extras: Vec<(&String, &String)> = extra_fields
        .map(|m| {
            let mut pairs: Vec<_> = m.iter().collect();
            pairs.sort_by_key(|(k, _)| *k);
            pairs
        })
        .unwrap_or_default();

    let mut results = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // Skip records matching skip_when conditions
        if let Some(conditions) = skip_when {
            let should_skip = conditions
                .iter()
                .all(|(k, expected)| v.get(k).and_then(|v| v.as_str()) == Some(expected.as_str()));
            if should_skip {
                continue;
            }
        }
        // Extract primary field value (supports string and numeric fields)
        let primary = if let Some(value) = v.get(field) {
            if let Some(s) = value.as_str() {
                s.to_string()
            } else if let Some(n) = value.as_i64() {
                n.to_string()
            } else {
                continue;
            }
        } else {
            continue;
        };

        let mut row = vec![primary];
        // Extract extra fields in sorted key order (positions 1+).
        for (_jsonb_key, source_field) in &sorted_extras {
            let val = v
                .get(source_field.as_str())
                .map(|fv| {
                    if let Some(s) = fv.as_str() {
                        s.to_string()
                    } else if let Some(n) = fv.as_i64() {
                        n.to_string()
                    } else {
                        String::new()
                    }
                })
                .unwrap_or_default();
            row.push(val);
        }
        results.push(row);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lines_simple() {
        let body = "example.com\ngoogle.com\n# comment\n\nbad";
        let config = ParseConfig::Lines { strip_prefix: None };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["example.com", "google.com", "bad"]);
    }

    #[test]
    fn test_lines_strip_prefix() {
        let body = "*.example.com\n*.google.com\nnaked.com";
        let config = ParseConfig::Lines {
            strip_prefix: Some("*.".to_string()),
        };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["example.com", "google.com", "naked.com"]);
    }

    #[test]
    fn test_csv_no_header() {
        let body = "1,google.com\n2,facebook.com\n# header";
        let config = ParseConfig::Csv {
            column: 1,
            delimiter: None,
            skip_header: None,
            extra_columns: None,
        };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["google.com", "facebook.com"]);
    }

    #[test]
    fn test_csv_with_header_and_tab() {
        let body = "Rank\tDomain\tDate\n1\texample.com\t2026-01-01\n2\tgoogle.com\t2026-01-02";
        let config = ParseConfig::Csv {
            column: 1,
            delimiter: Some("\t".to_string()),
            skip_header: Some(true),
            extra_columns: None,
        };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["example.com", "google.com"]);
    }

    #[test]
    fn test_jsonl_string_field() {
        let body = r#"{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"45.74.10.0/24","sblid":"SBL682262","rir":"arin"}
{"type":"metadata","timestamp":1774653242,"records":2}"#;
        let mut skip = HashMap::new();
        skip.insert("type".to_string(), "metadata".to_string());
        let config = ParseConfig::Jsonl {
            field: "cidr".to_string(),
            skip_when: Some(skip),
            extra_fields: None,
        };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["1.10.16.0/20", "45.74.10.0/24"]);
    }

    #[test]
    fn test_jsonl_numeric_field() {
        let body = r#"{"asn":245,"rir":"arin","cc":"US"}
{"asn":2601,"rir":"ripencc","cc":"UA"}
{"type":"metadata","timestamp":1774683842,"records":2}"#;
        let mut skip = HashMap::new();
        skip.insert("type".to_string(), "metadata".to_string());
        let config = ParseConfig::Jsonl {
            field: "asn".to_string(),
            skip_when: Some(skip),
            extra_fields: None,
        };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["245", "2601"]);
    }

    #[test]
    fn test_jsonl_skips_invalid() {
        let body = "  \n{invalid json\n{\"asn\":100,\"rir\":\"arin\"}\n";
        let config = ParseConfig::Jsonl {
            field: "asn".to_string(),
            skip_when: None,
            extra_fields: None,
        };
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["100"]);
    }

    #[test]
    fn test_default_config() {
        let config = ParseConfig::default();
        let body = "example.com\n# skip\ngoogle.com";
        let result = parse_indicators(body, &config);
        assert_eq!(result, vec!["example.com", "google.com"]);
    }

    #[test]
    fn test_parse_config_serde_roundtrip() {
        let configs = vec![
            r#"{"type": "lines"}"#,
            r#"{"type": "lines", "strip_prefix": "*."}"#,
            r#"{"type": "csv", "column": 2, "delimiter": "\t", "skip_header": true}"#,
            r#"{"type": "csv", "column": 1, "extra_columns": {"rank": 0}}"#,
            r#"{"type": "jsonl", "field": "cidr", "skip_when": {"type": "metadata"}}"#,
            r#"{"type": "jsonl", "field": "cidr", "extra_fields": {"sbl_id": "sblid"}}"#,
        ];
        for json in configs {
            let parsed: ParseConfig = serde_json::from_str(json).unwrap();
            let round_tripped = serde_json::to_string(&parsed).unwrap();
            let _: ParseConfig = serde_json::from_str(&round_tripped).unwrap();
        }
    }

    // --- parse_rows tests ---

    #[test]
    fn test_parse_rows_lines() {
        let body = "example.com\ngoogle.com\n# comment";
        let config = ParseConfig::Lines { strip_prefix: None };
        let rows = parse_rows(body, &config);
        assert_eq!(rows, vec![vec!["example.com"], vec!["google.com"]]);
    }

    #[test]
    fn test_parse_rows_csv_all_columns() {
        let body = "1,google.com\n2,facebook.com";
        let config = ParseConfig::Csv {
            column: 1,
            delimiter: None,
            skip_header: None,
            extra_columns: None,
        };
        let rows = parse_rows(body, &config);
        assert_eq!(
            rows,
            vec![vec!["1", "google.com"], vec!["2", "facebook.com"],]
        );
    }

    #[test]
    fn test_parse_rows_csv_tab_delimited() {
        let body = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARE";
        let config = ParseConfig::Csv {
            column: 0,
            delimiter: Some("\t".to_string()),
            skip_header: None,
            extra_columns: None,
        };
        let rows = parse_rows(body, &config);
        assert_eq!(
            rows,
            vec![vec!["1.0.0.0", "1.0.0.255", "13335", "US", "CLOUDFLARE"]]
        );
    }

    #[test]
    fn test_parse_rows_jsonl() {
        let body = r#"{"cidr":"1.10.16.0/20"}
{"cidr":"45.74.10.0/24"}"#;
        let config = ParseConfig::Jsonl {
            field: "cidr".to_string(),
            skip_when: None,
            extra_fields: None,
        };
        let rows = parse_rows(body, &config);
        assert_eq!(rows, vec![vec!["1.10.16.0/20"], vec!["45.74.10.0/24"]]);
    }

    #[test]
    fn test_primary_column_index() {
        assert_eq!(
            primary_column_index(&ParseConfig::Lines { strip_prefix: None }),
            0
        );
        assert_eq!(
            primary_column_index(&ParseConfig::Csv {
                column: 2,
                delimiter: None,
                skip_header: None,
                extra_columns: None,
            }),
            2
        );
        assert_eq!(
            primary_column_index(&ParseConfig::Jsonl {
                field: "x".into(),
                skip_when: None,
                extra_fields: None,
            }),
            0
        );
    }

    // --- build_extra tests ---

    #[test]
    fn test_build_extra_csv_with_rank() {
        let row = vec!["1".to_string(), "google.com".to_string()];
        let config = ParseConfig::Csv {
            column: 1,
            delimiter: None,
            skip_header: None,
            extra_columns: Some(HashMap::from([("rank".to_string(), 0)])),
        };
        let extra = build_extra(&row, &config);
        assert_eq!(extra, serde_json::json!({"rank": 1}));
    }

    #[test]
    fn test_build_extra_no_mapping() {
        let row = vec!["example.com".to_string()];
        let config = ParseConfig::Lines { strip_prefix: None };
        assert_eq!(build_extra(&row, &config), serde_json::json!({}));
    }

    #[test]
    fn test_build_extra_csv_no_extra_columns() {
        let row = vec!["1".to_string(), "google.com".to_string()];
        let config = ParseConfig::Csv {
            column: 1,
            delimiter: None,
            skip_header: None,
            extra_columns: None,
        };
        assert_eq!(build_extra(&row, &config), serde_json::json!({}));
    }

    #[test]
    fn test_parse_rows_jsonl_with_extra_fields() {
        let body = r#"{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"45.74.10.0/24","sblid":"SBL682262","rir":"arin"}"#;
        let config = ParseConfig::Jsonl {
            field: "cidr".to_string(),
            skip_when: None,
            extra_fields: Some(HashMap::from([
                ("rir".to_string(), "rir".to_string()),
                ("sbl_id".to_string(), "sblid".to_string()),
            ])),
        };
        let rows = parse_rows(body, &config);
        // Extra fields sorted by JSONB key: rir(1), sbl_id(2)
        assert_eq!(
            rows,
            vec![
                vec!["1.10.16.0/20", "apnic", "SBL256894"],
                vec!["45.74.10.0/24", "arin", "SBL682262"],
            ]
        );
    }

    #[test]
    fn test_build_extra_jsonl() {
        let row = vec![
            "1.10.16.0/20".to_string(),
            "apnic".to_string(),
            "SBL256894".to_string(),
        ];
        let config = ParseConfig::Jsonl {
            field: "cidr".to_string(),
            skip_when: None,
            extra_fields: Some(HashMap::from([
                ("rir".to_string(), "rir".to_string()),
                ("sbl_id".to_string(), "sblid".to_string()),
            ])),
        };
        let extra = build_extra(&row, &config);
        assert_eq!(extra["rir"], serde_json::json!("apnic"));
        assert_eq!(extra["sbl_id"], serde_json::json!("SBL256894"));
    }

    #[test]
    fn test_build_extra_string_value() {
        let row = vec!["1".to_string(), "google.com".to_string(), "US".to_string()];
        let config = ParseConfig::Csv {
            column: 1,
            delimiter: None,
            skip_header: None,
            extra_columns: Some(HashMap::from([
                ("rank".to_string(), 0),
                ("country".to_string(), 2),
            ])),
        };
        let extra = build_extra(&row, &config);
        assert_eq!(extra["rank"], serde_json::json!(1));
        assert_eq!(extra["country"], serde_json::json!("US"));
    }
}
