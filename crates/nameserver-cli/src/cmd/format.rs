use serde_json::Value;
use time::OffsetDateTime;

/// Format an optional epoch timestamp as a human-readable relative or absolute string.
pub fn format_epoch(epoch: Option<i64>) -> String {
    let Some(ts) = epoch else {
        return "never".to_string();
    };
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(ts) else {
        return "?".to_string();
    };
    let now = OffsetDateTime::now_utc();
    let diff = now - dt;
    let secs = diff.whole_seconds();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Format a scoring bar: "████████░░░░░░░░░░░░░░░░░   8/25"
#[allow(dead_code)]
pub fn score_bar(score: i64, max: i64, width: usize) -> String {
    let filled = if max > 0 {
        ((score as f64 / max as f64) * width as f64).round() as usize
    } else {
        0
    };
    let filled = filled.min(width);
    let empty = width - filled;
    format!(
        "{}{} {:>3}/{}",
        "█".repeat(filled),
        "░".repeat(empty),
        score,
        max
    )
}

/// Format DNSSEC detail: "SECURE ECDSAP256SHA256" or "BOGUS: reason" or "INSECURE"
pub fn dnssec_detail(status: &str, algorithm: &str, failure_reason: &str) -> String {
    let mut detail = status.to_string();
    if !algorithm.is_empty() {
        detail.push(' ');
        detail.push_str(algorithm);
    }
    if !failure_reason.is_empty() {
        detail.push_str(": ");
        detail.push_str(failure_reason);
    }
    detail
}

/// Format AllRecords from a JSON string or Value for display.
/// Each line is prefixed with `indent`.
pub fn format_all_records(records: &Value, indent: &str) -> String {
    let mut lines = Vec::new();

    // A records
    if let Some(arr) = records.get("a").and_then(|v| v.as_array()) {
        for r in arr {
            let ip = r["ip"].as_str().unwrap_or("-");
            let ttl = r["ttl"].as_u64().unwrap_or(0);
            lines.push(format!("{indent}A:    {ip} (TTL={ttl})"));
        }
    }

    // AAAA records
    if let Some(arr) = records.get("aaaa").and_then(|v| v.as_array()) {
        for r in arr {
            let ip = r["ip"].as_str().unwrap_or("-");
            let ttl = r["ttl"].as_u64().unwrap_or(0);
            lines.push(format!("{indent}AAAA: {ip} (TTL={ttl})"));
        }
    }

    // CNAME records
    if let Some(arr) = records.get("cname").and_then(|v| v.as_array()) {
        for r in arr {
            let target = r["target"].as_str().unwrap_or("-");
            let ttl = r["ttl"].as_u64().unwrap_or(0);
            lines.push(format!("{indent}CNAME: {target} (TTL={ttl})"));
        }
    }

    // NS records
    if let Some(arr) = records.get("ns").and_then(|v| v.as_array()) {
        let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
        if !names.is_empty() {
            lines.push(format!("{indent}NS:   {}", names.join(", ")));
        }
    }

    // MX records
    if let Some(arr) = records.get("mx").and_then(|v| v.as_array()) {
        for r in arr {
            let pref = r["preference"].as_u64().unwrap_or(0);
            let exchange = r["exchange"].as_str().unwrap_or("-");
            lines.push(format!("{indent}MX:   {pref} {exchange}"));
        }
    }

    // TXT records
    if let Some(arr) = records.get("txt").and_then(|v| v.as_array()) {
        for r in arr {
            let txt = r.as_str().unwrap_or("-");
            lines.push(format!("{indent}TXT:  \"{txt}\""));
        }
    }

    // SOA record
    if let Some(soa) = records.get("soa")
        && !soa.is_null()
    {
        let mname = soa["mname"].as_str().unwrap_or("-");
        let rname = soa["rname"].as_str().unwrap_or("-");
        let serial = soa["serial"].as_u64().unwrap_or(0);
        lines.push(format!("{indent}SOA:  {mname} {rname} (serial={serial})"));
    }

    // CAA records
    if let Some(arr) = records.get("caa").and_then(|v| v.as_array()) {
        for r in arr {
            let flags = r["flags"].as_u64().unwrap_or(0);
            let tag = r["tag"].as_str().unwrap_or("-");
            let value = r["value"].as_str().unwrap_or("-");
            lines.push(format!("{indent}CAA:  {flags} {tag} \"{value}\""));
        }
    }

    lines.join("\n")
}

/// Format AllRecords from the DnsFlow struct (nameserver_common types) for display.
pub fn format_all_records_struct(records: &nameserver_common::AllRecords, indent: &str) -> String {
    let mut lines = Vec::new();

    if let Some(ref arr) = records.a {
        for r in arr {
            lines.push(format!("{indent}A:    {} (TTL={})", r.ip, r.ttl));
        }
    }
    if let Some(ref arr) = records.aaaa {
        for r in arr {
            lines.push(format!("{indent}AAAA: {} (TTL={})", r.ip, r.ttl));
        }
    }
    if let Some(ref arr) = records.cname {
        for r in arr {
            lines.push(format!("{indent}CNAME: {} (TTL={})", r.target, r.ttl));
        }
    }
    if let Some(ref arr) = records.ns
        && !arr.is_empty()
    {
        let names: Vec<&str> = arr.iter().map(|r| r.name.as_str()).collect();
        lines.push(format!("{indent}NS:   {}", names.join(", ")));
    }
    if let Some(ref arr) = records.mx {
        for r in arr {
            lines.push(format!(
                "{indent}MX:   {} {} (TTL={})",
                r.preference, r.exchange, r.ttl
            ));
        }
    }
    if let Some(ref arr) = records.txt {
        for r in arr {
            lines.push(format!("{indent}TXT:  \"{}\"", r.value));
        }
    }
    if let Some(ref soa) = records.soa {
        lines.push(format!(
            "{indent}SOA:  {} {} (serial={})",
            soa.mname, soa.rname, soa.serial
        ));
    }
    if let Some(ref arr) = records.caa {
        for r in arr {
            lines.push(format!(
                "{indent}CAA:  {} {} \"{}\"",
                r.flags, r.tag, r.value
            ));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bar_zero() {
        let bar = score_bar(0, 25, 25);
        assert!(bar.starts_with("░"));
        assert!(bar.contains("0/25"));
    }

    #[test]
    fn score_bar_full() {
        let bar = score_bar(25, 25, 25);
        assert!(bar.starts_with("█"));
        assert!(bar.contains("25/25"));
    }

    #[test]
    fn score_bar_half() {
        let bar = score_bar(12, 25, 25);
        assert!(bar.contains("12/25"));
    }

    #[test]
    fn dnssec_detail_secure_with_algorithm() {
        assert_eq!(
            dnssec_detail("SECURE", "ECDSAP256SHA256", ""),
            "SECURE ECDSAP256SHA256"
        );
    }

    #[test]
    fn dnssec_detail_bogus_with_reason() {
        assert_eq!(
            dnssec_detail("BOGUS", "", "signature expired"),
            "BOGUS: signature expired"
        );
    }

    #[test]
    fn dnssec_detail_insecure() {
        assert_eq!(dnssec_detail("INSECURE", "", ""), "INSECURE");
    }
}
