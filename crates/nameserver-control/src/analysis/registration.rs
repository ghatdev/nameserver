// Registration data pipeline: RDAP + WHOIS fallback for domain age caching.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Cached RDAP/WHOIS registration data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistrationData {
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub registrar: Option<String>,
    pub status: Vec<String>,
    #[serde(default)]
    pub nameservers: Vec<String>,
    pub privacy_protected: bool,
    pub lookup_method: String,
    pub fetched_at: i64,
}

/// Parse ISO 8601 / RDAP date strings to Unix timestamp.
#[allow(dead_code)]
fn parse_timestamp(s: &str) -> Option<i64> {
    // Try RFC 3339 first (2024-01-15T10:30:00Z).
    if let Ok(dt) = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
        return Some(dt.unix_timestamp());
    }
    // Try date-only (2024-01-15).
    if s.len() >= 10 {
        let date_part = &s[..10];
        if let Ok(date) = time::Date::parse(
            date_part,
            &time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?,
        ) {
            let dt = date.with_hms(0, 0, 0).ok()?.assume_utc();
            return Some(dt.unix_timestamp());
        }
    }
    None
}

/// IANA RDAP bootstrap data: maps TLDs to RDAP service URLs.
#[derive(Debug, Clone)]
pub struct RdapBootstrap {
    /// TLD → RDAP base URL.
    pub services: Vec<(Vec<String>, String)>,
    #[allow(dead_code)]
    pub fetched_at: i64,
}

impl RdapBootstrap {
    /// Find the RDAP service URL for a given domain.
    pub fn find_service(&self, domain: &str) -> Option<&str> {
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        // Extract TLD (and SLD for ccTLDs like .co.kr).
        let parts: Vec<&str> = domain.rsplitn(3, '.').collect();

        // Try SLD.TLD first (e.g., "co.kr"), then TLD alone.
        let candidates: Vec<String> = match parts.len() {
            1 => vec![parts[0].to_string()],
            2 => vec![format!("{}.{}", parts[1], parts[0]), parts[0].to_string()],
            _ => vec![format!("{}.{}", parts[1], parts[0]), parts[0].to_string()],
        };

        for (tlds, url) in &self.services {
            for candidate in &candidates {
                if tlds.iter().any(|t| t == candidate) {
                    return Some(url.as_str());
                }
            }
        }
        None
    }
}

/// Fetch IANA RDAP bootstrap data.
pub async fn fetch_bootstrap(http: &reqwest::Client) -> anyhow::Result<RdapBootstrap> {
    let resp = http
        .get("https://data.iana.org/rdap/dns.json")
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("IANA RDAP bootstrap failed: HTTP {}", resp.status());
    }

    let body: serde_json::Value = resp.json().await?;
    let mut services = Vec::new();

    if let Some(svcs) = body["services"].as_array() {
        for svc in svcs {
            if let (Some(tlds), Some(urls)) = (svc[0].as_array(), svc[1].as_array()) {
                let tld_list: Vec<String> = tlds
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect();
                if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                    services.push((tld_list, url.trim_end_matches('/').to_string()));
                }
            }
        }
    }

    Ok(RdapBootstrap {
        services,
        fetched_at: time::OffsetDateTime::now_utc().unix_timestamp(),
    })
}

/// Fetch RDAP data for a specific domain.
pub async fn fetch_rdap(
    domain: &str,
    http: &reqwest::Client,
    bootstrap: &RdapBootstrap,
) -> RegistrationData {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    let Some(base_url) = bootstrap.find_service(domain) else {
        return RegistrationData {
            creation_date: None,
            expiration_date: None,
            registrar: None,
            status: vec![],
            nameservers: vec![],
            privacy_protected: false,
            lookup_method: "failed".into(),
            fetched_at: now,
        };
    };

    let url = format!("{base_url}/domain/{domain}");
    let result = http.get(&url).send().await;

    let resp = match result {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            debug!(status = %r.status(), "RDAP query failed");
            return RegistrationData {
                creation_date: None,
                expiration_date: None,
                registrar: None,
                status: vec![],
                nameservers: vec![],
                privacy_protected: false,
                lookup_method: "failed".into(),
                fetched_at: now,
            };
        }
        Err(e) => {
            warn!(error = %e, "RDAP request error");
            return RegistrationData {
                creation_date: None,
                expiration_date: None,
                registrar: None,
                status: vec![],
                nameservers: vec![],
                privacy_protected: false,
                lookup_method: "failed".into(),
                fetched_at: now,
            };
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "RDAP response parse error");
            return RegistrationData {
                creation_date: None,
                expiration_date: None,
                registrar: None,
                status: vec![],
                nameservers: vec![],
                privacy_protected: false,
                lookup_method: "failed".into(),
                fetched_at: now,
            };
        }
    };

    parse_rdap_response(&body, now)
}

/// Parse RDAP JSON response into RegistrationData.
fn parse_rdap_response(body: &serde_json::Value, now: i64) -> RegistrationData {
    let mut creation_date = None;
    let mut expiration_date = None;

    // Parse events for registration/expiration dates.
    if let Some(events) = body["events"].as_array() {
        for event in events {
            let action = event["eventAction"].as_str().unwrap_or("");
            let date = event["eventDate"].as_str().map(String::from);
            match action {
                "registration" => creation_date = date,
                "expiration" => expiration_date = date,
                _ => {}
            }
        }
    }

    // Parse registrar from entities.
    let mut registrar = None;
    if let Some(entities) = body["entities"].as_array() {
        for entity in entities {
            let roles = entity["roles"].as_array();
            let is_registrar = roles
                .map(|r| r.iter().any(|v| v.as_str() == Some("registrar")))
                .unwrap_or(false);
            if is_registrar {
                // Try vcardArray first, then handle field.
                if let Some(vcard) = entity["vcardArray"].as_array()
                    && let Some(entries) = vcard.get(1).and_then(|v| v.as_array())
                {
                    for entry in entries {
                        if let Some(arr) = entry.as_array()
                            && arr.first().and_then(|v| v.as_str()) == Some("fn")
                        {
                            registrar = arr.get(3).and_then(|v| v.as_str()).map(String::from);
                        }
                    }
                }
                if registrar.is_none() {
                    registrar = entity["handle"].as_str().map(String::from);
                }
            }
        }
    }

    // Parse status.
    let status: Vec<String> = body["status"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse nameservers.
    let nameservers: Vec<String> = body["nameservers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|ns| {
                    ns["ldhName"].as_str().map(|s| {
                        s.to_lowercase()
                            .strip_suffix('.')
                            .map(String::from)
                            .unwrap_or_else(|| s.to_lowercase())
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Detect privacy protection (REDACTED FOR PRIVACY in vcard or specific status).
    let body_str = body.to_string();
    let privacy_protected = body_str.contains("REDACTED FOR PRIVACY")
        || body_str.contains("redacted for privacy")
        || status
            .iter()
            .any(|s| s.contains("proxy") || s.contains("privacy"));

    RegistrationData {
        creation_date,
        expiration_date,
        registrar,
        status,
        nameservers,
        privacy_protected,
        lookup_method: "rdap".into(),
        fetched_at: now,
    }
}

// ---------------------------------------------------------------------------
// WHOIS fallback
// ---------------------------------------------------------------------------

/// Well-known WHOIS servers for common TLDs.
/// Fallback when RDAP fails or is unavailable.
const WHOIS_SERVERS: &[(&str, &str)] = &[
    ("com", "whois.verisign-grs.com"),
    ("net", "whois.verisign-grs.com"),
    ("org", "whois.pir.org"),
    ("info", "whois.afilias.net"),
    ("io", "whois.nic.io"),
    ("dev", "whois.nic.google"),
    ("app", "whois.nic.google"),
    ("ai", "whois.nic.ai"),
    ("co", "whois.nic.co"),
    ("me", "whois.nic.me"),
    ("kr", "whois.kr"),
    ("jp", "whois.jprs.jp"),
    ("uk", "whois.nic.uk"),
    ("de", "whois.denic.de"),
    ("fr", "whois.nic.fr"),
    ("it", "whois.nic.it"),
    ("ru", "whois.tcinet.ru"),
    ("cn", "whois.cnnic.cn"),
    ("au", "whois.auda.org.au"),
    ("br", "whois.registro.br"),
    ("nl", "whois.sidn.nl"),
    ("eu", "whois.eu"),
    ("xyz", "whois.nic.xyz"),
    ("top", "whois.nic.top"),
    ("cloud", "whois.nic.cloud"),
    ("site", "whois.nic.site"),
    ("online", "whois.nic.online"),
    ("tech", "whois.nic.tech"),
    ("store", "whois.nic.store"),
    ("club", "whois.nic.club"),
    ("icu", "whois.nic.icu"),
    ("tw", "whois.twnic.net.tw"),
    ("in", "whois.registry.in"),
    ("ua", "whois.ua"),
    ("pl", "whois.dns.pl"),
    ("se", "whois.iis.se"),
    ("ch", "whois.nic.ch"),
    ("be", "whois.dns.be"),
    ("ca", "whois.cira.ca"),
    ("mx", "whois.nic.mx"),
];

/// Find WHOIS server for a domain's TLD.
fn find_whois_server(domain: &str) -> Option<&'static str> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let parts: Vec<&str> = domain.rsplitn(3, '.').collect();

    // Try SLD.TLD first (e.g., "co.kr"), then TLD alone
    let candidates: Vec<String> = match parts.len() {
        1 => vec![parts[0].to_lowercase()],
        _ => vec![
            format!("{}.{}", parts[1], parts[0]).to_lowercase(),
            parts[0].to_lowercase(),
        ],
    };

    for &(tld, server) in WHOIS_SERVERS {
        for candidate in &candidates {
            if candidate == tld {
                return Some(server);
            }
        }
    }
    None
}

/// Fetch WHOIS data for a domain via TCP port 43.
/// Returns RegistrationData with lookup_method = "whois" on success.
pub async fn fetch_whois(domain: &str) -> RegistrationData {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    let Some(server) = find_whois_server(domain) else {
        return RegistrationData {
            creation_date: None,
            expiration_date: None,
            registrar: None,
            status: vec![],
            nameservers: vec![],
            privacy_protected: false,
            lookup_method: "no_whois_server".into(),
            fetched_at: now,
        };
    };

    let addr = format!("{server}:43");
    let response = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        whois_query(&addr, domain),
    )
    .await
    {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => {
            debug!(error = %e, server, "WHOIS query failed");
            return RegistrationData {
                creation_date: None,
                expiration_date: None,
                registrar: None,
                status: vec![],
                nameservers: vec![],
                privacy_protected: false,
                lookup_method: "whois_failed".into(),
                fetched_at: now,
            };
        }
        Err(_) => {
            debug!(server, "WHOIS query timed out");
            return RegistrationData {
                creation_date: None,
                expiration_date: None,
                registrar: None,
                status: vec![],
                nameservers: vec![],
                privacy_protected: false,
                lookup_method: "whois_timeout".into(),
                fetched_at: now,
            };
        }
    };

    parse_whois_response(&response, now)
}

/// Send WHOIS query over TCP and read the response.
async fn whois_query(addr: &str, domain: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;

    // JPRS requires "/e" suffix for English output
    let query = if addr.contains("whois.jprs.jp") {
        format!("{domain}/e\r\n")
    } else {
        format!("{domain}\r\n")
    };
    stream.write_all(query.as_bytes()).await?;

    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Parse WHOIS text response for creation_date and registrar.
/// WHOIS format varies by registry, but common patterns exist.
fn parse_whois_response(text: &str, now: i64) -> RegistrationData {
    let mut creation_date = None;
    let mut expiration_date = None;
    let mut registrar = None;
    let mut privacy_protected = false;

    let text_lower = text.to_lowercase();

    for line in text.lines() {
        let line_trimmed = line.trim();
        let line_lower = line_trimmed.to_lowercase();

        // Creation date patterns (various registries)
        if creation_date.is_none()
            && let Some(date) = extract_whois_date(
                &line_lower,
                &[
                    "creation date:",
                    "created:",
                    "created on:",
                    "registration date:",
                    "registered:",
                    "registered on:",
                    "registered date:",
                    "domain registered:",
                    "registration time:",
                    // UK Nominet
                    "registered on:",
                    // Japanese JPRS
                    "[registered date]",
                    "[created on]",
                    // Korean
                    "등록일:",
                ],
            )
        {
            creation_date = Some(date);
        }

        // Expiration date patterns
        if expiration_date.is_none()
            && let Some(date) = extract_whois_date(
                &line_lower,
                &[
                    "registry expiry date:",
                    "expiration date:",
                    "expires:",
                    "expires on:",
                    "expiry date:",
                    "paid-till:",
                    // Korean
                    "사용 종료일:",
                ],
            )
        {
            expiration_date = Some(date);
        }

        // Registrar patterns
        if registrar.is_none() {
            for prefix in &["registrar:", "registrar name:", "sponsoring registrar:"] {
                if line_lower.starts_with(prefix) {
                    let val = line_trimmed[prefix.len()..].trim();
                    if !val.is_empty() {
                        registrar = Some(val.to_string());
                    }
                }
            }
        }
    }

    // Status flags (domain lock indicators)
    let mut status = Vec::new();
    for line in text.lines() {
        let lower = line.trim().to_lowercase();
        if lower.starts_with("domain status:") || lower.starts_with("status:") {
            let val = line
                .trim()
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            // Extract status before URL (e.g., "clientTransferProhibited https://...")
            let flag = val.split_whitespace().next().unwrap_or("").to_string();
            if !flag.is_empty() && !status.contains(&flag) {
                status.push(flag);
            }
        }
    }

    // Privacy detection
    if text_lower.contains("redacted for privacy")
        || text_lower.contains("data protected")
        || text_lower.contains("privacy protect")
        || text_lower.contains("whoisguard")
        || text_lower.contains("domains by proxy")
    {
        privacy_protected = true;
    }

    RegistrationData {
        creation_date,
        expiration_date,
        registrar,
        status,
        nameservers: vec![],
        privacy_protected,
        lookup_method: "whois".into(),
        fetched_at: now,
    }
}

/// Match a WHOIS field key against a line, tolerating whitespace before the colon.
/// Korean WHOIS uses padded format: `Registered Date             : 2013. 09. 23.`
/// Standard WHOIS uses compact format: `Creation Date: 2024-01-15T10:30:00Z`
/// JPRS uses bracket format without colon: `[Registered Date]               2019/09/27`
/// Returns the value after the delimiter if matched.
fn match_whois_field<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.ends_with(':') {
        // Colon-delimited prefix: tolerate whitespace before the colon
        let key = prefix.trim_end_matches(':');
        let pos = line.find(key)?;
        let after_key = &line[pos + key.len()..];
        let after_ws = after_key.trim_start();
        if let Some(value) = after_ws.strip_prefix(':') {
            Some(value.trim_start())
        } else {
            None
        }
    } else {
        // Non-colon prefix (e.g., "[registered date]"): match literally
        let pos = line.find(prefix)?;
        Some(line[pos + prefix.len()..].trim_start())
    }
}

/// Try to parse Korean WHOIS date format: "2013. 09. 23." → "2013-09-23"
fn parse_korean_date(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let year: u32 = parts[0].trim().parse().ok()?;
    let month: u32 = parts[1].trim().parse().ok()?;
    let day: u32 = parts[2].trim().parse().ok()?;
    if !(1990..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Extract a date string from a WHOIS line matching any of the given prefixes.
fn extract_whois_date(line_lower: &str, prefixes: &[&str]) -> Option<String> {
    for prefix in prefixes {
        if let Some(after) = match_whois_field(line_lower, prefix) {
            // Try Korean format first: "2013. 09. 23."
            if let Some(date) = parse_korean_date(after) {
                return Some(date);
            }

            // Try human-readable format: "14-Feb-1999" or "14-Feb-2024"
            if let Some(date) = parse_human_date(after) {
                return Some(date);
            }

            // Try YYYYMMDD format (Brazilian .br): "19990518 #162310"
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.len() == 8 {
                let formatted = format!("{}-{}-{}", &digits[..4], &digits[4..6], &digits[6..8]);
                return Some(formatted);
            }

            // Standard: YYYY-MM-DD, YYYY/MM/DD, or ISO 8601
            let date_str: String = after
                .chars()
                .take_while(|c| {
                    c.is_ascii_digit()
                        || *c == '-'
                        || *c == '/'
                        || *c == 't'
                        || *c == ':'
                        || *c == 'z'
                        || *c == '+'
                        || *c == '.'
                        || *c == ' '
                })
                .collect();
            let date_str = date_str.trim().to_string();
            if date_str.len() >= 10 {
                return Some(date_str);
            }
        }
    }
    None
}

/// Parse human-readable date like "14-Feb-1999" or "14-Feb-2024" to "1999-02-14".
fn parse_human_date(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 3 {
        return None;
    }
    let day: u32 = parts[0].trim().parse().ok()?;
    let month = match parts[1].trim().to_lowercase().as_str() {
        "jan" | "january" => 1,
        "feb" | "february" => 2,
        "mar" | "march" => 3,
        "apr" | "april" => 4,
        "may" => 5,
        "jun" | "june" => 6,
        "jul" | "july" => 7,
        "aug" | "august" => 8,
        "sep" | "september" => 9,
        "oct" | "october" => 10,
        "nov" | "november" => 11,
        "dec" | "december" => 12,
        _ => return None,
    };
    // Year: take only digits from the third part
    let year_str: String = parts[2]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let year: u32 = year_str.parse().ok()?;
    if !(1990..=2100).contains(&year) || day > 31 {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_timestamp_rfc3339() {
        let ts = parse_timestamp("2024-01-15T10:30:00Z");
        assert!(ts.is_some());
        assert!(ts.unwrap() > 0);
    }

    #[test]
    fn test_parse_timestamp_date_only() {
        let ts = parse_timestamp("2024-01-15");
        assert!(ts.is_some());
        assert!(ts.unwrap() > 0);
    }

    #[test]
    fn test_whois_server_lookup() {
        assert_eq!(
            find_whois_server("example.com"),
            Some("whois.verisign-grs.com")
        );
        assert_eq!(find_whois_server("example.kr"), Some("whois.kr"));
        assert_eq!(find_whois_server("example.ua"), Some("whois.ua"));
        assert_eq!(find_whois_server("example.it"), Some("whois.nic.it"));
        assert_eq!(find_whois_server("example.xyz.nonexistent"), None);
    }

    #[test]
    fn test_parse_whois_verisign() {
        let text = "\
Domain Name: EXAMPLE.COM\r\n\
Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n\
Registrar WHOIS Server: whois.iana.org\r\n\
Registrar URL: http://www.iana.org\r\n\
Updated Date: 2024-08-14T07:01:34Z\r\n\
Creation Date: 1995-08-14T04:00:00Z\r\n\
Registry Expiry Date: 2025-08-13T04:00:00Z\r\n\
Registrar: RESERVED-Internet Assigned Numbers Authority\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(
            result.creation_date.as_deref(),
            Some("1995-08-14t04:00:00z")
        );
        assert_eq!(
            result.registrar.as_deref(),
            Some("RESERVED-Internet Assigned Numbers Authority")
        );
        assert_eq!(result.lookup_method, "whois");
    }

    #[test]
    fn test_parse_whois_korean() {
        // Real whois.kr output format: padded fields with Korean date "YYYY. MM. DD."
        let text = "\
query : digitaltoday.co.kr\r\n\
\r\n\
# KOREAN(UTF8)\r\n\
\r\n\
도메인이름                  : digitaltoday.co.kr\r\n\
등록일                      : 2013. 09. 23.\r\n\
최근 정보 변경일            : 2024. 10. 22.\r\n\
사용 종료일                 : 2026. 09. 23.\r\n\
등록대행자                  : 메가존(주)(http://HOSTING.KR)\r\n\
\r\n\
# ENGLISH\r\n\
\r\n\
Domain Name                 : digitaltoday.co.kr\r\n\
Registered Date             : 2013. 09. 23.\r\n\
Last Updated Date           : 2024. 10. 22.\r\n\
Expiration Date             : 2026. 09. 23.\r\n\
Authorized Agency           : Megazone(http://HOSTING.KR)\r\n\
DNSSEC                      : unsigned\r\n\
Domain Status               : clientTransferProhibited\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(result.creation_date.as_deref(), Some("2013-09-23"));
        assert_eq!(result.expiration_date.as_deref(), Some("2026-09-23"));
        assert_eq!(result.lookup_method, "whois");
    }

    #[test]
    fn test_parse_whois_italian() {
        let text = "\
Domain:             appsu.it\r\n\
Status:             ok\r\n\
Created:            2015-08-19 13:08:18\r\n\
Last Update:        2025-09-04 00:42:19\r\n\
Expire Date:        2026-08-19\r\n\
Registrar\r\n\
  Organization:     Tucows.com Co.\r\n\
  Name:             TUCOWS-REG\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(result.creation_date.as_deref(), Some("2015-08-19 13:08:18"));
        assert_eq!(result.lookup_method, "whois");
    }

    #[test]
    fn test_parse_whois_privacy() {
        let text = "\
Domain Name: SECRET.COM\r\n\
Creation Date: 2023-06-01T00:00:00Z\r\n\
Registrant Organization: REDACTED FOR PRIVACY\r\n\
";
        let result = parse_whois_response(text, 0);
        assert!(result.privacy_protected);
        assert!(result.creation_date.is_some());
    }

    #[test]
    fn test_parse_whois_uk_nominet() {
        let text = "\
    Domain name:\r\n\
        google.co.uk\r\n\
\r\n\
    Registered on: 14-Feb-1999\r\n\
    Expiry date:  14-Feb-2025\r\n\
    Last updated:  10-Jan-2024\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(result.creation_date.as_deref(), Some("1999-02-14"));
    }

    #[test]
    fn test_parse_whois_brazilian() {
        let text = "\
domain:      google.com.br\r\n\
created:     19990518 #162310\r\n\
changed:     20231212\r\n\
expires:     20250518\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(result.creation_date.as_deref(), Some("1999-05-18"));
    }

    #[test]
    fn test_parse_whois_japanese() {
        let text = "\
Domain Information:\r\n\
a. [Domain Name]                YAHOO.CO.JP\r\n\
[Registered Date]               2019/09/27\r\n\
[Connected Date]                2019/09/27\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(result.creation_date.as_deref(), Some("2019/09/27"));
    }

    #[test]
    fn test_parse_whois_russian() {
        let text = "\
domain:        YANDEX.RU\r\n\
nserver:       ns1.yandex.ru.\r\n\
state:         REGISTERED, DELEGATED, VERIFIED\r\n\
created:       1997-09-23T09:45:07Z\r\n\
paid-till:     2025-09-30T21:00:00Z\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(
            result.creation_date.as_deref(),
            Some("1997-09-23t09:45:07z")
        );
    }

    #[test]
    fn test_parse_whois_ukrainian() {
        let text = "\
domain:         google.com.ua\r\n\
status:         ok\r\n\
created:          2002-12-04 00:00:00+02\r\n\
modified:         2023-11-15 12:00:00+02\r\n\
expires:          2024-12-04 00:00:00+02\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(
            result.creation_date.as_deref(),
            Some("2002-12-04 00:00:00+02")
        );
    }

    #[test]
    fn test_parse_whois_french() {
        let text = "\
%%\r\n\
domain:      google.fr\r\n\
status:      ACTIVE\r\n\
created:                       2000-07-26T22:00:00Z\r\n\
last-update:                   2024-06-28T08:52:52.389578Z\r\n\
";
        let result = parse_whois_response(text, 0);
        assert_eq!(
            result.creation_date.as_deref(),
            Some("2000-07-26t22:00:00z")
        );
    }

    #[test]
    fn test_match_whois_field() {
        // Standard format (no extra spacing)
        assert_eq!(
            match_whois_field("creation date: 2024-01-15", "creation date:"),
            Some("2024-01-15"),
        );
        // Korean padded format
        assert_eq!(
            match_whois_field(
                "registered date             : 2013. 09. 23.",
                "registered date:"
            ),
            Some("2013. 09. 23."),
        );
        // Korean label with padding
        assert_eq!(
            match_whois_field("등록일                      : 2013. 09. 23.", "등록일:"),
            Some("2013. 09. 23."),
        );
        // Non-colon prefix (JPRS bracket format)
        assert_eq!(
            match_whois_field(
                "[registered date]               2019/09/27",
                "[registered date]"
            ),
            Some("2019/09/27"),
        );
        // No match
        assert_eq!(
            match_whois_field("some other field: value", "creation date:"),
            None,
        );
    }

    #[test]
    fn test_parse_korean_date() {
        assert_eq!(
            parse_korean_date("2013. 09. 23."),
            Some("2013-09-23".into())
        );
        assert_eq!(
            parse_korean_date("2026. 09. 23."),
            Some("2026-09-23".into())
        );
        // Not enough parts
        assert_eq!(parse_korean_date("2013. 09"), None);
        // Standard format should not match (no dots between parts)
        assert_eq!(parse_korean_date("2013-09-23"), None);
    }

    #[test]
    fn test_bootstrap_find_service() {
        let bootstrap = RdapBootstrap {
            services: vec![
                (
                    vec!["com".into(), "net".into()],
                    "https://rdap.verisign.com/com/v1".into(),
                ),
                (vec!["kr".into()], "https://rdap.kisa.or.kr/rdap".into()),
            ],
            fetched_at: 0,
        };

        assert_eq!(
            bootstrap.find_service("example.com"),
            Some("https://rdap.verisign.com/com/v1")
        );
        assert_eq!(
            bootstrap.find_service("example.kr"),
            Some("https://rdap.kisa.or.kr/rdap")
        );
        assert_eq!(bootstrap.find_service("example.xyz"), None);
    }
}
