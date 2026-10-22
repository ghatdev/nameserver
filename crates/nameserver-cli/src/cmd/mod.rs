pub mod allowlist;
pub mod apply;
pub mod filter;
pub mod intel;
pub mod source;
pub mod source_def;

pub mod detector;
pub mod dig;
pub mod domains;
pub mod flow;
pub mod inspect;
pub mod lookup;
pub mod status;
pub mod watch;

pub mod format;
pub mod geoip;
pub mod jarm;
pub mod profile;
pub mod profiles;
pub mod rdap;
pub mod stamp;
pub mod zone;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Watch live DNS queries in real-time
    Watch(watch::WatchArgs),
    /// Browse DNS flows
    Flow(flow::FlowArgs),
    /// List domains with scoring and classification
    Domains(domains::DomainsArgs),
    /// Deep dive into a domain or IP
    Inspect(inspect::InspectArgs),
    /// Quick domain reputation lookup
    Lookup(lookup::LookupArgs),
    /// Query a DoH/DoT DNS server (like dig)
    Dig(dig::DigArgs),
    /// ML-based detector — scores per scored flow
    Detector(detector::DetectorArgs),
    /// Show overview status
    Status,

    /// Manage compiled filters (per-resource diff/apply)
    Filter(filter::FilterArgs),
    /// Manage indicator sources (feeds, pull, enable/disable)
    Source(source::SourceArgs),
    /// Manage allowlist (user exceptions)
    Allowlist(allowlist::AllowlistArgs),

    /// Control plane intelligence (NRD, NS reputation, well-known domains)
    Intel(intel::IntelArgs),

    /// Manage DNS profiles (per-profile filtering, diff/apply)
    #[command(name = "profile")]
    Profiles(profiles::ProfilesArgs),

    /// GeoIP/ASN lookup and management (diff/apply)
    Geoip(geoip::GeoipArgs),
    /// RDAP domain registration data
    Rdap(rdap::RdapArgs),
    /// JARM TLS fingerprint a server
    Jarm(jarm::JarmArgs),
    /// Generate and decode DNS stamps (sdns://)
    Stamp(stamp::StampArgs),
    /// Generate Apple .mobileconfig for iOS/macOS
    Mobileconfig(profile::ProfileArgs),

    /// Zone management (config, records, DNSSEC)
    Zone(zone::ZoneArgs),
}
