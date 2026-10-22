#[allow(dead_code)]
mod client;
mod cmd;
mod config;
mod output;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "nameserver",
    version,
    about = "Nameserver CLI controller and DNS diagnostics"
)]
struct Cli {
    /// Control plane API URL (overrides NAMESERVER_CONTROL_URL)
    #[arg(long, global = true)]
    url: Option<String>,

    /// Output raw JSON instead of human-friendly format
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: cmd::Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    output::set_json_mode(cli.json);

    let mut cfg = config::Config::load();
    if let Some(url) = cli.url {
        cfg = cfg.with_url(url);
    }

    match cli.command {
        // Commands that don't need the API client
        cmd::Command::Watch(args) => cmd::watch::run(&cfg.control_url, args).await,
        cmd::Command::Detector(args) => {
            let api = client::Client::new(&cfg.control_url)?;
            cmd::detector::run(&cfg.control_url, &api, args).await
        }
        cmd::Command::Jarm(args) => cmd::jarm::run(args).await,
        cmd::Command::Dig(args) => cmd::dig::run(&cfg.dns_server, args).await,
        cmd::Command::Mobileconfig(args) => {
            let api = client::Client::new(&cfg.control_url)?;
            cmd::profile::run(&api, args).await
        }
        cmd::Command::Stamp(args) => cmd::stamp::run(args).await,

        // All other commands need the API client
        other => {
            let api = client::Client::new(&cfg.control_url)?;
            match other {
                // Core
                cmd::Command::Flow(args) => cmd::flow::run(&api, args).await,
                cmd::Command::Domains(args) => cmd::domains::run(&api, args).await,
                cmd::Command::Inspect(args) => cmd::inspect::run(&api, args).await,
                cmd::Command::Lookup(args) => cmd::lookup::run(&api, args).await,
                cmd::Command::Status => cmd::status::run(&api).await,

                // Filters + sources + allowlist
                cmd::Command::Filter(args) => cmd::filter::run(&api, args).await,
                cmd::Command::Source(args) => cmd::source::run(&api, args).await,
                cmd::Command::Allowlist(args) => cmd::allowlist::run(&api, args).await,

                // Intelligence
                cmd::Command::Intel(args) => cmd::intel::run(&api, args).await,

                // Profiles
                cmd::Command::Profiles(args) => cmd::profiles::run(&api, args).await,

                // Utilities
                cmd::Command::Geoip(args) => cmd::geoip::run(&api, args).await,
                cmd::Command::Rdap(args) => cmd::rdap::run(&api, args).await,

                // Zone + DNSSEC management
                cmd::Command::Zone(args) => cmd::zone::run(&api, args).await,

                // Already handled above
                cmd::Command::Watch(_)
                | cmd::Command::Detector(_)
                | cmd::Command::Jarm(_)
                | cmd::Command::Dig(_)
                | cmd::Command::Mobileconfig(_)
                | cmd::Command::Stamp(_) => unreachable!(),
            }
        }
    }
}
