use clap::{CommandFactory, FromArgMatches};
use nameserver_core::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Args::command()
        .name("nameserver-authority")
        .about("Standalone authoritative DNS server with zone files and DNSSEC signing")
        .get_matches();
    nameserver_core::run(
        Args::from_arg_matches(&matches)?,
        nameserver_authority::build,
    )
    .await
}
