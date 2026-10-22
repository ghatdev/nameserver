use clap::{CommandFactory, FromArgMatches};
use nameserver_core::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Args::command()
        .name("nameserver-resolver")
        .about("Personal filtering DNS resolver with UDP, TCP, DoH, and DoT")
        .get_matches();
    nameserver_core::run(
        Args::from_arg_matches(&matches)?,
        nameserver_resolver::build,
    )
    .await
}
