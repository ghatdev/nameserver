use anyhow::Result;
use clap::Args;
use rust_jarm::Jarm;

use crate::output;

#[derive(Args)]
pub struct JarmArgs {
    /// Target host (domain or IP)
    host: String,

    /// Target port
    #[arg(short, long, default_value = "443")]
    port: u16,
}

pub async fn run(args: JarmArgs) -> Result<()> {
    let host = args.host.clone();
    let port = args.port.to_string();

    // JARM uses blocking I/O — run on a blocking thread.
    // JarmError isn't Send, so we convert to String inside the closure.
    let result = tokio::task::spawn_blocking(move || {
        Jarm::new(host, port).hash().map_err(|e| format!("{e:?}"))
    })
    .await?;

    let hash = result.map_err(|e| anyhow::anyhow!("JARM probe failed: {e}"))?;

    if output::is_json() {
        let data = serde_json::json!({
            "host": args.host,
            "port": args.port,
            "jarm": hash,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        println!("Host: {}:{}", args.host, args.port);
        println!("JARM: {hash}");
    }

    Ok(())
}
