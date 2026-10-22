use anyhow::Result;
use clap::{Args, Subcommand};
use nameserver_common::messages::DetectorScore;

use crate::client::Client;

#[derive(Args)]
pub struct DetectorArgs {
    #[command(subcommand)]
    pub command: DetectorCommand,
}

#[derive(Subcommand)]
pub enum DetectorCommand {
    /// Watch live detector scores in real-time (connects to NATS)
    Watch(DetectorWatchArgs),
    /// Query saved detector scores from ClickHouse
    Scores(DetectorScoresArgs),
}

#[derive(Args)]
pub struct DetectorScoresArgs {
    /// Filter by domain (substring match, use % for wildcard)
    #[arg(long, short)]
    domain: Option<String>,

    /// Minimum ML probability
    #[arg(long)]
    min_prob: Option<f32>,

    /// Filter by ML class
    #[arg(long, short)]
    class: Option<String>,

    /// Time window (e.g., "1h", "24h", "7d")
    #[arg(long, default_value = "1h")]
    since: String,

    /// Maximum results
    #[arg(long, short, default_value = "50")]
    recent: u32,
}

#[derive(Args)]
pub struct DetectorWatchArgs {
    /// Filter by domain (substring match)
    #[arg(long, short)]
    domain: Option<String>,

    /// Minimum ML probability to show (0.0-1.0). Default 0.0 = show all.
    #[arg(long, default_value = "0.0")]
    min_prob: f32,

    /// Show only specific ML class (malicious, suspicious, safe, unknown)
    #[arg(long, short)]
    class: Option<String>,
}

pub async fn run(control_url: &str, api: &Client, args: DetectorArgs) -> Result<()> {
    match args.command {
        DetectorCommand::Watch(watch_args) => run_watch(control_url, watch_args).await,
        DetectorCommand::Scores(scores_args) => run_scores(api, scores_args).await,
    }
}

/// Render a probability so very small but nonzero values are visibly
/// different from a true zero. `{:.4}` rounds anything below 5e-5 to
/// "0.0000", which makes 99% of safe scores indistinguishable from
/// errors. Use scientific notation under 0.001 to keep precision and
/// width predictable; decimal above that for readability.
fn fmt_prob(p: f64) -> String {
    if p == 0.0 {
        "  0.0000".to_string()
    } else if p < 0.001 {
        format!("{p:>8.2e}")
    } else {
        format!("{p:>8.4}")
    }
}

fn parse_duration_secs(s: &str) -> u64 {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h') {
        h.parse::<u64>().unwrap_or(1) * 3600
    } else if let Some(d) = s.strip_suffix('d') {
        d.parse::<u64>().unwrap_or(1) * 86400
    } else if let Some(m) = s.strip_suffix('m') {
        m.parse::<u64>().unwrap_or(10) * 60
    } else {
        s.parse::<u64>().unwrap_or(3600)
    }
}

async fn run_scores(api: &Client, args: DetectorScoresArgs) -> Result<()> {
    let since_secs = parse_duration_secs(&args.since);

    let mut params = vec![
        ("recent".to_string(), args.recent.to_string()),
        ("since".to_string(), since_secs.to_string()),
    ];
    if let Some(ref domain) = args.domain {
        params.push(("domain".to_string(), domain.clone()));
    }
    if let Some(ref class) = args.class {
        params.push(("class".to_string(), class.clone()));
    }
    if let Some(min_prob) = args.min_prob {
        params.push(("min_prob".to_string(), min_prob.to_string()));
    }

    let query_string = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let resp: serde_json::Value = api
        .get_json(&format!("/api/detector/scores?{query_string}"))
        .await?;

    let scores = resp["scores"].as_array();
    let count = resp["count"].as_u64().unwrap_or(0);

    if count == 0 {
        eprintln!("No detector scores found for the given filters.");
        return Ok(());
    }

    eprintln!("{count} scores (last {}):", args.since);
    println!(
        "{:>19}  {:>8}  {:>8}  {:5}  {:40}  Override",
        "Time", "ML", "Final", "Cls", "Domain"
    );

    if let Some(rows) = scores {
        for p in rows {
            let ts = p["predicted_at"].as_i64().unwrap_or(0);
            let dt = time::OffsetDateTime::from_unix_timestamp(ts)
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
            let time_str = dt
                .format(
                    &time::format_description::parse_borrowed::<2>(
                        "[year]-[month]-[day] [hour]:[minute]:[second]",
                    )
                    .unwrap(),
                )
                .unwrap_or_default();

            let ml_prob = p["ml_probability"].as_f64().unwrap_or(0.0);
            let final_prob = p["final_probability"].as_f64().unwrap_or(0.0);
            let ml_class = p["ml_class"].as_str().unwrap_or("unknown");
            let domain = p["domain"].as_str().unwrap_or("");
            let override_rule = p["override_rule"].as_str().unwrap_or("");

            let class_colored = match ml_class {
                "malicious" => format!("\x1b[31m{:5}\x1b[0m", "MAL"),
                "suspicious" => format!("\x1b[33m{:5}\x1b[0m", "SUS"),
                "safe" => format!("\x1b[32m{:5}\x1b[0m", "SAFE"),
                _ => format!("{:5}", "UNK"),
            };

            println!(
                "{time_str:>19}  {}  {}  {class_colored}  {domain:40}  {override_rule}",
                fmt_prob(ml_prob),
                fmt_prob(final_prob),
            );
        }
    }

    Ok(())
}

async fn run_watch(control_url: &str, args: DetectorWatchArgs) -> Result<()> {
    let url = format!(
        "{}/api/detector/scores/live",
        control_url.trim_end_matches('/')
    );

    eprintln!(
        "\x1b[2m-- watching detector scores via SSE {} (ctrl-c to stop) --\x1b[0m",
        url
    );
    eprintln!(
        "\x1b[2m{:>8}  {:>8}  {:5}  {:40}  Override\x1b[0m",
        "ML", "Final", "Cls", "Domain"
    );

    let client = reqwest::Client::new();
    let mut response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("SSE endpoint returned {}", response.status());
    }

    let mut buffer = String::new();

    while let Some(chunk) = response.chunk().await? {
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buffer.find("\n\n") {
            let event = buffer[..pos].to_string();
            buffer = buffer[pos + 2..].to_string();

            for line in event.lines() {
                if let Some(json_str) = line.strip_prefix("data:") {
                    let json_str = json_str.trim();
                    if let Ok(score) = serde_json::from_str::<DetectorScore>(json_str)
                        && filter_score(&score, &args)
                    {
                        print_score(&score);
                    }
                }
            }
        }
    }

    Ok(())
}

fn filter_score(p: &DetectorScore, args: &DetectorWatchArgs) -> bool {
    if p.final_probability < args.min_prob {
        return false;
    }

    if let Some(ref pat) = args.domain
        && !p.domain.contains(pat.as_str())
    {
        return false;
    }

    if let Some(ref class) = args.class
        && p.classification != *class
    {
        return false;
    }

    true
}

fn print_score(p: &DetectorScore) {
    let class_colored = match p.classification.as_str() {
        "malicious" => format!("\x1b[31m{:5}\x1b[0m", "MAL"),
        "suspicious" => format!("\x1b[33m{:5}\x1b[0m", "SUS"),
        "safe" => format!("\x1b[32m{:5}\x1b[0m", "SAFE"),
        _ => format!("{:5}", "UNK"),
    };

    let override_str = p.override_rule.as_deref().unwrap_or("");

    println!(
        "{}  {}  {}  {:40}  {}",
        fmt_prob(p.ml_probability as f64),
        fmt_prob(p.final_probability as f64),
        class_colored,
        p.domain,
        override_str,
    );
}
