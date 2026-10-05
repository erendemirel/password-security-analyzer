//! `psa` — advisory password analysis CLI (not an authorization gate).

use std::io::{self, BufRead, Write};

use clap::{Parser, Subcommand};
use psa_core::{
    analyze, analyze_offline_with, has_embedded_model, AnalyzeOptions, BreachPolicy,
};

#[derive(Parser, Debug)]
#[command(
    name = "psa",
    about = "Advisory password strength analyzer (HIBP + optional Markov/Monte Carlo). Does not authorize accounts."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze a password (JSON on stdout).
    Analyze {
        /// Password to analyze (prefer env/pipe in real use).
        password: String,
        /// Skip Have I Been Pwned check.
        #[arg(long)]
        skip_breach: bool,
        /// Skip training-dependent Markov/Monte Carlo scoring (HIBP + keyspace bits only).
        #[arg(long)]
        no_model: bool,
        /// Local PwnedPasswordsDownloader store (directory of ranges or single dump).
        #[arg(long, value_name = "PATH")]
        hibp_offline: Option<String>,
        /// Custom User-Agent for HIBP.
        #[arg(long, default_value = "password-security-analyzer/0.1.0")]
        user_agent: String,
        /// HTTP timeout milliseconds for HIBP.
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
    },
    /// Check only HIBP pwned status (JSON).
    CheckPwned {
        password: String,
        #[arg(long, value_name = "PATH")]
        hibp_offline: Option<String>,
        #[arg(long, default_value = "password-security-analyzer/0.1.0")]
        user_agent: String,
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
    },
    /// Offline analyze (no network). Pass `--hibp-offline` for local breach checks.
    AnalyzeOffline {
        /// Password to analyze (omit when using `--batch`).
        #[arg(required_unless_present = "batch")]
        password: Option<String>,
        /// Read passwords from stdin (one per line); emit NDJSON (one object per line).
        /// Empty lines are skipped. Every non-empty line is scored as a password
        /// (including lines that start with `#` — those appear in real leaks).
        #[arg(long)]
        batch: bool,
        /// Skip Markov/Monte Carlo (keyspace bits only).
        #[arg(long)]
        no_model: bool,
        /// Local PwnedPasswordsDownloader store (directory of ranges or single dump).
        #[arg(long, value_name = "PATH")]
        hibp_offline: Option<String>,
    },
    /// Print whether this binary embeds the default training model.
    ModelInfo,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze {
            password,
            skip_breach,
            no_model,
            hibp_offline,
            user_agent,
            timeout_ms,
        } => {
            let opts = AnalyzeOptions {
                user_agent,
                breach_policy: if skip_breach {
                    BreachPolicy::Skip
                } else {
                    BreachPolicy::Check
                },
                timeout_ms,
                skip_model: no_model,
                hibp_offline_path: hibp_offline,
            };
            match analyze(&password, &opts, None) {
                Ok(r) => {
                    println!("{}", serde_json::to_string_pretty(&r).expect("serialize"));
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::CheckPwned {
            password,
            hibp_offline,
            user_agent,
            timeout_ms,
        } => {
            let opts = AnalyzeOptions {
                user_agent,
                breach_policy: BreachPolicy::Check,
                timeout_ms,
                skip_model: true,
                hibp_offline_path: hibp_offline,
            };
            match analyze(&password, &opts, None) {
                Ok(r) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&r.breach).expect("serialize")
                    );
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::AnalyzeOffline {
            password,
            batch,
            no_model,
            hibp_offline,
        } => {
            let opts = AnalyzeOptions {
                breach_policy: if hibp_offline.is_some() {
                    BreachPolicy::Check
                } else {
                    BreachPolicy::Skip
                },
                skip_model: no_model,
                hibp_offline_path: hibp_offline,
                ..AnalyzeOptions::default()
            };
            if batch {
                if let Err(e) = run_offline_batch(&opts) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            } else {
                let password = password.expect("password required without --batch");
                match analyze_offline_with(&password, None, opts) {
                    Ok(r) => {
                        println!("{}", serde_json::to_string_pretty(&r).expect("serialize"));
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::ModelInfo => {
            println!(
                "{}",
                serde_json::json!({
                    "embedded_model": has_embedded_model(),
                    "advisory": true,
                })
            );
        }
    }
}

fn run_offline_batch(opts: &AnalyzeOptions) -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let pw = line.trim_end_matches(['\r', '\n']);
        if pw.is_empty() {
            continue;
        }
        let r = analyze_offline_with(pw, None, opts.clone()).map_err(|e| e.to_string())?;
        let json = serde_json::to_string(&r).map_err(|e| e.to_string())?;
        writeln!(stdout, "{json}").map_err(|e| e.to_string())?;
    }
    Ok(())
}
