//! Command definitions shared by the binary and its completion generator.

use clap::{Parser, Subcommand};
use minsec_core::config::DEFAULT_CONFIG_DIR;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "minsec",
    version,
    about = "Minimalist security daemon: a tiny, fast, intrusion prevention system"
)]
pub(crate) struct Cli {
    /// Configuration directory.
    #[arg(short = 'c', long, default_value = DEFAULT_CONFIG_DIR, global = true)]
    pub(crate) config_dir: PathBuf,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Run the daemon in the foreground.
    Daemon {
        /// Override the backend (e.g. `null` to observe without banning).
        #[arg(long)]
        backend: Option<String>,
        /// Read existing log files from the beginning instead of the end.
        #[arg(long)]
        replay: bool,
    },
    /// Validate configuration and compile filters.
    Check {
        /// Compile every discovered filter, including disabled custom filters.
        #[arg(long)]
        all: bool,
    },
    /// Inspect merged configuration, files, filters, and effective policy.
    Inspect,
    /// Run a filter over a log file (or stdin) and show what would match.
    Test {
        filter: String,
        /// Log file; `-` or omitted reads stdin.
        file: Option<PathBuf>,
        /// Only print a summary.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Daemon status.
    Status,
    /// List active bans.
    List,
    /// Ban an address or network.
    Ban {
        net: String,
        /// Ban duration (e.g. 1h, 2d); default is the configured bantime.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Remove a ban.
    Unban { net: String },
    /// List built-in and custom filters.
    Filters,
    /// Enable a filter (writes conf.d/<name>.toml).
    Enable { name: String },
    /// Disable a filter.
    Disable { name: String },
    /// Print the event log.
    Events {
        #[arg(short = 'n', long, default_value_t = 50)]
        last: usize,
    },
}
