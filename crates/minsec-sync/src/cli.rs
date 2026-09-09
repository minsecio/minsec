//! Command definitions shared by the binary and its completion generator.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "minsec-sync",
    version,
    about = "minsec multiplayer client: report automatic bans, pull the crowd blocklist"
)]
pub(crate) struct Cli {
    /// Configuration file.
    #[arg(short = 'c', long, default_value = "/etc/minsec/sync.toml", global = true)]
    pub(crate) config: PathBuf,
    /// Print nft scripts instead of applying them.
    #[arg(long, global = true)]
    pub(crate) dry_run: bool,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Generate a key (first run) and enroll with the server.
    Enroll,
    /// Submit new automatic bans from the events log.
    Report,
    /// Fetch the crowd blocklist into the crowd4/crowd6 nftables sets.
    Pull,
    /// Report then pull; enrolls first if needed. Intended for the systemd
    /// timer — exits 0 quietly when multiplayer is not configured.
    Run,
    /// Show enrollment, cursor, and feed state.
    Status,
}
