//! `minsec-sync`: the multiplayer client. Short-lived, timer-driven; the
//! resident daemon has no network stack. See docs/MULTIPLAYER.md.

mod cli;
mod client;
mod config;
mod events;
mod nft;
mod pull;
mod report;
mod state;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::Parser;
use cli::{Cli, Cmd};
use client::Api;
use config::Config;
use minsec_proto::types::{EnrollRequest, POW_ALGO};
use state::Store;

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("minsec-sync: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let cfg = match Config::load(&cli.config)? {
        Some(cfg) => cfg,
        None => {
            if matches!(cli.cmd, Cmd::Run) {
                // Opt-in switch is the config file; timers on unconfigured
                // systems stay silent.
                return Ok(());
            }
            anyhow::bail!(
                "multiplayer is not configured: create {} (see sync.toml.example)",
                cli.config.display()
            );
        }
    };
    let store = Store::open(&cfg.state_dir)?;
    let mut state = store.load_state()?;
    let api = Api::new(&cfg.server);

    match cli.cmd {
        Cmd::Enroll => {
            enroll(&cfg, &api, &store, &mut state, true)?;
        }
        Cmd::Report => {
            let key = store.load_or_create_key()?;
            let out = report::run(&cfg, &api, &store, &mut state, &key)?;
            println!(
                "reported {} events ({} accepted, {} rejected, {} skipped)",
                out.sent, out.accepted, out.rejected, out.skipped
            );
        }
        Cmd::Pull => {
            let nft = nft::Nft::new(&cfg.nft, cli.dry_run);
            for o in pull::run(&cfg, &api, &store, &mut state, &nft)? {
                print_pull(&o);
            }
        }
        Cmd::Run => {
            enroll(&cfg, &api, &store, &mut state, false)?;
            if cfg.report {
                let key = store.load_or_create_key()?;
                let out = report::run(&cfg, &api, &store, &mut state, &key)?;
                if out.sent > 0 {
                    println!(
                        "reported {} events ({} accepted, {} rejected)",
                        out.sent, out.accepted, out.rejected
                    );
                }
            }
            if cfg.pull {
                let nft = nft::Nft::new(&cfg.nft, cli.dry_run);
                for o in pull::run(&cfg, &api, &store, &mut state, &nft)? {
                    if o.action != "unchanged" {
                        print_pull(&o);
                    }
                }
            }
        }
        Cmd::Status => {
            let key = store.load_or_create_key()?;
            println!("server:  {}", cfg.server);
            println!("pubkey:  {}", B64.encode(key.verifying_key().to_bytes()));
            match &state.host_id {
                Some(id) => println!("host_id: {id}"),
                None => println!("host_id: (not enrolled)"),
            }
            if let Some(org) = &state.org {
                println!("org:     {org}");
            }
            println!("seq:     {}", state.next_seq);
            match state.cursor {
                Some(c) => println!("cursor:  inode {} offset {}", c.ino, c.offset),
                None => println!("cursor:  (events log not read yet)"),
            }
            match state.last_pull_ok {
                0 => println!("pulled:  (never)"),
                t => println!("pulled:  {} ago", fmt_age(client::now_unix().saturating_sub(t))),
            }
            for (name, f) in &state.feeds {
                let age = client::now_unix().saturating_sub(f.last_full);
                println!(
                    "feed {name}: snapshot {} etag {} (full replace {} ago; entries expire {} after one)",
                    f.snapshot,
                    f.etag,
                    fmt_age(age),
                    nft::CROWD_TIMEOUT
                );
            }
        }
    }
    Ok(())
}

/// Coarse "3h" / "2d" for status output; exactness is not the point.
fn fmt_age(secs: u64) -> String {
    match secs {
        s if s < 90 => format!("{s}s"),
        s if s < 90 * 60 => format!("{}m", s / 60),
        s if s < 48 * 3600 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

fn print_pull(o: &pull::Outcome) {
    match o.action {
        "unchanged" => println!("feed v{}: unchanged", o.family),
        _ => {
            let invalid = if o.invalid > 0 {
                format!(", {} invalid entries skipped", o.invalid)
            } else {
                String::new()
            };
            let why = if o.refresh { " (timeout refresh)" } else { "" };
            println!(
                "feed v{}: {} update{why}, {} entries{invalid}",
                o.family, o.action, o.entries
            );
        }
    }
}

/// Enroll, solving the proof-of-work challenge, unless already enrolled.
/// With `verbose` (interactive use) progress goes to stdout. Handles the
/// lost-state case: if the server says our key is already enrolled but we
/// have no host_id, the key is rotated and enrollment retried once (per
/// docs/API.md).
///
/// An install token added to a host enrolled anonymously joins it to the
/// organization: the host enrolls again with a new key, and the anonymous
/// enrollment is left to go quiet.
fn enroll(cfg: &Config, api: &Api, store: &Store, state: &mut state::State, verbose: bool) -> anyhow::Result<()> {
    let token = cfg.install_token.as_deref().map(str::trim);
    let joining = match (&state.host_id, &state.org, token) {
        (Some(id), None, Some(_)) if !state.token_enrolled => Some(id.clone()),
        (Some(id), _, _) => {
            if verbose {
                println!("already enrolled as {id}");
            }
            return Ok(());
        }
        _ => None,
    };
    let mut key = store.load_or_create_key()?;
    for attempt in 0..2 {
        // A bad token is refused here, before the anonymous identity is
        // given up.
        let ch = api.challenge(token)?;
        if let (Some(id), 0) = (&joining, attempt) {
            eprintln!("minsec-sync: install_token set; re-enrolling {id} into the organization with a new key");
            state.host_id = None;
            key = store.rotate_key()?;
        }
        if verbose {
            println!("solving {POW_ALGO} challenge (difficulty {})...", ch.difficulty);
        }
        let nonce = minsec_proto::pow::solve(&ch.challenge, ch.difficulty);
        let req = EnrollRequest {
            challenge: ch.challenge,
            pow_nonce: nonce,
            pubkey: B64.encode(key.verifying_key().to_bytes()),
            agent_version: concat!("minsec-sync/", env!("CARGO_PKG_VERSION")).to_string(),
            install_token: token.map(str::to_string),
            label: token.and_then(|_| cfg.label()),
            product: None,
        };
        match api.enroll(&req) {
            Ok(resp) => {
                state.host_id = Some(resp.host_id.clone());
                state.org = resp.org.clone();
                state.token_enrolled = token.is_some();
                state.min_report_interval = resp.min_report_interval;
                store.save_state(state)?;
                if token.is_some() && resp.org.is_none() {
                    eprintln!("minsec-sync: the server did not bind this host to an organization");
                }
                if verbose {
                    match &resp.org {
                        Some(org) => println!("enrolled as {} in {org}", resp.host_id),
                        None => println!("enrolled as {}", resp.host_id),
                    }
                }
                return Ok(());
            }
            Err(e) if e.code == "already_enrolled" && attempt == 0 => {
                // The key is known but our host_id is gone (lost state
                // file). Start over with a fresh key.
                eprintln!("minsec-sync: key already enrolled but host_id lost; generating a new key");
                key = store.rotate_key()?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("enrollment failed after key rotation")
}
