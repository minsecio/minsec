//! `minsec`: daemon and CLI in one binary.

mod cli;
mod daemon;

use clap::Parser;
use cli::{Cli, Cmd};
use minsec_core::config::{BackendKind, Config};
use minsec_core::control::{self, Request};
use minsec_core::{builtin, CompiledFilter};

fn main() {
    if let Err(e) = run() {
        eprintln!("minsec: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon { backend, replay } => {
            init_logging();
            let mut cfg = Config::load_dir(&cli.config_dir)?;
            if let Some(b) = backend {
                cfg.defaults.backend = match b.as_str() {
                    "nft" => BackendKind::Nft,
                    "null" => BackendKind::Null,
                    "exec" => BackendKind::Exec,
                    other => unreachable!("clap validates --backend, got `{other}`"),
                };
            }
            daemon::run(cfg, replay)
        }
        Cmd::Check { all } => {
            let result = minsec_core::inspection::check(&cli.config_dir, all);
            if cli.json {
                println!("{}", serde_json::to_string(&result)?);
            } else if result.ok {
                println!("ok: {} filter(s) checked", result.checked_filters.len());
            } else {
                for error in &result.errors {
                    if let Some(filter) = &error.filter {
                        eprintln!("filter `{filter}`: {}", error.error);
                    } else {
                        eprintln!("{}", error.error);
                    }
                }
            }
            if result.ok {
                Ok(())
            } else {
                anyhow::bail!("configuration check failed")
            }
        }
        Cmd::Inspect => match minsec_core::inspection::inspect(&cli.config_dir, env!("CARGO_PKG_VERSION")) {
            Ok(inspection) => {
                if cli.json {
                    println!("{}", serde_json::to_string(&inspection)?);
                } else {
                    print_inspection(&inspection);
                }
                Ok(())
            }
            Err(error) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": minsec_core::inspection::SCHEMA_VERSION,
                            "ok": false,
                            "error": format!("{error:#}"),
                        })
                    );
                }
                Err(error)
            }
        },
        Cmd::Test { filter, file, quiet } => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let def = cfg.filter_def(&filter)?;
            let flt = CompiledFilter::compile(def)?;
            let mut reader: Box<dyn std::io::BufRead> = match file {
                Some(p) if p.as_os_str() != "-" => Box::new(std::io::BufReader::new(std::fs::File::open(&p)?)),
                _ => Box::new(std::io::stdin().lock()),
            };
            let (mut lines, mut hits) = (0u64, 0u64);
            let mut per_ip: std::collections::BTreeMap<std::net::IpAddr, u64> = Default::default();
            let mut line = String::new();
            while {
                line.clear();
                std::io::BufRead::read_line(&mut *reader, &mut line).unwrap_or(0) > 0
            } {
                let line = line.trim_end_matches(['\n', '\r']);
                lines += 1;
                if let Some(m) = flt.match_line(line) {
                    hits += 1;
                    *per_ip.entry(m.ip).or_default() += 1;
                    if !quiet {
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::json!({"ip": m.ip, "user": m.user, "pattern": m.pattern, "line": line})
                            );
                        } else {
                            println!("{:<40} #{:<2} {}", m.ip, m.pattern, line);
                        }
                    }
                }
            }
            if cli.json && quiet {
                println!(
                    "{}",
                    serde_json::json!({"lines": lines, "matched": hits, "addresses": per_ip})
                );
            } else {
                eprintln!("{lines} lines, {hits} matched, {} distinct addresses", per_ip.len());
                if quiet {
                    for (ip, n) in &per_ip {
                        println!("{ip:<40} {n}");
                    }
                }
            }
            Ok(())
        }
        Cmd::Status => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let r = control::call(&cfg.paths.socket, &Request::Status)?;
            if cli.json {
                println!("{}", serde_json::to_string(&r)?);
                return Ok(());
            }
            let s = r.status.ok_or_else(|| anyhow::anyhow!(r.error.unwrap_or_default()))?;
            println!(
                "minsec {} · backend {} · up {} · {} lines · {} tracked · {} active bans ({} total)",
                s.version,
                s.backend,
                minsec_core::duration::format(std::time::Duration::from_secs(s.uptime)),
                s.lines,
                s.tracked,
                s.active_bans,
                s.bans_total
            );
            for f in s.filters {
                println!(
                    "  {:<16} retry {}/{} ban {}  matched {}  banned {}  {}",
                    f.name,
                    f.maxretry,
                    minsec_core::duration::format(std::time::Duration::from_secs(f.findtime)),
                    minsec_core::duration::format(std::time::Duration::from_secs(f.bantime)),
                    f.matched,
                    f.banned,
                    if f.journal {
                        "journal".to_string()
                    } else {
                        f.files.join(",")
                    }
                );
            }
            Ok(())
        }
        Cmd::List => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let r = control::call(&cfg.paths.socket, &Request::List)?;
            if cli.json {
                println!("{}", serde_json::to_string(&r)?);
                return Ok(());
            }
            let bans = r.bans.ok_or_else(|| anyhow::anyhow!(r.error.unwrap_or_default()))?;
            for b in bans {
                println!(
                    "{:<44} {:<12} {}",
                    minsec_core::ip::key_to_nft(&b.net),
                    b.expires_in
                        .map(|s| minsec_core::duration::format(std::time::Duration::from_secs(s)))
                        .unwrap_or_else(|| "-".into()),
                    b.filter.unwrap_or_default()
                );
            }
            Ok(())
        }
        Cmd::Ban { net, ttl } => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let net = parse_net(&net)?;
            let ttl = ttl
                .map(|t| minsec_core::duration::parse(&t).map_err(anyhow::Error::msg))
                .transpose()?;
            let r = control::call(
                &cfg.paths.socket,
                &Request::Ban {
                    net,
                    ttl: ttl.map(|d| d.as_secs()),
                    reason: None,
                },
            )?;
            finish(&r, cli.json)
        }
        Cmd::Unban { net } => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let net = parse_net(&net)?;
            let r = control::call(&cfg.paths.socket, &Request::Unban { net })?;
            finish(&r, cli.json)
        }
        Cmd::Filters => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let mut names: Vec<String> = builtin::names().map(String::from).collect();
            if let Ok(rd) = std::fs::read_dir(cli.config_dir.join("filters")) {
                for e in rd.flatten() {
                    if let Some(n) = e.path().file_stem().and_then(|s| s.to_str()) {
                        if e.path().extension().is_some_and(|x| x == "toml") {
                            names.push(n.to_string());
                        }
                    }
                }
            }
            names.sort();
            names.dedup();
            if cli.json {
                let v: Vec<_> = names
                    .iter()
                    .map(|n| {
                        let d = cfg.filter_def(n).ok();
                        serde_json::json!({
                            "name": n,
                            "enabled": cfg.filters.get(n).is_some_and(|f| f.enabled),
                            "description": d.as_ref().map(|d| d.description.clone()),
                            "files": d.as_ref().map(|d| d.files.clone()),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string(&v)?);
            } else {
                for n in names {
                    let enabled = cfg.filters.get(&n).is_some_and(|f| f.enabled);
                    let desc = cfg.filter_def(&n).map(|d| d.description).unwrap_or_default();
                    println!("{} {:<16} {}", if enabled { "*" } else { " " }, n, desc);
                }
            }
            Ok(())
        }
        Cmd::Enable { name } => set_enabled(&cli.config_dir, &name, true),
        Cmd::Disable { name } => set_enabled(&cli.config_dir, &name, false),
        Cmd::Events { last } => {
            let cfg = Config::load_dir(&cli.config_dir).unwrap_or_default();
            let all = minsec_core::events::EventLog::read_all(&cfg.paths.state_dir.join("events.jsonl"));
            for ev in all.iter().rev().take(last).rev() {
                println!("{}", serde_json::to_string(ev)?);
            }
            Ok(())
        }
    }
}

fn parse_net(s: &str) -> anyhow::Result<ipnet::IpNet> {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(ipnet::IpNet::from(minsec_core::ip::normalize(ip)));
    }
    s.parse::<ipnet::IpNet>()
        .map(|n| n.trunc())
        .map_err(|e| anyhow::anyhow!("invalid address `{s}`: {e}"))
}

fn finish(r: &control::Response, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string(r)?);
        return Ok(());
    }
    if r.ok {
        if let Some(m) = &r.message {
            println!("{m}");
        }
        Ok(())
    } else {
        anyhow::bail!("{}", r.error.clone().unwrap_or_default())
    }
}

fn set_enabled(dir: &std::path::Path, name: &str, enabled: bool) -> anyhow::Result<()> {
    let cfg = Config::load_dir(dir).unwrap_or_default();
    let cfg = Config {
        config_dir: dir.to_path_buf(),
        ..cfg
    };
    cfg.filter_def(name)?; // must exist
    let confd = dir.join("conf.d");
    std::fs::create_dir_all(&confd)?;
    let path = confd.join(format!("{name}.toml"));
    let mut table: toml::Table = match std::fs::read_to_string(&path) {
        Ok(s) => toml::from_str(&s)?,
        Err(_) => toml::Table::new(),
    };
    let filters = table
        .entry("filters")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    let f = filters
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: `filters` is not a table", path.display()))?
        .entry(name)
        .or_insert_with(|| toml::Value::Table(Default::default()));
    f.as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: `filters.{name}` is not a table", path.display()))?
        .insert("enabled".into(), toml::Value::Boolean(enabled));
    std::fs::write(&path, toml::to_string(&table)?)?;
    println!(
        "{} {name} ({}); restart minsec to apply",
        if enabled { "enabled" } else { "disabled" },
        path.display()
    );
    Ok(())
}

/// One-screen human summary of an inspection: where configuration came from,
/// the effective defaults, the full allow list, and what each enabled filter
/// actually reads. `--json` has everything else.
fn print_inspection(inspection: &minsec_core::inspection::Inspection) {
    use minsec_core::duration::format as fmt_duration;
    use std::time::Duration;

    let secs = |s: u64| fmt_duration(Duration::from_secs(s));
    let relative = |path: &std::path::Path| {
        path.strip_prefix(&inspection.paths.config_dir)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let defaults = &inspection.effective.defaults;

    println!(
        "minsec {} · config {} · schema {}",
        inspection.version,
        inspection.paths.config_dir.display(),
        inspection.schema_version
    );
    let mut files: Vec<String> = Vec::new();
    match &inspection.files.main {
        Some(main) => files.push(relative(main)),
        None => files.push(format!("{} (missing)", relative(&inspection.paths.main_config))),
    }
    files.extend(inspection.files.dropins.iter().map(|p| relative(p)));
    files.extend(inspection.files.custom_filters.iter().map(|p| relative(p)));
    println!("files: {}", files.join(", "));
    println!(
        "paths: socket {} · state {}",
        inspection.paths.control_socket.display(),
        inspection.paths.state_dir.display()
    );
    let escalate = if defaults.escalate_enabled {
        format!(
            "escalate x{} up to {} (remembered {})",
            defaults.escalate.factor,
            secs(defaults.escalate.max_seconds),
            secs(defaults.escalate.memory_seconds)
        )
    } else {
        "escalate off".to_string()
    };
    println!(
        "defaults: retry {} in {} · ban {} · {} · ipv6 /{} · max tracked {}",
        defaults.maxretry,
        secs(defaults.findtime_seconds),
        secs(defaults.bantime_seconds),
        escalate,
        defaults.ipv6_prefix,
        defaults.max_tracked
    );
    let journal = match (defaults.journal, inspection.journal_available) {
        (false, _) => "off (files only)",
        (true, true) => "on",
        (true, false) => "on but not available (files only)",
    };
    let backend = match (defaults.backend, &defaults.exec_command) {
        (BackendKind::Nft, _) => "nft".to_string(),
        (BackendKind::Null, _) => "null (deciding, not enforcing)".to_string(),
        (BackendKind::Exec, Some(command)) => format!("exec `{command}`"),
        (BackendKind::Exec, None) => "exec (no exec_command set)".to_string(),
    };
    println!("backend: {backend} · journald: {journal}");

    let configured: Vec<String> = defaults.allow.iter().map(|n| n.to_string()).collect();
    println!(
        "allow: {}",
        if configured.is_empty() {
            "(none configured)".to_string()
        } else {
            configured.join(", ")
        }
    );
    let mut host: Vec<String> = minsec_core::ip::local_addresses()
        .into_iter()
        .filter(|ip| !minsec_core::ip::is_loopback_or_unspecified(*ip))
        .map(|ip| ip.to_string())
        .collect();
    host.sort();
    host.dedup();
    println!(
        "  always: loopback, {}",
        if host.is_empty() {
            "this host's addresses".to_string()
        } else {
            host.join(", ")
        }
    );

    let (enabled, disabled): (Vec<_>, Vec<_>) = inspection.filters.iter().partition(|f| f.enabled);
    println!("enabled filters ({} of {}):", enabled.len(), inspection.filters.len());
    for f in &enabled {
        let p = &f.effective_policy;
        let ports = if p.ports.is_empty() {
            String::new()
        } else {
            format!(
                " · ports {}",
                p.ports.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
            )
        };
        let origin = if f.builtin {
            String::new()
        } else {
            format!("  ({})", relative(std::path::Path::new(&f.source)))
        };
        println!(
            "  {:<14} retry {} in {} · ban {}{}{}",
            f.name,
            p.maxretry,
            secs(p.findtime_seconds),
            secs(p.bantime_seconds),
            ports,
            origin
        );
        if p.via_journal {
            println!("{:<17}journal: {}", "", p.journal.matches().join(", "));
        } else if p.files.is_empty() {
            println!(
                "{:<17}source: none (no files and journald not in use) — filter is inert",
                ""
            );
        } else {
            let files: Vec<String> = p
                .files
                .iter()
                .map(|file| {
                    if p.absent_files.contains(file) {
                        format!("{file} (absent)")
                    } else {
                        file.clone()
                    }
                })
                .collect();
            println!("{:<17}files: {}", "", files.join(", "));
        }
    }
    if !disabled.is_empty() {
        let names: Vec<String> = disabled
            .iter()
            .map(|f| {
                if f.builtin {
                    f.name.clone()
                } else {
                    format!("{} (custom)", f.name)
                }
            })
            .collect();
        println!("disabled: {}", names.join(", "));
    }
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("MINSEC_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time() // journald stamps for us
        .with_ansi(false)
        .init();
}
