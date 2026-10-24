//! Writing the crowd blocklist into nftables. The daemon owns the
//! `inet minsec` table, its chains, and the rules referencing the crowd sets
//! (see minsec-core's setup script); minsec-sync only manages their
//! contents. `ensure_sets` makes the sets themselves idempotently so pulls
//! work even before the daemon has restarted onto a crowd-aware version —
//! the sets are simply unreferenced until then.
//!
//! Each family has two sets. Single keys (an IPv4 host, an IPv6 /64) go in
//! the hash sets `crowd4`/`crowd6`; `crowd6` holds the /64's network address
//! and the daemon's rule masks the source before the lookup. Wider prefixes
//! go in the interval sets `crowdnet4`/`crowdnet6`. Interval sets with
//! timeouts have corrupted on EL8 kernels (an element lost its end marker
//! and grew into a range over a fifth of IPv4), so the bulk of the feed
//! stays out of them, and `check_nets` looks for that damage after each
//! delta so a pull can repair it with a full replace.
//!
//! Every entry is parsed as an address/prefix of the right family before it
//! goes anywhere near a script: feed bytes are never interpolated raw.

use ipnet::IpNet;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

pub const TABLE: &str = "inet minsec";

/// How long a crowd element survives in the kernel without a refresh. Crowd
/// entries have no TTL of their own — expiry arrives as removals in a later
/// delta — so without this a sync that stops running (network, backend
/// outage, a disabled timer) would leave its last snapshot enforced until
/// the machine reboots. The kernel ages the list out instead.
///
/// Must match minsec-core's crowd set definitions exactly: whichever process
/// creates the sets first wins, and `add set` on an existing set with a
/// different definition fails. The daemon rebuilds a mismatched set at
/// start (keeping its elements), so a disagreement here means the crowd
/// sets churn on every daemon restart, and pulls fail until the daemon
/// has run once on the version that defines them the same way.
pub const CROWD_TIMEOUT: &str = "24h";

/// IPv6 prefix of a `crowd6` key: the server aggregates reports to /64.
/// Must match minsec-core's `CROWD_V6_PREFIX`.
pub const CROWD_V6_PREFIX: u8 = 64;

/// Refresh deadline: a full replace re-adds every live element with a fresh
/// timeout, so one is forced whenever the last is this old. Comfortably
/// inside `CROWD_TIMEOUT` so a couple of missed runs cannot expire a list
/// that is still being synced.
pub const FULL_REFRESH_SECS: u64 = 12 * 60 * 60;

pub struct Nft {
    bin: String,
    dry_run: bool,
}

/// The hash set and the interval set holding a family's entries.
pub fn set_names(family: u8) -> [&'static str; 2] {
    if family == 4 {
        ["crowd4", "crowdnet4"]
    } else {
        ["crowd6", "crowdnet6"]
    }
}

/// The set an entry belongs in, and its element key there.
fn place(net: &IpNet) -> (&'static str, String) {
    match net {
        IpNet::V4(n) if n.prefix_len() == 32 => ("crowd4", n.addr().to_string()),
        IpNet::V6(n) if n.prefix_len() == CROWD_V6_PREFIX => ("crowd6", n.trunc().addr().to_string()),
        IpNet::V4(_) => ("crowdnet4", fmt_net(net)),
        IpNet::V6(_) => ("crowdnet6", fmt_net(net)),
    }
}

/// Parse and validate one feed entry (bare address or CIDR) for a family.
pub fn parse_entry(entry: &str, family: u8) -> Option<IpNet> {
    let net = if let Ok(addr) = entry.parse::<IpAddr>() {
        IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok()?
    } else {
        entry.parse::<IpNet>().ok()?
    };
    let ok = match net {
        IpNet::V4(_) => family == 4,
        IpNet::V6(_) => family == 6,
    };
    ok.then_some(net)
}

impl Nft {
    pub fn new(bin: &str, dry_run: bool) -> Self {
        Self {
            bin: bin.to_string(),
            dry_run,
        }
    }

    fn run(&self, script: &str) -> anyhow::Result<()> {
        if self.dry_run {
            print!("{script}");
            return Ok(());
        }
        let mut child = Command::new(&self.bin)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("cannot run `{}`: {e}", self.bin))?;
        child.stdin.take().expect("piped").write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "nft failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    pub fn ensure_sets(&self) -> anyhow::Result<()> {
        let mut s = format!("add table {TABLE}\n");
        for (set, ty, flags) in [
            ("crowd4", "ipv4_addr", "timeout"),
            ("crowd6", "ipv6_addr", "timeout"),
            ("crowdnet4", "ipv4_addr", "interval, timeout"),
            ("crowdnet6", "ipv6_addr", "interval, timeout"),
        ] {
            s.push_str(&format!(
                "add set {TABLE} {set} {{ type {ty}; flags {flags}; timeout {CROWD_TIMEOUT}; }}\n"
            ));
        }
        self.run(&s)
    }

    /// Atomically replace a family's sets (flush + add in one transaction).
    pub fn replace(&self, family: u8, nets: &[IpNet]) -> anyhow::Result<()> {
        let mut s = String::new();
        for set in set_names(family) {
            s.push_str(&format!("flush set {TABLE} {set}\n"));
        }
        push_elements(&mut s, "add", nets);
        self.run(&s)
    }

    /// Apply a delta. Removals of entries nft no longer has must not fail
    /// the batch, so removals go one at a time with errors ignored;
    /// additions are transactional. On error the caller falls back to a
    /// full replace.
    pub fn apply_delta(&self, added: &[IpNet], removed: &[IpNet]) -> anyhow::Result<()> {
        for net in removed {
            let (set, key) = place(net);
            let _ = self.run(&format!("delete element {TABLE} {set} {{ {key} }}\n"));
        }
        if !added.is_empty() {
            let mut s = String::new();
            push_elements(&mut s, "add", added);
            self.run(&s)?;
        }
        Ok(())
    }

    /// Fail if a family's interval set holds a range that is not a CIDR.
    /// Nothing in the feed can produce one, so it is kernel set corruption,
    /// and only a full replace (which flushes the set) clears it.
    pub fn check_nets(&self, family: u8) -> anyhow::Result<()> {
        if self.dry_run {
            return Ok(());
        }
        let set = set_names(family)[1];
        let out = Command::new(&self.bin)
            .args(["-j", "list", "set", "inet", "minsec", set])
            .output()
            .map_err(|e| anyhow::anyhow!("cannot run `{}`: {e}", self.bin))?;
        if !out.status.success() {
            anyhow::bail!(
                "nft list set {set} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let bad = corrupt_ranges(&v);
        if !bad.is_empty() {
            anyhow::bail!(
                "{set} holds ranges the feed never sent (kernel set corruption): {}",
                bad.join(", ")
            );
        }
        Ok(())
    }
}

fn fmt_net(net: &IpNet) -> String {
    // Single hosts as bare addresses: nft normalizes /32 and /128 away, so
    // feeding them bare keeps our elements comparable with nft's output.
    if net.prefix_len() == net.max_prefix_len() {
        net.addr().to_string()
    } else {
        net.to_string()
    }
}

fn push_elements(s: &mut String, verb: &str, nets: &[IpNet]) {
    let mut by_set: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for net in nets {
        let (set, key) = place(net);
        by_set.entry(set).or_default().push(key);
    }
    for (set, keys) in by_set {
        for chunk in keys.chunks(500) {
            s.push_str(&format!("{verb} element {TABLE} {set} {{ {} }}\n", chunk.join(", ")));
        }
    }
}

/// `lo-hi` for every `{"range": [lo, hi]}` element in an `nft -j` set
/// listing that does not span exactly one CIDR.
fn corrupt_ranges(v: &serde_json::Value) -> Vec<String> {
    let mut bad = Vec::new();
    let sets = v.get("nftables").and_then(|n| n.as_array()).into_iter().flatten();
    for o in sets {
        let elems = o.pointer("/set/elem").and_then(|e| e.as_array()).into_iter().flatten();
        for e in elems {
            let val = e.pointer("/elem/val").unwrap_or(e);
            let Some(r) = val.get("range") else {
                continue;
            };
            let lo = r.get(0).and_then(|x| x.as_str()).unwrap_or("?");
            let hi = r.get(1).and_then(|x| x.as_str()).unwrap_or("?");
            if !is_cidr(lo, hi) {
                bad.push(format!("{lo}-{hi}"));
            }
        }
    }
    bad
}

/// Whether `lo..=hi` is exactly one CIDR: 2^k addresses on a 2^k boundary.
fn is_cidr(lo: &str, hi: &str) -> bool {
    let (Ok(lo), Ok(hi)) = (lo.parse::<IpAddr>(), hi.parse::<IpAddr>()) else {
        return false;
    };
    let (a, b) = match (lo, hi) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b)),
        _ => return false,
    };
    let Some(span) = b.checked_sub(a) else {
        return false;
    };
    span & span.wrapping_add(1) == 0 && a & span == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_validation() {
        assert_eq!(parse_entry("203.0.113.7", 4).unwrap().to_string(), "203.0.113.7/32");
        assert_eq!(
            parse_entry("198.51.100.0/24", 4).unwrap().to_string(),
            "198.51.100.0/24"
        );
        assert_eq!(parse_entry("2001:db8::/64", 6).unwrap().to_string(), "2001:db8::/64");
        assert!(parse_entry("203.0.113.7", 6).is_none(), "family mismatch");
        assert!(parse_entry("2001:db8::1", 4).is_none(), "family mismatch");
        assert!(parse_entry("not-an-ip", 4).is_none());
        assert!(parse_entry("203.0.113.7; drop table", 4).is_none());
    }

    #[test]
    fn scripts() {
        let nets: Vec<IpNet> = ["203.0.113.7", "198.51.100.0/24", "203.0.113.8"]
            .iter()
            .map(|e| parse_entry(e, 4).unwrap())
            .collect();
        let mut s = String::new();
        push_elements(&mut s, "add", &nets);
        assert_eq!(
            s,
            "add element inet minsec crowd4 { 203.0.113.7, 203.0.113.8 }\n\
             add element inet minsec crowdnet4 { 198.51.100.0/24 }\n"
        );
    }

    #[test]
    fn places_single_keys_in_hash_sets() {
        let p = |e: &str, f: u8| place(&parse_entry(e, f).unwrap());
        assert_eq!(p("203.0.113.7", 4), ("crowd4", "203.0.113.7".into()));
        assert_eq!(p("198.51.100.0/24", 4), ("crowdnet4", "198.51.100.0/24".into()));
        assert_eq!(p("2001:db8:1:2::/64", 6), ("crowd6", "2001:db8:1:2::".into()));
        assert_eq!(p("2001:db8::/48", 6), ("crowdnet6", "2001:db8::/48".into()));
        assert_eq!(p("2001:db8::1", 6), ("crowdnet6", "2001:db8::1".into()));
    }

    #[test]
    fn finds_corrupt_ranges() {
        let v = serde_json::json!({"nftables": [{"set": {"name": "crowdnet4", "elem": [
            {"elem": {"val": {"prefix": {"addr": "192.0.2.0", "len": 24}}, "expires": 60}},
            {"elem": {"val": {"range": ["198.51.100.0", "198.51.100.127"]}, "expires": 60}},
            {"elem": {"val": {"range": ["52.128.227.50", "103.187.165.25"]}, "expires": 60}}
        ]}}]});
        assert_eq!(corrupt_ranges(&v), ["52.128.227.50-103.187.165.25"]);
        assert!(is_cidr("2001:db8::", "2001:db8::ffff:ffff:ffff:ffff"));
        assert!(!is_cidr("192.0.2.1", "192.0.2.2"));
        assert!(!is_cidr("192.0.2.9", "192.0.2.1"));
    }
}
