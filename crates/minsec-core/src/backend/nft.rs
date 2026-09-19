//! nftables backend. Owns `table inet minsec` and nothing else.
//!
//! Bans are set elements with kernel timeouts: the kernel expires them, they
//! survive daemon restarts, and listing them is one netlink dump. Chains hook
//! `input`/`forward` at priority -10 so drops happen before firewalld's or
//! iptables-nft's filter chains (priority 0) without touching either.
//!
//! The table outlives the daemon, so a set created by an earlier version may
//! carry a definition this version no longer uses. `add set` on such a set
//! fails with EEXIST; `setup` then rebuilds just that set, carrying its
//! elements (and their remaining timeouts) across.
//!
//! MVP drives the `nft` binary with a script on stdin; a native netlink
//! implementation can replace `run()` later behind the same trait.

use super::{Ban, Entry, Firewall};
use ipnet::IpNet;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const TABLE: &str = "inet minsec";

/// How long a crowd-blocklist element survives in the kernel without being
/// refreshed by a pull. See the crowd sets in `setup_script`.
pub const CROWD_TIMEOUT: &str = "24h";

const HOOKS: [&str; 2] = ["input", "forward"];

pub struct Nft {
    nft: String,
}

impl Default for Nft {
    fn default() -> Self {
        Self::new()
    }
}

impl Nft {
    pub fn new() -> Self {
        Self { nft: "nft".into() }
    }

    pub fn with_binary(nft: impl Into<String>) -> Self {
        Self { nft: nft.into() }
    }

    fn run(&self, script: &str) -> anyhow::Result<String> {
        tracing::trace!(target: "minsec::nft", %script);
        let mut child = Command::new(&self.nft)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("cannot run `{}`: {e}", self.nft))?;
        child.stdin.take().expect("piped").write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "nft failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Every set the daemon owns, with its definition body.
    fn set_defs() -> [(&'static str, String); 6] {
        // Crowd blocklist sets are populated by minsec-sync (multiplayer
        // mode); empty and free until the user opts in. The daemon owns the
        // sets and rules so that flushing its chains on startup cannot strip
        // crowd filtering.
        //
        // The crowd element timeout is a dead-man's switch. Crowd entries
        // expire server-side and normally leave as removals in the next
        // delta, so nothing in the feed protocol bounds how long an entry
        // lives here. If minsec-sync stops running the kernel must still let
        // the list decay rather than enforce a frozen blocklist forever;
        // minsec-sync refreshes the timeout well inside the window. This
        // definition and minsec-sync's must agree: whichever process runs
        // first creates the sets, and on a mismatch the daemon rebuilds the
        // set at every start.
        [
            ("ban4", "{ type ipv4_addr; flags interval, timeout; }".into()),
            ("ban6", "{ type ipv6_addr; flags interval, timeout; }".into()),
            ("allow4", "{ type ipv4_addr; flags interval; }".into()),
            ("allow6", "{ type ipv6_addr; flags interval; }".into()),
            (
                "crowd4",
                format!("{{ type ipv4_addr; flags interval, timeout; timeout {CROWD_TIMEOUT}; }}"),
            ),
            (
                "crowd6",
                format!("{{ type ipv6_addr; flags interval, timeout; timeout {CROWD_TIMEOUT}; }}"),
            ),
        ]
    }

    /// Create-or-keep both chains and empty them. Rules referencing a set
    /// must be gone before the set can be deleted, and `flush chain` on a
    /// missing chain is an error, hence the `add chain` first.
    fn reset_chains(s: &mut String) {
        for hook in HOOKS {
            s.push_str(&format!(
                "add chain {TABLE} {hook} {{ type filter hook {hook} priority -10; policy accept; }}\n"
            ));
            s.push_str(&format!("flush chain {TABLE} {hook}\n"));
        }
    }

    pub fn setup_script() -> String {
        let mut s = String::new();
        s.push_str(&format!("add table {TABLE}\n"));
        for (name, def) in Self::set_defs() {
            s.push_str(&format!("add set {TABLE} {name} {def}\n"));
        }
        Self::reset_chains(&mut s);
        for hook in HOOKS {
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @allow4 accept\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip6 saddr @allow6 accept\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @ban4 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip6 saddr @ban6 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @crowd4 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip6 saddr @crowd6 counter drop\n"));
        }
        s
    }

    /// One transaction that replaces `name` with definition `def` and puts
    /// `entries` back. Elements with a known remaining lifetime keep it;
    /// the rest take the set's default (or none). The chains are emptied
    /// first because their rules pin the set; `setup_script` refills them.
    fn recreate_script(name: &str, def: &str, entries: &[Entry]) -> String {
        let mut s = String::new();
        Self::reset_chains(&mut s);
        s.push_str(&format!("delete set {TABLE} {name}\n"));
        s.push_str(&format!("add set {TABLE} {name} {def}\n"));
        let elems: Vec<String> = entries
            .iter()
            .map(|e| match e.expires_in {
                Some(d) => format!("{} timeout {}s", crate::ip::key_to_nft(&e.net), d.as_secs().max(1)),
                None => crate::ip::key_to_nft(&e.net),
            })
            .collect();
        if !elems.is_empty() {
            s.push_str(&format!("add element {TABLE} {name} {{ {} }}\n", elems.join(", ")));
        }
        s
    }

    /// Find sets that exist with a definition other than ours and rebuild
    /// each one with its contents preserved. Returns the names rebuilt.
    fn recreate_stale_sets(&self) -> anyhow::Result<Vec<&'static str>> {
        let mut rebuilt = Vec::new();
        for (name, def) in Self::set_defs() {
            // `add set` succeeds when the set is absent or identical and
            // fails with EEXIST when it exists with another definition.
            if self
                .run(&format!("add table {TABLE}\nadd set {TABLE} {name} {def}\n"))
                .is_ok()
            {
                continue;
            }
            let entries = self.list_set(name)?;
            self.run(&Self::recreate_script(name, &def, &entries))?;
            tracing::warn!(target: "minsec::nft", set = name, elements = entries.len(), "rebuilt set with stale definition");
            rebuilt.push(name);
        }
        Ok(rebuilt)
    }

    fn set_for(net: &IpNet, prefix: &str) -> &'static str {
        match (net, prefix) {
            (IpNet::V4(_), "ban") => "ban4",
            (IpNet::V6(_), "ban") => "ban6",
            (IpNet::V4(_), _) => "allow4",
            (IpNet::V6(_), _) => "allow6",
        }
    }

    fn delete_elements(&self, set: &str, nets: &[&IpNet]) -> anyhow::Result<()> {
        // Deleting a missing element is an error for nft, so delete one at a
        // time and ignore failures; bans are rare enough that this is fine.
        for n in nets {
            let _ = self.run(&format!(
                "delete element {TABLE} {set} {{ {} }}\n",
                crate::ip::key_to_nft(n)
            ));
        }
        Ok(())
    }

    fn list_set(&self, set: &str) -> anyhow::Result<Vec<Entry>> {
        let out = Command::new(&self.nft)
            .args(["-j", "list", "set", "inet", "minsec", set])
            .output()
            .map_err(|e| anyhow::anyhow!("cannot run `{}`: {e}", self.nft))?;
        if !out.status.success() {
            anyhow::bail!(
                "nft list set {set} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let mut entries = Vec::new();
        let Some(objs) = v.get("nftables").and_then(|n| n.as_array()) else {
            return Ok(entries);
        };
        for o in objs {
            let Some(elems) = o.get("set").and_then(|s| s.get("elem")).and_then(|e| e.as_array()) else {
                continue;
            };
            for e in elems {
                let (val, expires) = match e {
                    serde_json::Value::Object(m) if m.contains_key("elem") => {
                        let inner = &m["elem"];
                        (
                            inner.get("val").cloned().unwrap_or_default(),
                            inner.get("expires").and_then(|x| x.as_u64()),
                        )
                    }
                    other => (other.clone(), None),
                };
                if let Some(net) = json_to_net(&val) {
                    entries.push(Entry {
                        net,
                        expires_in: expires.map(Duration::from_secs),
                    });
                }
            }
        }
        Ok(entries)
    }
}

fn json_to_net(v: &serde_json::Value) -> Option<IpNet> {
    if let Some(s) = v.as_str() {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return Some(IpNet::from(ip));
        }
        return s.parse().ok();
    }
    let p = v.get("prefix")?;
    let addr = p.get("addr")?.as_str()?;
    let len = p.get("len")?.as_u64()? as u8;
    format!("{addr}/{len}").parse().ok()
}

impl Firewall for Nft {
    fn name(&self) -> &'static str {
        "nft"
    }

    fn setup(&mut self) -> anyhow::Result<()> {
        let Err(first) = self.run(&Self::setup_script()) else {
            return Ok(());
        };
        if self.recreate_stale_sets()?.is_empty() {
            return Err(first);
        }
        self.run(&Self::setup_script())?;
        Ok(())
    }

    fn ban(&mut self, bans: &[Ban]) -> anyhow::Result<()> {
        if bans.is_empty() {
            return Ok(());
        }
        // Re-adding an existing element fails, so clear first.
        let v4: Vec<&IpNet> = bans
            .iter()
            .filter(|b| matches!(b.net, IpNet::V4(_)))
            .map(|b| &b.net)
            .collect();
        let v6: Vec<&IpNet> = bans
            .iter()
            .filter(|b| matches!(b.net, IpNet::V6(_)))
            .map(|b| &b.net)
            .collect();
        self.delete_elements("ban4", &v4)?;
        self.delete_elements("ban6", &v6)?;
        let mut script = String::new();
        for set in ["ban4", "ban6"] {
            let elems: Vec<String> = bans
                .iter()
                .filter(|b| Self::set_for(&b.net, "ban") == set)
                .map(|b| format!("{} timeout {}s", crate::ip::key_to_nft(&b.net), b.ttl.as_secs().max(1)))
                .collect();
            if !elems.is_empty() {
                script.push_str(&format!("add element {TABLE} {set} {{ {} }}\n", elems.join(", ")));
            }
        }
        self.run(&script)?;
        Ok(())
    }

    fn unban(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        let v4: Vec<&IpNet> = nets.iter().filter(|n| matches!(n, IpNet::V4(_))).collect();
        let v6: Vec<&IpNet> = nets.iter().filter(|n| matches!(n, IpNet::V6(_))).collect();
        self.delete_elements("ban4", &v4)?;
        self.delete_elements("ban6", &v6)
    }

    fn list(&mut self) -> anyhow::Result<Option<Vec<Entry>>> {
        let mut all = self.list_set("ban4")?;
        all.extend(self.list_set("ban6")?);
        Ok(Some(all))
    }

    fn set_allow(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        let mut script = String::new();
        for set in ["allow4", "allow6"] {
            script.push_str(&format!("flush set {TABLE} {set}\n"));
            let elems: Vec<String> = nets
                .iter()
                .filter(|n| Self::set_for(n, "allow") == set)
                .map(crate::ip::key_to_nft)
                .collect();
            if !elems.is_empty() {
                script.push_str(&format!("add element {TABLE} {set} {{ {} }}\n", elems.join(", ")));
            }
        }
        self.run(&script)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_json() {
        let v: serde_json::Value = serde_json::json!({"prefix": {"addr": "2001:db8::", "len": 64}});
        assert_eq!(json_to_net(&v).unwrap().to_string(), "2001:db8::/64");
        let v = serde_json::json!("10.1.2.3");
        assert_eq!(json_to_net(&v).unwrap().to_string(), "10.1.2.3/32");
    }

    #[test]
    fn setup_script_is_scoped_to_our_table() {
        let s = Nft::setup_script();
        assert!(s.lines().all(|l| l.contains("inet minsec")));
        assert!(s.contains("priority -10"));
        // Crowd sets exist (populated by minsec-sync) and are enforced
        // after allow and local bans.
        for set in ["crowd4", "crowd6"] {
            assert!(s.contains(&format!("add set inet minsec {set}")));
            assert!(s.contains(&format!("@{set} counter drop")));
        }
        let allow = s.find("@allow4 accept").unwrap();
        assert!(allow < s.find("@crowd4 counter drop").unwrap());
    }

    #[test]
    fn recreate_script_keeps_elements_and_lifetimes() {
        let entries = vec![
            Entry {
                net: "10.9.9.9/32".parse().unwrap(),
                expires_in: Some(Duration::from_secs(3599)),
            },
            Entry {
                net: "198.51.100.0/24".parse().unwrap(),
                expires_in: None,
            },
        ];
        let s = Nft::recreate_script(
            "crowd4",
            "{ type ipv4_addr; flags interval, timeout; timeout 24h; }",
            &entries,
        );
        let lines: Vec<&str> = s.lines().collect();
        // Rules pinning the set go before the delete, in the same batch.
        let flush = lines
            .iter()
            .position(|l| l.starts_with("flush chain inet minsec input"))
            .unwrap();
        let delete = lines
            .iter()
            .position(|l| *l == "delete set inet minsec crowd4")
            .unwrap();
        assert!(flush < delete);
        assert_eq!(
            lines[delete + 1],
            "add set inet minsec crowd4 { type ipv4_addr; flags interval, timeout; timeout 24h; }"
        );
        assert_eq!(
            lines[delete + 2],
            "add element inet minsec crowd4 { 10.9.9.9 timeout 3599s, 198.51.100.0/24 }"
        );
        assert!(s.lines().all(|l| l.contains("inet minsec")));
        // An empty set is recreated without an `add element`.
        assert!(!Nft::recreate_script("crowd6", "{ type ipv6_addr; }", &[]).contains("add element"));
    }
}
