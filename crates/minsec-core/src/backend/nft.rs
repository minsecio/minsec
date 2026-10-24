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
//! Bans of a single key (an IPv4 host, or an IPv6 network of exactly
//! `ipv6_prefix`) live in the hash sets `ban4`/`ban6`; `ban6` holds the
//! network address and its rule masks the source before the lookup. Only
//! manual bans of other networks use the interval sets `bannet4`/`bannet6`.
//! Interval sets with timeouts have corrupted on older kernels (seen on
//! EL8's 4.18): a one-address element lost its end marker and became a range
//! covering a fifth of IPv4. Hash sets keep ordinary bans out of that code,
//! and `list` rebuilds an interval ban set holding a range that is not a
//! CIDR, since minsec never adds one. The crowd sets minsec-sync fills are
//! split the same way: `crowd4`/`crowd6` (hosts and /64s) and
//! `crowdnet4`/`crowdnet6` (wider prefixes).
//!
//! MVP drives the `nft` binary with a script on stdin; a native netlink
//! implementation can replace `run()` later behind the same trait.

use super::{Ban, Entry, Firewall};
use ipnet::{IpNet, Ipv6Net};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const TABLE: &str = "inet minsec";

/// How long a crowd-blocklist element survives in the kernel without being
/// refreshed by a pull. See the crowd sets in `setup_script`.
pub const CROWD_TIMEOUT: &str = "24h";

/// IPv6 prefix of a `crowd6` key: the server aggregates reports to /64, so
/// this is fixed rather than following `ipv6_prefix`. Must match
/// minsec-sync's `CROWD_V6_PREFIX`.
pub const CROWD_V6_PREFIX: u8 = 64;

const HOOKS: [&str; 2] = ["input", "forward"];

/// Sets holding local bans.
const BAN_SETS: [&str; 4] = ["ban4", "ban6", "bannet4", "bannet6"];

/// Sets holding the crowd blocklist.
const CROWD_SETS: [&str; 4] = ["crowd4", "crowd6", "crowdnet4", "crowdnet6"];

pub struct Nft {
    nft: String,
    /// `defaults.ipv6_prefix`: IPv6 bans of exactly this length go in `ban6`.
    v6_prefix: u8,
}

/// A set's elements as the kernel reports them.
struct Listing {
    entries: Vec<Entry>,
    /// Ranges that are not a CIDR, each a corrupted element; `entries` holds
    /// its start address, which is the key minsec added.
    corrupt: Vec<String>,
}

impl Default for Nft {
    fn default() -> Self {
        Self::new()
    }
}

impl Nft {
    pub fn new() -> Self {
        Self::with_binary("nft")
    }

    pub fn with_binary(nft: impl Into<String>) -> Self {
        Self {
            nft: nft.into(),
            v6_prefix: 64,
        }
    }

    pub fn with_v6_prefix(mut self, prefix: u8) -> Self {
        self.v6_prefix = prefix.clamp(1, 128);
        self
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
    fn set_defs() -> [(&'static str, String); 10] {
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
            ("ban4", "{ type ipv4_addr; flags timeout; }".into()),
            ("ban6", "{ type ipv6_addr; flags timeout; }".into()),
            ("bannet4", "{ type ipv4_addr; flags interval, timeout; }".into()),
            ("bannet6", "{ type ipv6_addr; flags interval, timeout; }".into()),
            ("allow4", "{ type ipv4_addr; flags interval; }".into()),
            ("allow6", "{ type ipv6_addr; flags interval; }".into()),
            (
                "crowd4",
                format!("{{ type ipv4_addr; flags timeout; timeout {CROWD_TIMEOUT}; }}"),
            ),
            (
                "crowd6",
                format!("{{ type ipv6_addr; flags timeout; timeout {CROWD_TIMEOUT}; }}"),
            ),
            (
                "crowdnet4",
                format!("{{ type ipv4_addr; flags interval, timeout; timeout {CROWD_TIMEOUT}; }}"),
            ),
            (
                "crowdnet6",
                format!("{{ type ipv6_addr; flags interval, timeout; timeout {CROWD_TIMEOUT}; }}"),
            ),
        ]
    }

    fn def_of(name: &str) -> String {
        Self::set_defs()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, d)| d)
            .expect("known set")
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

    /// The source expression for a hash set of `prefix` network addresses.
    fn v6_match(prefix: u8) -> String {
        if prefix >= 128 {
            return "ip6 saddr".into();
        }
        let mask = Ipv6Net::new(Ipv6Addr::UNSPECIFIED, prefix)
            .expect("valid prefix")
            .netmask();
        format!("ip6 saddr & {mask}")
    }

    /// The prefix a hash set's IPv6 elements stand for, if it has one.
    fn v6_key_len(&self, set: &str) -> Option<u8> {
        match set {
            "ban6" => Some(self.v6_prefix),
            "crowd6" => Some(CROWD_V6_PREFIX),
            _ => None,
        }
    }

    pub fn setup_script(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("add table {TABLE}\n"));
        for (name, def) in Self::set_defs() {
            s.push_str(&format!("add set {TABLE} {name} {def}\n"));
        }
        Self::reset_chains(&mut s);
        let ban6 = Self::v6_match(self.v6_prefix);
        let crowd6 = Self::v6_match(CROWD_V6_PREFIX);
        for hook in HOOKS {
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @allow4 accept\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip6 saddr @allow6 accept\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @ban4 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} {ban6} @ban6 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @bannet4 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip6 saddr @bannet6 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @crowd4 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} {crowd6} @crowd6 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip saddr @crowdnet4 counter drop\n"));
            s.push_str(&format!("add rule {TABLE} {hook} ip6 saddr @crowdnet6 counter drop\n"));
        }
        s
    }

    /// The set a ban of `net` belongs in, and its element key there.
    fn place(&self, net: &IpNet) -> (&'static str, String) {
        match net {
            IpNet::V4(n) if n.prefix_len() == 32 => ("ban4", n.addr().to_string()),
            IpNet::V6(n) if n.prefix_len() == self.v6_prefix => ("ban6", n.trunc().addr().to_string()),
            IpNet::V4(_) => ("bannet4", crate::ip::key_to_nft(net)),
            IpNet::V6(_) => ("bannet6", crate::ip::key_to_nft(net)),
        }
    }

    /// The crowd set `net` belongs in, as minsec-sync places it.
    fn place_crowd(net: &IpNet) -> (&'static str, String) {
        match net {
            IpNet::V4(n) if n.prefix_len() == 32 => ("crowd4", n.addr().to_string()),
            IpNet::V6(n) if n.prefix_len() == CROWD_V6_PREFIX => ("crowd6", n.trunc().addr().to_string()),
            IpNet::V4(_) => ("crowdnet4", crate::ip::key_to_nft(net)),
            IpNet::V6(_) => ("crowdnet6", crate::ip::key_to_nft(net)),
        }
    }

    /// `entries` taken from set `name`, rendered as elements and grouped by
    /// the set each belongs in. Ban and crowd entries are placed afresh,
    /// which moves them out of a set whose layout changed; other sets keep
    /// their own entries.
    fn group(&self, name: &'static str, entries: &[Entry]) -> BTreeMap<&'static str, Vec<String>> {
        let mut seen = HashSet::new();
        let mut groups: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for e in entries {
            let (set, key) = if BAN_SETS.contains(&name) {
                self.place(&e.net)
            } else if CROWD_SETS.contains(&name) {
                Self::place_crowd(&e.net)
            } else {
                (name, crate::ip::key_to_nft(&e.net))
            };
            if seen.insert((set, key.clone())) {
                groups.entry(set).or_default().push(elem(key, e.expires_in));
            }
        }
        groups
    }

    /// One transaction that replaces `name` with definition `def` and puts
    /// `entries` back. Elements with a known remaining lifetime keep it;
    /// the rest take the set's default (or none). The chains are emptied
    /// first because their rules pin the set; `setup_script` refills them.
    fn recreate_script(&self, name: &'static str, def: &str, entries: &[Entry]) -> String {
        let mut s = String::new();
        Self::reset_chains(&mut s);
        s.push_str(&format!("delete set {TABLE} {name}\n"));
        s.push_str(&format!("add set {TABLE} {name} {def}\n"));
        for (set, elems) in self.group(name, entries) {
            if set != name {
                s.push_str(&format!("add set {TABLE} {set} {}\n", Self::def_of(set)));
            }
            s.push_str(&format!("add element {TABLE} {set} {{ {} }}\n", elems.join(", ")));
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
            let listing = self.list_set(name)?;
            warn_corrupt(name, &listing);
            self.run(&self.recreate_script(name, &def, &listing.entries))?;
            tracing::warn!(target: "minsec::nft", set = name, elements = listing.entries.len(), "rebuilt set with stale definition");
            rebuilt.push(name);
        }
        Ok(rebuilt)
    }

    /// `ban6` keys are network addresses for `ipv6_prefix`. After a wider
    /// prefix is configured, elements off the new boundary would never
    /// match, so move them onto it. (A narrower prefix leaves the old
    /// elements aligned; they stay as narrower bans until they expire.)
    fn rekey_ban6(&self) -> anyhow::Result<()> {
        let entries = self.list_set("ban6")?.entries;
        let held: HashSet<IpNet> = entries.iter().map(|e| e.net).collect();
        let stale: Vec<&Entry> = entries.iter().filter(|e| e.net != e.net.trunc()).collect();
        if stale.is_empty() {
            return Ok(());
        }
        let mut s = String::new();
        for e in &stale {
            s.push_str(&format!("delete element {TABLE} ban6 {{ {} }}\n", e.net.addr()));
        }
        let moved: Vec<Entry> = stale
            .iter()
            .map(|e| Entry {
                net: e.net.trunc(),
                expires_in: e.expires_in,
            })
            .filter(|e| !held.contains(&e.net))
            .collect();
        for (set, elems) in self.group("ban6", &moved) {
            s.push_str(&format!("add element {TABLE} {set} {{ {} }}\n", elems.join(", ")));
        }
        self.run(&s)?;
        tracing::warn!(target: "minsec::nft", elements = stale.len(), prefix = self.v6_prefix, "re-keyed ban6 elements to ipv6_prefix");
        Ok(())
    }

    fn delete_elements(&self, set: &str, keys: &[String]) -> anyhow::Result<()> {
        // Deleting a missing element is an error for nft, so delete one at a
        // time and ignore failures; bans are rare enough that this is fine.
        for k in keys {
            let _ = self.run(&format!("delete element {TABLE} {set} {{ {k} }}\n"));
        }
        Ok(())
    }

    fn list_set(&self, set: &str) -> anyhow::Result<Listing> {
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
        Ok(self.parse_listing(set, &v))
    }

    fn parse_listing(&self, set: &str, v: &serde_json::Value) -> Listing {
        let mut listing = Listing {
            entries: Vec::new(),
            corrupt: Vec::new(),
        };
        let Some(objs) = v.get("nftables").and_then(|n| n.as_array()) else {
            return listing;
        };
        for o in objs {
            let Some(s) = o.get("set") else {
                continue;
            };
            let interval = match s.get("flags") {
                Some(serde_json::Value::Array(a)) => a.iter().any(|f| f == "interval"),
                Some(f) => f == "interval",
                None => false,
            };
            // A hash `ban6` or `crowd6` holds the network address of each
            // key; an interval one (from an older version) holds real
            // prefixes.
            let key_len = if interval { None } else { self.v6_key_len(set) };
            let Some(elems) = s.get("elem").and_then(|e| e.as_array()) else {
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
                let net = match val.get("range") {
                    Some(r) => range_to_net(r).or_else(|| {
                        let lo = r.get(0).and_then(|x| x.as_str()).unwrap_or("?");
                        let hi = r.get(1).and_then(|x| x.as_str()).unwrap_or("?");
                        listing.corrupt.push(format!("{lo}-{hi}"));
                        lo.parse::<IpAddr>().ok().map(IpNet::from)
                    }),
                    None => json_to_net(&val),
                };
                let Some(mut net) = net else {
                    continue;
                };
                if let (Some(len), IpNet::V6(n)) = (key_len, net) {
                    net = IpNet::V6(Ipv6Net::new(n.addr(), len).expect("valid prefix"));
                }
                listing.entries.push(Entry {
                    net,
                    expires_in: expires.map(Duration::from_secs),
                });
            }
        }
        listing
    }
}

fn elem(key: String, ttl: Option<Duration>) -> String {
    match ttl {
        Some(d) => format!("{key} timeout {}s", d.as_secs().max(1)),
        None => key,
    }
}

fn warn_corrupt(set: &str, listing: &Listing) {
    if !listing.corrupt.is_empty() {
        tracing::error!(
            target: "minsec::nft",
            set,
            ranges = %listing.corrupt.join(", "),
            "set holds ranges minsec never added (kernel set corruption); rebuilding it"
        );
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

/// A `{"range": [lo, hi]}` value as the CIDR it spans, or None if it spans
/// anything else.
fn range_to_net(r: &serde_json::Value) -> Option<IpNet> {
    let lo: IpAddr = r.get(0)?.as_str()?.parse().ok()?;
    let hi: IpAddr = r.get(1)?.as_str()?.parse().ok()?;
    let (a, b, width) = match (lo, hi) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, 32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return None,
    };
    let span = b.checked_sub(a)?;
    // A CIDR covers 2^k addresses starting on a 2^k boundary.
    if span & span.wrapping_add(1) != 0 || a & span != 0 {
        return None;
    }
    let host_bits = 128 - span.leading_zeros();
    IpNet::new(lo, (width - host_bits) as u8).ok()
}

impl Firewall for Nft {
    fn name(&self) -> &'static str {
        "nft"
    }

    fn setup(&mut self) -> anyhow::Result<()> {
        if let Err(first) = self.run(&self.setup_script()) {
            if self.recreate_stale_sets()?.is_empty() {
                return Err(first);
            }
            self.run(&self.setup_script())?;
        }
        self.rekey_ban6()
    }

    fn ban(&mut self, bans: &[Ban]) -> anyhow::Result<()> {
        if bans.is_empty() {
            return Ok(());
        }
        let mut keys: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut elems: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for b in bans {
            let (set, key) = self.place(&b.net);
            elems.entry(set).or_default().push(elem(key.clone(), Some(b.ttl)));
            keys.entry(set).or_default().push(key);
        }
        // Re-adding an existing element fails, so clear first.
        for (set, k) in &keys {
            self.delete_elements(set, k)?;
        }
        let mut script = String::new();
        for (set, e) in elems {
            script.push_str(&format!("add element {TABLE} {set} {{ {} }}\n", e.join(", ")));
        }
        self.run(&script)?;
        Ok(())
    }

    fn unban(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        for n in nets {
            let (set, key) = self.place(n);
            self.delete_elements(set, &[key])?;
        }
        Ok(())
    }

    fn list(&mut self) -> anyhow::Result<Option<Vec<Entry>>> {
        let mut all = Vec::new();
        for set in BAN_SETS {
            let listing = self.list_set(set)?;
            if !listing.corrupt.is_empty() {
                warn_corrupt(set, &listing);
                let mut s = self.recreate_script(set, &Self::def_of(set), &listing.entries);
                s.push_str(&self.setup_script());
                self.run(&s)?;
            }
            all.extend(listing.entries);
        }
        Ok(Some(all))
    }

    fn set_allow(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        let mut script = String::new();
        for set in ["allow4", "allow6"] {
            script.push_str(&format!("flush set {TABLE} {set}\n"));
            let elems: Vec<String> = nets
                .iter()
                .filter(|n| matches!((n, set), (IpNet::V4(_), "allow4") | (IpNet::V6(_), "allow6")))
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
    fn ranges_are_cidrs_or_nothing() {
        let r = |lo: &str, hi: &str| range_to_net(&serde_json::json!([lo, hi])).map(|n| n.to_string());
        assert_eq!(r("192.0.2.0", "192.0.2.255").as_deref(), Some("192.0.2.0/24"));
        assert_eq!(r("192.0.2.7", "192.0.2.7").as_deref(), Some("192.0.2.7/32"));
        assert_eq!(
            r("2001:db8::", "2001:db8::ffff:ffff:ffff:ffff").as_deref(),
            Some("2001:db8::/64")
        );
        assert_eq!(r("0.0.0.0", "255.255.255.255").as_deref(), Some("0.0.0.0/0"));
        // The corruption seen in the field: a lost end marker.
        assert_eq!(r("52.128.227.50", "103.187.165.25"), None);
        assert_eq!(r("192.0.2.1", "192.0.2.2"), None);
        assert_eq!(r("192.0.2.9", "192.0.2.1"), None);
    }

    #[test]
    fn places_single_keys_in_hash_sets() {
        let nft = Nft::new();
        let p = |s: &str| nft.place(&s.parse().unwrap());
        assert_eq!(p("198.51.100.7/32"), ("ban4", "198.51.100.7".into()));
        assert_eq!(p("2001:db8:1:2::/64"), ("ban6", "2001:db8:1:2::".into()));
        assert_eq!(p("192.0.2.0/24"), ("bannet4", "192.0.2.0/24".into()));
        assert_eq!(p("2001:db8::/48"), ("bannet6", "2001:db8::/48".into()));
        assert_eq!(p("2001:db8::1/128"), ("bannet6", "2001:db8::1".into()));
        let nft = Nft::new().with_v6_prefix(128);
        assert_eq!(
            nft.place(&"2001:db8::1/128".parse().unwrap()),
            ("ban6", "2001:db8::1".into())
        );
    }

    #[test]
    fn listing_rekeys_ban6_and_recovers_corrupt_ranges() {
        let nft = Nft::new();
        let v = serde_json::json!({"nftables": [{"set": {
            "name": "ban6", "flags": ["timeout"],
            "elem": [{"elem": {"val": "2001:db8:1:2::", "timeout": 600, "expires": 300}}]
        }}]});
        let l = nft.parse_listing("ban6", &v);
        assert_eq!(l.entries[0].net.to_string(), "2001:db8:1:2::/64");
        assert_eq!(l.entries[0].expires_in, Some(Duration::from_secs(300)));

        let v = serde_json::json!({"nftables": [{"set": {
            "name": "ban4", "flags": ["interval", "timeout"],
            "elem": [
                {"elem": {"val": {"range": ["52.128.227.50", "103.187.165.25"]}, "expires": 9000}},
                {"elem": {"val": {"prefix": {"addr": "192.0.2.0", "len": 24}}, "expires": 60}},
                {"elem": {"val": {"range": ["198.51.100.0", "198.51.100.127"]}, "expires": 60}}
            ]
        }}]});
        let l = nft.parse_listing("ban4", &v);
        assert_eq!(l.corrupt, ["52.128.227.50-103.187.165.25"]);
        let nets: Vec<String> = l.entries.iter().map(|e| e.net.to_string()).collect();
        assert_eq!(nets, ["52.128.227.50/32", "192.0.2.0/24", "198.51.100.0/25"]);
    }

    #[test]
    fn setup_script_is_scoped_to_our_table() {
        let s = Nft::new().setup_script();
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
        // Single-key bans are hash sets; ban6 is looked up by network.
        assert!(s.contains("add set inet minsec ban4 { type ipv4_addr; flags timeout; }"));
        assert!(s.contains("ip6 saddr & ffff:ffff:ffff:ffff:: @ban6 counter drop"));
        assert!(s.contains("ip saddr @bannet4 counter drop"));
        assert!(s.contains("ip6 saddr & ffff:ffff:ffff:ffff:: @crowd6 counter drop"));
        assert!(s.contains("ip saddr @crowdnet4 counter drop"));
        assert!(s.contains("add set inet minsec crowd4 { type ipv4_addr; flags timeout; timeout 24h; }"));
        let s = Nft::new().with_v6_prefix(128).setup_script();
        assert!(s.contains("ip6 saddr @ban6 counter drop"));
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
        let s = Nft::new().recreate_script(
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
            "add element inet minsec crowd4 { 10.9.9.9 timeout 3599s }"
        );
        // A prefix in an older interval crowd4 moves to crowdnet4.
        assert_eq!(
            lines[delete + 4],
            "add element inet minsec crowdnet4 { 198.51.100.0/24 }"
        );
        assert!(s.lines().all(|l| l.contains("inet minsec")));
        // An empty set is recreated without an `add element`.
        assert!(!Nft::new()
            .recreate_script("crowd6", "{ type ipv6_addr; }", &[])
            .contains("add element"));
    }

    #[test]
    fn recreating_a_ban_set_moves_networks_out() {
        // An older version's interval ban4, holding a host and a network.
        let entries = vec![
            Entry {
                net: "10.9.9.9/32".parse().unwrap(),
                expires_in: Some(Duration::from_secs(60)),
            },
            Entry {
                net: "192.0.2.0/24".parse().unwrap(),
                expires_in: Some(Duration::from_secs(120)),
            },
        ];
        let s = Nft::new().recreate_script("ban4", &Nft::def_of("ban4"), &entries);
        assert!(s.contains("add set inet minsec ban4 { type ipv4_addr; flags timeout; }\n"));
        assert!(s.contains("add element inet minsec ban4 { 10.9.9.9 timeout 60s }\n"));
        assert!(s.contains("add set inet minsec bannet4 { type ipv4_addr; flags interval, timeout; }\n"));
        assert!(s.contains("add element inet minsec bannet4 { 192.0.2.0/24 timeout 120s }\n"));
    }
}
