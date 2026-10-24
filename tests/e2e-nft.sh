#!/bin/bash
# End-to-end test against real nftables inside a private network namespace.
# Usage: sudo tests/e2e-nft.sh /path/to/minsec   (or: unshare -rn tests/e2e-nft.sh ...)
set -euo pipefail
B=${1:-target/release/minsec}
W=$(mktemp -d)
trap 'kill $DPID 2>/dev/null; rm -rf "$W"' EXIT
mkdir -p "$W/etc" "$W/state"; : > "$W/secure"
cat > "$W/etc/minsec.toml" <<CFG
[defaults]
backend = "nft"
journal = false
maxretry = 3
findtime = "1m"
bantime = "5m"
[paths]
socket = "$W/minsec.sock"
state_dir = "$W/state"
[filters.sshd]
enabled = true
files = ["$W/secure"]
CFG
run() { if [ "$(id -u)" = 0 ] && [ -z "${IN_NS:-}" ]; then IN_NS=1 exec unshare -n "$0" "$B"; fi; }
run
"$B" -c "$W/etc" daemon & DPID=$!
sleep 0.5
for i in 1 2 3; do echo "sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2" >> "$W/secure"; done
sleep 0.7
nft list set inet minsec ban4 | grep -q 198.51.100.7 || { echo "FAIL: kernel set missing ban"; exit 1; }
"$B" -c "$W/etc" list | grep -q 198.51.100.7 || { echo "FAIL: list"; exit 1; }
kill $DPID; wait $DPID || true
"$B" -c "$W/etc" daemon & DPID=$!
sleep 0.5
"$B" -c "$W/etc" list | grep -q 198.51.100.7 || { echo "FAIL: ban lost across restart"; exit 1; }
"$B" -c "$W/etc" unban 198.51.100.7
nft list set inet minsec ban4 | grep -q 198.51.100.7 && { echo "FAIL: unban"; exit 1; }

# Upgrade path: a set left behind by an older version with a definition this
# version no longer uses. The daemon must still start, rebuild the set, and
# keep its contents (and the bans' remaining lifetimes) across the rebuild.
for i in 1 2 3; do echo "sshd[1]: Failed password for root from 198.51.100.8 port 1 ssh2" >> "$W/secure"; done
sleep 0.7
kill $DPID; wait $DPID || true
nft -f - <<NFT
flush chain inet minsec input
flush chain inet minsec forward
delete set inet minsec crowd4
add set inet minsec crowd4 { type ipv4_addr; flags interval; }
add element inet minsec crowd4 { 203.0.113.7, 192.0.2.0/24 }
NFT
"$B" -c "$W/etc" daemon & DPID=$!
sleep 0.5
kill -0 $DPID 2>/dev/null || { echo "FAIL: daemon died on stale set definition"; exit 1; }
nft list set inet minsec crowd4 | grep -q "interval" && { echo "FAIL: crowd4 not rebuilt as a hash set"; nft list set inet minsec crowd4; exit 1; }
nft list set inet minsec crowd4 | grep -q 203.0.113.7 || { echo "FAIL: crowd4 element lost in rebuild"; exit 1; }
nft list set inet minsec crowdnet4 | grep -q 192.0.2.0/24 || { echo "FAIL: crowd4 prefix not moved to crowdnet4"; nft list table inet minsec; exit 1; }
nft list chain inet minsec input | grep -q "@crowd4" || { echo "FAIL: crowd4 rule missing after rebuild"; exit 1; }
nft list chain inet minsec input | grep -q "@crowdnet4" || { echo "FAIL: crowdnet4 rule missing after rebuild"; exit 1; }
nft list chain inet minsec input | grep -qE "ip6 saddr & ffff:ffff:ffff:ffff:: (== )?@crowd6" || { echo "FAIL: crowd6 rule not masked"; exit 1; }
"$B" -c "$W/etc" list | grep -q 198.51.100.8 || { echo "FAIL: ban lost across rebuild"; exit 1; }

# Upgrade from interval ban sets. Hosts and /64s move to the hash sets and
# networks to bannet4/6; 198.51.100.20-29 stands in for an element whose
# end marker the kernel lost, which must come back as its start address.
kill $DPID; wait $DPID || true
nft -f - <<NFT
flush chain inet minsec input
flush chain inet minsec forward
delete set inet minsec ban4
delete set inet minsec ban6
add set inet minsec ban4 { type ipv4_addr; flags interval, timeout; }
add set inet minsec ban6 { type ipv6_addr; flags interval, timeout; }
add element inet minsec ban4 { 198.51.100.9 timeout 1h, 192.0.2.0/24 timeout 1h, 198.51.100.20-198.51.100.29 timeout 1h }
add element inet minsec ban6 { 2001:db8:1:2::/64 timeout 1h }
NFT
"$B" -c "$W/etc" daemon & DPID=$!
sleep 0.5
kill -0 $DPID 2>/dev/null || { echo "FAIL: daemon died upgrading ban sets"; exit 1; }
nft list set inet minsec ban4 | grep -q "interval" && { echo "FAIL: ban4 still an interval set"; exit 1; }
for want in "ban4 198.51.100.9" "ban4 198.51.100.20" "bannet4 192.0.2.0/24" "ban6 2001:db8:1:2::"; do
    nft list set inet minsec ${want% *} | grep -qF "${want#* }" || { echo "FAIL: $want missing after upgrade"; nft list table inet minsec; exit 1; }
done
nft list set inet minsec ban4 | grep -q 198.51.100.29 && { echo "FAIL: corrupt range survived upgrade"; exit 1; }
"$B" -c "$W/etc" list | grep -q 2001:db8:1:2::/64 || { echo "FAIL: ban6 key not listed as /64"; exit 1; }
nft list chain inet minsec input | grep -qE "ip6 saddr & ffff:ffff:ffff:ffff:: (== )?@ban6" || { echo "FAIL: ban6 rule not masked"; exit 1; }

# Manual network bans land in bannet4; a corrupt range found there at
# runtime is repaired by the next listing.
"$B" -c "$W/etc" ban 203.0.113.0/25
nft list set inet minsec bannet4 | grep -q 203.0.113.0/25 || { echo "FAIL: manual network ban not in bannet4"; exit 1; }
nft add element inet minsec bannet4 "{ 203.0.113.140-203.0.113.150 timeout 1h }"
"$B" -c "$W/etc" list > /dev/null
nft list set inet minsec bannet4 | grep -q 203.0.113.150 && { echo "FAIL: corrupt bannet4 range not repaired"; nft list set inet minsec bannet4; exit 1; }
nft list set inet minsec ban4 | grep -q 203.0.113.140 || { echo "FAIL: repaired range start not kept"; exit 1; }
nft list set inet minsec bannet4 | grep -q 203.0.113.0/25 || { echo "FAIL: bannet4 lost a ban in repair"; exit 1; }
nft list chain inet minsec input | grep -q "@bannet4" || { echo "FAIL: rules missing after repair"; exit 1; }
echo "e2e-nft: ok"
