#!/usr/bin/env bash
# Puts a test container into a state where the firewall plugin selects the
# nftables backend. Run as root.
#
# No new container image is needed, contrary to what issue #52 assumed. Backend
# selection takes the first ACTIVE backend rather than the first installed one
# (`find_winner`, crates/hardener-plugins/src/firewall/mod.rs), `nft` is already
# installed on all five images, and the nftables backend's `is_enabled` only
# requires a ruleset containing an input-hook chain. Stopping the incumbent and
# loading one chain is therefore enough.
#
# Usage: sudo ./scripts/containers/nftables-fixture.sh [machine-name]
set -euo pipefail

MACHINE="${1:-hardener-test-debian}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Matches boot-ssh-test-container.sh's container end of the veth pair. Fixed,
# which is why only one container can be booted at a time and why a recreated
# one collides with its predecessor's host key.
CONTAINER_IP="10.242.117.2"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

if [[ ! -d "/var/lib/machines/$MACHINE" ]]; then
    echo "no image at /var/lib/machines/$MACHINE" >&2
    echo "create it with create-container.sh first" >&2
    exit 1
fi

# The veth address is hard-coded, so every recreated container reuses
# $CONTAINER_IP with a fresh host key. `accept-new` accepts an unknown host and
# correctly REFUSES a changed one, and boot-ssh-test-container.sh then reports
# "container never became reachable over SSH" for what is really a host-key
# mismatch, with port 22 open throughout. Clear the entry before booting.
INVOKER="${SUDO_USER:-$USER}"
sudo -u "$INVOKER" ssh-keygen -R "$CONTAINER_IP" > /dev/null 2>&1 || true

# A recreate replaces the image underneath a still-registered machine, and the
# boot script skips booting whenever `machinectl status` succeeds, so a stale
# registration would leave this driving the old runtime.
if machinectl status "$MACHINE" > /dev/null 2>&1; then
    machinectl stop "$MACHINE" || true
    for _ in $(seq 1 10); do
        machinectl status "$MACHINE" > /dev/null 2>&1 || break
        sleep 1
    done
fi

"$SCRIPT_DIR/boot-ssh-test-container.sh" "$MACHINE"

systemd-run --machine="$MACHINE" --wait --pipe --quiet /usr/bin/bash -s <<'INNER'
set -euo pipefail

command -v nft > /dev/null || {
    echo "nft absent in container" >&2
    exit 1
}

# Disable the incumbent. Not fatal if it was never enabled.
ufw --force disable 2> /dev/null || true
systemctl stop firewalld 2> /dev/null || true

nft flush ruleset

cat > /etc/nftables-fixture.conf <<'NFT'
table inet hardener_fixture {
    chain input {
        type filter hook input priority 0; policy accept;
    }
}
NFT

nft -f /etc/nftables-fixture.conf

# The assertion that makes this fixture mean anything. Debian's ufw drives
# iptables-nft, so ufw's own rules appear in the nftables ruleset as chains
# that DO hook input. Left in place, the nftables backend would report itself
# active off ufw's chains and every measurement would be of ufw while claiming
# to be of nftables.
ruleset="$(nft list ruleset)"
hooks="$(grep -c 'hook input' <<< "$ruleset" || true)"
echo "--- ruleset ---"
echo "$ruleset"
echo "---------------"
[[ "$hooks" == "1" ]] || {
    echo "expected exactly 1 input hook, got $hooks: the incumbent's rules are still loaded" >&2
    exit 1
}
grep -q 'table inet hardener_fixture' <<< "$ruleset" || {
    echo "the fixture's own table is missing" >&2
    exit 1
}

echo "OK: nftables is the only active input-hook firewall in this container"
INNER

cat <<EOF

Fixture ready. Verify the plugin selects nftables (no root needed):
  hardener scan --plugin firewall --ssh root@$CONTAINER_IP

Stop with: sudo machinectl stop $MACHINE
EOF
