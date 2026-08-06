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

# Only one container may be booted at a time: the veth address above is
# fixed, so two live machines both claim it and whichever one the kernel
# happens to route to answers for both. Measured live: booting
# hardener-test-opensuse while hardener-test-debian was still up left both
# running, traffic to $CONTAINER_IP kept reaching Debian, and a live test
# then ran, PASSED, and reported the Debian boot path while this script
# claimed an openSUSE run. Nothing in the test or this script noticed. The
# comment above used to describe that constraint without enforcing it, and
# the old code here only stopped a machine of the SAME name, which covers a
# recreate (the boot script skips booting whenever `machinectl status`
# succeeds, so a stale registration would leave this driving the old image)
# but does nothing about a DIFFERENT one left running. Stop every machine
# machinectl reports, this one included, and wait for each stop to actually
# land rather than assuming it is instant, the same way the old loop did for
# a single name.
while IFS= read -r other; do
    [[ -n "$other" ]] || continue
    machinectl stop "$other" || true
    for _ in $(seq 1 10); do
        machinectl status "$other" > /dev/null 2>&1 || break
        sleep 1
    done
done < <(machinectl list --no-legend --no-pager 2>/dev/null | awk '{print $1}')

"$SCRIPT_DIR/boot-ssh-test-container.sh" "$MACHINE"

# boot-ssh-test-container.sh's own wait loop already probes with a real
# login before it returns, but this script trusted that exit code rather
# than confirming SSH for itself, and it is THIS script's "Fixture ready"
# below that promises `--ssh root@$CONTAINER_IP` will work. A liveness check
# (port 22 accepts a TCP connection) is not a readiness check (root can
# actually authenticate), and the two only look the same until a container
# refuses every login. Authenticate independently, as the invoking user,
# with the same key the live tests use; derive it the same way
# boot-ssh-test-container.sh does rather than assuming $HOME under sudo is
# the invoker's own.
HOME_DIR="$(getent passwd "$INVOKER" | cut -d: -f6)"
KEY="${SSH_TEST_KEY:-$HOME_DIR/.ssh/hardener_test_ed25519}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$KEY")

sudo -u "$INVOKER" ssh "${SSH_OPTS[@]}" "root@$CONTAINER_IP" true || {
    echo "cannot authenticate as root@$CONTAINER_IP with $KEY" >&2
    echo "check: does /var/lib/machines/$MACHINE/root/.ssh/authorized_keys" >&2
    echo "hold $KEY.pub, and does the container's sshd still permit root key login?" >&2
    exit 1
}

# The other half of what would have caught the wrong-host failure above
# immediately, rather than after a full test run passed against the wrong
# distribution. SSH has no opinion about WHICH host answered, only that some
# host did, so ask the container what it actually is and compare that
# against the name we asked for.
os_release="$(sudo -u "$INVOKER" ssh "${SSH_OPTS[@]}" "root@$CONTAINER_IP" cat /etc/os-release)"
# Guard against the same pipefail/set-e trap boot-ssh-test-container.sh's
# registration wait already documents: a bare `x="$(cmd)"` assignment aborts
# the script if any stage of a piped command fails, which a missing NAME=
# line would do here, so fall back to empty instead of a bare bash error.
name="$(grep -i '^NAME=' <<< "$os_release" | cut -d= -f2- | tr -d '"' || true)"
version="$(grep -i '^VERSION_ID=' <<< "$os_release" | cut -d= -f2- | tr -d '"' || true)"
echo "container reports: ${name:-unknown} ${version:-unknown}"

# Loose, case-insensitive membership rather than an exact match: NAME varies
# in ways that are not the point ("openSUSE Leap" vs "opensuse"), only the
# family is. hardener-test-rhel actually boots Rocky Linux, a RHEL rebuild
# (create-container.sh), so its os-release NAME says "Rocky Linux" and not
# anything containing "rhel"; matched here against what the image genuinely
# reports rather than the machine name's own wording. A machine name outside
# this fixture's five known images warns and skips the check rather than
# failing, so a future distro does not need this script edited before it can
# be booted.
case "$MACHINE" in
    hardener-test) expect="arch" ;;
    hardener-test-debian) expect="debian" ;;
    hardener-test-fedora) expect="fedora" ;;
    hardener-test-rhel) expect="rocky" ;;
    hardener-test-opensuse) expect="opensuse" ;;
    *) expect="" ;;
esac

if [[ -n "$expect" ]]; then
    grep -qiE "$expect" <<< "$name" || {
        echo "machine name '$MACHINE' does not match what it answered: '$name'" >&2
        echo "this is exactly how a stale second container passed as the wrong host earlier; refusing to continue" >&2
        exit 1
    }
else
    echo "warning: no known os-release mapping for '$MACHINE', skipping the identity check" >&2
fi

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
