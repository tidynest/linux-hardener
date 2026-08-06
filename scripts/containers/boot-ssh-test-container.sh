#!/usr/bin/env bash
# Boot an existing hardener-test* container with networking + sshd for the
# #[ignore] SSH integration tests, injecting a dedicated test key.
#
# The standard root suite runs containers via `nspawn --pipe` (no network, no
# sshd); this fixture is the booted-with-veth variant those tests need.
#
# Networking is configured statically on both veth ends (the containers do not
# run systemd-networkd, and the host running NetworkManager leaves ve-* alone),
# so nothing persistent is enabled on host or container, the addresses die
# with the machine.
#
# Usage: sudo ./scripts/containers/boot-ssh-test-container.sh [machine-name]
#   machine-name defaults to hardener-test (see create-container.sh arch).
set -euo pipefail

MACHINE="${1:-hardener-test}"
ROOT="/var/lib/machines/$MACHINE"
UNIT="nspawn-$MACHINE"
HOST_IP="10.242.117.1"
CONTAINER_IP="10.242.117.2"
# Key lives in the invoking user's home even under sudo.
HOME_DIR="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
KEY="${SSH_TEST_KEY:-$HOME_DIR/.ssh/hardener_test_ed25519}"

[[ -d "$ROOT" ]] || {
    echo "container $ROOT missing: run create-container.sh arch first" >&2
    exit 1
}
if [[ ! -f "$KEY" ]]; then
    sudo -u "${SUDO_USER:-$USER}" ssh-keygen -t ed25519 -N '' -f "$KEY" -C hardener-ssh-tests
fi

install -d -m 700 "$ROOT/root/.ssh"
install -m 600 "$KEY.pub" "$ROOT/root/.ssh/authorized_keys"

# A transient unit with a passive console: nspawn --boot in a backgrounded
# shell job would be stopped by the kernel on its first tty read (SIGTTIN).
# No --collect: a failed unit must stay inspectable.
if ! machinectl status "$MACHINE" > /dev/null 2>&1; then
    systemctl reset-failed "$UNIT" 2> /dev/null || true
    systemd-run --unit="$UNIT" \
        systemd-nspawn --machine="$MACHINE" --directory="$ROOT" \
        --boot --network-veth --console=passive
fi

diagnose() {
    echo "--- $UNIT status ---" >&2
    systemctl status "$UNIT" --no-pager >&2 || true
    echo "--- last journal lines ---" >&2
    journalctl -u "$UNIT" --no-pager -n 25 >&2 || true
}

# 60s window: a cold-cache first boot can take over 30s to register (observed
# live 2026-07-19; the old 15x2s loop expired and the script bailed).
echo "waiting for machine registration..."
IFACE=""
for _ in $(seq 1 30); do
    # `|| true` is load-bearing, not defensive. Until the machine registers,
    # `machinectl status` exits non-zero; `pipefail` promotes that to the
    # pipeline's status, and a bare `x="$(cmd)"` under `set -e` aborts on it,
    # unlike `local x="$(cmd)"`. So the first iteration killed the script
    # silently, before the timeout branch or `diagnose` could run, and the
    # 60s window below was unreachable. The script therefore only ever
    # succeeded against a machine that was ALREADY registered, which is the
    # one case it does not exist to handle.
    IFACE="$(machinectl status "$MACHINE" 2>/dev/null | awk '/Iface:/ {print $2; exit}' || true)"
    [[ -n "$IFACE" ]] && break
    sleep 2
done
[[ -n "$IFACE" ]] || {
    echo "machine never registered a veth interface" >&2
    diagnose
    exit 1
}

# Static addressing, both ends. `replace` keeps re-runs idempotent; host0 is
# nspawn's fixed name for the container end of the veth pair.
ip addr replace "$HOST_IP/30" dev "$IFACE"
ip link set "$IFACE" up
systemd-run --machine="$MACHINE" --wait --pipe --quiet /usr/bin/sh -c \
    "ip addr replace $CONTAINER_IP/30 dev host0 && ip link set host0 up"

# Some images arrive already hardened by this tool from an earlier run, and
# the SSH plugin's own hardening sets `PermitRootLogin no`, which the key we
# just installed above cannot get past. sshd keeps the first value it finds
# for a directive, the Include glob that pulls in
# /etc/ssh/sshd_config.d/*.conf expands alphabetically, and this project's
# own drop-in is named 00-hardener.conf, so nothing sorted after it has any
# effect: a 99-prefixed override is dead text. Root key login is exactly
# what this script exists to provide, so win the ordering instead of
# touching that file: 00-0- sorts before 00-h. Left unfixed, the wait loop
# below burns its whole window failing "Permission denied" on every
# attempt, which looks identical to a container that never came up at all,
# and the diagnostics dumped on that path show a perfectly healthy sshd,
# because the refusal is policy, not fault. Applied unconditionally: on an
# image nothing has hardened yet, `prohibit-password` is what upstream
# OpenSSH already defaults to, so nothing here changes behaviour.
echo "unlocking root key login, in case an earlier hardening run disabled it..."
systemd-run --machine="$MACHINE" --wait --pipe --quiet /usr/bin/bash -s <<'INNER'
set -euo pipefail
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-0-hardener-test.conf <<'CONF'
PermitRootLogin prohibit-password
CONF
sshd -t
systemctl restart sshd
value="$(sshd -T | grep -i '^permitrootlogin' || true)"
[[ "$value" == *prohibit-password* ]] || {
    echo "PermitRootLogin did not take (sshd -T says: ${value:-nothing})" >&2
    echo "check 00-hardener.conf and the sshd_config.d Include order" >&2
    exit 1
}
INNER

echo "waiting for sshd on $CONTAINER_IP..."
READY=""
for _ in $(seq 1 15); do
    if sudo -u "${SUDO_USER:-$USER}" \
        ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=2 -i "$KEY" "root@$CONTAINER_IP" true 2>/dev/null; then
        READY=1
        break
    fi
    sleep 2
done
[[ -n "$READY" ]] || {
    echo "container never became reachable over SSH" >&2
    diagnose
    exit 1
}

cat << EOF
Fixture ready. In your test shell:
  export SSH_TEST_HOST=$CONTAINER_IP SSH_TEST_USER=root SSH_TEST_PORT=22 SSH_TEST_KEY=$KEY
  ssh-add \$SSH_TEST_KEY   # ad-hoc --ssh targets resolve keys via the agent
Run:  cargo test -p hardener-cli --test batch_ssh_integration -- --ignored
Stop: sudo machinectl stop $MACHINE
EOF
