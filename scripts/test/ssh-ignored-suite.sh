#!/usr/bin/env bash
# Run every #[ignore] test that needs the booted SSH fixture, in one go.
#
# Three test binaries gate on SSH_TEST_HOST: hardener-core's
# ssh_executor_tests, hardener-plugins' ssh_integration_tests and
# hardener-cli's batch_ssh_integration. They run only when someone boots the
# fixture, exports four variables and names each binary by hand, which is how
# 25 tests become the part of the suite nobody runs. This script does those
# steps in order and stops the fixture afterwards.
#
# Usage: ./scripts/test/ssh-ignored-suite.sh [machine-name]
#   Run as yourself, not as root: cargo has to go through the PATH shim. The
#   fixture boot asks for sudo once; the stop at the end asks again on a host
#   whose sudo caches nothing. Exit status is the first failing binary's,
#   after all three have run.
#
# Run it against a FRESH container. One test applies the SSH plugin and then
# asserts the config changed; on a container an earlier run already hardened,
# nothing changes and the assertion fails on a true reading. Recreate first:
#   sudo ./scripts/containers/create-container.sh arch clean
#   sudo ./scripts/containers/create-container.sh arch
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
MACHINE="${1:-hardener-test}"

# The fixture prints its `export` line for a human to paste; it is read here
# from the same output, so the two cannot name different variables.
fixture_out="$(sudo ./scripts/containers/boot-ssh-test-container.sh "$MACHINE")"
printf '%s\n' "$fixture_out"
eval "$(printf '%s\n' "$fixture_out" | sed -n 's/^  export /export /p')"
: "${SSH_TEST_HOST:?fixture printed no SSH_TEST_HOST line}"
ssh-add "$SSH_TEST_KEY"

# Some tests in ssh_integration_tests apply a default-drop firewall to
# whatever NFTABLES_LIVE_APPLY_HOST names and panic when it is unset, on
# purpose (see that file). Unless the operator set it, they are skipped by
# name rather than run into that panic. The names are read from the source
# at run time, the function enclosing each `env::var(...)` read: a hand list
# missed the third of them on the first run (2026-09-02), and the obvious
# shared substring, `remote_apply`, also matches an SSH_TEST_HOST test.
skip=()
if [[ -z "${NFTABLES_LIVE_APPLY_HOST:-}" ]]; then
    while read -r name; do
        skip+=(--skip "$name")
    done < <(awk '
        /^(async )?fn [a-z_0-9]+\(/ { match($0, /fn [a-z_0-9]+/); name = substr($0, RSTART + 3, RLENGTH - 3) }
        /env::var\("NFTABLES_LIVE_APPLY_HOST"\)/ { print name }
    ' crates/hardener-plugins/tests/ssh_integration_tests.rs)
fi

# One thread per binary: the tests share one sshd, and an apply that restarts
# it while a sibling test is connecting reads as "Connection refused" on the
# sibling. Three of ten failed that way on the first run.
status=0
for target in \
    "hardener-core ssh_executor_tests" \
    "hardener-plugins ssh_integration_tests" \
    "hardener-cli batch_ssh_integration"; do
    read -r package binary <<< "$target"
    cargo test -p "$package" --test "$binary" -- --ignored --test-threads=1 "${skip[@]}" \
        || status=$?
done

sudo machinectl stop "$MACHINE"
exit "$status"
