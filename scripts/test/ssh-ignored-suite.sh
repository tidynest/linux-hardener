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
#   fixture boot asks for sudo once; the stop at the end reuses that ticket.
#   Exit status is the first failing binary's, after all three have run.
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

# Two tests in ssh_integration_tests apply a default-drop firewall to
# whatever NFTABLES_LIVE_APPLY_HOST names and panic when it is unset, on
# purpose (see that file). Unless the operator set it, they are skipped by
# name rather than run into that panic. Named in full: the obvious shared
# substring, `remote_apply`, also matches an SSH_TEST_HOST test.
skip=()
[[ -n "${NFTABLES_LIVE_APPLY_HOST:-}" ]] || skip=(
    --skip the_remote_apply_keeps_the_connection_it_arrived_on
    --skip a_second_remote_apply_reports_every_rule_already_present
)

status=0
for target in \
    "hardener-core ssh_executor_tests" \
    "hardener-plugins ssh_integration_tests" \
    "hardener-cli batch_ssh_integration"; do
    read -r package binary <<< "$target"
    cargo test -p "$package" --test "$binary" -- --ignored "${skip[@]}" || status=$?
done

sudo machinectl stop "$MACHINE"
exit "$status"
