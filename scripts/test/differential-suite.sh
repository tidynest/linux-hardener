#!/usr/bin/env bash
# Differential test suite: prove the system agrees with what the tool reported.
#
# Every check asks the setting's real consumer (sshd -T, chage -l), never this
# project's own parser. Re-reading a file with our own reader is what let a
# whole class of defect ship: the reader and the writer agreed with each other
# and disagreed with Linux.
#
# Run INSIDE an nspawn test container, as root. Never on a real system: this
# applies hardening and creates users.
#
# Usage:
#   differential-suite.sh --self-test   # extractors only, safe anywhere
#   differential-suite.sh               # full run, container + root only

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  differential-suite.sh --self-test   # extractors only, safe anywhere
  differential-suite.sh               # full run, container + root only
EOF
}

# Extract one directive's effective value from captured `sshd -T` output.
# Matched case insensitively: sshd has printed these lowercased in the past and
# preserves case now, and a matcher that assumes either finds nothing on the
# other, which reads exactly like "directive absent".
# Prints nothing and returns 1 when the directive really is absent, which the
# caller must treat as a failure rather than a pass.
extract_sshd_value() {
    local output="$1" directive="$2" line
    line="$(printf '%s\n' "$output" | grep -im1 "^${directive}[[:space:]]" || true)"
    if [[ -z "$line" ]]; then
        return 1
    fi
    printf '%s' "$(printf '%s' "$line" | cut -d' ' -f2-)"
}

# Extract one value from captured `chage -l` output by its label prefix.
# Returns 1 when the label is absent.
extract_chage_value() {
    local output="$1" label="$2" line
    line="$(printf '%s\n' "$output" | grep -m1 "^${label}" || true)"
    if [[ -z "$line" ]]; then
        return 1
    fi
    printf '%s' "$(printf '%s' "${line#*:}" | tr -d '[:space:]')"
}

# Container detection follows scripts/test/root-test-suite.sh, checking the same
# four indicators so the tree carries one convention rather than two.
# It differs in one way on purpose: that script prompts, this one refuses. The
# suite applies hardening and creates users, and on a real host there is nothing
# to say no to afterwards.
in_container() {
    [[ -f /run/systemd/container ]] ||
        [[ -f /.dockerenv ]] ||
        grep -q "systemd-nspawn" /proc/1/cgroup 2>/dev/null ||
        [[ "$(systemd-detect-virt 2>/dev/null)" == "systemd-nspawn" ]]
}

# Gate for the full run. Reports every reason at once, so a container entered as
# an ordinary user is not discovered one message at a time.
require_container_root() {
    local refused=0
    if ! in_container; then
        echo "FATAL: not running inside a container." >&2
        echo "  This suite applies hardening and creates users. Run it inside an" >&2
        echo "  nspawn container built by scripts/containers/create-container.sh." >&2
        refused=1
    fi
    if [[ "$EUID" -ne 0 ]]; then
        echo "FATAL: not running as root; the oracles write host keys and create users." >&2
        refused=1
    fi
    if (( refused > 0 )); then
        echo "  --self-test exercises the extractors only and is safe anywhere." >&2
        return 1
    fi
}

# sshd -T refuses to run without host keys, so generate any that are missing.
# This changes nothing the tool manages.
ensure_host_keys() {
    ssh-keygen -A >/dev/null 2>&1 || {
        echo "FATAL: ssh-keygen -A failed; sshd -T cannot run" >&2
        return 1
    }
}

# sshd's own effective configuration, which resolves Include precedence and
# Match block scoping. This is the point of using it rather than reading
# sshd_config ourselves.
capture_sshd_effective() {
    local out
    if ! out="$(sshd -T 2>&1)"; then
        echo "FATAL: sshd -T failed: $out" >&2
        return 1
    fi
    printf '%s' "$out"
}

# Captured once per run by ssh_oracle_init. Empty means the capture never
# happened, which ssh_system_value treats as fatal: a missing capture must not
# read like an absent directive, and an absent directive must not read like a
# pass.
SSHD_EFFECTIVE=""

ssh_oracle_init() {
    ensure_host_keys || return 1
    local out
    if ! out="$(capture_sshd_effective)"; then
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo "FATAL: sshd -T succeeded but printed nothing" >&2
        return 1
    fi
    SSHD_EFFECTIVE="$out"
}

# Print the value sshd itself is enforcing for one directive.
# Returns non-zero, loudly, when the oracle was never initialised or the
# directive is absent, so the caller fails the check instead of skipping it.
ssh_system_value() {
    local directive="$1"
    if [[ -z "$SSHD_EFFECTIVE" ]]; then
        echo "FATAL: ssh oracle not initialised; ssh_oracle_init must run first" >&2
        return 1
    fi
    if ! extract_sshd_value "$SSHD_EFFECTIVE" "$directive"; then
        echo "FATAL: sshd -T does not report '$directive'" >&2
        return 1
    fi
}

self_test() {
    local failures=0
    local sshd_fixture="PermitRootLogin no
MaxAuthTries 3
X11Forwarding yes
subsystem sftp /usr/lib/ssh/sftp-server"
    local chage_fixture="Last password change					: Dec 24, 2024
Minimum number of days between password change		: 0
Maximum number of days between password change		: 99999
Number of days of warning before password expires	: 7"

    check_eq() {
        local got="$1" want="$2" what="$3"
        if [[ "$got" == "$want" ]]; then
            echo "  ok   $what"
        else
            echo "  FAIL $what: got '$got', want '$want'"
            failures=$((failures + 1))
        fi
    }

    check_eq "$(extract_sshd_value "$sshd_fixture" PermitRootLogin)" "no" "sshd PermitRootLogin"
    check_eq "$(extract_sshd_value "$sshd_fixture" MaxAuthTries)" "3" "sshd MaxAuthTries"
    check_eq "$(extract_sshd_value "$sshd_fixture" X11Forwarding)" "yes" "sshd X11Forwarding"
    check_eq "$(extract_sshd_value "$sshd_fixture" Subsystem)" "sftp /usr/lib/ssh/sftp-server" "sshd value containing spaces"
    check_eq "$(extract_chage_value "$chage_fixture" "Maximum number of days")" "99999" "chage max"
    check_eq "$(extract_chage_value "$chage_fixture" "Minimum number of days")" "0" "chage min"
    check_eq "$(extract_chage_value "$chage_fixture" "Number of days of warning")" "7" "chage warn"

    if extract_sshd_value "$sshd_fixture" NoSuchDirective >/dev/null 2>&1; then
        echo "  FAIL absent sshd directive must return non-zero"
        failures=$((failures + 1))
    else
        echo "  ok   absent sshd directive returns non-zero"
    fi

    if extract_chage_value "$chage_fixture" "No Such Label" >/dev/null 2>&1; then
        echo "  FAIL absent chage label must return non-zero"
        failures=$((failures + 1))
    else
        echo "  ok   absent chage label returns non-zero"
    fi

    # ssh_system_value is pure once the capture is stubbed, so its two failure
    # modes are pinned here rather than only by hand. Both must return non-zero:
    # an oracle that was never initialised and a directive sshd does not report
    # would otherwise print nothing and read exactly like a pass.
    SSHD_EFFECTIVE=""
    if ssh_system_value PermitRootLogin >/dev/null 2>&1; then
        echo "  FAIL uninitialised ssh oracle must return non-zero"
        failures=$((failures + 1))
    else
        echo "  ok   uninitialised ssh oracle returns non-zero"
    fi

    SSHD_EFFECTIVE="$sshd_fixture"
    check_eq "$(ssh_system_value PermitRootLogin)" "no" "ssh_system_value reads the captured output"
    if ssh_system_value NoSuchDirective >/dev/null 2>&1; then
        echo "  FAIL ssh_system_value must return non-zero for an absent directive"
        failures=$((failures + 1))
    else
        echo "  ok   ssh_system_value returns non-zero for an absent directive"
    fi
    SSHD_EFFECTIVE=""

    if (( failures > 0 )); then
        echo "self-test: $failures failure(s)"
        return 1
    fi
    echo "self-test: all extractor checks passed"
}

# The full run: gate, then oracles, then assertions.
# The assertions arrive with the remaining tasks. Until they do this returns
# non-zero deliberately, because a suite that checks nothing and exits 0 is the
# exact failure this harness exists to catch.
run_full_suite() {
    require_container_root || return 1
    ssh_oracle_init || return 1
    echo "INCOMPLETE: the ssh oracle is wired but no assertions run yet." >&2
    echo "  Refusing to report success for a run that checked nothing." >&2
    return 1
}

main() {
    case "${1:-}" in
        --self-test)
            self_test
            ;;
        -h|--help)
            usage
            ;;
        "")
            run_full_suite
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            return 1
            ;;
    esac
}

main "$@"
