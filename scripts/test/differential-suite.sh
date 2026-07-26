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

    if (( failures > 0 )); then
        echo "self-test: $failures failure(s)"
        return 1
    fi
    echo "self-test: all extractor checks passed"
}

main() {
    case "${1:-}" in
        --self-test)
            self_test
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Only --self-test is available so far; refusing to run." >&2
            usage >&2
            return 1
            ;;
    esac
}

main "$@"
