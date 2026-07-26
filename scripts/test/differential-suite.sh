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

usage() {
    cat <<'EOF'
Usage:
  differential-suite.sh --self-test   # extractors only, safe anywhere
  differential-suite.sh               # full run, container + root only
EOF
}

# The first line of captured output matching a pattern, or nothing when the
# pattern matched nothing.
# Matched case insensitively: sshd has printed its directives lowercased in the
# past and preserves case now, and a matcher that assumes either finds nothing on
# the other, which reads exactly like "directive absent". chage's labels are
# stable English, so this costs nothing there.
# Returns 2, loudly, when grep rejected the pattern itself. A plain `|| true`
# swallowed that into "no match", so a malformed pattern read as an absent
# directive: fail-closed, but misdiagnosed, and the two are worth telling apart.
first_matching_line() {
    local output="$1" pattern="$2" line status=0
    line="$(printf '%s\n' "$output" | grep -im1 "$pattern")" || status=$?
    if (( status > 1 )); then
        echo "FATAL: grep rejected the pattern '$pattern'" >&2
        return 2
    fi
    printf '%s' "$line"
}

# Extract one directive's effective value from captured `sshd -T` output.
# Prints nothing and returns 1 when the directive really is absent, which the
# caller must treat as a failure rather than a pass.
extract_sshd_value() {
    local output="$1" directive="$2" line rest
    line="$(first_matching_line "$output" "^${directive}[[:space:]]")" || return 2
    if [[ -z "$line" ]]; then
        return 1
    fi
    # Split on the whitespace class the matcher accepts. `cut -d' '` split on a
    # literal space alone, so a tab-separated line would have matched and then
    # yielded the whole line, directive name included, as its own value.
    read -r _ rest <<<"$line"
    printf '%s' "$rest"
}

# Extract one value from captured `chage -l` output by its label prefix.
# Returns 1 when the label is absent, 2 when the pattern was rejected.
extract_chage_value() {
    local output="$1" label="$2" line
    line="$(first_matching_line "$output" "^${label}")" || return 2
    if [[ -z "$line" ]]; then
        return 1
    fi
    printf '%s' "${line#*:}" | tr -d '[:space:]'
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

# The freshness stamp, shared by both oracle families.
#
# An oracle capture is evidence about the system as it stood when it was taken,
# and this suite exists to compare the system AFTER apply. A capture taken before
# apply is not merely weaker evidence, it is wrong in the one direction that
# matters: against a stock sshd, X11Forwarding and PermitEmptyPasswords already
# hold the values the tool targets, so two of the seven ssh checks would report
# green on a container nothing had been applied to.
#
# So staleness is detected rather than avoided by convention. `apply` bumps the
# counter, each oracle records the counter's value as it captures, and each
# accessor refuses a capture stamped with anything but the current value.
#
# Generation 0 means no apply has been recorded at all, which every accessor
# refuses outright. Otherwise "call bump_apply_generation from the apply step"
# would be the convention this replaces, and forgetting it would leave the whole
# stamp silent.
APPLY_GENERATION=0

# Call this from whatever performs `apply`, before reading any oracle again.
bump_apply_generation() {
    APPLY_GENERATION=$((APPLY_GENERATION + 1))
}

# Refuse a capture that was never taken, that no apply preceded, or that predates
# the most recent apply.
# Arguments: the oracle's name (which is also its init function's prefix), the
# capture itself, and the generation the capture recorded.
require_fresh_capture() {
    local oracle="$1" capture="$2" generation="$3"
    if [[ -z "$capture" ]]; then
        echo "FATAL: $oracle oracle not initialised; ${oracle}_oracle_init must run first" >&2
        return 1
    fi
    if (( APPLY_GENERATION == 0 )); then
        echo "FATAL: $oracle oracle read before any apply was recorded." >&2
        echo "  Whatever runs apply must call bump_apply_generation, or every check" >&2
        echo "  compares the tool's targets against the container as it was found." >&2
        return 1
    fi
    if [[ "$generation" != "$APPLY_GENERATION" ]]; then
        echo "FATAL: $oracle oracle holds a stale capture: taken at generation" \
            "${generation:-unset}, apply has reached generation $APPLY_GENERATION." >&2
        echo "  Run ${oracle}_oracle_init after every apply. A capture taken before one" >&2
        echo "  describes the unhardened system and can read as a pass." >&2
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

# Captured by ssh_oracle_init, which must run after apply. Empty means the
# capture never happened, which ssh_system_value treats as fatal: a missing
# capture must not read like an absent directive, and an absent directive must
# not read like a pass.
SSHD_EFFECTIVE=""
SSHD_EFFECTIVE_GENERATION=""

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
    SSHD_EFFECTIVE_GENERATION="$APPLY_GENERATION"
}

# Print the value sshd itself is enforcing for one directive.
# Returns non-zero, loudly, when the oracle was never initialised, the capture
# predates the last apply, or the directive is absent or carries no value, so the
# caller fails the check instead of skipping it.
ssh_system_value() {
    local directive="$1" value
    require_fresh_capture ssh "$SSHD_EFFECTIVE" "$SSHD_EFFECTIVE_GENERATION" || return 1
    if ! value="$(extract_sshd_value "$SSHD_EFFECTIVE" "$directive")"; then
        echo "FATAL: sshd -T does not report '$directive'" >&2
        return 1
    fi
    # sshd -T prints no such line, but a directive present with an empty value
    # would otherwise return 0 with empty stdout, which is the shape of a check
    # that silently passes. This makes "undeterminable is a failure" total.
    if [[ -z "$value" ]]; then
        echo "FATAL: sshd -T reports '$directive' with no value" >&2
        return 1
    fi
    printf '%s' "$value"
}

# login.defs supplies defaults for NEW accounts only, so the only honest way to
# ask what it currently means is to create a user and read what shadow gave it.
# chage -l on an account that already exists reports that account's /etc/shadow
# row, written when it was created, which says nothing about the file today.
DIFF_PROBE_USER="hardenerdiffprobe"

# The PASS_* directives, the chage -l label reporting each one, and the value
# the tool targets. Fields: directive|label|target.
LOGIN_DEFS_CHECKS=(
    "PASS_MIN_DAYS|Minimum number of days|1"
    "PASS_MAX_DAYS|Maximum number of days|90"
    "PASS_WARN_AGE|Number of days of warning|7"
)

# Refuse to touch an account this suite did not create. The probe deletes the
# user it makes, so one that is already there must stop the run rather than be
# removed: it may be a real account, or a leak from an interrupted run.
require_absent_probe_user() {
    if id "$DIFF_PROBE_USER" >/dev/null 2>&1; then
        echo "FATAL: user '$DIFF_PROBE_USER' already exists; refusing to delete it." >&2
        echo "  This suite creates that account as a probe and removes it again." >&2
        echo "  If it is left over from an interrupted run, remove it by hand:" >&2
        echo "    userdel -r $DIFF_PROBE_USER" >&2
        return 1
    fi
}

# Remove the probe user and confirm it is gone. userdel's own status is not
# enough: it reports 12 when the account went but the home directory stayed.
# A survivor is fatal, because every later run then aborts at the guard above.
remove_probe_user() {
    userdel -r "$DIFF_PROBE_USER" >/dev/null 2>&1 || true
    if id "$DIFF_PROBE_USER" >/dev/null 2>&1; then
        echo "FATAL: probe user '$DIFF_PROBE_USER' survived cleanup; remove it by hand" >&2
        return 1
    fi
}

# Create the probe user, read the shadow row login.defs just gave it, and remove
# the user again. Prints chage -l verbatim, which carries min, max and warn.
# Callers want login_defs_system_value; this runs once, through the init below.
login_defs_system_values() {
    require_absent_probe_user || return 1
    if ! useradd -m "$DIFF_PROBE_USER" >/dev/null 2>&1; then
        echo "FATAL: could not create probe user" >&2
        return 1
    fi
    local out
    # LC_ALL=C: the labels in LOGIN_DEFS_CHECKS are chage's untranslated
    # English, and a translated label would match nothing, which reads exactly
    # like an absent value.
    if ! out="$(LC_ALL=C chage -l "$DIFF_PROBE_USER" 2>&1)"; then
        echo "FATAL: chage -l failed: $out" >&2
        remove_probe_user || true
        return 1
    fi
    remove_probe_user || return 1
    printf '%s' "$out"
}

# Captured by login_defs_oracle_init, which must run after apply. Empty means the
# capture never happened, which login_defs_system_value treats as fatal for the
# same reason as the ssh oracle: a missing capture must not read like an absent
# value, and an absent value must not read like a pass.
# The probe reads what login.defs means NOW, so a capture taken before apply
# describes the old file. That is what the generation stamp catches.
LOGIN_DEFS_CHAGE=""
LOGIN_DEFS_CHAGE_GENERATION=""

login_defs_oracle_init() {
    local out
    if ! out="$(login_defs_system_values)"; then
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo "FATAL: chage -l succeeded but printed nothing" >&2
        return 1
    fi
    LOGIN_DEFS_CHAGE="$out"
    LOGIN_DEFS_CHAGE_GENERATION="$APPLY_GENERATION"
}

# The chage -l label that reports one PASS_* directive.
login_defs_label() {
    local directive="$1" entry name label
    for entry in "${LOGIN_DEFS_CHECKS[@]}"; do
        IFS='|' read -r name label _ <<<"$entry"
        if [[ "$name" == "$directive" ]]; then
            printf '%s' "$label"
            return 0
        fi
    done
    return 1
}

# Print what login.defs currently means for one PASS_* directive, as shadow
# applied it to a brand new account.
# Returns non-zero, loudly, when the oracle was never initialised, its capture
# predates the last apply, the directive is not in the table, or chage did not
# report it.
login_defs_system_value() {
    local directive="$1" label
    require_fresh_capture login_defs "$LOGIN_DEFS_CHAGE" "$LOGIN_DEFS_CHAGE_GENERATION" || return 1
    if ! label="$(login_defs_label "$directive")"; then
        echo "FATAL: no chage label known for '$directive'" >&2
        return 1
    fi
    if ! extract_chage_value "$LOGIN_DEFS_CHAGE" "$label"; then
        echo "FATAL: chage -l does not report '$label' for '$directive'" >&2
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

    # Assert a command's own exit status. Taken directly, never through a pipe,
    # which would report the last stage's status instead. Every fail-closed path
    # in this script is checked with this: a function that returns 0 while
    # printing nothing is the exact shape of a check that silently passes.
    check_status() {
        local want="$1" what="$2"
        shift 2
        local got=0
        "$@" >/dev/null 2>&1 || got=$?
        if [[ "$got" == "$want" ]]; then
            echo "  ok   $what"
        else
            echo "  FAIL $what: exit $got, want $want"
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

    check_status 1 "absent sshd directive returns non-zero" \
        extract_sshd_value "$sshd_fixture" NoSuchDirective
    check_status 1 "absent chage label returns non-zero" \
        extract_chage_value "$chage_fixture" "No Such Label"

    # A pattern grep rejects must not read as an absent directive. An unmatched
    # '\(' is an invalid BRE, so grep exits 2, which the old `|| true` swallowed.
    check_status 2 "a rejected sshd pattern is not reported as an absent directive" \
        extract_sshd_value "$sshd_fixture" '\('
    check_status 2 "a rejected chage pattern is not reported as an absent label" \
        extract_chage_value "$chage_fixture" '\('

    # ssh_system_value is pure once the capture is stubbed, so its failure modes
    # are pinned here rather than only by hand. Each must return non-zero: an
    # oracle that was never initialised, a capture no apply preceded, a capture
    # older than the last apply, a directive sshd does not report, and a
    # directive present with no value would all otherwise print nothing, or the
    # wrong thing, and read as a pass.
    SSHD_EFFECTIVE=""
    SSHD_EFFECTIVE_GENERATION=""
    check_status 1 "uninitialised ssh oracle returns non-zero" \
        ssh_system_value PermitRootLogin

    # Driven through the real init, with the capture stubbed: ssh-keygen -A and
    # sshd -T both want root, and --self-test must stay runnable with neither
    # root nor a container. The fixture is a variable rather than a second stub
    # definition, so it can be swapped without redefining the function.
    local sshd_capture="$sshd_fixture"
    ensure_host_keys() { :; }
    capture_sshd_effective() { printf '%s' "$sshd_capture"; }

    # The freshness stamp, walked through the lifecycle a real run has. Against a
    # stock sshd, X11Forwarding and PermitEmptyPasswords already hold the values
    # the tool targets, so a capture taken before apply reads as a pass for two
    # of the seven ssh directives on a container nothing has been applied to.
    # Both routes to one must fail: an apply step that never bumps the
    # generation, and a capture taken above the apply that did.
    #
    # The inits are called directly rather than through check_status, because a
    # static analyser resolves which commands the stubs above stand in for, and a
    # function name passed as an argument breaks that chain, which makes every
    # stub in this function read as dead code.
    local init_status=0
    ssh_oracle_init || init_status=$?
    check_eq "$init_status" "0" "ssh_oracle_init succeeds against the stubbed capture"
    check_status 1 "ssh read with no apply recorded returns non-zero" \
        ssh_system_value PermitRootLogin
    bump_apply_generation
    check_status 1 "ssh read from a capture older than the last apply returns non-zero" \
        ssh_system_value PermitRootLogin
    init_status=0
    ssh_oracle_init || init_status=$?
    check_eq "$init_status" "0" "ssh_oracle_init re-captures after apply"
    check_eq "$(ssh_system_value PermitRootLogin)" "no" "a capture taken after apply reads"

    check_status 1 "ssh_system_value returns non-zero for an absent directive" \
        ssh_system_value NoSuchDirective

    # A directive present with no value. Built with printf so the trailing
    # separator survives anything that strips trailing whitespace.
    sshd_capture="$(printf 'PermitRootLogin no\nValuelessDirective \n')"
    init_status=0
    ssh_oracle_init || init_status=$?
    check_eq "$init_status" "0" "ssh_oracle_init captures the valueless fixture"
    check_status 1 "a valueless sshd directive returns non-zero" \
        ssh_system_value ValuelessDirective

    APPLY_GENERATION=0
    SSHD_EFFECTIVE=""
    SSHD_EFFECTIVE_GENERATION=""
    unset -f ensure_host_keys capture_sshd_effective

    # The login.defs oracle. The fixture values are deliberately unlike the
    # targets (1, 90, 7) and unlike the values the shipped defect leaves behind
    # (0, 99999, 7): against either of those a stub returning a constant would
    # read as a pass, and the oracle would be proving nothing.
    local probe_fixture="Last password change					: Dec 24, 2024
Minimum number of days between password change		: 5
Maximum number of days between password change		: 42
Number of days of warning before password expires	: 11"

    LOGIN_DEFS_CHAGE=""
    LOGIN_DEFS_CHAGE_GENERATION=""
    check_status 1 "uninitialised login.defs oracle returns non-zero" \
        login_defs_system_value PASS_MAX_DAYS

    # Distinct values per label, so a table that crosses two directives fails
    # here rather than reporting the wrong setting as compliant. The probe stubs
    # the accessor needs are defined further down, so the capture is planted
    # directly, generation included: an unstamped capture is a stale one, and a
    # capture with no apply recorded is refused outright. The bump stands in for
    # the apply step a real run has above this point.
    bump_apply_generation
    LOGIN_DEFS_CHAGE="$probe_fixture"
    LOGIN_DEFS_CHAGE_GENERATION="$APPLY_GENERATION"
    check_eq "$(login_defs_system_value PASS_MIN_DAYS)" "5" "login.defs PASS_MIN_DAYS reads the min label"
    check_eq "$(login_defs_system_value PASS_MAX_DAYS)" "42" "login.defs PASS_MAX_DAYS reads the max label"
    check_eq "$(login_defs_system_value PASS_WARN_AGE)" "11" "login.defs PASS_WARN_AGE reads the warn label"
    check_status 1 "login.defs directive outside the table returns non-zero" \
        login_defs_system_value PASS_NO_SUCH_DIRECTIVE
    LOGIN_DEFS_CHAGE=""
    LOGIN_DEFS_CHAGE_GENERATION=""

    # The probe creates a real account, so its two safety properties are pinned
    # here rather than only by hand: it never deletes a user it did not create,
    # and it never leaves one behind. useradd, userdel, chage and id are stubbed
    # against a variable standing in for the account database, which keeps
    # --self-test runnable with no root and no container.
    local probe_stub_exists=0 probe_stub_chage=0 probe_stub_userdel=1
    useradd() { probe_stub_exists=1; }
    userdel() {
        if [[ "$probe_stub_userdel" == 1 ]]; then
            probe_stub_exists=0
        fi
    }
    id() { [[ "$probe_stub_exists" == 1 ]]; }
    chage() {
        if [[ "$probe_stub_chage" != 0 ]]; then
            return "$probe_stub_chage"
        fi
        printf '%s\n' "$probe_fixture"
    }

    probe_stub_exists=1
    check_status 1 "probe refuses when the probe user already exists" \
        login_defs_system_values
    check_eq "$probe_stub_exists" "1" "probe leaves a pre-existing user alone"

    probe_stub_exists=0
    probe_stub_chage=1
    check_status 1 "probe returns non-zero when chage fails" login_defs_system_values
    check_eq "$probe_stub_exists" "0" "probe removes the user after a chage failure"

    probe_stub_chage=0
    check_status 0 "probe returns zero on the success path" login_defs_system_values
    check_eq "$probe_stub_exists" "0" "probe removes the user on the success path"

    # A cleanup that failed quietly would leak the account and abort every later
    # run at the guard, so the survivor check is pinned too: with userdel
    # neutered the probe must fail rather than report a value.
    probe_stub_userdel=0
    check_status 1 "probe fails when cleanup leaves the user behind" login_defs_system_values
    probe_stub_userdel=1
    probe_stub_exists=0

    # The whole chain, from the probe through the init to one directive.
    init_status=0
    login_defs_oracle_init || init_status=$?
    check_eq "$init_status" "0" "login_defs_oracle_init succeeds against the stubbed probe"
    check_eq "$(login_defs_system_value PASS_MAX_DAYS)" "42" "login_defs_oracle_init feeds the accessor"

    # The same freshness stamp as the ssh oracle, and the same hazard: the probe
    # reads what login.defs means NOW, so a capture taken before apply describes
    # the old file. PASS_WARN_AGE's target already equals the value several
    # distributions ship, which is exactly how that reads as a pass.
    bump_apply_generation
    check_status 1 "login.defs read from a capture older than the last apply returns non-zero" \
        login_defs_system_value PASS_MAX_DAYS
    init_status=0
    login_defs_oracle_init || init_status=$?
    check_eq "$init_status" "0" "login_defs_oracle_init re-captures after apply"
    check_eq "$(login_defs_system_value PASS_MAX_DAYS)" "42" "a login.defs capture taken after apply reads again"

    APPLY_GENERATION=0
    LOGIN_DEFS_CHAGE=""
    LOGIN_DEFS_CHAGE_GENERATION=""
    unset -f useradd userdel id chage

    if (( failures > 0 )); then
        echo "self-test: $failures failure(s)"
        return 1
    fi
    echo "self-test: all extractor checks passed"
}

# The full run: gate, then apply, then the oracle captures, then the assertions.
#
# Apply and the assertions arrive with the remaining task. Until they do this
# returns non-zero deliberately, because a suite that checks nothing and exits 0
# is the exact failure this harness exists to catch.
#
# The order is load-bearing, so neither oracle is initialised here. Whatever runs
# apply must call bump_apply_generation, and both ssh_oracle_init and
# login_defs_oracle_init must run after it. An init left above apply is caught at
# the first read by require_fresh_capture rather than quietly answering from a
# snapshot of the unhardened container.
run_full_suite() {
    require_container_root || return 1
    echo "INCOMPLETE: apply, the oracle captures and the assertions are not wired yet." >&2
    echo "  Refusing to report success for a run that checked nothing." >&2
    return 1
}

main() {
    set -euo pipefail
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

# Run only on direct execution. Sourcing this file to drive one function, which
# is how its failure paths get exercised, would otherwise run the whole dispatch
# with the caller's positional parameters. `set -euo pipefail` moved into main
# for the same reason: it belongs to this script's own run, not to the shell of
# whoever sourced it.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
