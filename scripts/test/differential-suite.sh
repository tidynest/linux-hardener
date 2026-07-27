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

# The tree this script sits in, and the CLI under test. Same resolution as
# scripts/test/full-test-suite.sh: the musl build first, because that is what
# the containers execute, then a host build.
# Resolved when the file loads, so --self-test still runs where neither exists;
# the full run refuses before it applies anything.
DIFF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIFF_PROJECT_DIR="$(cd "$DIFF_SCRIPT_DIR/../.." && pwd)"

# An explicit $BINARY is taken exactly as given, and is never replaced by a
# build from the tree when it turns out not to be executable. Falling back there
# runs a binary the operator did not name and reports the result as if it were
# theirs, so a typo in the path silently moves the whole run onto whatever the
# tree happens to hold. Kept in a function so --self-test can drive both
# branches without a second copy of the resolution.
BINARY_EXPLICIT=0

resolve_binary() {
    if [[ -n "${BINARY:-}" ]]; then
        BINARY_EXPLICIT=1
        return 0
    fi
    BINARY_EXPLICIT=0
    BINARY="$DIFF_PROJECT_DIR/target/x86_64-unknown-linux-musl/release/hardener"
    [[ -x "$BINARY" ]] || BINARY="$DIFF_PROJECT_DIR/target/release/hardener"
}
resolve_binary

# The plugins whose settings this suite compares. Applying only these keeps the
# run to what is actually asserted.
DIFF_PLUGINS=(ssh-hardening pam-hardening)

# Every external command the full run depends on.
#
# jq is listed first because it is the newest of them and the likeliest to be
# absent: the openSUSE package install in scripts/containers/create-container.sh
# ends in `|| log_warn`, so a container can be built successfully with packages
# missing. Without jq the scan comparison would find nothing, and finding
# nothing is indistinguishable from "the tool reported no finding", which is the
# pass condition. An oracle that cannot run is a failure, never a skip, so the
# whole set is checked up front and named when it is incomplete.
REQUIRED_COMMANDS=(jq grep sshd ssh-keygen useradd userdel chage id)

# Refuse, naming every command that is missing rather than one per run.
require_commands() {
    local cmd missing=()
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        echo "FATAL: required command(s) not found: ${missing[*]}" >&2
        echo "  Every check depends on them, and a check that cannot run is a" >&2
        echo "  failure here, not a skip. Install them and run the suite again." >&2
        return 1
    fi
}

# sshd refuses to parse a configuration without its compiled-in privilege
# separation directory, and on a booted host systemd creates that directory
# through `RuntimeDirectory=sshd`. This suite runs under `nspawn --pipe`, where
# nothing boots, so on Debian the directory is simply absent and every ssh
# oracle dies on "Missing privilege separation directory" before it can read a
# single value. The container is not wrong; it has just never been booted.
#
# Create exactly the directory sshd names, and only when sshd names one: a
# container that already has it is left untouched, and any other sshd complaint
# is left for the oracle to report rather than being second-guessed here.
require_sshd_privsep_dir() {
    local complaint dir
    # `if` rather than `sshd -t && return 0`: under `set -e` the exemption for a
    # failing left operand does not extend to the status of the list itself.
    if complaint=$(sshd -t 2>&1); then
        return 0
    fi
    # sshd's message arrives carriage-return terminated under nspawn's console
    # handling, and `mkdir "/run/sshd\r"` creates a directory sshd will never
    # look for while the line reporting it reads exactly right. Strip the
    # carriage returns, and any other surrounding blank, before the path is used
    # for anything at all.
    dir=$(printf '%s\n' "$complaint" | tr -d '\r' |
        sed -n 's/^Missing privilege separation directory:[[:space:]]*//p' |
        sed 's/[[:space:]]*$//' | head -1)
    [[ -n "$dir" ]] || return 0
    if ! mkdir -p "$dir" || ! chmod 0755 "$dir"; then
        echo "FATAL: sshd needs the privilege separation directory $dir, and it" >&2
        echo "  could not be created. Every ssh oracle reads through sshd, so a" >&2
        echo "  run without it would compare nothing and print a clean summary." >&2
        return 1
    fi
    # Creating it is not the same as fixing it. Ask sshd again rather than
    # assume, and carry what it still says: a guard that reports a success it
    # never observed is the exact failure this suite exists to catch, and the
    # first version of this function shipped with that defect.
    if complaint=$(sshd -t 2>&1); then
        echo "Created sshd privilege separation directory $dir (nothing booted to create it)"
        return 0
    fi
    echo "FATAL: created $dir, and sshd still refuses to parse a configuration:" >&2
    printf '  %s\n' "$complaint" >&2
    ls -ld "$dir" >&2 || echo "  and $dir does not stat" >&2
    return 1
}

# Refuse a binary that is absent or not executable, before apply rather than
# after: half a destructive run tells nobody anything.
require_binary() {
    if [[ ! -x "$BINARY" ]]; then
        echo "FATAL: no executable hardener binary at '$BINARY'" >&2
        if (( BINARY_EXPLICIT == 1 )); then
            echo "  BINARY names that path, so no build from the tree was substituted" >&2
            echo "  for it. Correct the path, or unset BINARY to test the tree's build." >&2
        else
            echo "  Build the musl CLI, or set BINARY to the one you want tested." >&2
        fi
        return 1
    fi
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

# The ssh directives this suite checks and the value the tool targets for each,
# verified against SSH_DIRECTIVES in crates/hardener-plugins/src/ssh/mod.rs.
# Fields: directive|target.
SSH_CHECKS=(
    "PermitRootLogin|no"
    "PasswordAuthentication|no"
    "PermitEmptyPasswords|no"
    "MaxAuthTries|3"
    "X11Forwarding|no"
    "ClientAliveInterval|300"
    "ClientAliveCountMax|2"
)

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

# The lengths of the three tables the run is sized by, pinned as literals.
#
# A count derived from a table cannot notice that table being edited down: with
# SSH_CHECKS emptied, a run over the login.defs directives alone would agree
# with itself, exit 0, and be reported as a PASS by
# scripts/test/run-cross-distro-tests.sh. So the sizes are written out here, and
# every expectation below is counted off these literals rather than off the
# tables, which is what keeps the two independent: the tables are what the run
# iterates, and these are what it is measured against. Adding a directive means
# changing the literal on purpose.
SSH_CHECKS_EXPECTED=7
LOGIN_DEFS_CHECKS_EXPECTED=3
DIFF_PLUGINS_EXPECTED=2

require_check_tables() {
    local entry name got want refused=0
    for entry in \
        "SSH_CHECKS ${#SSH_CHECKS[@]} $SSH_CHECKS_EXPECTED" \
        "LOGIN_DEFS_CHECKS ${#LOGIN_DEFS_CHECKS[@]} $LOGIN_DEFS_CHECKS_EXPECTED" \
        "DIFF_PLUGINS ${#DIFF_PLUGINS[@]} $DIFF_PLUGINS_EXPECTED"; do
        read -r name got want <<<"$entry"
        if [[ "$got" != "$want" ]]; then
            echo "FATAL: $name holds $got, expected $want." >&2
            refused=1
        fi
    done
    if (( refused > 0 )); then
        echo "  A shortened table makes a smaller run look like a complete one, because" >&2
        echo "  every total printed below is counted off the tables themselves. Restore" >&2
        echo "  the entry, or change the expected length beside the table if it was" >&2
        echo "  removed deliberately." >&2
        return 1
    fi
}

# Two assertions per compared directive, plus one pre-apply control per plugin.
# print_summary refuses a run whose totals do not come to this: a loop that
# skipped a directive, or a check that recorded nothing at all, would otherwise
# leave a partial run reading as a complete one.
#
# Counted off the pinned lengths above, never off the tables themselves. Read
# from ${#SSH_CHECKS[@]} the expectation would follow the table it exists to
# police: emptying that table would drop the number from 22 to 8 and
# print_summary would then accept the shorter run, which is the guard asking the
# tables whether the tables are right.
expected_check_total() {
    printf '%s' "$(( 2 * (SSH_CHECKS_EXPECTED + LOGIN_DEFS_CHECKS_EXPECTED) + DIFF_PLUGINS_EXPECTED ))"
}

# The two plugins spell their finding ids differently, and a filter written for
# one convention matches NOTHING under the other. Matching nothing returns an
# empty result, which reads as "the tool reported no finding", which is the pass
# condition, so this is the single most likely way to build a harness that
# passes on broken code. Each convention is derived in exactly one place and
# pinned to a literal id by the self-test.

# ssh lowercases the directive: format!("ssh-{}", name.to_lowercase()), so
# PermitRootLogin becomes ssh-permitrootlogin.
ssh_finding_id() {
    printf 'ssh-%s' "${1,,}"
}

# pam does not: format!("pam-{}", name), so PASS_MAX_DAYS keeps its case and
# becomes pam-PASS_MAX_DAYS.
pam_finding_id() {
    printf 'pam-%s' "$1"
}

# What the tool REPORTED, as against what the system holds. Captured by
# scan_oracle_init, which must run after apply: a scan taken before it describes
# the container as it was found, and the generation stamp catches that.
SCAN_JSON=""
SCAN_JSON_GENERATION=""

# The same document captured BEFORE apply, which is this suite's positive
# control. Its own variable and its own stamp, so neither rule has to be
# loosened for the other: a post-apply capture is refused unless it carries the
# current generation, and this one is refused unless it was taken at 0.
#
# Why it exists. After a successful apply every compared directive sits at its
# target, so every second assertion expects zero findings and is given zero:
# on a green run not one finding filter is ever asked to match anything. A
# mistyped id, a renamed plugin_id and a plugin whose scan failed outright all
# produce that same zero, and the JSON cannot even express the last of them.
# `scan --format json` serialises plugin_id, plugin_name, findings and
# unchecked, and neither scan_success nor scan_error, so a plugin that failed to
# scan emits exactly what a fully compliant host emits. A capture taken while
# the container is known to be unhardened is the only thing in reach that tells
# those apart.
PRE_APPLY_SCAN_JSON=""
PRE_APPLY_SCAN_GENERATION=""

# `scan --format json` prints an array of plugin objects on stdout; in JSON mode
# its status, warning and error lines go to stderr. The command's own status is
# tested, never a pipeline's.
#
# Its stderr is deliberately left alone rather than discarded: it is where the
# tool explains a failure, and the container run folds stderr into the same log.
# It cannot reach stdout, so it cannot corrupt the document.
#
# What stdout carries is checked rather than assumed. Today the scan path prints
# the array and nothing else, but output::info prints a JSON object on stdout in
# JSON mode, so validate_scan_document requires exactly one document there.
capture_scan_json() {
    local out args=() plugin
    for plugin in "${DIFF_PLUGINS[@]}"; do
        args+=(--plugin "$plugin")
    done
    if ! out="$("$BINARY" --format json scan "${args[@]}")"; then
        echo "FATAL: scan --format json failed" >&2
        return 1
    fi
    printf '%s' "$out"
}

# One of the plugin object's two arrays, present and actually an array. Silent:
# the caller names the array it asked about, because the two absences mean
# different things and want different advice.
#
# Compared against the single-element array rather than read through `jq -e`, so
# the result is one value whatever the document holds.
has_scan_array() {
    local document="$1" plugin="$2" array="$3"
    jq --exit-status --arg p "$plugin" --arg a "$array" \
        '[.[] | select(.plugin_id == $p) | has($a) and (.[$a] | type == "array")] == [true]' \
        >/dev/null <<<"$document"
}

# Refuse a scan document this suite cannot read the way it intends to.
#
# Every refusal below covers a shape that would otherwise read as a clean bill
# of health, because each filter here counts entries and zero is the pass
# condition. The plugin object's key set is built by hand in
# crates/hardener-cli/src/output.rs, is not a checked contract, and has already
# changed once in this project's history: `unchecked` was added to it after the
# first of these filters was written. A key that is absent or renamed counts
# zero under a `// []` default, so the keys are required rather than defaulted.
validate_scan_document() {
    local document="$1" label="$2" plugin count
    # jq's own parse error is left visible above this message: "not an array"
    # and "not JSON at all" are worth telling apart.
    #
    # Slurped, so the whole of stdout is judged rather than its last value.
    # `jq -e` reports on the last value a filter produced, and output::info
    # prints a JSON object on stdout in JSON mode, so a document with an info
    # line ahead of it would satisfy an unslurped guard. That call site is one
    # command away from the scan path today.
    if ! jq -e -s 'length == 1 and (.[0] | type == "array")' >/dev/null <<<"$document"; then
        echo "FATAL: $label did not print exactly one JSON array on stdout" >&2
        return 1
    fi
    # Every plugin being compared must appear exactly once. A plugin the config
    # disabled, or one that failed to run, contributes no object at all, and
    # then every finding filter against it matches nothing, which reads as a
    # clean directive rather than as the missing evidence it is.
    for plugin in "${DIFF_PLUGINS[@]}"; do
        if ! count="$(jq -r --arg p "$plugin" '[.[] | select(.plugin_id == $p)] | length' <<<"$document")"; then
            echo "FATAL: jq could not read the $label output" >&2
            return 1
        fi
        if [[ "$count" != "1" ]]; then
            echo "FATAL: $label reported $count object(s) for plugin '$plugin', expected exactly 1." >&2
            echo "  Every finding filter for that plugin would match nothing, which reads as a pass." >&2
            return 1
        fi
        # Asked one array at a time, so the refusal can name the one that is
        # missing. The two absences are not the same fault: output with no
        # `findings` is not the shape this suite reads at all, while output with
        # no `unchecked` is a CLI built before 3c15dc2 added the key, and only
        # the second is fixed by rebuilding.
        if ! has_scan_array "$document" "$plugin" findings; then
            echo "FATAL: the $label object for plugin '$plugin' has no 'findings' array." >&2
            echo "  Findings are counted by id here, and a key that is absent or renamed" >&2
            echo "  counts zero, which is this suite's pass condition. 'scan --format" >&2
            echo "  json' does not emit this shape: the key set output.rs builds by hand" >&2
            echo "  has changed." >&2
            return 1
        fi
        if ! has_scan_array "$document" "$plugin" unchecked; then
            echo "FATAL: the $label object for plugin '$plugin' has no 'unchecked' array." >&2
            echo "  It is what tells a check the tool could not run from one it ran and" >&2
            echo "  passed, and an absent key counts zero, which is this suite's pass" >&2
            echo "  condition. Rebuild the CLI from this tree, or set BINARY to a build" >&2
            echo "  that carries the key." >&2
            return 1
        fi
        # And the inner key those entries are read by, which nothing else can
        # prove. `finding_id` is exercised against live output on every run by
        # the pre-apply control; `unchecked_check_id` cannot be, because under
        # root the array is expected to be empty, and an empty array is what a
        # filter reading the wrong key returns as well. Renamed, every unchecked
        # lookup counts zero, and a directive the tool has stated it did not
        # check records two passes.
        #
        # Vacuously true while the array is empty, so it costs a correct run
        # nothing and bites only where there is something to read.
        if ! jq --exit-status --arg p "$plugin" \
            '[.[] | select(.plugin_id == $p)
                  | all(.unchecked[]; has("unchecked_check_id"))] == [true]' \
            >/dev/null <<<"$document"; then
            echo "FATAL: an 'unchecked' entry in the $label object for plugin '$plugin'" \
                "carries no 'unchecked_check_id'." >&2
            echo "  That id is the only thing that tells a check the tool could not run" >&2
            echo "  from one it ran and passed, and under a renamed key it counts zero," >&2
            echo "  which is this suite's pass condition. Rebuild the CLI from this tree," >&2
            echo "  or set BINARY to a build that carries the key." >&2
            return 1
        fi
    done
}

scan_oracle_init() {
    local out
    if ! out="$(capture_scan_json)"; then
        return 1
    fi
    validate_scan_document "$out" scan || return 1
    SCAN_JSON="$out"
    SCAN_JSON_GENERATION="$APPLY_GENERATION"
}

# The pre-apply capture, refused outright once an apply has been recorded. A
# "before" capture taken afterwards is not weaker evidence, it is the wrong
# document: it would report no finding for the directives apply has just fixed,
# which is the very silence this control exists to detect.
preapply_scan_oracle_init() {
    local out
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply scan capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It is what proves the finding filters can match anything at all, so it" >&2
        echo "  has to be taken while the container is still unhardened." >&2
        return 1
    fi
    if ! out="$(capture_scan_json)"; then
        return 1
    fi
    validate_scan_document "$out" "pre-apply scan" || return 1
    PRE_APPLY_SCAN_JSON="$out"
    PRE_APPLY_SCAN_GENERATION="$APPLY_GENERATION"
}

# The pre-apply capture's own freshness rule, the mirror image of
# require_fresh_capture: the only stamp that can be right on a document
# describing the system before apply is generation 0.
require_preapply_capture() {
    if [[ -z "$PRE_APPLY_SCAN_JSON" ]]; then
        echo "FATAL: pre-apply scan oracle not initialised;" \
            "preapply_scan_oracle_init must run before apply" >&2
        return 1
    fi
    if [[ "$PRE_APPLY_SCAN_GENERATION" != "0" ]]; then
        echo "FATAL: the pre-apply scan capture is stamped generation" \
            "${PRE_APPLY_SCAN_GENERATION:-unset}, so it was taken after an apply" \
            "and describes a system that had already been hardened." >&2
        return 1
    fi
}

# How many entries one of the document's two arrays holds for one id.
#
# `findings` and `unchecked` carry the same ids under different key names, and
# both are counted here so neither name is spelled in more than one place. The
# arrays are indexed directly rather than through `// []`: validate_scan_document
# has already refused a document where either is missing, and defaulting here
# would put back the very substitution of zero for "unreadable" that this suite
# exists to refuse.
count_scan_entries() {
    local document="$1" plugin="$2" array="$3" id="$4" field count
    case "$array" in
        findings) field="finding_id" ;;
        unchecked) field="unchecked_check_id" ;;
        *)
            echo "FATAL: no such scan array '$array'" >&2
            return 1
            ;;
    esac
    if ! count="$(jq -r --arg p "$plugin" --arg a "$array" --arg k "$field" --arg f "$id" \
        '[.[] | select(.plugin_id == $p) | .[$a][] | select(.[$k] == $f)] | length' \
        <<<"$document")"; then
        echo "FATAL: jq could not count $array entries for '$id'" >&2
        return 1
    fi
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        echo "FATAL: the $array count for '$id' is not a number: '$count'" >&2
        return 1
    fi
    printf '%s' "$count"
}

# How many findings the tool reported under one plugin for one finding id.
# Prints the count, which is legitimately 0 for a directive the tool considers
# compliant. Returns non-zero, loudly, when the oracle was never initialised,
# its capture predates the last apply, or jq could not produce a number, so an
# unreadable verdict is never mistaken for a clean one.
scan_finding_count() {
    local plugin="$1" finding="$2"
    require_fresh_capture scan "$SCAN_JSON" "$SCAN_JSON_GENERATION" || return 1
    count_scan_entries "$SCAN_JSON" "$plugin" findings "$finding"
}

# How many times the tool listed one id as a check it could NOT evaluate.
#
# The two arrays use identical ids on purpose, so this asks about the very id
# the finding filter counts. A directive listed here has no finding, and no
# finding is this suite's pass condition, which is its founding principle
# inverted: the tool's own "I could not determine this" would be scored as
# verification. The ssh plugin reaches that state for every one of its
# directives at once when sshd_config cannot be read, and reports the scan as
# successful while doing so.
scan_unchecked_count() {
    local plugin="$1" check="$2"
    require_fresh_capture scan "$SCAN_JSON" "$SCAN_JSON_GENERATION" || return 1
    count_scan_entries "$SCAN_JSON" "$plugin" unchecked "$check"
}

# How many findings the tool reported for one id BEFORE apply.
preapply_finding_count() {
    local plugin="$1" finding="$2"
    require_preapply_capture || return 1
    count_scan_entries "$PRE_APPLY_SCAN_JSON" "$plugin" findings "$finding"
}

# The second assertion, on its own so it can be pinned in all four directions.
# scan's verdict agrees with the system when a system that disagrees with the
# target produces at least one finding, and one that agrees produces none.
verdict_agrees() {
    local system="$1" target="$2" findings="$3"
    if [[ "$system" == "$target" ]]; then
        (( findings == 0 ))
    else
        (( findings > 0 ))
    fi
}

# Per-check bookkeeping. The summary vocabulary below is the one that
# scripts/test/run-cross-distro-tests.sh already parses out of a suite's log,
# so the host-side runner reports this suite through the machinery it has. No
# line printed before the summary may repeat those labels.
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0

record_pass() {
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    printf '  ok   %s\n' "$1"
}

record_fail() {
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    printf '  FAIL %s\n' "$1"
}

# The two assertions for one directive, given the value its oracle reported.
# Both are always recorded, so every directive contributes the same two checks
# whatever happens and one cannot quietly contribute fewer by going wrong.
compare_directive() {
    local plugin="$1" directive="$2" system="$3" target="$4" finding_id="$5" reported unchecked

    if [[ "$system" == "$target" ]]; then
        record_pass "$plugin $directive: the system holds '$system', the value the tool targets"
    else
        record_fail "$plugin $directive: the system holds '$system' but the tool targets '$target'; apply did not take effect"
    fi

    # Asked before the findings are counted, because it decides whether that
    # count means anything: the tool reports no finding for a check it never
    # ran, and no finding is the pass condition here.
    if ! unchecked="$(scan_unchecked_count "$plugin" "$finding_id")"; then
        record_fail "$plugin $directive: the tool's unchecked list could not be read for '$finding_id'"
        return 0
    fi
    if (( unchecked > 0 )); then
        record_fail "$plugin $directive: the tool did not check '$finding_id'; it lists the id as unchecked, which is neither agreement with the system nor a contradiction of it"
        return 0
    fi
    if ! reported="$(scan_finding_count "$plugin" "$finding_id")"; then
        record_fail "$plugin $directive: the tool's verdict for '$finding_id' could not be read"
        return 0
    fi
    if verdict_agrees "$system" "$target" "$reported"; then
        record_pass "$plugin $directive: the tool agrees with the system ($reported finding(s) for '$finding_id')"
    elif [[ "$system" == "$target" ]]; then
        record_fail "$plugin $directive: the tool reports $reported finding(s) for '$finding_id' while the system holds the target value '$system'"
    else
        record_fail "$plugin $directive: the tool claims a compliance the system does not have: no finding for '$finding_id' while the system holds '$system' and the tool targets '$target'"
    fi
}

# An oracle that cannot answer for one directive costs that directive both of
# its checks, as failures. Recording two keeps the totals comparable between a
# run where every oracle answered and one where some did not.
record_unresolved() {
    local plugin="$1" directive="$2" reason="$3"
    record_fail "$plugin $directive: $reason"
    record_fail "$plugin $directive: the tool's verdict was not compared, there is no system value to compare it against"
}

# Every (plugin, finding id) pair this suite compares, one per line, derived
# from the same two tables the checks below iterate, so a control cannot come to
# cover something other than what is actually compared.
compared_finding_ids() {
    local entry directive
    for entry in "${SSH_CHECKS[@]}"; do
        IFS='|' read -r directive _ <<<"$entry"
        printf '%s %s\n' ssh-hardening "$(ssh_finding_id "$directive")"
    done
    for entry in "${LOGIN_DEFS_CHECKS[@]}"; do
        IFS='|' read -r directive _ <<<"$entry"
        printf '%s %s\n' pam-hardening "$(pam_finding_id "$directive")"
    done
}

# The positive control: one check per plugin, over the capture taken before
# apply.
#
# After a successful apply every compared directive holds its target, so every
# second assertion expects no finding and is given none. Nothing in a green run
# then shows that these filters can match anything: a filter written under the
# other plugin's id convention, one naming a plugin_id that no longer exists,
# and a plugin whose scan failed all produce the same empty result. So the
# pre-apply capture, taken while the container is still unhardened, is required
# to have produced at least one finding for each plugin, counted through the
# very filter the comparison uses.
#
# Per plugin rather than in total, because a scan fails one plugin at a time.
# The JSON carries neither scan_success nor scan_error, so a plugin that failed
# emits the same empty arrays a fully compliant host does, and only a control
# scoped to that plugin can see the difference.
run_preapply_control() {
    local plugin entry_plugin id count matched total unreadable
    for plugin in "${DIFF_PLUGINS[@]}"; do
        matched=0
        total=0
        unreadable=0
        while read -r entry_plugin id; do
            [[ "$entry_plugin" == "$plugin" ]] || continue
            total=$((total + 1))
            if ! count="$(preapply_finding_count "$plugin" "$id")"; then
                unreadable=1
                break
            fi
            if (( count > 0 )); then
                matched=$((matched + 1))
            fi
        done < <(compared_finding_ids)
        if (( unreadable > 0 )); then
            record_fail "$plugin: the pre-apply scan could not be read, so nothing shows this plugin's finding filter can match at all"
        elif (( matched > 0 )); then
            record_pass "$plugin: before apply the tool reported findings for $matched of the $total compared directives, so the filter is proven against live output"
        else
            record_fail "$plugin: before apply the tool reported no finding for any of the $total compared directives, on a container nothing had been applied to; either the filter matches nothing or this plugin's scan produced nothing, and the JSON cannot tell those apart"
        fi
    done
}

run_ssh_checks() {
    local entry directive target system
    for entry in "${SSH_CHECKS[@]}"; do
        IFS='|' read -r directive target <<<"$entry"
        if ! system="$(ssh_system_value "$directive")"; then
            record_unresolved ssh-hardening "$directive" "sshd -T reported no usable value"
            continue
        fi
        compare_directive ssh-hardening "$directive" "$system" "$target" \
            "$(ssh_finding_id "$directive")"
    done
}

run_login_defs_checks() {
    local entry directive target system
    for entry in "${LOGIN_DEFS_CHECKS[@]}"; do
        IFS='|' read -r directive _ target <<<"$entry"
        if ! system="$(login_defs_system_value "$directive")"; then
            record_unresolved pam-hardening "$directive" "shadow reported no value for the probe account"
            continue
        fi
        compare_directive pam-hardening "$directive" "$system" "$target" \
            "$(pam_finding_id "$directive")"
    done
}

# Apply the plugins this suite compares, then record that an apply happened.
# Every oracle refuses to answer until this has run, and refuses any capture
# taken above it.
#
# A non-zero apply is reported and does not stop the run. The pam plugin
# reports failure when it declines to rewrite a file in /etc/pam.d by hand,
# which is correct behaviour and says nothing about login.defs. The assertions
# below are the evidence, not this exit status.
apply_hardening() {
    local args=() plugin out status=0 line
    for plugin in "${DIFF_PLUGINS[@]}"; do
        args+=(--plugin "$plugin")
    done
    out="$("$BINARY" apply "${args[@]}" 2>&1)" || status=$?
    bump_apply_generation
    echo "apply exit status $status (non-zero is expected when a plugin reports a manual action)"
    # Prefixed, so no line of the tool's own output can be mistaken for one of
    # this suite's summary counters by whatever parses the log.
    while IFS= read -r line; do
        printf '  apply| %s\n' "$line"
    done <<<"$out"
}

# The run's own summary. The four labels match full-test-suite.sh so the
# host-side runner parses this log with the machinery it already has. There is
# no skip outcome to report: a check that could not be determined is recorded
# as a failure, which is the whole point, so Skipped is always 0.
print_summary() {
    local expected
    expected="$(expected_check_total)"
    echo ""
    echo "  Total Tests:  $CHECKS_TOTAL"
    echo "  Passed:       $CHECKS_PASSED"
    echo "  Failed:       $CHECKS_FAILED"
    echo "  Skipped:      0"
    echo ""
    if (( CHECKS_TOTAL == 0 )); then
        echo "No checks ran. Refusing to report success for a run that checked nothing."
        return 1
    fi
    if [[ "$CHECKS_TOTAL" != "$expected" ]]; then
        echo "Recorded $CHECKS_TOTAL check(s) where the tables ask for $expected: two per"
        echo "compared directive, plus one pre-apply control per plugin. A run that"
        echo "checked less than it was asked to is not a pass, whatever its failure"
        echo "count says, because the directives it skipped are simply unproven."
        return 1
    fi
    if (( CHECKS_FAILED > 0 )); then
        echo "The system disagrees with what the tool reported, or an oracle could"
        echo "not be read. Neither is a flaky test: a disagreement is a product"
        echo "defect, and an oracle that cannot answer leaves a directive unproven."
        echo "Each FAIL line above names the directive, and where the two disagree,"
        echo "the value the system holds and the value the tool targets."
        return 1
    fi
    echo "The system agrees with what the tool reported."
}

self_test() {
    local failures=0
    # The filter proofs below run jq, so --self-test depends on it as well.
    # Refusing beats skipping them: a proof that quietly did not run is worth
    # less than no proof at all, because it still prints a clean summary.
    require_commands jq || return 1
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

    # The privilege separation directory guard. The stub reports the directory
    # missing only while it really is missing, so a second call after the guard
    # has run answers the way real sshd would.
    local privsep_root="${TMPDIR:-/tmp}/diffsuite-privsep-$$"
    mkdir -p "$privsep_root"
    local sshd_stub_missing_dir="" sshd_stub_other=0 sshd_stub_unfixable=0
    local sshd_stub_crlf=0
    # `printf` rather than `echo` so the carriage return is emitted literally:
    # this is how the message really arrives under nspawn's console handling.
    sshd_complain() {
        if (( sshd_stub_crlf == 1 )); then
            printf 'Missing privilege separation directory: %s\r\n' "$1" >&2
        else
            printf 'Missing privilege separation directory: %s\n' "$1" >&2
        fi
    }
    sshd() {
        if (( sshd_stub_other == 1 )); then
            echo "/etc/ssh/sshd_config: No such file or directory" >&2
            return 1
        fi
        if (( sshd_stub_unfixable == 1 )); then
            sshd_complain "$sshd_stub_missing_dir"
            return 1
        fi
        [[ -n "$sshd_stub_missing_dir" && ! -d "$sshd_stub_missing_dir" ]] || return 0
        sshd_complain "$sshd_stub_missing_dir"
        return 1
    }

    check_status 0 "privsep guard leaves a healthy sshd alone" \
        require_sshd_privsep_dir

    sshd_stub_missing_dir="$privsep_root/run-sshd"
    check_status 0 "privsep guard accepts the directory it can create" \
        require_sshd_privsep_dir
    check_eq "$([[ -d "$privsep_root/run-sshd" ]] && echo created || echo absent)" \
        "created" "privsep guard creates the directory sshd names"

    # An unrelated sshd failure is the oracle's to report. Creating something
    # here on the strength of a message this guard does not understand would be
    # guessing.
    sshd_stub_missing_dir=""
    sshd_stub_other=1
    check_status 0 "privsep guard defers an unrelated sshd complaint" \
        require_sshd_privsep_dir
    sshd_stub_other=0

    # mkdir cannot create a directory below a regular file, as root or anyone
    # else, so this refusal is deterministic rather than permission-dependent.
    : > "$privsep_root/not-a-dir"
    sshd_stub_missing_dir="$privsep_root/not-a-dir/sshd"
    check_status 1 "privsep guard refuses when it cannot create the directory" \
        require_sshd_privsep_dir

    # Creating the directory is not the same as fixing the problem. This is the
    # case seen live on debian: the guard created /run/sshd, reported success it
    # had not observed, and the run died at the first oracle anyway.
    sshd_stub_unfixable=1
    sshd_stub_missing_dir="$privsep_root/still-refused"
    check_status 1 "privsep guard refuses when sshd still objects after creating it" \
        require_sshd_privsep_dir
    sshd_stub_unfixable=0

    # The live debian failure. sshd's message arrives with a trailing carriage
    # return, so the path captured from it names a directory sshd will never
    # look for, while the log line reporting it looks exactly right.
    sshd_stub_crlf=1
    sshd_stub_missing_dir="$privsep_root/crlf-sshd"
    check_status 0 "privsep guard survives a carriage return in sshd's message" \
        require_sshd_privsep_dir
    check_eq "$([[ -d "$privsep_root/crlf-sshd" ]] && echo created || echo absent)" \
        "created" "privsep guard strips the carriage return before creating"
    sshd_stub_crlf=0

    sshd_stub_missing_dir=""
    unset -f sshd sshd_complain
    rm -rf "$privsep_root"

    # The preflight itself, both ways round. A guard that can never refuse is as
    # useless as one that never runs.
    check_status 0 "require_commands accepts a command that exists" \
        require_commands jq
    check_status 1 "require_commands refuses a command that does not exist" \
        require_commands hardener-no-such-command
    check_status 1 "require_commands refuses when one of several is missing" \
        require_commands jq hardener-no-such-command

    # The binary the run tests. An explicit BINARY is the operator saying which
    # one they mean, so a fallback to a build from the tree would report a run
    # of one binary as a run of another. Both branches of the resolution are
    # driven here, and the value in force is put back afterwards.
    local saved_binary="$BINARY" saved_binary_explicit="$BINARY_EXPLICIT"
    BINARY="/hardener/no/such/binary"
    resolve_binary
    check_eq "$BINARY" "/hardener/no/such/binary" \
        "an explicit BINARY is not replaced by a build from the tree"
    check_eq "$BINARY_EXPLICIT" "1" "an explicit BINARY is recorded as the operator's choice"
    check_status 1 "require_binary refuses an explicit path that is not executable" \
        require_binary
    BINARY=""
    resolve_binary
    check_eq "$BINARY_EXPLICIT" "0" "an unset BINARY resolves against the tree"
    BINARY="/bin/sh"
    check_status 0 "require_binary accepts an executable binary" require_binary
    BINARY="$saved_binary"
    BINARY_EXPLICIT="$saved_binary_explicit"

    # The tables the whole run is sized by, pinned as literals. Every total the
    # suite prints is counted off them, so a shortened table agrees with itself
    # and reads as a complete run; only a literal notices.
    check_eq "${#SSH_CHECKS[@]}" "7" "the ssh table holds seven directives"
    check_eq "${#LOGIN_DEFS_CHECKS[@]}" "3" "the login.defs table holds three directives"
    check_eq "${#DIFF_PLUGINS[@]}" "2" "two plugins are compared"
    local pinned_total
    pinned_total="$(expected_check_total)"
    check_eq "$pinned_total" "22" \
        "the run is sized at two checks per directive plus one control per plugin"
    check_status 0 "require_check_tables accepts the tables as they stand" \
        require_check_tables

    local saved_ssh_checks=("${SSH_CHECKS[@]}")
    SSH_CHECKS=("PermitRootLogin|no")
    check_status 1 "require_check_tables refuses a table edited down" require_check_tables
    # And the size the run is measured against does not follow the table down.
    # Counted off ${#SSH_CHECKS[@]} it would, and print_summary would then accept
    # a run that skipped six directives as a complete one. Compared against the
    # value taken while the tables were whole, which the literal above pins.
    check_eq "$(expected_check_total)" "$pinned_total" \
        "the expected total does not move when a table is edited down"
    SSH_CHECKS=("${saved_ssh_checks[@]}")
    check_status 0 "require_check_tables accepts the table once it is restored" \
        require_check_tables

    # The scan side. Its filters are where a harness most easily goes green on
    # broken code: one that matches nothing returns an empty result, which is
    # exactly what "the tool reported no finding" looks like, and that is the
    # pass condition. So both id conventions are pinned to the literal ids the
    # plugins emit, and each filter is proven to match, AND proven to match
    # nothing when written under the other plugin's convention.
    check_eq "$(ssh_finding_id PermitRootLogin)" "ssh-permitrootlogin" "ssh lowercases its finding id"
    check_eq "$(ssh_finding_id MaxAuthTries)" "ssh-maxauthtries" "ssh lowercases a mixed-case directive"
    check_eq "$(pam_finding_id PASS_MAX_DAYS)" "pam-PASS_MAX_DAYS" "pam keeps its directive's case"

    # Shaped after real `scan --format json` output: an array of plugin objects
    # carrying plugin_id, plugin_name, findings and unchecked. One finding under
    # each plugin, so a filter can be proven to match; the directives absent
    # from each findings array stand in for the compliant case, where matching
    # nothing is the correct answer. The plugin order is deliberately not the
    # order DIFF_PLUGINS lists, because the tool's own order is not that either.
    local scan_fixture='[
  {
    "plugin_id": "pam-hardening",
    "plugin_name": "PAM Hardening",
    "findings": [
      { "finding_id": "pam-PASS_MAX_DAYS", "finding_current_value": "99999" }
    ],
    "unchecked": []
  },
  {
    "plugin_id": "ssh-hardening",
    "plugin_name": "SSH Hardening",
    "findings": [
      { "finding_id": "ssh-permitrootlogin", "finding_current_value": "yes" }
    ],
    "unchecked": []
  }
]'

    SCAN_JSON=""
    SCAN_JSON_GENERATION=""
    check_status 1 "uninitialised scan oracle returns non-zero" \
        scan_finding_count ssh-hardening ssh-permitrootlogin

    local scan_capture="$scan_fixture"
    capture_scan_json() { printf '%s' "$scan_capture"; }

    # The same freshness lifecycle as the two value oracles, for the same
    # reason: a scan captured before apply describes the container as it was
    # found, and on an unhardened container that is a document full of findings
    # for directives apply has since fixed.
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "0" "scan_oracle_init succeeds against the stubbed capture"
    check_status 1 "scan read with no apply recorded returns non-zero" \
        scan_finding_count ssh-hardening ssh-permitrootlogin
    bump_apply_generation
    check_status 1 "scan read from a capture older than the last apply returns non-zero" \
        scan_finding_count ssh-hardening ssh-permitrootlogin
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "0" "scan_oracle_init re-captures after apply"

    check_eq "$(scan_finding_count ssh-hardening ssh-permitrootlogin)" "1" \
        "the ssh filter matches a finding the tool emitted"
    check_eq "$(scan_finding_count ssh-hardening "$(ssh_finding_id PermitRootLogin)")" "1" \
        "the ssh filter matches through the id derivation"
    check_eq "$(scan_finding_count pam-hardening "$(pam_finding_id PASS_MAX_DAYS)")" "1" \
        "the pam filter matches through the id derivation"
    check_eq "$(scan_finding_count ssh-hardening "$(ssh_finding_id MaxAuthTries)")" "0" \
        "a directive the tool reported nothing for counts 0"
    check_eq "$(scan_finding_count pam-hardening "pam-pass_max_days")" "0" \
        "ssh's lowercasing applied to a pam id matches nothing"
    check_eq "$(scan_finding_count ssh-hardening "ssh-PermitRootLogin")" "0" \
        "pam's case preservation applied to an ssh id matches nothing"

    # A plugin missing from the output must stop the run. Every filter against
    # it would return 0, and 0 is the pass condition, so silence there would
    # report a clean bill of health for a plugin that never ran.
    scan_capture='[
  {
    "plugin_id": "ssh-hardening",
    "plugin_name": "SSH Hardening",
    "findings": [],
    "unchecked": []
  }
]'
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses output missing a compared plugin"

    scan_capture='{ "error": "not an array" }'
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses output that is not a JSON array"

    # More than one document on stdout. output::info prints a JSON object there
    # in JSON mode, so this is the shape stdout takes the moment the scan path
    # calls it, and an unslurped guard would judge only the last value.
    scan_capture="$(printf '{"info":"scanning"}\n%s' "$scan_fixture")"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses more than one document on stdout"

    # The plugin object's key set, which output.rs builds by hand and which has
    # already gained a key since these filters were written. Each mutation is
    # derived from the good fixture rather than written out again, so what is
    # being tested is visible as the mutation itself. Every one of them would
    # have counted zero findings through a `// []` default, and zero is the pass
    # condition.
    scan_capture="$(jq 'map(if .plugin_id == "ssh-hardening" then del(.findings) else . end)' <<<"$scan_fixture")"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses a plugin object with no findings key"

    scan_capture="$(jq 'map(if .plugin_id == "ssh-hardening" then .findings = {} else . end)' <<<"$scan_fixture")"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses a findings key that is not an array"

    scan_capture="$(jq 'map(if .plugin_id == "pam-hardening" then del(.unchecked) else . end)' <<<"$scan_fixture")"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses a plugin object with no unchecked key"

    # The tool's own "I could not check this". The ids in `unchecked` are
    # identical to the finding ids by design, so an unchecked directive has no
    # finding, and no finding is what this suite scores as agreement. The ssh
    # plugin puts every one of its directives here at once when sshd_config
    # cannot be read, and still reports the scan as successful.
    local unchecked_fixture='[
  {
    "plugin_id": "pam-hardening",
    "plugin_name": "PAM Hardening",
    "findings": [],
    "unchecked": [
      { "unchecked_check_id": "pam-PASS_MAX_DAYS", "unchecked_reason": "reading /etc/login.defs requires root" }
    ]
  },
  {
    "plugin_id": "ssh-hardening",
    "plugin_name": "SSH Hardening",
    "findings": [],
    "unchecked": [
      { "unchecked_check_id": "ssh-permitrootlogin", "unchecked_reason": "reading /etc/ssh/sshd_config requires root" }
    ]
  }
]'
    scan_capture="$unchecked_fixture"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "0" "scan_oracle_init accepts a document whose checks are all unchecked"
    check_eq "$(scan_finding_count ssh-hardening "$(ssh_finding_id PermitRootLogin)")" "0" \
        "a directive the tool did not check reports no finding"
    check_eq "$(scan_unchecked_count ssh-hardening "$(ssh_finding_id PermitRootLogin)")" "1" \
        "the unchecked filter matches through the ssh id derivation"
    check_eq "$(scan_unchecked_count pam-hardening "$(pam_finding_id PASS_MAX_DAYS)")" "1" \
        "the unchecked filter matches through the pam id derivation"
    check_eq "$(scan_unchecked_count ssh-hardening "$(ssh_finding_id MaxAuthTries)")" "0" \
        "a directive the tool did check is not in the unchecked list"

    # The counters alone are not the point: the refusal has to reach the verdict.
    # With the system holding the target and no finding reported, this pair used
    # to record two passes. It must now record the system assertion as a pass and
    # the tool's verdict as a failure, and still contribute exactly two checks,
    # so the run's expected total does not move.
    local before_total=$CHECKS_TOTAL before_passed=$CHECKS_PASSED before_failed=$CHECKS_FAILED
    compare_directive ssh-hardening PermitRootLogin no no "$(ssh_finding_id PermitRootLogin)" >/dev/null
    check_eq "$((CHECKS_TOTAL - before_total))" "2" "an unchecked directive still contributes two checks"
    check_eq "$((CHECKS_PASSED - before_passed))" "1" "an unchecked directive still passes the system assertion"
    check_eq "$((CHECKS_FAILED - before_failed))" "1" "a directive the tool did not check is recorded as a failure"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    # The inner key everything above depends on, renamed and nothing else
    # touched. It is the one key in this document no run can prove: the
    # pre-apply control exercises `finding_id` against live output every time,
    # while `unchecked` is expected to be empty under root, and an empty result
    # is also what a filter reading the wrong key returns. Accepted, this
    # document scores the pair above as two passes for a directive the tool
    # states it did not check.
    scan_capture="$(jq 'map(.unchecked |= map(.check_id = .unchecked_check_id | del(.unchecked_check_id)))' <<<"$unchecked_fixture")"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" \
        "scan_oracle_init refuses an unchecked entry whose id key was renamed"

    # And the branch must not fire on a directive the tool did check, or every
    # green run would fail here instead.
    scan_capture="$scan_fixture"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "0" "scan_oracle_init re-captures the checked fixture"
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    compare_directive ssh-hardening MaxAuthTries 3 3 "$(ssh_finding_id MaxAuthTries)" >/dev/null
    check_eq "$((CHECKS_PASSED - before_passed))" "2" \
        "a directive the tool checked and agreed on records two passes"
    check_eq "$((CHECKS_FAILED - before_failed))" "0" "and records no failure"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    # The pre-apply capture: its own variable, its own stamp, and generation 0
    # the only value either will accept. It is read after apply, which is why
    # the rule is written the other way round from require_fresh_capture rather
    # than borrowed from it.
    PRE_APPLY_SCAN_JSON=""
    PRE_APPLY_SCAN_GENERATION=""
    check_status 1 "uninitialised pre-apply scan oracle returns non-zero" \
        preapply_finding_count ssh-hardening ssh-permitrootlogin

    APPLY_GENERATION=0
    init_status=0
    preapply_scan_oracle_init || init_status=$?
    check_eq "$init_status" "0" "preapply_scan_oracle_init succeeds before any apply"
    check_eq "$(preapply_finding_count ssh-hardening "$(ssh_finding_id PermitRootLogin)")" "1" \
        "the pre-apply filter matches a finding the tool emitted"

    bump_apply_generation
    init_status=0
    preapply_scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "preapply_scan_oracle_init refuses to capture once apply has run"
    check_eq "$(preapply_finding_count ssh-hardening "$(ssh_finding_id PermitRootLogin)")" "1" \
        "a capture stamped before apply is still readable after one"
    PRE_APPLY_SCAN_GENERATION="$APPLY_GENERATION"
    check_status 1 "a pre-apply capture stamped after an apply returns non-zero" \
        preapply_finding_count ssh-hardening ssh-permitrootlogin
    PRE_APPLY_SCAN_GENERATION=0

    # The control over the whole compared set. The ids come from the two tables,
    # so a directive added to either is covered without touching this.
    local compared_ids=()
    mapfile -t compared_ids < <(compared_finding_ids)
    check_eq "${#compared_ids[@]}" "10" "the control covers every compared directive"
    check_eq "${compared_ids[0]}" "ssh-hardening ssh-permitrootlogin" \
        "the control names each directive by the id its own plugin emits"

    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_preapply_control >/dev/null
    check_eq "$((CHECKS_TOTAL - before_total))" "2" "the control records one check per plugin"
    check_eq "$((CHECKS_PASSED - before_passed))" "2" \
        "a plugin that reported a finding before apply passes its control"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    # A plugin with nothing to report before apply. That is what a plugin whose
    # scan failed looks like in this JSON, which carries no scan_success and no
    # scan_error to say otherwise, and it is also what a filter that matches
    # nothing looks like. Neither may pass.
    PRE_APPLY_SCAN_JSON="$(jq 'map(if .plugin_id == "ssh-hardening" then .findings = [] else . end)' <<<"$scan_fixture")"
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_preapply_control >/dev/null
    check_eq "$((CHECKS_PASSED - before_passed))" "1" \
        "the plugin that did report findings still passes its control"
    check_eq "$((CHECKS_FAILED - before_failed))" "1" \
        "a plugin that reported nothing before apply fails its control"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    APPLY_GENERATION=0
    SCAN_JSON=""
    SCAN_JSON_GENERATION=""
    PRE_APPLY_SCAN_JSON=""
    PRE_APPLY_SCAN_GENERATION=""
    unset -f capture_scan_json

    # The summary is the last thing between a shortened run and a green exit
    # status, so each of its refusals is pinned. The counters belong to the full
    # run, so they are put back untouched afterwards.
    local saved_total=$CHECKS_TOTAL saved_passed=$CHECKS_PASSED saved_failed=$CHECKS_FAILED
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    check_status 1 "print_summary refuses a run that checked nothing" print_summary
    CHECKS_TOTAL=3
    CHECKS_PASSED=3
    check_status 1 "print_summary refuses a run shorter than the tables ask for" print_summary
    CHECKS_TOTAL="$(expected_check_total)"
    CHECKS_PASSED="$CHECKS_TOTAL"
    check_status 0 "print_summary accepts a complete run with no failures" print_summary
    CHECKS_FAILED=1
    CHECKS_PASSED=$((CHECKS_TOTAL - 1))
    check_status 1 "print_summary refuses a complete run carrying a failure" print_summary
    CHECKS_TOTAL=$saved_total
    CHECKS_PASSED=$saved_passed
    CHECKS_FAILED=$saved_failed

    # The verdict rule itself, in all four directions. The last one is the shape
    # of the defect this harness exists to catch: the system holds something
    # other than the target and the tool reports nothing wrong.
    check_status 0 "verdict agrees when the system holds the target and nothing is reported" \
        verdict_agrees no no 0
    check_status 1 "verdict disagrees when the system holds the target and a finding is reported" \
        verdict_agrees no no 1
    check_status 0 "verdict agrees when the system differs and a finding is reported" \
        verdict_agrees yes no 1
    check_status 1 "verdict disagrees when the system differs and nothing is reported" \
        verdict_agrees yes no 0

    if (( failures > 0 )); then
        echo "self-test: $failures failure(s)"
        return 1
    fi
    echo "self-test: all extractor checks passed"
}

# The full run: gate, the control capture, apply, the oracle captures, then the
# assertions.
#
# The order is load-bearing. Every capture that describes the hardened system is
# taken BELOW apply_hardening, which is what bumps the generation, so an init
# moved above it is caught at the first read by require_fresh_capture rather
# than quietly answering from a snapshot of the unhardened container.
#
# The pre-apply control is the one capture that must be taken above it, and it
# is refused if it is not: it is the only evidence a green run carries that the
# finding filters can match anything.
#
# A failed capture ends the run rather than pressing on: printing a summary over
# a subset of the directives would show a green count for a run that never
# looked at the rest.
run_full_suite() {
    require_container_root || return 1
    require_commands "${REQUIRED_COMMANDS[@]}" || return 1
    # After require_commands, which is what guarantees there is an sshd to ask.
    require_sshd_privsep_dir || return 1
    require_binary || return 1
    require_check_tables || return 1
    # Checked before apply, not inside the probe that needs it: aborting halfway
    # through a destructive run over a name collision helps nobody.
    require_absent_probe_user || return 1

    echo "Differential suite: $BINARY"
    echo "Plugins: ${DIFF_PLUGINS[*]}"
    preapply_scan_oracle_init || return 1

    apply_hardening

    ssh_oracle_init || return 1
    login_defs_oracle_init || return 1
    scan_oracle_init || return 1

    run_preapply_control
    run_ssh_checks
    run_login_defs_checks
    print_summary
}

main() {
    set -euo pipefail
    # Extra arguments are refused rather than ignored. `--self-test --anything`
    # used to exit 0 having silently dropped everything after the first word,
    # which reads as a clean run of whatever the caller believed it asked for.
    if (( $# > 1 )); then
        echo "Unexpected argument: $2" >&2
        usage >&2
        return 1
    fi
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
