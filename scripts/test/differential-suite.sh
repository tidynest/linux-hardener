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

# Whether this run owns a network namespace, which is what makes /proc/sys/net
# writable and is the whole of what the kernel oracle needs.
#
# One variable used to answer this question and the one below it, under the name
# KERNEL_BOOTED, and the reason it gave was wrong: booting is one way of having
# been given a namespace and not the condition itself. Measured on 2026-08-08
# against /var/lib/machines/hardener-test, `systemd-nspawn --private-network
# --pipe` makes /proc/sys/net writable with no --boot anywhere, so gating the
# kernel rows on the booted signal declared all 11 of them unaskable in every
# --pipe run for the cost of one flag (#137).
#
# The two signals are independent and neither is inferred from the other. A
# runner that boots a container and declares only the signal below leaves the
# kernel rows unaskable, which is the safe direction: failing toward "not
# verified" is what this file does everywhere.
#
# Only the literal 1 turns it on, and the signal is reduced to 0 or 1 here
# rather than carried through as whatever arrived. A value the runner never
# meant as a signal, "true" or "yes" or an empty string, leaves the oracle off,
# and the header below then reports 0 rather than reprinting a word that reads
# as enabled beside arithmetic that is not.
RUN_NETNS=0
if [[ "${HARDENER_DIFF_NETNS:-}" == "1" ]]; then
    RUN_NETNS=1
fi

# Whether systemd is PID 1 here, which is what the services oracle needs and
# what nothing else in this file does. `systemctl mask` and `systemctl
# is-enabled` need a running service manager, which `nspawn --pipe` does not
# provide. That is this repository's own measurement, recorded at
# full-test-suite.sh:993, and it is inherited here rather than re-measured.
#
# Read from the same environment variable the runner has always exported, and
# it still means what it says. What changed in #137 is that it no longer
# answers for the kernel oracle as well.
RUN_BOOTED=0
if [[ "${HARDENER_DIFF_BOOTED:-}" == "1" ]]; then
    RUN_BOOTED=1
fi

# The two signals asked as questions rather than by comparing the variables at
# each site.
#
# Defined here, above every use, because the conditional that reads them runs at
# load time and a function exists only once its definition line has executed.
run_has_netns() {
    [[ "$RUN_NETNS" == "1" ]]
}

run_is_booted() {
    [[ "$RUN_BOOTED" == "1" ]]
}

# The plugins whose settings this suite compares. Applying only these keeps the
# run to what is actually asserted.
#
# Defined below the booted flag rather than at the top of the file, because its
# last member depends on it.
#
# mac-hardening is compared for what it must NOT do. On a kernel exposing
# neither selinux nor apparmor its apply is required to be a no-op, and the MAC
# oracle reads the configuration tree rather than the tool to say whether it was
# one. What that cannot see is stated at the oracle, and it is most of the
# plugin.
DIFF_PLUGINS=(ssh-hardening pam-hardening permissions-hardening firewall-hardening kernel-hardening audit-hardening mac-hardening)

# The services plugin joins the compared set only in a booted run, and this is
# the only place that decision is made.
#
# Joining unconditionally is the smaller change and is deliberately not taken.
# Under `--pipe` the services scan errors and the apply does nothing, so the two
# generic per-plugin rows, introduced-findings and preview-agreement, would
# compare an empty reading against an empty reading and pass. A row that reads
# as coverage while proving nothing is what issue #47 exists to remove. Under
# `--pipe` the services checks are declared unaskable instead, which is this
# file's way of being absent out loud.
# The services plugin's id, written once because two places need it and they
# must not drift: the list above, and the skip in run_preapply_control.
#
# The FULL id, not a guess at one. `--plugin` takes the id or the segment
# before its first hyphen (crates/hardener-cli/src/commands/plugin_filter.rs),
# so `services-hardening` names nothing and is REFUSED with "Unknown
# plugin(s)", and the same string is matched against `.plugin_id` in the scan
# document besides. The self-test reads every compared id back out of the
# plugin sources for this reason.
SERVICES_PLUGIN_ID="service-minimisation"

# The list before that append, kept because --self-test drives fixtures rather
# than a host, and every scan fixture in it describes a run of exactly the
# plugins compared in every mode.
DIFF_PLUGINS_BASE=("${DIFF_PLUGINS[@]}")

# An id no plugin has and no fixture will ever carry.
#
# Several self-test assertions have an ABSENCE as their subject: that a reader
# refuses a plugin the document does not cover, rather than answering an empty
# reading, which is every such reader's pass condition. Those assertions named a
# real but uncompared plugin, and each time one joined the compared set the
# fixtures gained it and the absence quietly ceased to exist. That happened to
# audit-hardening in 24b5c03a, and it would have happened to mac-hardening here,
# which was the last uncompared plugin there was.
#
# So the absence is made structural instead of borrowed. The self-test asserts
# this id is in neither the compared set nor the tool's own listing, which is
# what stops the same drift a third time.
NEVER_COMPARED_PLUGIN="no-such-plugin"

if run_is_booted; then
    DIFF_PLUGINS+=("$SERVICES_PLUGIN_ID")
fi

# How many plugins this run compares.
#
# Read by require_check_tables and by expected_check_total, so the guard and the
# arithmetic cannot come to disagree about the size of a run. Derived from the
# mode and NOT from ${#DIFF_PLUGINS[@]}: reading the array would make the guard
# ask the table whether the table is right, which is the rule
# expected_check_total already states for every other pinned length.
diff_plugin_count() {
    if run_is_booted; then
        printf '%s' "$(( DIFF_PLUGINS_EXPECTED + 1 ))"
    else
        printf '%s' "$DIFF_PLUGINS_EXPECTED"
    fi
}

# Whether this host's shadow implements a minimum password age at all.
#
# The second mode signal, and it works like the one above: declared before any
# check runs, printed in the header, and the arithmetic below branches on it.
# Arch builds shadow without the field. `chage` there has no `-m/--mindays` and
# `useradd` leaves it empty while honouring PASS_MAX_DAYS and PASS_WARN_AGE from
# the same /etc/login.defs, so PASS_MIN_DAYS can never be carried by an account
# and there is nothing for the oracle to compare against.
#
# 1 means the field exists, which is the default so that a suite sourced but
# never probed does not silently declare rows unaskable.
SHADOW_MIN_DAYS=1

# The directive that mode governs. One row, named once.
MIN_DAYS_DIRECTIVE="PASS_MIN_DAYS"

# Ask chage, which is shadow's own reader for these fields and ships with
# useradd, so its usage text is the closest thing to a direct question about the
# build. The plugin asks the same question of the same tool
# (`min_days_enforceable` in crates/hardener-plugins/src/pam/mod.rs), so the two
# cannot come to disagree about what the host can do.
#
# Judged on the usage text rather than the exit status, because shadow builds
# differ on whether --help exits zero and several print it to stderr. A probe
# that printed nothing is FATAL rather than an assumption either way: this
# decides which totals the run expects, and a mode concluded from a failed read
# is one value standing for several outcomes. That is stricter than the plugin,
# which falls through to comparing the value, and deliberately so: the plugin
# must not lose a check it could still make, and this must not mis-total a run.
detect_shadow_min_days() {
    local usage
    usage="$(LC_ALL=C chage --help 2>&1 || true)"
    if [[ -z "${usage//[[:space:]]/}" ]]; then
        echo "FATAL: chage --help printed nothing, so whether this host's shadow" >&2
        echo "  has a minimum-password-age field could not be determined, and the" >&2
        echo "  totals below depend on the answer." >&2
        return 1
    fi
    if [[ "$usage" == *--mindays* ]]; then
        SHADOW_MIN_DAYS=1
    else
        SHADOW_MIN_DAYS=0
    fi
}

# Every external command the full run depends on.
#
# jq is listed first because it is the newest of them and the likeliest to be
# absent: the openSUSE package install in scripts/containers/create-container.sh
# ends in `|| log_warn`, so a container can be built successfully with packages
# missing. Without jq the scan comparison would find nothing, and finding
# nothing is indistinguishable from "the tool reported no finding", which is the
# pass condition. An oracle that cannot run is a failure, never a skip, so the
# whole set is checked up front and named when it is incomplete.
#
# chpasswd, stat and su belong to the vendor survival probe: it sets a password
# so the hashing scheme can be read, asks the filesystem for the home
# directory's mode, and asks a login session for its umask. Each is listed for
# the same reason as jq, that a missing one would leave a reading empty, and an
# empty reading compared against another empty reading is a check that agrees
# with itself. The account rows themselves are read by the shell, so that probe
# adds no command of its own.
#
# passwd is the login.defs probe's second reader, for the one directive chage
# cannot report on every distribution. It is listed even though the run only
# consults it where chage came up short, because create-container.sh installs it
# on every distribution it builds: `debootstrap --include=...,passwd` at :362 and
# `dnf -y install ... passwd shadow-utils` at :427. It is NOT always the same
# package as chage, which is why that is not the reason given: on the dnf family
# passwd and shadow-utils are two packages, and on Arch both binaries come from
# `shadow`. Refusing here names a container missing it once, rather than leaving
# one directive to fail much later for a reason that reads like a distribution
# difference.
REQUIRED_COMMANDS=(jq grep sshd ssh-keygen useradd userdel chage id chpasswd stat su passwd)

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

# The version string of the binary under test, or a loud stand-in for it.
#
# The path this suite already prints cannot attribute a run to a commit: the
# same path holds a different build after every rebuild, and the logs are read
# long afterwards. The habit of checking the version before starting is one no
# artefact can prove was kept.
#
# A failed or empty `--version` must never print as a blank, because a log that
# silently omits what it tested reads exactly like one that recorded it. Never
# fatal: require_binary has already proved the file executable, and refusing a
# whole destructive run over a banner would cost more than it saves.
binary_version() {
    local output
    if ! output="$("$1" --version 2>&1)" || [[ -z "$output" ]]; then
        echo "UNAVAILABLE (--version gave: ${output:-no output})"
        return 0
    fi
    # First line only. A multi-line answer would break the banner into a shape
    # no reader can attribute to the path printed above it.
    printf '%s' "${output%%$'\n'*}"
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

# Extract one field from a captured `passwd -S` line, numbered as passwd(1)
# documents them: login name, status, date of last change, minimum age, maximum
# age, warning period, inactivity period.
#
# This exists because chage cannot answer PASS_MIN_DAYS on every distribution
# the suite supports. Arch builds shadow without the field entirely: `chage -l`
# prints no minimum line, `chage --help` offers no -m, and the word appears
# nowhere in the binary, which rules out a translated label and a privilege
# difference alike. passwd -S reads the same /etc/shadow row and does report it.
#
# The width is asserted rather than assumed, and a line of any other width is
# refused instead of indexed. Seven is the documented shape, and the one field
# that could ever gain a space is the date, which shadow has printed both as
# 2024-12-24 and as 12/24/2024. Indexing past a spacey date would answer with
# the neighbour of the field asked for, and a wrong value that reads like a real
# one is the single outcome this suite must never produce.
# Returns 1 when the capture cannot be read that way, which every caller treats
# as "no value", never as a pass.
extract_passwd_status_value() {
    local output="$1" field="$2"
    local -a parts
    # The index is checked before it is used, and against the seven fields
    # rather than merely for being a number. An empty or non-numeric subscript
    # is arithmetic 0, and bash reads a subscript of -1 as the LAST element, so
    # a table row that had lost its fourth column would have answered
    # PASS_MIN_DAYS with the inactivity period: a wrong value that reads like a
    # real one, which is the single outcome this suite must never produce. An
    # index past the end fails differently and no better, aborting the run under
    # `set -u` with no message at all.
    if ! [[ "$field" =~ ^[1-7]$ ]]; then
        echo "FATAL: '$field' is not one of the seven passwd -S fields" >&2
        return 1
    fi
    read -r -a parts <<<"$output"
    if (( ${#parts[@]} != 7 )); then
        return 1
    fi
    printf '%s' "${parts[field - 1]}"
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

# The ssh directives this suite checks and the value the system must hold after
# apply, verified against SSH_DIRECTIVES in
# crates/hardener-plugins/src/ssh/mod.rs. Fields: directive|expected.
#
# For five of the seven, expected is the tool's own target and the container
# arrives with the directive unset, so the check reads "the tool set it".
#
# For the two named in SEEDED_SSH_CHECKS below, expected is the SEEDED value,
# which is stricter than the tool's target, and the check reads "the tool left
# a stricter host alone". Those two therefore no longer cover the unset path;
# the other five do, and run_seeded_checks logs the trade rather than leaving a
# reader to infer it.
#
# These stay equality assertions. On a container created clean no distribution
# default is stricter than the tool's baseline, so an unseeded directive must
# read exactly the target. A distribution that started shipping, say,
# MaxAuthTries 2 would leave the 2 in place and fail here, and that would be the
# tool behaving correctly and this table being out of date: widen the entry
# rather than the tool.
SSH_CHECKS=(
    "PermitRootLogin|no"
    "PasswordAuthentication|no"
    "PermitEmptyPasswords|no"
    "MaxAuthTries|2"
    "X11Forwarding|no"
    "ClientAliveInterval|60"
    "ClientAliveCountMax|2"
)

# The whole point of the seeded pair: a value STRICTER than the tool's own
# target, written into the container before the first apply, which the tool must
# then leave alone. Nothing a freshly created container ships is stricter than
# the baseline, so without this the suite can only ever prove that the tool
# hardens an unhardened host, never that it declines to un-harden a good one.
# That second property is the one whose absence wrote MaxAuthTries from 2 up to
# 3 and reported success.
#
# Fields: directive|seed|sshd-default.
#
# The three numbers in each row are distinct on purpose. sshd's default, the
# seed and the tool's target are all different, so a probe that has silently
# started reading a constant cannot produce the seed: the seed exists only
# because the write took effect. The default column is OpenSSH's documented
# default and is not measured, so it is carried here only to keep that
# three-way distinction checkable by eye when a future reader changes a row.
#
# ClientAliveCountMax is deliberately not seeded: it exercises the same
# direction as MaxAuthTries and would cost a third directive's unset coverage
# for nothing. It is the standby if a distribution turns out to ship one of
# these two at its seed value.
SEEDED_SSH_CHECKS=(
    "MaxAuthTries|2|6"
    "ClientAliveInterval|60|0"
)

# Appended rather than prepended, and that is load-bearing.
#
# sshd takes the FIRST value it obtains and reads the drop-in directory through
# an Include that sits near the top of the main file. A seed written above that
# Include would beat anything the tool later writes to its own fragment, which
# would make this check pass even if the tool had written the looser target
# there. Appended, the fragment wins, so a tool that loosens the directive is
# visible to sshd -T and fails the check. The placement is what makes it an
# oracle rather than a restatement of the seed.
# The file the seed is written to. A variable rather than a literal so the
# self-test can point it at a scratch file: a self-test that appends to the
# developer's own sshd_config would be a poor way to learn this rule.
SEED_TARGET_FILE="/etc/ssh/sshd_config"

seed_stricter_than_baseline() {
    local entry directive seed
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the stricter-than-baseline seed was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It has to be in place before the first apply, because what is being" >&2
        echo "  tested is what that apply does when it meets it." >&2
        return 1
    fi
    for entry in "${SEEDED_SSH_CHECKS[@]}"; do
        IFS='|' read -r directive seed _ <<<"$entry"
        if ! printf '%s %s\n' "$directive" "$seed" >>"$SEED_TARGET_FILE"; then
            echo "FATAL: could not seed $directive into $SEED_TARGET_FILE" >&2
            return 1
        fi
    done
}

# The kernel counterpart of the pair above, and it exists for the same reason: a
# container arrives with nothing stricter than the tool's own baseline, so
# without a seed the kernel oracle can only ever prove the tool hardens a host
# below its target, never that it declines to un-harden one already above it.
#
# Fields: parameter|seed|tool-target, matching SEEDED_SSH_CHECKS' shape of "the
# name, the value written in, and a third value carried for the eye rather than
# measured".
#
# net.ipv4.tcp_syncookies is an at-least row targeting 1, and 2 sends SYN
# cookies unconditionally rather than only under pressure, which is not weaker.
# kernel/mod.rs says so where it declares the row, and its apply clamps its own
# target up to whatever the host already runs before deciding whether to write,
# so a correct apply leaves a host at 2 reading 2 in the runtime AND writes 2
# into /etc/sysctl.d rather than handing 1 back at the next boot.
#
# rp_filter is deliberately NOT the seeded row, though it looks like the obvious
# candidate. Its ranked order is 0, 2, 1 weakest first: 2 is LOOSE mode and
# ranks BELOW the target of strict mode 1, so seeding 2 would seed a looser
# value, a correct tool would tighten it to 1, and this check would then report
# a defect against every distribution.
#
# The seed is distinct from the tool's own target on purpose, exactly as the ssh
# pair's three columns are: a probe that has silently started reading a constant
# cannot produce 2, because 2 exists only where the seed took effect.
SEEDED_KERNEL_CHECKS=(
    "net.ipv4.tcp_syncookies|2|1"
)

seed_kernel_stricter_than_baseline() {
    local entry name seed
    if ! run_has_netns; then
        return 0
    fi
    for entry in "${SEEDED_KERNEL_CHECKS[@]}"; do
        IFS='|' read -r name seed _ <<<"$entry"
        if ! sysctl -w "$name=$seed" >/dev/null 2>&1; then
            echo "FATAL: could not seed $name=$seed." >&2
            echo "  This run claims its own network namespace, where /proc/sys/net is" >&2
            echo "  writable. If that is not true the mode signal is wrong, and every" >&2
            echo "  kernel row below would be measuring the host." >&2
            return 1
        fi
    done
}

# The mirror of the seed above, and the reason a container that arrives already
# hardened can still be measured. The RHEL container is that container: it ships
# every managed parameter at or above its target, so run_kernel_preapply_control
# correctly refused to certify checks that would have passed whether or not the
# tool had run, and no repetition of the run could change that.
#
# The stricter seed cannot serve here. It proves the tool declines to un-harden
# a host already above its target, which is the opposite question.
#
# Fields: parameter|seed|tool-target, the same shape as SEEDED_KERNEL_CHECKS.
#
# Every askable row but one, which is what #47 asked for. A single seeded row
# left the other ten passing on an already-compliant host whether or not the
# tool had run: each read its target before the apply and read it again after,
# and no mutation of the kernel plugin could have made either reading move. A
# row that arrives loosened cannot do that. If the plugin does nothing, the seed
# is still standing when run_kernel_checks reads it, and the row fails.
#
# tcp_syncookies is the row deliberately NOT here, because SEEDED_KERNEL_CHECKS
# has it. That table seeds it STRICTER than the tool's target to ask whether an
# apply un-hardens a host already ahead of it, and the two questions cannot
# share a parameter: whichever write landed second would decide the reading, and
# the check that lost would be scoring the other one's seed. Its row is
# therefore vacuous in KERNEL_CHECKS and answered by run_seeded_kernel_check
# instead, which is the sharper of the two questions. The self-test pins the
# arithmetic, so an eleventh parameter cannot be added to the kernel table
# without a seed in one table or the other.
#
# The looser value per direction, and none of them is arbitrary:
#
#   at-most 0    seeded 1, unambiguously looser in the one direction the row is
#                scored in.
#   at-least 1   seeded 0, the same the other way up.
#   ranked       seeded 0, the weakest position in the declared space.
#                rp_filter is the trap here rather than the obvious case: its
#                space is 0,2,1 weakest first, so 2 is LOOSE mode ranking below
#                strict mode 1, and the looser value is 0 and not the larger
#                number.
#
# The seeds are written on every distribution rather than only where the control
# would otherwise fail. Seeding only the hosts that needed it would have the
# five runs measuring five different things, and the one host whose behaviour
# had changed would be the one with nothing to be compared against.
SEEDED_LOOSER_KERNEL_CHECKS=(
    "net.ipv4.conf.all.rp_filter|0|1"
    "net.ipv4.conf.default.rp_filter|0|1"
    "net.ipv4.conf.all.log_martians|0|1"
    "net.ipv4.conf.default.log_martians|0|1"
    "net.ipv4.conf.all.accept_source_route|1|0"
    "net.ipv4.conf.default.accept_source_route|1|0"
    "net.ipv4.conf.all.accept_redirects|1|0"
    "net.ipv4.conf.default.accept_redirects|1|0"
    "net.ipv4.conf.all.secure_redirects|1|0"
    "net.ipv4.conf.default.secure_redirects|1|0"
)

seed_kernel_looser_than_baseline() {
    local entry name seed reading
    # The guard seed_stricter_than_baseline carries, for a reason that bites
    # harder here. Moved below the apply, this would loosen a parameter the tool
    # had already hardened: every kernel row would then fail on every
    # distribution, while the pre-apply control went on printing a green line
    # about a real question being asked.
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the looser-than-baseline seed was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It has to be in place before the first apply, because what the" >&2
        echo "  control below measures is the host that apply is about to meet." >&2
        return 1
    fi
    if ! run_has_netns; then
        return 0
    fi
    for entry in "${SEEDED_LOOSER_KERNEL_CHECKS[@]}"; do
        IFS='|' read -r name seed _ <<<"$entry"
        if ! sysctl -w "$name=$seed" >/dev/null 2>&1; then
            echo "FATAL: could not seed $name=$seed." >&2
            echo "  This run claims its own network namespace, where /proc/sys/net is" >&2
            echo "  writable. If that is not true the mode signal is wrong, and every" >&2
            echo "  kernel row below would be measuring the host." >&2
            return 1
        fi
        # Read back, which the stricter seed has no need to do. That one is
        # proved after apply by run_seeded_kernel_check, so a write the kernel
        # accepted and then ignored shows up there. This one has no row of its
        # own: unread, a seed that did not take would leave the control scoring
        # the value the container shipped while the log said a seed was placed.
        reading="$(kernel_reading "$name")"
        if [[ "$reading" != "$seed" ]]; then
            echo "FATAL: seeded $name=$seed but the kernel reports '$reading'." >&2
            echo "  The pre-apply control below would then be scoring the value this" >&2
            echo "  container shipped, which is the reading the seed exists to replace." >&2
            return 1
        fi
    done
}

# Whether this suite loosened a parameter itself, so the control's evidence can
# say so. Every run now arrives holding one, and a message that read the same
# for a seeded row and a naturally away one would let a log claim a container
# was non-compliant when this suite had made it so.
kernel_seeded_looser() {
    local name="$1" entry seeded
    for entry in "${SEEDED_LOOSER_KERNEL_CHECKS[@]}"; do
        IFS='|' read -r seeded _ <<<"$entry"
        if [[ "$seeded" == "$name" ]]; then
            return 0
        fi
    done
    return 1
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

# What sshd enforced BEFORE any apply. Captured by preapply_seeded_init, which
# refuses to run once apply has happened, because a capture taken afterwards
# would be describing the thing under test rather than its starting point.
SEEDED_BEFORE=""
SEEDED_BEFORE_GENERATION=""

preapply_seeded_init() {
    local out
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply seeded capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It is the control proving the seed took effect, so it has to be taken" >&2
        echo "  while the container still holds only the seed." >&2
        return 1
    fi
    ensure_host_keys || return 1
    if ! out="$(capture_sshd_effective)"; then
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo "FATAL: sshd -T succeeded but printed nothing for the seeded capture" >&2
        return 1
    fi
    SEEDED_BEFORE="$out"
    SEEDED_BEFORE_GENERATION="$APPLY_GENERATION"
}

# One pre-apply reading. The mirror of ssh_system_value, written out rather than
# borrowed, because its freshness rule is the opposite one: this capture is only
# usable if it predates every apply.
seeded_baseline_value() {
    local directive="$1" value
    if [[ -z "$SEEDED_BEFORE" ]]; then
        echo "FATAL: seeded baseline not captured;" \
            "preapply_seeded_init must run before apply" >&2
        return 1
    fi
    if [[ "$SEEDED_BEFORE_GENERATION" != "0" ]]; then
        echo "FATAL: the seeded baseline is stamped generation" \
            "${SEEDED_BEFORE_GENERATION:-unset}, so it was taken after an apply and" \
            "describes a system that had already been changed." >&2
        return 1
    fi
    if ! value="$(extract_sshd_value "$SEEDED_BEFORE" "$directive")"; then
        echo "FATAL: the seeded capture does not report '$directive'" >&2
        return 1
    fi
    if [[ -z "$value" ]]; then
        echo "FATAL: the seeded capture reports '$directive' with no value" >&2
        return 1
    fi
    printf '%s' "$value"
}

# Task 7's acceptance criterion (issue #67): a rollback restored files but
# never asked sshd to reload them, so a host kept enforcing hardening it had
# just been told to undo. Every other block in this file reads a document
# apply or scan already produced; this one is the exception, because the
# defect is in a step neither of those documents can see. It runs its own
# apply, on ssh-hardening alone, then its own rollback, and asks sshd -T
# directly at three points rather than reading anything the tool wrote.
#
# It has to run before every other apply in this file, seeded or otherwise:
# the baseline it rolls back to is "whatever this container shipped", and a
# seed or an apply above it would make that baseline a value this suite wrote
# rather than the host's own starting point.
#
# Two watched directives, not one: both are unseeded SSH_CHECKS rows the tool
# always drives to 'no' (see SSH_CHECKS above), so a working apply is
# guaranteed to move at least one of them off whatever the distribution
# shipped, whatever that default happens to be.
ROLLBACK_RELOAD_DIRECTIVES=(PermitRootLogin PasswordAuthentication)

# Both watched directives from one sshd -T dump, joined into a single string
# so one equality covers both and a difference in either is caught. Built
# through extract_sshd_value, the primitive every other ssh reading in this
# file already goes through, rather than a second grep over the raw dump: two
# readers of the same output agreeing with each other is exactly the failure
# this suite exists to catch (see the file header).
rollback_reload_snapshot() {
    local capture="$1" directive value out=""
    for directive in "${ROLLBACK_RELOAD_DIRECTIVES[@]}"; do
        if ! value="$(extract_sshd_value "$capture" "$directive")"; then
            echo "FATAL: sshd -T does not report '$directive' for the rollback reload check" >&2
            return 1
        fi
        out+="${out:+ }${directive}=${value}"
    done
    printf '%s' "$out"
}

# sshd -T, reduced to the one string the checks below compare, with the same
# host-key prerequisite every other capture point in this file carries. A
# single call for run_rollback_reload_check to make at each of its three
# points, and one seam for self_test to stub the same way ssh_oracle_init's
# proof already does.
rollback_reload_capture() {
    local out
    ensure_host_keys || return 1
    out="$(capture_sshd_effective)" || return 1
    rollback_reload_snapshot "$out"
}

# The positive control, Task 7 step 3, and it is not optional: without it, a
# rollback that restores files sshd never re-reads would still pass the
# restoration check below, because sshd's answer would never have moved away
# from the baseline in the first place, and nothing would show the apply
# reached sshd at all.
rollback_reload_assert_changed() {
    local baseline="$1" after_apply="$2"
    if [[ "$after_apply" != "$baseline" ]]; then
        record_pass "rollback reload positive control: sshd enforced '$baseline' before apply and '$after_apply' after, so the apply reached sshd and the rollback below is testing something real"
    else
        record_fail "rollback reload positive control: sshd still enforces '$baseline' after apply; the apply did not change what sshd enforces, so a rollback that appears to restore it would prove nothing"
    fi
}

# The assertion issue #67 is about. Once the checkpoint the apply took has
# been rolled back, does sshd, asked directly, enforce what it enforced before
# the apply, or did the files come back with nobody telling the running daemon?
rollback_reload_assert_restored() {
    local baseline="$1" after_rollback="$2"
    if [[ "$after_rollback" == "$baseline" ]]; then
        record_pass "rollback reload: sshd enforces '$after_rollback' after rollback, exactly what it enforced before apply, so the reload the rollback triggers reached sshd"
    else
        record_fail "rollback reload: sshd enforced '$baseline' before apply but enforces '$after_rollback' after rollback; the files were restored without sshd being told to reload, which is issue #67"
    fi
}

# The cycle itself. Unlike every apply elsewhere in this file it shells out on
# its own rather than through apply_hardening: apply_hardening covers every
# plugin in DIFF_PLUGINS and is called after the seeds and captures below have
# already been taken, and this check has to run before all of that with only
# ssh-hardening in scope, so the checkpoint it rolls back really is named
# 'ssh-hardening-pre-apply' and really does hold the container's own starting
# values.
#
# Every path records exactly two checks, whatever goes wrong and wherever:
# the positive control and the restoration assertion. A capture, apply,
# checkpoint lookup or rollback that fails is recorded as a failure of
# whichever check(s) it leaves unanswered rather than returning silently, so a
# fixture where this block cannot complete names the defect on its own two
# lines and does not leave the total quietly expecting them.
#
# Whether the run continues past those failures is not decided here. That is
# the gate below, which is what the suite calls.
rollback_reload_cycle() {
    local baseline apply_out apply_status=0 after_apply
    local list_json checkpoint_id rollback_out rollback_status=0 after_rollback

    if ! baseline="$(rollback_reload_capture)"; then
        record_fail "rollback reload positive control: sshd -T could not be read before apply, so nothing shows the apply reached sshd"
        record_fail "rollback reload: sshd -T could not be read before apply, so there is no baseline to roll back to"
        return 0
    fi

    apply_out="$("$BINARY" apply --plugin ssh-hardening 2>&1)" || apply_status=$?
    bump_apply_generation
    echo "rollback reload: apply exit status $apply_status"
    while IFS= read -r line; do
        printf '  rollback-reload apply| %s\n' "$line"
    done <<<"$apply_out"

    if ! after_apply="$(rollback_reload_capture)"; then
        record_fail "rollback reload positive control: sshd -T could not be read after apply"
        record_fail "rollback reload: sshd -T could not be read after apply, so there is no post-apply state to roll back from"
        return 0
    fi
    rollback_reload_assert_changed "$baseline" "$after_apply"

    if ! list_json="$("$BINARY" --format json checkpoint list --all 2>&1)"; then
        record_fail "rollback reload: 'checkpoint list' failed, so no checkpoint id could be found to roll back to"
        return 0
    fi
    # Guarded rather than assigned outright, for the reason the kernel control
    # gives: this function is called directly, so a jq that exits non-zero on a
    # document it cannot parse would end the run from this assignment with the
    # `2>/dev/null` having swallowed the only explanation. The empty-string
    # branch below is where a missing checkpoint is meant to be reported, and it
    # cannot be reached from an abort.
    checkpoint_id="$(jq -r '[.[] | select(.checkpoint_name == "ssh-hardening-pre-apply")] | map(.checkpoint_id) | first // empty' <<<"$list_json" 2>/dev/null || true)"
    if [[ -z "$checkpoint_id" ]]; then
        record_fail "rollback reload: no 'ssh-hardening-pre-apply' checkpoint was found in 'checkpoint list', so there is nothing to roll back to"
        return 0
    fi

    rollback_out="$("$BINARY" rollback "$checkpoint_id" 2>&1)" || rollback_status=$?
    echo "rollback reload: rollback exit status $rollback_status"
    while IFS= read -r line; do
        printf '  rollback-reload rollback| %s\n' "$line"
    done <<<"$rollback_out"

    if ! after_rollback="$(rollback_reload_capture)"; then
        record_fail "rollback reload: sshd -T could not be read after rollback"
        return 0
    fi
    rollback_reload_assert_restored "$baseline" "$after_rollback"
}

# The gate the suite calls, and the reason the cycle above can run first without
# the apply it performs derailing every seed below it.
#
# APPLY_GENERATION is how this file refuses a reading taken on the wrong side of
# an apply, so the seeds and pre-apply captures in run_full_suite all require it
# to read 0. The cycle applies, which takes it to 1, and then rolls that apply
# back. Handing the counter back afterwards is sound for exactly one reason: the
# cycle's own restoration assertion is that sshd -T reports precisely what it
# reported before the apply, so a cycle that PASSED has already proved the
# container is standing in its pre-apply state. The restore is not papering over
# an apply, it records that the apply was undone and that the undoing was
# checked against the daemon rather than assumed.
#
# Which is why a cycle that FAILED must not hand it back. A rollback that never
# reached sshd leaves the container holding the hardening, and every seed,
# capture and check below would then measure a host this suite had already
# changed while reporting the answers as the host's own. That is worse than no
# results, so it ends the run the way every other unrecoverable precondition in
# this file does: the two FAIL lines above name what sshd enforced at each
# reading, and nothing under them is printed with a confidence it has not
# earned.
run_rollback_reload_check() {
    local saved_generation=$APPLY_GENERATION saved_failed=$CHECKS_FAILED
    rollback_reload_cycle
    if (( CHECKS_FAILED != saved_failed )); then
        echo "FATAL: the rollback-reload check failed, so this container is left" \
            "holding ssh hardening it was told to undo." >&2
        echo "  Every check below it reads a host it assumes no apply has touched," >&2
        echo "  so the run stops here rather than measuring a hardened container and" >&2
        echo "  reporting what it finds as the container's own starting values." >&2
        return 1
    fi
    APPLY_GENERATION=$saved_generation
}

# login.defs supplies defaults for NEW accounts only, so the only honest way to
# ask what it currently means is to create a user and read what shadow gave it.
# chage -l on an account that already exists reports that account's /etc/shadow
# row, written when it was created, which says nothing about the file today.
DIFF_PROBE_USER="hardenerdiffprobe"

# The PASS_* directives, the chage -l label reporting each one, the value the
# tool targets, and the passwd -S field carrying the same setting.
# Fields: directive|label|target|passwd-field.
#
# The fourth column is the second reader, and it is consulted only where the
# first cannot answer. On Arch chage reports no minimum at all, so PASS_MIN_DAYS
# has no label to find there however the run is invoked; see
# extract_passwd_status_value for what was measured. Every other distribution
# keeps reading the label it always read, which is why the fallback is per
# directive rather than a replacement: passwd -S could answer all three, but
# swapping a reader proven on four distributions for one proven on none would
# put the four already passing at risk to fix the one that is not.
LOGIN_DEFS_CHECKS=(
    "PASS_MIN_DAYS|Minimum number of days|1|4"
    "PASS_MAX_DAYS|Maximum number of days|90|5"
    "PASS_WARN_AGE|Number of days of warning|7|6"
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
#
# The logind session has to go first, and only a BOOTED container has one. The
# umask probe runs `su - probe`, which under a running systemd opens a login
# session and starts `user@UID.service`; userdel then refuses to remove an
# account that still owns processes, and every later run aborts at the guard.
# Measured 2026-07-30: this killed the differential suite on debian, fedora,
# rhel and openSUSE the first time it ran under --booted, before a single check
# had executed. Both calls are best-effort because neither binary exists in an
# unbooted container, where there is no session to end and userdel simply works.
remove_probe_user() {
    if command -v loginctl > /dev/null 2>&1; then
        loginctl terminate-user "$DIFF_PROBE_USER" > /dev/null 2>&1 || true
        # logind tears the session down asynchronously, so a userdel issued in
        # the same breath still races it.
        local waited=0
        while (( waited < 10 )) && pgrep -u "$DIFF_PROBE_USER" > /dev/null 2>&1; do
            sleep 1
            waited=$((waited + 1))
        done
    fi
    userdel -r "$DIFF_PROBE_USER" > /dev/null 2>&1 || true
    if id "$DIFF_PROBE_USER" > /dev/null 2>&1; then
        # -f removes an account that still owns processes. Reached only when the
        # wait above timed out, and safe here in a way it would not be on a real
        # host: the container is recreated before every measurement.
        userdel -f -r "$DIFF_PROBE_USER" > /dev/null 2>&1 || true
    fi
    if id "$DIFF_PROBE_USER" > /dev/null 2>&1; then
        echo "FATAL: probe user '$DIFF_PROBE_USER' survived cleanup; remove it by hand" >&2
        return 1
    fi
}

# The probe's two readings, published as globals rather than printed.
#
# They are globals because there are two of them and a function has one stdout.
# The alternative, printing both and splitting them apart again, was written
# first and was wrong in a way worth recording: the assignment sat inside a
# function every caller invoked as `$(...)`, so the second reading was set in a
# subshell and the parent never saw it. The fallback could not fire at all. A
# value that has to survive the call must not be returned by assignment from
# inside one.
LOGIN_DEFS_PROBE_CHAGE=""
LOGIN_DEFS_PROBE_PASSWD=""

# Create the probe user, read the shadow row login.defs just gave it with both
# readers, and remove the user again. Sets the two globals above; prints
# nothing, so no caller can wrap it in a command substitution and lose half.
# Callers want login_defs_system_value; this runs once, through the init below.
login_defs_system_values() {
    LOGIN_DEFS_PROBE_CHAGE=""
    LOGIN_DEFS_PROBE_PASSWD=""
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
    # The second reader, taken here because both readings describe the same
    # probe account and this is the only point at which it exists to be asked.
    #
    # A failure is deliberately not fatal. On four of the five distributions
    # chage answers every directive and this capture is never consulted, so a
    # passwd that could not be run must not end a run it was not needed for.
    # The directive that does need it says so loudly at the point of use.
    local status
    if ! status="$(LC_ALL=C passwd -S "$DIFF_PROBE_USER" 2>/dev/null)"; then
        status=""
    fi
    remove_probe_user || return 1
    LOGIN_DEFS_PROBE_CHAGE="$out"
    LOGIN_DEFS_PROBE_PASSWD="$status"
}

# Captured by login_defs_oracle_init, which must run after apply. Empty means the
# capture never happened, which login_defs_system_value treats as fatal for the
# same reason as the ssh oracle: a missing capture must not read like an absent
# value, and an absent value must not read like a pass.
# The probe reads what login.defs means NOW, so a capture taken before apply
# describes the old file. That is what the generation stamp catches.
LOGIN_DEFS_CHAGE=""
LOGIN_DEFS_CHAGE_GENERATION=""
# The second reader's capture, taken from the same probe account in the same
# breath as the one above and therefore covered by that one's generation stamp.
# Empty means passwd -S could not be run or has not run yet, and the only
# directive that consults it treats empty as no value rather than as a pass.
LOGIN_DEFS_PASSWD_STATUS=""

login_defs_oracle_init() {
    # Called directly, never as `$(...)`: the probe publishes two readings
    # through globals, and a subshell would drop both.
    login_defs_system_values || return 1
    if [[ -z "$LOGIN_DEFS_PROBE_CHAGE" ]]; then
        echo "FATAL: chage -l succeeded but printed nothing" >&2
        return 1
    fi
    LOGIN_DEFS_CHAGE="$LOGIN_DEFS_PROBE_CHAGE"
    LOGIN_DEFS_PASSWD_STATUS="$LOGIN_DEFS_PROBE_PASSWD"
    LOGIN_DEFS_CHAGE_GENERATION="$APPLY_GENERATION"
}

# The whole LOGIN_DEFS_CHECKS row for one PASS_* directive, so the caller
# unpacks both readers from one lookup rather than searching the table twice.
login_defs_row() {
    local directive="$1" entry name
    for entry in "${LOGIN_DEFS_CHECKS[@]}"; do
        IFS='|' read -r name _ <<<"$entry"
        if [[ "$name" == "$directive" ]]; then
            printf '%s' "$entry"
            return 0
        fi
    done
    return 1
}

# Print what login.defs currently means for one PASS_* directive, as shadow
# applied it to a brand new account.
# Returns non-zero, loudly, when the oracle was never initialised, its capture
# predates the last apply, the directive is not in the table, or neither reader
# reported it.
login_defs_system_value() {
    local directive="$1" row label field value status=0
    require_fresh_capture login_defs "$LOGIN_DEFS_CHAGE" "$LOGIN_DEFS_CHAGE_GENERATION" || return 1
    if ! row="$(login_defs_row "$directive")"; then
        echo "FATAL: no chage label known for '$directive'" >&2
        return 1
    fi
    IFS='|' read -r _ label _ field <<<"$row"
    value="$(extract_chage_value "$LOGIN_DEFS_CHAGE" "$label")" || status=$?
    if (( status == 0 )); then
        printf '%s' "$value"
        return 0
    fi
    # Only an absent label falls through to the second reader. A pattern grep
    # rejected is status 2, which extract_chage_value has already shouted about,
    # and answering that from elsewhere would hide a malformed table entry
    # behind a value that looked correct.
    if (( status != 1 )); then
        return 1
    fi
    if [[ -n "$LOGIN_DEFS_PASSWD_STATUS" ]] &&
        value="$(extract_passwd_status_value "$LOGIN_DEFS_PASSWD_STATUS" "$field")"; then
        printf '%s' "$value"
        return 0
    fi
    # The output goes with the message. The arch run that raised this said only
    # that the label was missing, so the log could not show what chage had
    # actually printed and the cause could not be diagnosed from the evidence
    # the run produced.
    {
        echo "FATAL: neither reader reports '$label' for '$directive'."
        echo "  chage -l printed:"
        printf '%s\n' "$LOGIN_DEFS_CHAGE" | sed 's/^/    /'
        echo "  passwd -S printed: ${LOGIN_DEFS_PASSWD_STATUS:-<nothing>}"
    } >&2
    return 1
}

# Settings this tool does not manage, and must therefore leave exactly as it
# found them.
#
# This is the check the suite was missing, and the reason 110/110 was never
# proof. Every other check here asks whether a setting the tool targets reached
# its target. None asked whether the settings it does not target survived the
# run, so the openSUSE defect, where a three-directive /etc/login.defs masked
# the 35 keys the vendor file set, could reappear with every existing check
# green.
#
# The assertion is the invariant, never a value. Measured across the five
# containers, ENCRYPT_METHOD is yescrypt on arch, debian, fedora and rhel and
# sha512 on openSUSE Leap, and UMASK is 0002 on debian against 0022 elsewhere;
# hardcoding any of them would make the check distribution-specific for no gain,
# and the obvious guess would have been wrong in both cases.
#
# Each of the three has been watched moving under the masking this exists to
# catch, so none of them is a check that cannot fail. Replacing the vendor file
# with the one-directive /etc/login.defs that releases up to 1.5.0 wrote takes
# ENCRYPT_METHOD from sha512 to DES and HOME_MODE from 0700 to 755 on openSUSE
# Leap, and UMASK from 0002 to 0022 on debian. Deleting one as untestable would
# be deleting a proven check. The tool does not manage these, so any
# change to them is damage whatever the value was, and comparing before against
# after catches masking the suite has never seen as well as the one it has.
VENDOR_SURVIVAL_CHECKS=(ENCRYPT_METHOD HOME_MODE UMASK)

# The password the probe account is given so ENCRYPT_METHOD has something to
# hash. Long, mixed-case, with a digit and a symbol, because the apply under
# test hardens pwquality and a password chpasswd rejected after apply but
# accepted before would read as damage this suite invented.
# shellcheck disable=SC2016  # a literal password, not an expression to expand
DIFF_PROBE_PASSWORD='Qv7#tRm2!xLb9$Zk'

# The hashing scheme a shadow password field was written with, as `$id$`.
#
# ENCRYPT_METHOD is read this way rather than out of login.defs because the
# hash is what the setting produced: crypt wrote the prefix, so it is the
# consumer's own answer, and it stays readable when the file that chose it has
# been masked away.
#
# A field carrying no usable hash is refused rather than reported. "!", "!!",
# "*" and a "!"-prefixed hash all mean the account cannot authenticate, and all
# of them are stable across an apply, so returning one would let a reading that
# proves nothing pass as a setting that survived.
shadow_hash_scheme() {
    local field="$1" scheme_pattern='^(\$[^$]+\$)'
    if [[ -z "$field" ]]; then
        echo "FATAL: the probe account has no shadow password field" >&2
        return 1
    fi
    if [[ "$field" == '!'* || "$field" == '*'* ]]; then
        echo "FATAL: the probe account's password field is '$field', which is a" \
            "locked or empty password and names no hashing scheme" >&2
        return 1
    fi
    if [[ "$field" =~ $scheme_pattern ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
        return 0
    fi
    # No "$id$" prefix at all is the historic DES format, which is a real
    # answer and a different one from every prefixed scheme.
    printf 'descrypt'
}

# One field of the probe account's row in a colon-separated account file.
#
# Read with the shell rather than through awk. gawk is not in the package set
# scripts/containers/create-container.sh installs for the dnf family or for
# openSUSE, and a command that turns out to be missing would refuse the entire
# run over a reading bash can take unaided.
#
# Returns non-zero when the account has no row, which is a different thing from
# a row whose field is empty: the first means the probe is not there at all.
probe_account_field() {
    local file="$1" field="$2" line fields
    while IFS= read -r line; do
        IFS=: read -r -a fields <<<"$line"
        # Exact match. A prefix match would read the row of any account whose
        # name merely starts the same way.
        [[ "${fields[0]:-}" == "$DIFF_PROBE_USER" ]] || continue
        printf '%s' "${fields[$((field - 1))]:-}"
        return 0
    done <"$file"
    return 1
}

# The three readings, taken from an existing probe account.
#
# Each asks the setting's consumer: crypt for the hashing scheme, the
# filesystem for the mode useradd gave the home directory, and a login session
# for the umask it starts with. None of them re-reads login.defs, which is the
# file whose masking these checks exist to catch.
vendor_survival_probe_readings() {
    local field scheme home mode session_umask octal='^[0-7]{3,4}$'
    # A here-string rather than a pipe: chpasswd's own status is what matters,
    # and a pipeline reports its last stage's.
    if ! chpasswd <<<"$DIFF_PROBE_USER:$DIFF_PROBE_PASSWORD"; then
        echo "FATAL: chpasswd failed for the probe account" >&2
        return 1
    fi
    if ! field="$(probe_account_field /etc/shadow 2)"; then
        echo "FATAL: /etc/shadow holds no row for the probe account" >&2
        return 1
    fi
    scheme="$(shadow_hash_scheme "$field")" || return 1
    if ! home="$(probe_account_field /etc/passwd 6)"; then
        echo "FATAL: /etc/passwd holds no row for the probe account" >&2
        return 1
    fi
    if [[ -z "$home" || ! -d "$home" ]]; then
        echo "FATAL: the probe account has no home directory to read a mode from" >&2
        return 1
    fi
    if ! mode="$(stat -c %a "$home")"; then
        echo "FATAL: stat could not read the mode of $home" >&2
        return 1
    fi
    # The umask a login session starts with, which is what login.defs UMASK
    # feeds through pam_umask. Where a distribution's su stack does not load
    # pam_umask this reports the shell's own default, and the comparison then
    # says that default did not move: a weaker claim than the other two, and
    # still a true one, because it is what a user's session actually gets.
    if ! session_umask="$(su - "$DIFF_PROBE_USER" -c umask)"; then
        echo "FATAL: su could not open a login session for the probe account" >&2
        return 1
    fi
    session_umask="${session_umask//[[:space:]]/}"
    # Both are printed into a KEY value line, so a value carrying whitespace or
    # an error string would silently reshape the capture the extractor reads.
    if [[ ! "$mode" =~ $octal ]]; then
        echo "FATAL: the home directory mode '$mode' is not an octal mode" >&2
        return 1
    fi
    if [[ ! "$session_umask" =~ $octal ]]; then
        echo "FATAL: the session umask '$session_umask' is not an octal mask" >&2
        return 1
    fi
    printf '%s\n' "ENCRYPT_METHOD $scheme" "HOME_MODE $mode" "UMASK $session_umask"
}

# Whether an unmanaged setting survived: the value after apply is the value
# before it, and both were actually read.
#
# An empty side never agrees. Two silences comparing equal is the shape this
# whole family exists to refuse, and it is reachable: a reading that could not
# be taken twice in a row would otherwise report the setting as untouched.
vendor_survival_agrees() {
    local before="$1" after="$2"
    [[ -n "$before" && -n "$after" && "$before" == "$after" ]]
}

# Create the probe account, take the three readings, remove it again. Prints
# one `KEY value` line per check, the shape sshd -T uses, so the extractor below
# is the one the ssh oracle already has rather than a second reader.
#
# The account is removed on the failure path too, exactly as the login.defs
# probe does it: a leaked account aborts every later run at the guard above.
vendor_survival_values() {
    require_absent_probe_user || return 1
    # The shell is pinned rather than inherited from /etc/default/useradd. The
    # umask reading needs a login session, and a default of nologin would make
    # the probe fail on the distribution rather than report on it.
    if ! useradd -m -s /bin/sh "$DIFF_PROBE_USER" >/dev/null 2>&1; then
        echo "FATAL: could not create probe user for the vendor survival checks" >&2
        return 1
    fi
    local out status=0
    out="$(vendor_survival_probe_readings)" || status=$?
    if (( status != 0 )); then
        remove_probe_user || true
        return 1
    fi
    remove_probe_user || return 1
    printf '%s' "$out"
}

# The capture taken BEFORE apply, and the one taken after.
#
# The before capture is this family's positive control as well as half of its
# comparison: it is taken while the container is known to be untouched, and
# every reading in it must have been read for real, so a probe that silently
# answers nothing fails the run at the start rather than agreeing with itself
# at the end.
VENDOR_SURVIVAL_BEFORE=""
VENDOR_SURVIVAL_BEFORE_GENERATION=""
VENDOR_SURVIVAL_AFTER=""
VENDOR_SURVIVAL_AFTER_GENERATION=""

# Taken above apply, and refused once one has run: a "before" capture taken
# afterwards describes the system this suite is trying to compare against.
preapply_vendor_survival_init() {
    local out
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply vendor survival capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It is the value these checks compare against, so it has to be taken" >&2
        echo "  while the container is still unhardened." >&2
        return 1
    fi
    if ! out="$(vendor_survival_values)"; then
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo "FATAL: the vendor survival probe succeeded but read nothing" >&2
        return 1
    fi
    VENDOR_SURVIVAL_BEFORE="$out"
    VENDOR_SURVIVAL_BEFORE_GENERATION="$APPLY_GENERATION"
}

vendor_survival_oracle_init() {
    local out
    if ! out="$(vendor_survival_values)"; then
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo "FATAL: the vendor survival probe succeeded but read nothing" >&2
        return 1
    fi
    VENDOR_SURVIVAL_AFTER="$out"
    VENDOR_SURVIVAL_AFTER_GENERATION="$APPLY_GENERATION"
}

# One reading out of a capture. The capture is written in the `KEY value` shape
# sshd -T prints, so the ssh extractor reads it: one reader, and its absent and
# valueless paths are already pinned by the self-test.
vendor_survival_reading() {
    local capture="$1" key="$2" value
    if ! value="$(extract_sshd_value "$capture" "$key")"; then
        echo "FATAL: the vendor survival capture does not report '$key'" >&2
        return 1
    fi
    if [[ -z "$value" ]]; then
        echo "FATAL: the vendor survival capture reports '$key' with no value" >&2
        return 1
    fi
    printf '%s' "$value"
}

# What the system holds now, refused unless the capture followed the last apply.
vendor_survival_system_value() {
    local key="$1"
    require_fresh_capture vendor_survival "$VENDOR_SURVIVAL_AFTER" \
        "$VENDOR_SURVIVAL_AFTER_GENERATION" || return 1
    vendor_survival_reading "$VENDOR_SURVIVAL_AFTER" "$key"
}

# What it held before, refused unless the capture predates every apply. The
# mirror image of the rule above, written out rather than borrowed, for the
# same reason the pre-apply scan capture has its own.
vendor_survival_baseline_value() {
    local key="$1"
    if [[ -z "$VENDOR_SURVIVAL_BEFORE" ]]; then
        echo "FATAL: vendor survival baseline not captured;" \
            "preapply_vendor_survival_init must run before apply" >&2
        return 1
    fi
    if [[ "$VENDOR_SURVIVAL_BEFORE_GENERATION" != "0" ]]; then
        echo "FATAL: the vendor survival baseline is stamped generation" \
            "${VENDOR_SURVIVAL_BEFORE_GENERATION:-unset}, so it was taken after an" \
            "apply and describes a system that had already been changed." >&2
        return 1
    fi
    vendor_survival_reading "$VENDOR_SURVIVAL_BEFORE" "$key"
}

# Applying twice must change nothing the second time.
#
# The scheduler applies on a cadence, so a second apply that undoes the first is
# a fleet host returning to an unhardened state on a timer while reporting
# success at every step. A single-apply oracle structurally cannot see that,
# which is how the defect fixed in 2f10089 and 4c715fe reached a released
# branch: every check in this suite was green after one apply, and the tool
# removed its own drop-in on the next run.
#
# The readings are whole, not per directive. A directive nobody thought to list
# is exactly what this class of defect moves, so each reading is the consumer's
# entire answer and the comparison is byte equality.
# permission-modes is FIRST, and the position is load-bearing. Reading login-defs
# creates and removes a probe account, and useradd and userdel rewrite /etc/passwd
# and /etc/shadow. Taking the permission baseline ahead of it keeps one probe cycle
# out from between the two readings this check compares.
IDEMPOTENCE_CHECKS=(permission-modes sshd-effective sshd-dropins login-defs)

# The fragment directory as names and contents.
#
# sshd -T answers what the daemon enforces, which is the more important
# question, but a fragment can be rewritten or removed without moving any
# effective value, and "the second apply changed nothing" is a claim about the
# files as well. Every branch prints something: two empty readings compare equal
# and would pass by saying nothing at all.
sshd_dropin_listing() {
    local dir="${1:-/etc/ssh/sshd_config.d}" file found=0
    if [[ ! -d "$dir" ]]; then
        printf 'directory absent'
        return 0
    fi
    # Glob expansion is sorted, so this describes the directory rather than the
    # order the filesystem happened to return it in.
    for file in "$dir"/*; do
        [[ -f "$file" ]] || continue
        found=$((found + 1))
        printf '=== %s\n' "$file"
        cat -- "$file" || return 1
    done
    if (( found == 0 )); then
        printf 'directory empty'
    fi
}

# One idempotency reading, by key, delegating to the same consumer the rest of
# the suite asks so a reading cannot come to mean something different here than
# it does there.
idempotence_reading() {
    local key="$1" reading line
    case "$key" in
        sshd-effective)
            ensure_host_keys || return 1
            capture_sshd_effective
            ;;
        sshd-dropins)
            sshd_dropin_listing
            ;;
        permission-modes)
            # Every managed mode as one whole reading, which is the point: a
            # second apply that moves a mode nobody thought to list still shows
            # up. The kernel plugin's sysctl.d fragment is the closest structural
            # analogue to the ssh one and has never been applied twice under
            # test, so this is the second plugin in the repo whose apply is
            # checked for idempotency at all.
            permission_modes_capture
            ;;
        login-defs)
            # A fresh probe account is created for each reading, so the date it
            # records is a property of when the reading was taken rather than of
            # what login.defs means. Left in, a run straddling midnight would
            # report a change the tool did not make. Assigned before filtering
            # rather than piped, because a pipeline reports its last stage's
            # status and would swallow a probe that failed. The probe is called
            # directly rather than as `$(...)`, because it publishes its two
            # readings through globals; only chage's is compared here.
            login_defs_system_values || return 1
            reading="$LOGIN_DEFS_PROBE_CHAGE"
            while IFS= read -r line; do
                if [[ "$line" != "Last password change"* ]]; then
                    printf '%s\n' "$line"
                fi
            done <<<"$reading"
            ;;
        *)
            echo "FATAL: no idempotency reading known for '$key'" >&2
            return 1
            ;;
    esac
}

# The readings taken between the two applies, keyed by check name, and the
# generation they were taken at.
declare -A IDEMPOTENCE_BEFORE=()
IDEMPOTENCE_BEFORE_GENERATION=""

# Capture every reading after the first apply and before the second.
#
# Refused unless exactly one apply has happened. Taken any later, the comparison
# is a reading against itself, which is the shape of a check that cannot fail.
# An empty reading is refused for the same reason.
first_apply_idempotence_init() {
    local key reading
    if (( APPLY_GENERATION != 1 )); then
        echo "FATAL: the idempotency baseline must be taken between the first apply" \
            "and the second; apply is at generation $APPLY_GENERATION." >&2
        return 1
    fi
    for key in "${IDEMPOTENCE_CHECKS[@]}"; do
        if ! reading="$(idempotence_reading "$key")"; then
            echo "FATAL: the idempotency baseline for '$key' could not be read" >&2
            return 1
        fi
        if [[ -z "$reading" ]]; then
            echo "FATAL: the idempotency baseline for '$key' is empty, so it would" \
                "compare equal to any other empty reading" >&2
            return 1
        fi
        IDEMPOTENCE_BEFORE["$key"]="$reading"
    done
    IDEMPOTENCE_BEFORE_GENERATION="$APPLY_GENERATION"
}

# The reading taken after the first apply.
#
# Refused when it was never taken, when it carries any generation other than the
# first apply's, and when no second apply has happened. Each of those turns the
# comparison into a reading against itself.
idempotence_baseline() {
    local key="$1"
    if [[ -z "$IDEMPOTENCE_BEFORE_GENERATION" ]]; then
        echo "FATAL: idempotency baseline not captured;" \
            "first_apply_idempotence_init must run between the two applies" >&2
        return 1
    fi
    if [[ "$IDEMPOTENCE_BEFORE_GENERATION" != "1" ]]; then
        echo "FATAL: the idempotency baseline is stamped generation" \
            "$IDEMPOTENCE_BEFORE_GENERATION, so it does not describe what one apply" \
            "produced." >&2
        return 1
    fi
    if (( APPLY_GENERATION < 2 )); then
        echo "FATAL: the idempotency comparison needs a second apply; apply is at" \
            "generation $APPLY_GENERATION." >&2
        return 1
    fi
    if [[ -z "${IDEMPOTENCE_BEFORE[$key]+set}" ]]; then
        echo "FATAL: no idempotency baseline was captured for '$key'" >&2
        return 1
    fi
    printf '%s' "${IDEMPOTENCE_BEFORE[$key]}"
}

# The lines one reading has and the other does not, both ways round, prefixed so
# no line of a reading can be mistaken for one of this suite's own counters by
# whatever parses the log.
#
# grep rather than diff: diff is not in the package set
# scripts/containers/create-container.sh installs, and a FAIL that cannot say
# what moved sends the next person to hand-run containers, which is the cost
# this suite exists to remove.
idempotence_report_difference() {
    local key="$1" before="$2" after="$3" line
    while IFS= read -r line; do
        printf '  diff| %s only after the first apply: %s\n' "$key" "$line"
    done < <(grep -Fxv -f <(printf '%s\n' "$after") <(printf '%s\n' "$before") || true)
    while IFS= read -r line; do
        printf '  diff| %s only after the second apply: %s\n' "$key" "$line"
    done < <(grep -Fxv -f <(printf '%s\n' "$before") <(printf '%s\n' "$after") || true)
}

# === Password quality actually being enforced ===

# /etc/security/pwquality.conf is read by pam_pwquality.so and by nothing else.
# A host whose PAM stack never loads that module enforces no password policy
# however the file is written, so every check that reads the file agrees with
# itself and with the tool while the system enforces nothing. That is the shape
# this suite exists to catch, and it needed a consumer to ask rather than a
# second parser: the stack decides whether the file is read at all, and
# libpwquality decides what the file means once it is.
#
# Two readings, one check each. The first compares the stack against the tool's
# verdict, which is the differential proper. The second is the positive control
# the first cannot supply: a policy that rejects everything and a policy that
# rejects nothing both make a one-sided filter look right, so the strong
# password must be accepted in the same breath as the weak one is refused.
PWQUALITY_ENFORCEMENT_CHECKS=(module-loaded weak-password-refused)

# The stack files the tool searches, in the same order and with the same names.
# A distribution keeping its stack elsewhere reads as unreadable below, never as
# absent: concluding "no module" from a file that is not there would fail every
# such host on the strength of this list being short.
PWQUALITY_STACK_FILES=(
    /etc/pam.d/system-auth
    /etc/pam.d/password-auth
    /etc/pam.d/common-password
)

# A password no policy worth having accepts: three characters, one class, and
# far below the minlen of 14 the tool targets. Kept beside the strong probe
# password so the pair that forms the control is read together.
PWQUALITY_WEAK_PASSWORD='abc'

# Whether PAM stack text loads pam_pwquality.
#
# Pure, so the self-test can pin it without a container. A commented line is not
# a loaded module: openSUSE's pam-config writes exactly that when libpwquality
# is not installed, which is the host this check was written for.
pwquality_module_loaded_in() {
    local content="$1" line
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ "$line" == '#'* ]] && continue
        [[ "$line" == *pam_pwquality.so* ]] && return 0
    done <<<"$content"
    return 1
}

# What the system says about the module: 'loaded', 'absent', or a refusal.
#
# A refusal when not one candidate could be read, because absence concluded from
# nothing is the same mistake as a filter that matches nothing: it would score a
# host this suite never looked at as a host with no module.
pwquality_stack_reading() {
    local file content read_one=0
    for file in "${PWQUALITY_STACK_FILES[@]}"; do
        [[ -e "$file" ]] || continue
        if ! content="$(cat "$file" 2>/dev/null)"; then
            continue
        fi
        read_one=1
        if pwquality_module_loaded_in "$content"; then
            printf 'loaded'
            return 0
        fi
    done
    if (( read_one == 0 )); then
        echo "FATAL: none of ${PWQUALITY_STACK_FILES[*]} could be read, so whether" \
            "pam_pwquality is loaded is not a question this run answered" >&2
        return 1
    fi
    printf 'absent'
}

# libpwquality's own verdict on a password: 'refused', 'accepted', or 'no-tool'.
#
# pwscore ships with libpwquality and applies /etc/security/pwquality.conf, so
# it is the file's consumer answering rather than this script re-reading it.
# Its absence is a real answer and not a skip: no libpwquality means no
# pam_pwquality.so either, so the policy cannot be in force.
pwquality_verdict() {
    local password="$1"
    if ! command -v pwscore >/dev/null 2>&1; then
        printf 'no-tool'
        return 0
    fi
    if printf '%s\n' "$password" | pwscore >/dev/null 2>&1; then
        printf 'accepted'
    else
        printf 'refused'
    fi
}

# Why libpwquality refused a password, in its own words.
#
# Called only on the failure path, and it exists because the first version of
# this family did not have it. fedora refused the probe password where rhel
# accepted it, and the check reported 'refused' against 'accepted' without
# saying why, which is a diagnostic that has discarded the only thing it was
# for. A refusal that names no rule cannot be told apart from a refusal by a
# rule this suite should be honouring.
pwquality_refusal_detail() {
    local password="$1" message
    command -v pwscore >/dev/null 2>&1 || {
        printf 'pwscore is not installed'
        return 0
    }
    # `|| true` because a non-zero pwscore is the NORMAL case here: this
    # function is called only on the failure path, so the password has already
    # been refused and pwscore is being asked why. Every caller today reaches it
    # from inside a command substitution, where `set -e` does not apply without
    # `inherit_errexit`, so the abort is latent rather than live: one direct
    # call would arm it.
    message="$(printf '%s\n' "$password" | pwscore 2>&1 >/dev/null || true)"
    if [[ -z "$message" ]]; then
        printf 'pwscore refused it and said nothing'
        return 0
    fi
    printf '%s' "${message//$'\n'/ }"
}

# Every file libpwquality reads, not only the one the tool writes.
#
# libpwquality 1.4.1 and later read /etc/security/pwquality.conf.d/*.conf after
# the main file, so a drop-in there overrides it, and this tool writes only the
# main file. Reported beside a refusal so a stricter-than-expected policy can be
# told apart from a rule of the file the tool controls.
pwquality_configuration_sources() {
    local dropins=() file
    for file in /etc/security/pwquality.conf.d/*.conf; do
        [[ -e "$file" ]] && dropins+=("$file")
    done
    if (( ${#dropins[@]} == 0 )); then
        printf '/etc/security/pwquality.conf only'
        return 0
    fi
    printf '/etc/security/pwquality.conf plus %s' "${dropins[*]}"
}

# The system and the tool agree about whether password quality is enforced.
#
# Pure, and pinned in all four directions by the self-test, because this is the
# comparison the whole check reduces to: the tool must report minlen unsatisfied
# exactly when the stack cannot enforce it. Either direction alone passes on a
# broken harness, which is why neither is asserted on its own.
pwquality_enforcement_agrees() {
    local reading="$1" findings="$2"
    case "$reading" in
        loaded) (( findings == 0 )) ;;
        absent) (( findings > 0 )) ;;
        *) return 1 ;;
    esac
}

# One check per reading, both determinate on every path.
#
# A reading that could not be taken is a failure and costs that entry its check,
# never a skip, so the totals stay comparable between a run whose probes
# answered and one whose did not.
run_pwquality_enforcement_checks() {
    local reading findings weak strong
    if ! reading="$(pwquality_stack_reading)"; then
        record_fail "pwquality module-loaded: no PAM stack file could be read, so nothing shows whether the policy can be enforced at all"
        record_fail "pwquality weak-password-refused: without a stack reading there is nothing to hold the password verdict against"
        return
    fi

    if ! findings="$(scan_finding_count pam-hardening "$(pam_finding_id minlen)")"; then
        record_fail "pwquality module-loaded: the post-apply scan could not be read, so the tool's verdict is unknown"
    elif pwquality_enforcement_agrees "$reading" "$findings"; then
        record_pass "pwquality module-loaded: the stack reads '$reading' and the tool reported $findings minlen finding(s), which is what that stack allows"
    else
        record_fail "pwquality module-loaded: the stack reads '$reading' but the tool reported $findings minlen finding(s); a policy nothing loads cannot be satisfied, and one that is loaded and applied should not be failing"
    fi

    weak="$(pwquality_verdict "$PWQUALITY_WEAK_PASSWORD")"
    strong="$(pwquality_verdict "$DIFF_PROBE_PASSWORD")"
    if [[ "$reading" == loaded ]]; then
        if [[ "$weak" == refused && "$strong" == accepted ]]; then
            record_pass "pwquality weak-password-refused: libpwquality refused the weak password and accepted the probe password, so the policy is applied rather than merely written"
        else
            record_fail "pwquality weak-password-refused: libpwquality returned '$weak' for the weak password and '$strong' for the probe password on a host whose stack loads the module; a policy that refuses everything or nothing proves the same amount. It read $(pwquality_configuration_sources), and of the probe password it said: $(pwquality_refusal_detail "$DIFF_PROBE_PASSWORD")"
        fi
    elif [[ "$weak" == refused ]]; then
        record_fail "pwquality weak-password-refused: libpwquality refused the weak password on a host whose stack does not load pam_pwquality, so the two readings describe different hosts"
    else
        record_pass "pwquality weak-password-refused: the stack loads no pam_pwquality and libpwquality returned '$weak', which is consistent: nothing here enforces the file"
    fi
}

# === Kernel parameters the running kernel enforces ===
#
# What the kernel currently enforces for one parameter, asked of sysctl.
#
# Prints `unreadable` rather than an empty string on failure, so a value that
# could not be read is a token the comparison rejects rather than a silence that
# compares equal to another silence.
kernel_reading() {
    local name="$1" value
    if ! value="$(sysctl -n "$name" 2>/dev/null)"; then
        printf 'unreadable'
        return 0
    fi
    # Trim, never delete. Deleting whitespace would turn a multi-value
    # parameter such as the tcp_*_mem triples into one plausible-looking
    # integer, which then passes the numeric guard below and is compared
    # arithmetically against a target nobody meant it to meet. None of the
    # parameters in KERNEL_CHECKS is multi-value today, so this is a property
    # of the reader rather than a live case: a reading this function cannot
    # represent as a single value is `unreadable`, which satisfies nothing.
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ -z "$value" || "$value" =~ [[:space:]] ]]; then
        printf 'unreadable'
        return 0
    fi
    printf '%s' "$value"
}

# Whether a reading is at least as strict as the target, in that parameter's
# own direction. Returns 0 when satisfied.
#
# `unreadable` satisfies nothing, in every direction. That is the suite's rule
# that an undeterminable value is a failure, kept intact: a parameter the
# fixture cannot be asked about is declared in KERNEL_UNASKABLE and never
# reaches this function.
kernel_satisfies() {
    local reading="$1" target="$2" direction="$3"

    if [[ "$reading" == "unreadable" ]]; then
        return 1
    fi

    if [[ "$direction" == ranked:* ]]; then
        local order="${direction#ranked:}" position=0 got=-1 want=-1 entry
        local -a _kernel_rank
        IFS=',' read -r -a _kernel_rank <<<"$order"
        for entry in "${_kernel_rank[@]}"; do
            [[ "$entry" == "$reading" ]] && got=$position
            [[ "$entry" == "$target" ]] && want=$position
            position=$((position + 1))
        done
        # A value outside the declared space cannot be placed, and an
        # unplaceable value is not evidence of compliance.
        if (( got < 0 || want < 0 )); then
            return 1
        fi
        (( got >= want ))
        return
    fi

    if ! [[ "$reading" =~ ^-?[0-9]+$ && "$target" =~ ^-?[0-9]+$ ]]; then
        return 1
    fi

    case "$direction" in
        at-least) (( reading >= target )) ;;
        at-most) (( reading <= target )) ;;
        *) return 1 ;;
    esac
}

# The kernel parameters this suite can ask about, and the direction each
# comparison has.
#
# Read `sysctl -n`, which is the parameter's real consumer, never the file the
# tool wrote: a reader and a writer sharing one mistake agree with each other
# and disagree with Linux.
#
# The direction is not decoration. Every row mirrors the Strictness the plugin
# declares in crates/hardener-plugins/src/kernel/mod.rs, and an equality
# comparison would report a false failure on any host already stricter than the
# target: tcp_syncookies 2 sends cookies unconditionally rather than under
# pressure, and a host at 2 is ahead of the target of 1, not broken.
#
# rp_filter is the sharp case, and it is sharp in the opposite direction to the
# arithmetic. 0 is off, 2 is loose mode, which accepts a packet whose source is
# reachable through any interface, and 1 is strict mode, which requires the
# interface it arrived on. The larger number is therefore the weaker setting and
# no numeric direction can express that at all, which is why the row carries the
# value space itself. The order below is RP_FILTER_ORDER from the plugin,
# copied rather than restated.
#
#   at-least  the reading must be at least the target
#   at-most   the reading must be at most the target
#   ranked    a listed value space, weakest first, compared by position
KERNEL_CHECKS=(
    "net.ipv4.conf.all.rp_filter|1|ranked:0,2,1"
    "net.ipv4.conf.default.rp_filter|1|ranked:0,2,1"
    "net.ipv4.tcp_syncookies|1|at-least"
    "net.ipv4.conf.all.log_martians|1|at-least"
    "net.ipv4.conf.default.log_martians|1|at-least"
    "net.ipv4.conf.all.accept_source_route|0|at-most"
    "net.ipv4.conf.default.accept_source_route|0|at-most"
    "net.ipv4.conf.all.accept_redirects|0|at-most"
    "net.ipv4.conf.default.accept_redirects|0|at-most"
    "net.ipv4.conf.all.secure_redirects|0|at-most"
    "net.ipv4.conf.default.secure_redirects|0|at-most"
)

# The parameters this fixture cannot be asked about, with the reason each is
# out of reach. Declared, never inferred: see record_unaskable.
#
# Measured 2026-07-29 and 2026-07-30, under --pipe AND under --boot: nspawn
# mounts /proc/sys read-only and it is the HOST's, so these read the host's
# values and a write is refused with
# `sysctl: permission denied on key "kernel.kptr_restrict"`. Only /proc/sys/net
# is remounted read-write, and only for a container holding its own network
# namespace, which is why the table above is entirely net.ipv4.
#
# The two tables together are the plugin's whole KERNEL_PARAMS list: the 11 rows
# above plus the 7 below are the 18 parameters kernel/mod.rs manages, and both
# sizes are pinned so neither can shrink without the other being noticed.
KERNEL_UNASKABLE=(
    "kernel.randomize_va_space|/proc/sys is the host's and read-only in a container"
    "kernel.kptr_restrict|/proc/sys is the host's and read-only in a container"
    "kernel.dmesg_restrict|/proc/sys is the host's and read-only in a container"
    "kernel.yama.ptrace_scope|/proc/sys is the host's and read-only in a container"
    "fs.suid_dumpable|/proc/sys is the host's and read-only in a container"
    "fs.protected_hardlinks|/proc/sys is the host's and read-only in a container"
    "fs.protected_symlinks|/proc/sys is the host's and read-only in a container"
)

# === Permission modes actually on disk ===
#
# The oracle is the filesystem, asked through `stat -c %a`, which is the only
# consumer a mode has: nothing parses a permission the way sshd parses a
# directive, so the mode the kernel reports IS the enforced value.
#
# Fields: path|mode|comparison. The nine rows mirror CRITICAL_PERMISSIONS in
# crates/hardener-plugins/src/permissions/mod.rs, and the comparison column is
# that table's permission_max_mask spelled the way this suite asks questions:
# `exact` for its seven exact-match directives, `mask` for the two whose mode is
# an allowed-bits mask.
#
# The two mask rows are the reason requirement_satisfied has a direction at all.
# /etc/shadow ships at 0600 on Arch and 0000 on Fedora and RHEL, all stricter than
# the 0640 mask and all correct, and the tool deliberately leaves them alone. An
# equality oracle would have reported a defect on THREE of the five distributions
# against a tool doing exactly what it was designed to do. Measured 2026-07-30:
# 600 arch, 640 debian, 0 fedora, 0 rhel, 640 openSUSE. This comment said "two of
# five" until the readings were counted; Fedora was the one it missed.
PERMISSION_CHECKS=(
    "/root|700|exact"
    "/boot|700|exact"
    "/etc/ssh|755|exact"
    "/etc/sudoers|440|exact"
    "/etc/sudoers.d|750|exact"
    "/etc/passwd|644|exact"
    "/etc/group|644|exact"
    "/etc/shadow|640|mask"
    "/etc/gshadow|640|mask"
)

# permissions spells its ids off the path: format!("perm-{}", path.replace('/',
# "-")), so /etc/shadow becomes perm--etc-shadow. The doubled dash is not a typo
# and is pinned by the self-test: the leading slash becomes a dash of its own.
# A filter written without it matches nothing, and matching nothing reads as "the
# tool reported no finding", which is this suite's pass condition.
permission_finding_id() {
    printf 'perm-%s' "${1//\//-}"
}

# Every path's reading, taken in one pass, as `path mode` lines.
#
# Three outcomes, never two. A mode is a reading; a path that is not there is
# `absent`, which is a determinate answer and not the same as a failure; and a
# path that exists but cannot be statted is fatal, because a mode this suite
# could not read must never be scored as either agreement or absence.
#
# Absence is concluded from the shell test rather than from stat's message, which
# is locale-dependent prose. A dangling symlink reads as absent here, and the
# tool agrees: its path_exists follows the link exactly as `-e` does.
# The `/usr/etc` counterpart of an `/etc` path, when there is one. Mirrors
# vendor_path_for in crates/hardener-common/src/vendor_config.rs, including its
# refusal to invent one for a path outside /etc: /root and /boot have no vendor
# copy, and asking for one would compare a mode against a file that cannot exist.
permission_vendor_path() {
    local path="$1"
    [[ "$path" == /etc/?* ]] || return 1
    printf '/usr/etc/%s' "${path#/etc/}"
}

# One path's mode, or a named refusal. One definition, because both layers need
# it and two copies would come to disagree about what stat is allowed to print.
#
# One to four digits: `stat -c %a` prints `0` for mode 0000, and four digits for a
# mode carrying a setuid, setgid or sticky bit. Anything else is stat having said
# something other than a mode, and comparing it would be comparing prose.
permission_mode_of() {
    local path="$1" mode octal='^[0-7]{1,4}$'
    if ! mode="$(stat -c %a "$path" 2>&1)"; then
        echo "FATAL: stat could not read the mode of $path: $mode" >&2
        return 1
    fi
    if [[ ! "$mode" =~ $octal ]]; then
        echo "FATAL: stat reported '$mode' for $path, which is not an octal mode" >&2
        return 1
    fi
    printf '%s' "$mode"
}

permission_modes_capture() {
    local entry path mode vendor out=()
    for entry in "${PERMISSION_CHECKS[@]}"; do
        IFS='|' read -r path _ _ <<<"$entry"
        if [[ -e "$path" ]]; then
            mode="$(permission_mode_of "$path")" || return 1
            out+=("$path $mode")
            continue
        fi
        # Absent from /etc is not absent from the host. openSUSE ships its
        # configuration under /usr/etc and reserves /etc for administrator
        # overrides, so the vendor copy is the file in force, and an oracle that
        # stopped at the first absence would agree with a tool that was blind to
        # it. That is exactly what happened on 2026-07-30: /etc/sudoers does not
        # exist there, /usr/etc/sudoers does at 0444 against a 0440 target, and
        # both the tool and the first version of this oracle said nothing.
        if vendor="$(permission_vendor_path "$path")" && [[ -e "$vendor" ]]; then
            mode="$(permission_mode_of "$vendor")" || return 1
            out+=("$path vendor:$mode")
            continue
        fi
        out+=("$path absent")
    done
    printf '%s\n' "${out[@]}"
}

# One reading out of a capture, by exact path.
#
# Deliberately not extract_sshd_value, which is what the ssh and vendor survival
# captures use. That reader interpolates its key into a grep BRE and matches
# case-insensitively, and a path is neither a regex nor case-insensitive: the `.`
# in /etc/sudoers.d would also match /etc/sudoersXd. Two of the keys here contain
# a metacharacter, so the compare is a string compare.
permission_capture_reading() {
    local capture="$1" path="$2" candidate reading
    while read -r candidate reading; do
        if [[ "$candidate" == "$path" ]]; then
            printf '%s' "$reading"
            return 0
        fi
    done <<<"$capture"
    return 1
}

# Captured by permissions_oracle_init, which must run after apply. Empty means
# the capture never happened, which permission_system_value treats as fatal, for
# the same reason the ssh oracle does: a missing capture must not read like an
# absent path, and an absent path must not read like a pass.
PERMISSION_MODES=""
PERMISSION_MODES_GENERATION=""

permissions_oracle_init() {
    local out
    if ! out="$(permission_modes_capture)"; then
        return 1
    fi
    if [[ -z "$out" ]]; then
        echo "FATAL: the permission capture succeeded but read nothing" >&2
        return 1
    fi
    PERMISSION_MODES="$out"
    PERMISSION_MODES_GENERATION="$APPLY_GENERATION"
}

# What the filesystem holds now, refused unless the capture followed the last
# apply. Prints the mode, or the word `absent`.
permission_system_value() {
    local path="$1" reading
    require_fresh_capture permissions "$PERMISSION_MODES" \
        "$PERMISSION_MODES_GENERATION" || return 1
    if ! reading="$(permission_capture_reading "$PERMISSION_MODES" "$path")"; then
        echo "FATAL: the permission capture holds no row for '$path'" >&2
        return 1
    fi
    if [[ -z "$reading" ]]; then
        echo "FATAL: the permission capture reports '$path' with no reading" >&2
        return 1
    fi
    printf '%s' "$reading"
}

# Two assertions per path, whatever the path turns out to be, so a distribution
# that ships fewer of them cannot quietly shorten the run.
#
# An absent path still has a verdict worth checking. The tool treats a confirmed
# absence as nothing to report, so the requirement there is that it reports
# nothing, and a tool inventing a finding for a path that is not there fails the
# second assertion. What is given up is the mode comparison, and the count of
# paths that gave it up is printed rather than left for a reader to notice.
run_permission_checks() {
    local entry path target comparison reading id vendor mode requirement satisfied
    local absent=0 at_vendor=0
    for entry in "${PERMISSION_CHECKS[@]}"; do
        IFS='|' read -r path target comparison <<<"$entry"
        id="$(permission_finding_id "$path")"
        if ! reading="$(permission_system_value "$path")"; then
            record_unresolved permissions-hardening "$path" "the filesystem reported no usable mode"
            continue
        fi
        # A vendor reading is compared exactly like an /etc one, against the same
        # target and by the same comparison, because the control is about the
        # setting rather than about which directory a distribution keeps it in.
        # The tool's finding id is keyed on the /etc path for the same reason, so
        # the verdict half needs no special case at all.
        if [[ "$reading" == vendor:* ]]; then
            at_vendor=$((at_vendor + 1))
            vendor="$(permission_vendor_path "$path")"
            mode="${reading#vendor:}"
            requirement="$(requirement_wording "$target" "$comparison")"
            satisfied=no
            requirement_satisfied "$mode" "$target" "$comparison" && satisfied=yes
            # The first assertion records the reading rather than demanding the
            # mode be compliant, and that is deliberate. This tool does not write
            # the vendor layer, so a violating vendor file is a state it reports
            # and cannot correct: requiring compliance here would leave the suite
            # permanently red against a tool behaving exactly as designed. The
            # message states the mode and the requirement so a reader sees the
            # violation, and the verdict assertion below is the one that can fail.
            record_pass "permissions-hardening $path: absent from /etc, and $vendor holds '$mode' where this run requires $requirement; the mode in force was read, and this tool does not write the vendor layer"
            compare_reported_verdict permissions-hardening "$path" "$satisfied" "$id" \
                "$vendor holds '$mode' and this run requires $requirement"
            continue
        fi
        if [[ "$reading" == absent ]]; then
            absent=$((absent + 1))
            record_pass "permissions-hardening $path: the path is absent, so there is no mode for the tool to hold"
            compare_reported_verdict permissions-hardening "$path" yes "$id" \
                "the path is absent, so there is nothing on it to enforce"
            continue
        fi
        compare_directive permissions-hardening "$path" "$reading" "$target" "$id" "$comparison"
    done
    # No silent caps: an absent path costs its mode comparison, and a run where
    # several are absent proves less than one where none is. A vendor reading
    # loses nothing, and is reported because it means this distribution keeps the
    # file somewhere else, which is worth seeing in a log.
    if (( absent > 0 )); then
        echo "  note| $absent of ${#PERMISSION_CHECKS[@]} permission paths are absent on this distribution, so those rows assert only that the tool reports nothing for a path that is not there"
    fi
    if (( at_vendor > 0 )); then
        echo "  note| $at_vendor of ${#PERMISSION_CHECKS[@]} permission paths are absent from /etc and were read at the vendor layer instead, which is where the mode in force lives on this distribution"
    fi
}

# The lengths of every table the run is sized by, pinned as literals.
#
# A count derived from a table cannot notice that table being edited down: with
# SSH_CHECKS emptied, a run over the login.defs directives alone would agree
# with itself, exit 0, and be reported as a PASS by
# scripts/test/run-cross-distro-tests.sh. So the sizes are written out here, and
# every expectation below is counted off these literals rather than off the
# tables, which is what keeps the two independent: the tables are what the run
# iterates, and these are what it is measured against. Adding a directive means
# changing the literal on purpose.

# === Firewall rules actually in the kernel ===
#
# The oracle is netfilter, read through `nft list ruleset`, which is the only
# consumer a firewall rule has. `ufw status` and `firewall-cmd --list-all` are
# the tools' own frontends and would be family 2: a reader and a writer sharing
# one mistake agree with each other and disagree with the kernel.
#
# Four things about this oracle were measured on real containers 2026-07-30 and
# each would have produced a check that passes on broken code:
#
# 1. `iptables -S` cannot see firewalld. After a successful apply on fedora it
#    prints three policy lines and nothing else, because every rule firewalld
#    wrote lives in `table inet firewalld`. An `iptables -S` oracle matches
#    nothing on three of five distributions, and matching nothing is this
#    suite's pass condition. Its policy lines are still read below, because ufw
#    expresses its default disposition there and nowhere else.
#
# 2. Presence is not evidence, because the baseline is not empty. fedora's
#    container starts with 344 lines of firewalld ruleset already loaded,
#    including `ct state {established, related} accept` and `iifname "lo"
#    accept`. Asserting those exist passes against a tool that did nothing. arch
#    starts at 4 lines, so the same assertion would be honest there and vacuous
#    three distributions over. Everything below compares against a pre-apply
#    capture rather than asking what exists.
#
# 3. `tcp dport 22 accept` is present BEFORE the apply on firewalld, because the
#    default public zone allows the ssh service. It is checked below as a safety
#    property (hardening must not lock the operator out) and is deliberately NOT
#    treated as proof the tool acted. 4.1 item 13 in the handoff is the finding
#    that came out of noticing it.
#
# 4. A ruleset is what the kernel holds NOW and carries nothing about the next
#    boot. A firewall started by hand renders identically to one that comes back
#    after a reboot, so both assertions above stayed green against the arch
#    container that had no multi-user.target.wants symlink for ufw at all.
#    Measured, by comparing the run before 61a33f9 existed against the run
#    after it: all 68 assertion lines are byte-identical on all five
#    distributions, so nothing here would have caught the repair regressing.
#    boot-persistence asks systemd instead, either side of the same apply. Its
#    before reading is taken from systemd directly and NOT from the ruleset
#    capture beside it, for the reason recorded at FIREWALL_UNIT_CANDIDATES.
FIREWALL_CHECKS=(
    "default-inbound-drop"
    "ssh-still-accepted"
    "boot-persistence"
)

# Counters and handles change between two snapshots of an UNCHANGED rule, so a
# raw diff of two captures is mostly noise and the real delta is buried in it.
# Returns non-zero when NEITHER view could be read, which is a different outcome
# from "there are no rules" and must not share a value with it. An earlier
# version of this function always emitted its own marker line, so the capture was
# never empty, and a container where nft and iptables both failed reported
# exactly what a container with a clean ruleset reports. That is the sentinel
# conflation this suite exists to find, written into the suite itself.
firewall_ruleset_snapshot() {
    local nft_out ipt_out nft_rc=0 ipt_rc=0
    nft_out="$(nft list ruleset 2>&1)" || nft_rc=$?
    # ufw expresses its default disposition as an iptables chain policy and
    # nowhere in the nft output, so both views are needed. firewalld needs only
    # the first. grep's own non-match is not a read failure, so iptables is asked
    # first and filtered after.
    ipt_out="$(iptables -S 2>&1)" || ipt_rc=$?
    if (( nft_rc != 0 && ipt_rc != 0 )); then
        echo "FATAL: neither 'nft list ruleset' nor 'iptables -S' could be read." >&2
        echo "  nft said: ${nft_out:-(nothing)}" >&2
        echo "  iptables said: ${ipt_out:-(nothing)}" >&2
        return 1
    fi
    {
        (( nft_rc == 0 )) && printf '%s\n' "$nft_out"
        echo "=== iptables policies ==="
        (( ipt_rc == 0 )) && grep '^-P' <<< "$ipt_out"
    } | sed -E 's/counter packets [0-9]+ bytes [0-9]+ ?//; s/ # handle [0-9]+//; s/[[:space:]]+$//'
}

# Which backend is in force, decided from the ruleset rather than from installed
# packages: all six images ship both ufw/firewalld and nftables, so presence
# proves nothing about which one the tool selected.
firewall_backend_kind() {
    local snapshot="$1"
    if [[ "$snapshot" == *"table inet firewalld"* ]]; then
        printf 'firewalld'
    elif [[ "$snapshot" == *"ufw-before-input"* || "$snapshot" == *"ufw-user-input"* ]]; then
        printf 'ufw'
    else
        printf 'none'
    fi
}

# Is inbound traffic dropped by default in this snapshot?
#
# The two backends express the same property in unrelated syntax, and both
# spellings were read off real containers rather than guessed. ufw sets an
# iptables chain policy. firewalld renders a zone's DROP target by replacing the
# zone chain's trailing `reject with icmpx admin-prohibited` with a bare `drop`,
# which is the single most surprising thing in this file: a pattern written for
# "policy drop" matches firewalld never.
firewall_default_is_drop() {
    local snapshot="$1"
    case "$(firewall_backend_kind "$snapshot")" in
        ufw) [[ "$snapshot" == *"-P INPUT DROP"* ]] ;;
        firewalld)
            # A bare `drop` on its own line inside the zone chains. The
            # pre-apply capture holds `reject with icmpx admin-prohibited` in
            # those positions instead, which is what makes this discriminating.
            grep -qE '^[[:space:]]+drop$' <<< "$snapshot"
            ;;
        *) return 1 ;;
    esac
}

# Is tcp/22 still accepted? Asked of both backends the same way, because both
# render it identically once the rule exists.
firewall_ssh_accepted() {
    grep -qE 'tcp dport (22|\{[^}]*22[^}]*\}) accept|--dport 22 -j ACCEPT' <<< "$1"
}

# The six words systemd uses for a unit that will NOT be started at boot, copied
# from NOT_AT_BOOT_STATES in crates/hardener-plugins/src/firewall/mod.rs:366
# rather than restated in this file's own words: the oracle has to fail on
# exactly the set the tool repairs, or the two disagree about what "hardened"
# means. `enabled-runtime` and `masked-runtime` are the reason this is a word
# list and not an exit status, both exit 0 and neither survives a reboot.
firewall_not_at_boot() {
    case "$1" in
        disabled|enabled-runtime|linked|linked-runtime|masked|masked-runtime) return 0 ;;
        *) return 1 ;;
    esac
}

# What systemd says about ONE named unit being started at boot: the printed word
# alone, empty when nothing was printed.
#
# Not firewall-specific, and named so: the services oracle asks the same
# question of its own unit through this function rather than growing a second
# copy of the exit-status rule below.
#
# The exit status is deliberately discarded and only the printed word kept.
# `systemctl is-enabled` prints `disabled` on stdout while exiting 1, and prints
# `enabled-runtime` while exiting 0, so a reading taken from the status would be
# wrong in both directions. Going by the status is the defect 7fd250e repaired in
# the plugin, and an oracle that reproduced it would agree with the bug.
systemd_unit_boot_word() {
    local word=""
    word="$(systemctl is-enabled "$1" 2>/dev/null)" || true
    # Every whitespace character, not only the ends. An answer arriving over
    # more than one line collapses into something that is not the word
    # `enabled`, which fails, and failing toward "not verified" is the safe
    # direction here as everywhere else in this file.
    printf '%s' "${word//[[:space:]]/}"
}

# What systemd says about the unit of the backend a capture holds, as
# `<unit>|<word>`.
#
# The unit name is taken from the backend kind and from nothing else, because
# that is what the tool itself does: FirewallBackend::systemd_unit returns the
# bare words `ufw` (crates/hardener-plugins/src/firewall/ufw.rs:162) and
# `firewalld` (firewalld.rs:139), no `.service` suffix. A kind of `none` has no
# unit to ask about and says so rather than guessing at one.
#
# This is the AFTER reading, where the backend in force is the one the apply
# managed. The before reading is NOT taken this way; see below for the measured
# reason it cannot be.
firewall_boot_reading() {
    local unit
    unit="$(firewall_backend_kind "$1")"
    if [[ "$unit" == "none" ]]; then
        printf 'none|'
        return 0
    fi
    printf '%s|%s' "$unit" "$(systemd_unit_boot_word "$unit")"
}

# Every unit the apply might end up managing, written out here rather than
# derived from the pre-apply ruleset.
#
# Deriving it was the defect this list repairs. On arch and debian ufw is
# installed but not enabled before the apply, so its chains do not exist, the
# pre-apply kind reads `none`, and a before reading taken off that kind never
# asks systemd anything at all. Measured on the 2026-07-30 container run: both
# distributions then reported "no backend was in force before apply, so the
# apply is what put a unit at boot". That is true on arch and almost certainly
# false on debian, whose ufw package enables the unit at install, which is why
# debian's firewall survived a reboot on 9b400b9 before the repair in 61a33f9
# existed and arch's did not. Two rows read as evidence where one was.
#
# These have to stay the units of the two backends firewall_backend_kind can
# name, and no code path makes them: the self-test reads that function's own
# body back and compares, and the boot-persistence row says so in its message
# when the two come apart during a run.
FIREWALL_UNIT_CANDIDATES=(firewalld ufw)

# Those units asked before the apply, as space-separated `<unit>|<word>` pairs.
# Neither a unit name nor a word systemd prints carries whitespace, and the
# reading above strips whatever does arrive, so the separator needs no quoting.
#
# A candidate the distribution does not ship is asked all the same, and answers.
# Measured under systemd 261: `is-enabled` on a unit with no unit file prints
# `not-found` on stdout and exits 4, so arch reads `firewalld|not-found
# ufw|disabled` and fedora reads `firewalld|enabled ufw|not-found`. Only the
# pair naming the unit the apply managed is ever read out of this.
firewall_boot_readings_before() {
    local unit out=""
    for unit in "${FIREWALL_UNIT_CANDIDATES[@]}"; do
        out+="${out:+ }$unit|$(systemd_unit_boot_word "$unit")"
    done
    printf '%s' "$out"
}

FIREWALL_BEFORE=""
FIREWALL_AFTER=""

# The same pair for the one question a ruleset cannot answer. Captured beside
# the rulesets rather than asked inside the check, exactly like them: a check
# that shells out live cannot be driven by --self-test, and an assertion nothing
# proves is not an oracle.
#
# The two are not the same shape. AFTER is one `<unit>|<word>` for the backend
# that ended up in force. BEFORE is a `<unit>|<word>` for EVERY candidate unit,
# because before the apply there is no backend in force to pick one by.
#
# Two fields rather than one word in each pair, because "no backend was in
# force, so no unit was asked" and "the unit was asked and answered nothing" are
# different outcomes, and one value standing for several outcomes is the
# sentinel conflation this suite exists to find.
FIREWALL_BOOT_BEFORE=""
FIREWALL_BOOT_AFTER=""

# The before word for one named unit, non-zero when the pair list holds no such
# unit at all.
#
# Non-zero rather than an empty word, for the reason above: a list that never
# covered this unit and a unit that was asked and answered nothing must not
# share a value, because only one of them is a fault in this file.
firewall_boot_word_before() {
    local unit="$1" pair pairs=()
    read -ra pairs <<<"$FIREWALL_BOOT_BEFORE"
    for pair in "${pairs[@]}"; do
        if [[ "${pair%%|*}" == "$unit" ]]; then
            printf '%s' "${pair#*|}"
            return 0
        fi
    done
    return 1
}

# The capture that has to be taken while the container is still unhardened. It
# is not a control over the checks below so much as half of what they compare:
# taken after apply it would agree with itself.
preapply_firewall_init() {
    local out
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply firewall capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It is the value these checks compare against, so it has to be taken" >&2
        echo "  while the container is still unhardened." >&2
        return 1
    fi
    if ! out="$(firewall_ruleset_snapshot)"; then
        return 1
    fi
    FIREWALL_BEFORE="$out"
    # Taken here and not later, for the same reason as the ruleset above it: the
    # apply is what enables the unit, so a boot reading taken afterwards would
    # agree with itself.
    #
    # Asked of every candidate unit and NOT of the kind `$out` names. On arch
    # and debian that kind is `none`, because ufw's chains do not exist until
    # the unit starts, so a reading taken off it asks systemd nothing and the
    # row below then has no before state to compare against. It filled that gap
    # by crediting the apply, on debian wrongly.
    FIREWALL_BOOT_BEFORE="$(firewall_boot_readings_before)"
}

firewall_oracle_init() {
    local out
    if (( APPLY_GENERATION == 0 )); then
        echo "FATAL: the post-apply firewall capture was asked for before any apply." >&2
        return 1
    fi
    if ! out="$(firewall_ruleset_snapshot)"; then
        return 1
    fi
    FIREWALL_AFTER="$out"
    FIREWALL_BOOT_AFTER="$(firewall_boot_reading "$out")"
}

# firewall's pre-apply positive control, and it is deliberately NOT the
# finding-count control the other three plugins get.
#
# That control asks whether the tool reported a finding for each compared
# directive before apply. firewall's only scan finding is `{backend}-disabled`,
# and on fedora, rhel and openSUSE firewalld is ALREADY ACTIVE in the container,
# so the tool correctly reports nothing and a finding-count control would fail
# on three of five distributions against a tool behaving exactly as designed.
#
# The stronger question, and the one this asks: was the property we are about to
# assert already true before the apply? If inbound was already dropped, the check
# below proves nothing whatever it reports. Measured: arch has no `-P INPUT DROP`
# before apply and firewalld's zone chains hold `reject with icmpx
# admin-prohibited` rather than `drop`, so this control passes on both backends
# for a real reason.
run_firewall_preapply_control() {
    local kind
    kind="$(firewall_backend_kind "$FIREWALL_BEFORE")"
    if [[ -z "$FIREWALL_BEFORE" ]]; then
        record_fail "firewall-hardening: the pre-apply ruleset capture is empty, so nothing below can be shown to be a change rather than a pre-existing state"
    elif [[ "$kind" == "none" ]]; then
        # Not a failure, and an earlier version of this control wrongly made it
        # one. On arch and debian ufw is installed but NOT enabled before the
        # apply, so its chains do not exist yet and the capture is four lines of
        # iptables policy. That is the strongest form of "the property is not
        # already true" this control can see: nothing is enforcing anything.
        record_pass "firewall-hardening: no backend ruleset was in force before apply, so nothing was dropping inbound and the check below is asking a real question"
    elif firewall_default_is_drop "$FIREWALL_BEFORE"; then
        record_fail "firewall-hardening: inbound traffic was ALREADY dropped by default before apply on the $kind backend, so the check below would pass without the tool having done anything"
    else
        record_pass "firewall-hardening: before apply the $kind backend did not drop inbound traffic by default, so the check below is asking a real question"
    fi
}

run_firewall_checks() {
    local key kind boot_unit boot_word before_word before_found before_phrase
    kind="$(firewall_backend_kind "$FIREWALL_AFTER")"
    for key in "${FIREWALL_CHECKS[@]}"; do
        case "$key" in
            default-inbound-drop)
                if [[ -z "$FIREWALL_AFTER" ]]; then
                    record_fail "firewall $key: the ruleset after apply could not be read"
                elif firewall_default_is_drop "$FIREWALL_AFTER"; then
                    record_pass "firewall $key: the $kind backend drops inbound traffic by default, and did not before apply"
                elif [[ "$kind" == "none" ]]; then
                    # Distinct from "the backend is there and did not drop":
                    # the apply reported rules it wrote and the kernel holds no
                    # ruleset either backend recognises. The capture travels
                    # with the verdict, because a message naming a cause is an
                    # assertion and this one has been wrong before.
                    record_fail "firewall $key: the apply reported success and the kernel holds no ufw or firewalld ruleset at all; captured after apply: $(head -c 400 <<< "$FIREWALL_AFTER" | tr '\n' '/')"
                else
                    record_fail "firewall $key: the $kind backend does not drop inbound traffic by default after apply, so the hardening the tool reported is not what the kernel will enforce"
                fi
                ;;
            ssh-still-accepted)
                # A safety property rather than proof the tool acted: on
                # firewalld this rule exists before the apply as well, so it
                # would pass against a tool that did nothing. It is here because
                # a firewall that drops inbound AND drops ssh has locked the
                # operator out of the host, and no other check would notice.
                if [[ -z "$FIREWALL_AFTER" ]]; then
                    record_fail "firewall $key: the ruleset after apply could not be read"
                elif firewall_ssh_accepted "$FIREWALL_AFTER"; then
                    record_pass "firewall $key: tcp/22 is still accepted after hardening, so the apply has not locked the operator out"
                else
                    record_fail "firewall $key: tcp/22 is NOT accepted after hardening; combined with a default drop this locks the operator out of the host"
                fi
                ;;
            boot-persistence)
                # Deliberately NOT gated on the booted signal, unlike the
                # services rows. Whether `systemctl is-enabled` answers inside an
                # unbooted --pipe container is unmeasured, so a gate written for
                # it would be written on a guess. Ungated, an unbooted run that
                # cannot ask goes red rather than quiet, which is the direction
                # this file takes everywhere else. A red row here on the
                # unbooted fixture is a real finding about that fixture and
                # wants measuring, not silencing.
                IFS='|' read -r boot_unit boot_word <<<"$FIREWALL_BOOT_AFTER"
                # The before word is looked up by the unit the AFTER reading
                # names, which is the unit the apply managed. Deriving it from
                # the pre-apply ruleset instead is what made this row credit
                # debian's apply with an enablement its ufw package had already
                # done at install time.
                before_found=0
                before_word=""
                if before_word="$(firewall_boot_word_before "$boot_unit")"; then
                    before_found=1
                fi
                # Which of the two things a pass may claim. Measured on the
                # 2026-07-30 run: fedora, rhel and openSUSE ship firewalld
                # already enabled and debian's ufw package enables the unit at
                # install, so four of five distributions read `enabled` here
                # with the repair reverted and only arch is load-bearing. One
                # wording for all five would make a single row of evidence look
                # like five rows of it.
                if [[ -z "$FIREWALL_BOOT_BEFORE" ]]; then
                    before_phrase="no reading was taken before apply, so this row cannot say whether the apply is what did it"
                elif (( before_found == 0 )); then
                    # Not a wording that reads normal. The candidate list and
                    # firewall_backend_kind name the same backends by hand, so
                    # an after unit no before reading covers means a third
                    # backend reached one of them and not the other.
                    before_phrase="the units asked before apply do not include '$boot_unit', so the candidate list and firewall_backend_kind have come apart and this row cannot say whether the apply is what did it"
                elif [[ "$before_word" == "enabled" ]]; then
                    before_phrase="the $boot_unit unit already read 'enabled' before apply, so this row asserts agreement rather than proving the apply acted"
                elif firewall_not_at_boot "$before_word"; then
                    before_phrase="the $boot_unit unit read '$before_word' before apply, so the apply is what enabled it"
                else
                    # A before state that could not be read, or that systemd
                    # worded in a way this file cannot name. Every phrase in
                    # this chain is printed by the pass branch below and by
                    # nothing else, so what this one must not do is fill the gap
                    # by claiming the apply acted: that claim is the whole
                    # defect the chain exists to prevent, and making it here
                    # instead would be worth nothing.
                    before_phrase="the $boot_unit unit read '${before_word:-nothing at all}' before apply, which is neither 'enabled' nor a state this can name, so this row cannot say whether the apply is what did it"
                fi
                if [[ -z "$boot_unit" ]]; then
                    record_fail "firewall $key: no boot-persistence reading was taken after apply, so nothing here says whether the firewall survives a reboot"
                elif [[ "$boot_unit" == "none" ]]; then
                    record_fail "firewall $key: the apply reported success and no ufw or firewalld ruleset is in force, so there is no unit whose boot persistence could be asked about"
                elif [[ "$boot_word" == "enabled" ]]; then
                    record_pass "firewall $key: systemd starts the $boot_unit unit at boot ('enabled'); $before_phrase"
                elif firewall_not_at_boot "$boot_word"; then
                    # The word travels, because the several ways of not starting
                    # at boot are not interchangeable: a masked unit has to be
                    # unmasked before enabling it can work, and an
                    # enabled-runtime one reads as enabled right up to the
                    # reboot that discards it.
                    record_fail "firewall $key: systemd says the $boot_unit unit is '$boot_word', so the firewall this run reports as hardened will not be there after a reboot"
                else
                    record_fail "firewall $key: systemd answered '${boot_word:-nothing at all}' about the $boot_unit unit, which is neither 'enabled' nor a state this can name, so whether the firewall survives a reboot was not established"
                fi
                ;;
            *)
                record_fail "firewall $key: no probe is defined for this key, so the table and the checks have come apart"
                ;;
        esac
    done
}

# === Audit rules the audit package's own tool compiled ===
#
# The oracle is `augenrules`, which ships with the audit package and merges
# /etc/audit/rules.d/*.rules into /etc/audit/audit.rules. It is a different
# program from the one under test, and it needs no running auditd, which is what
# makes an audit oracle possible in a container at all: the apply's reload FAILS
# here by design, because the kernel's netlink audit socket cannot be opened, and
# the merge still happens before that failure.
#
# Measured in the arch container 2026-08-09, with the reload failing exactly as
# expected: /etc/audit/audit.rules did not exist before the apply, and afterwards
# it held the tool's rules, `ls` reported /etc/audit/rules.d/hardening.rules at
# 0640, and `augenrules --check` printed "No change" and exited 0 while writing
# "Cannot open netlink audit socket" to stderr.
#
# WHAT THIS ORACLE CANNOT SEE, which is the rule issue #47 states for every new
# oracle. `augenrules` reads the same directory this tool writes into, so a tool
# writing correct rules to the WRONG directory is agreed with by both and both
# are wrong. It is the same limit the permissions oracle carries and states.
# Closing it needs a second source for the directory, not a second reader of it.
#
# And it says nothing about enforcement. No auditd runs, no rule reaches the
# kernel, and `auditctl -l` cannot be asked. A rule the kernel would REFUSE is
# indistinguishable here from one it would accept, so every row below is about
# what the next boot would load rather than what is being audited now.
AUDIT_CHECKS=(
    "rules-file-mode"
    "compiled-names-rule"
    "compiled-is-current"
)

# The rule the compiled-file row looks for, and it is one of the plugin's own
# rather than a guess: `audit/mod.rs`'s AUDIT_RULES table declares it, and the
# self-test reads it back out of that source so the two cannot drift. A rule this
# suite invented would be a row asking whether the tool wrote what this suite
# imagined, which is a question about this suite.
#
# A watch rule rather than a syscall rule, because the syscall rules carry an
# `arch=` that differs between the container's architecture and the reader's
# expectations, and this row is about whether the merge happened rather than
# about which architecture it happened for.
AUDIT_PROBE_RULE="-w /etc/shadow -p wa -k identity"

# The file the tool writes, and the file augenrules compiles.
AUDIT_RULES_FILE="/etc/audit/rules.d/hardening.rules"
AUDIT_COMPILED_FILE="/etc/audit/audit.rules"

AUDIT_COMPILED_BEFORE=""

# Whether this fixture has the audit package's merge tool at all. Without it
# nothing here can be asked, and saying so is better than a row that passes
# because a grep found nothing to disagree with.
audit_askable() {
    command -v augenrules >/dev/null 2>&1
}

# The pre-apply reading. Its only job is to establish that the compiled file did
# NOT already name the probe rule, which is what stops the row below passing
# against a container that shipped it.
preapply_audit_init() {
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply audit capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        return 1
    fi
    AUDIT_COMPILED_BEFORE="absent"
    if [[ -f "$AUDIT_COMPILED_FILE" ]]; then
        AUDIT_COMPILED_BEFORE="$(cat "$AUDIT_COMPILED_FILE" 2>/dev/null || printf 'unreadable')"
    fi
}

run_audit_preapply_control() {
    if ! audit_askable; then
        record_unaskable "audit-hardening pre-apply control: augenrules is not installed here, so the audit package's own merge tool cannot be asked what it compiled"
        return 0
    fi
    if [[ "$AUDIT_COMPILED_BEFORE" == "unreadable" ]]; then
        record_fail "audit-hardening: $AUDIT_COMPILED_FILE exists and could not be read before apply, so this control cannot say whether the rule below was already there"
        return 0
    fi
    if [[ "$AUDIT_COMPILED_BEFORE" != "absent" ]] \
        && grep -qF -- "$AUDIT_PROBE_RULE" <<<"$AUDIT_COMPILED_BEFORE"; then
        record_fail "audit-hardening: $AUDIT_COMPILED_FILE already named '$AUDIT_PROBE_RULE' before apply, so the row below would pass whether or not the tool wrote anything; recreate the container first"
        return 0
    fi
    local state="present and naming other rules"
    [[ "$AUDIT_COMPILED_BEFORE" == "absent" ]] && state="absent"
    record_pass "audit-hardening: $AUDIT_COMPILED_FILE was $state before apply and did not name '$AUDIT_PROBE_RULE', so the checks below are asking a real question"
}

run_audit_checks() {
    local key mode compiled
    for key in "${AUDIT_CHECKS[@]}"; do
        if ! audit_askable; then
            record_unaskable "audit $key: augenrules is not installed here, so the audit package's own merge tool cannot be asked what it compiled"
            continue
        fi
        case "$key" in
            rules-file-mode)
                # The same limit the permissions oracle states: `stat` is asked
                # about the path the tool chose, so a tool writing the right
                # mode to the wrong file is agreed with here.
                if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
                    record_fail "audit $key: the apply reported writing rules and $AUDIT_RULES_FILE does not exist, so nothing was left for auditd to load"
                elif ! mode="$(stat -c %a "$AUDIT_RULES_FILE" 2>/dev/null)"; then
                    record_fail "audit $key: $AUDIT_RULES_FILE could not be stat'd, so its mode is unproven"
                elif [[ "$mode" == "640" ]]; then
                    record_pass "audit $key: $AUDIT_RULES_FILE is mode $mode, which is what STIG asks of a rules drop-in"
                else
                    record_fail "audit $key: $AUDIT_RULES_FILE is mode $mode rather than 640, so a rules file the tool reported writing is readable by accounts that should not see it"
                fi
                ;;
            compiled-names-rule)
                # The row this oracle exists for. The file is augenrules'
                # output, not this tool's, so a tool that wrote a rules file
                # augenrules refuses to merge fails here while every check that
                # reads its own output would pass.
                if [[ ! -f "$AUDIT_COMPILED_FILE" ]]; then
                    record_fail "audit $key: $AUDIT_COMPILED_FILE does not exist after apply, so augenrules never merged the rules the tool wrote and the next boot loads none of them"
                elif ! compiled="$(cat "$AUDIT_COMPILED_FILE" 2>/dev/null)"; then
                    record_fail "audit $key: $AUDIT_COMPILED_FILE could not be read after apply, so what augenrules compiled is unproven"
                elif grep -qF -- "$AUDIT_PROBE_RULE" <<<"$compiled"; then
                    record_pass "audit $key: augenrules compiled '$AUDIT_PROBE_RULE' into $AUDIT_COMPILED_FILE, which is the audit package's own reading of what this tool wrote"
                else
                    record_fail "audit $key: $AUDIT_COMPILED_FILE does not name '$AUDIT_PROBE_RULE' after apply, so the rules the tool reported writing are not what the next boot would load"
                fi
                ;;
            compiled-is-current)
                # `augenrules --check` compares the compiled file against the
                # drop-in directory and says whether a merge is outstanding. It
                # writes "Cannot open netlink audit socket" to stderr in a
                # container and still exits 0, measured 2026-08-09, so stderr is
                # discarded and the status is what is read.
                if augenrules --check >/dev/null 2>&1; then
                    record_pass "audit $key: augenrules reports $AUDIT_COMPILED_FILE current against $(dirname "$AUDIT_RULES_FILE"), so no merge is outstanding after the apply"
                else
                    record_fail "audit $key: augenrules reports a merge outstanding after the apply, so what the next boot loads is not what the rules directory now says"
                fi
                ;;
            *)
                record_fail "audit $key: no probe is defined for this key, so the table and the checks have come apart"
                ;;
        esac
    done
}

# === MAC configuration on a kernel that has no MAC system ===
#
# The oracle is the kernel's own LSM registry, /sys/kernel/security/lsm, read
# beside the MAC configuration tree as it stands either side of the apply.
# Neither is the tool's reading of anything.
#
# This is the inverse of every other oracle in this file. The others ask whether
# the tool did what it reported. This one asks whether it did NOTHING, on a host
# where nothing is the only correct answer, and that is worth asking on its own:
# writing an SELinux configuration onto a host with no SELinux is a change no
# operator asked for and no boot would honour.
#
# Measured on the development host 2026-08-09. /sys/kernel/security/lsm reads
# "capability,landlock,lockdown,yama,bpf", while mac/mod.rs:118 probes
# /sys/fs/selinux and /sys/kernel/security/apparmor, neither of which exists.
# The plugin therefore reports MacDetection::Absent, and its apply pushes one
# Skipped change and writes nothing. A container shares the host's kernel, so
# this holds in every fixture this suite can be run in.
#
# The registry is a DIFFERENT source from the two paths the tool probes, and
# that is what makes the control an oracle rather than an echo of the tool. A
# tool looking for SELinux in the wrong place on a host that has it is caught by
# the disagreement between the registry and the tool's verdict.
#
# WHAT THIS ORACLE CANNOT SEE, which is the rule issue #47 states for every new
# oracle. It cannot see whether the tool does the RIGHT thing where a MAC system
# EXISTS, which is the whole of the plugin's enforcing behaviour. That needs a
# kernel carrying selinux or apparmor and this machine's carries neither, so it
# is #18 rather than something a fixture can arrange. Where the registry DOES
# name one, every row here is declared unaskable rather than passed: a no-op
# oracle asserted against a host that should not be a no-op would be a row
# asserting the opposite of the requirement.
#
# And both readings come from one kernel. A kernel misreporting its own LSM
# registry and its own securityfs together is indistinguishable here from a
# kernel that genuinely has no MAC system.
MAC_CHECKS=(
    "config-untouched"
)

MAC_LSM_REGISTRY="/sys/kernel/security/lsm"

# The paths the plugin checkpoints, which are the paths it could write
# (mac/mod.rs:858-862). A correct run on this host reads them and writes none.
MAC_CONFIG_PATHS=(/etc/selinux /etc/apparmor /etc/apparmor.d)

MAC_CONFIG_BEFORE=""
MAC_LSM_READING=""

# A digest of the MAC configuration tree: every path with its mode and size,
# and the content hash of every file under it.
#
# mtime is deliberately absent. The apply checkpoints these paths, which READS
# them, and a digest carrying timestamps would then have to tell a read from a
# write. Content, mode and size answer the question actually being asked, which
# is whether anything a boot would read has changed.
mac_config_digest() {
    local path
    for path in "${MAC_CONFIG_PATHS[@]}"; do
        [[ -e "$path" ]] || continue
        find "$path" -printf '%p %m %s\n' 2>/dev/null | LC_ALL=C sort
        find "$path" -type f -exec sha256sum {} + 2>/dev/null | LC_ALL=C sort
    done
}

# The registry as the RUNNER read it on the host, for the fixtures that do not
# mount securityfs.
#
# Measured on all six booted containers 2026-08-09: /sys/kernel/security is not
# mounted in any of them, so the first container run of this oracle asked
# nothing at all and declared every row unaskable. That is the oracle behaving
# correctly and it is also the oracle proving nothing, which is not a state to
# leave it in.
#
# A container shares the host's kernel, so the host's registry and the
# container's would be the same file if the container had one. The runner's
# reading is therefore the same fact rather than a second one, and it is the
# same shape as HARDENER_DIFF_BOOTED and HARDENER_DIFF_NETNS: something the
# runner knows and the payload cannot see.
#
# What it costs. This row now depends on the runner declaring the truth, where
# before it depended only on the kernel. A runner that declared a wrong value
# would mislead it, which is why the value and its source are both printed in
# the header rather than merely used.
RUN_LSM="${HARDENER_DIFF_LSM:-}"

# Where the reading above came from, for the log. Set by detect_mac_askable and
# NOT by the reader below, because the reader is called in a command
# substitution and an assignment made there happens in a subshell and is lost.
MAC_LSM_SOURCE=""

# What the kernel says about its own LSMs, read here if securityfs is mounted
# and taken from the runner if it is not. Non-zero when neither can answer,
# which is not the same as "no MAC system" and is never folded into it.
mac_lsm_reading() {
    if [[ -r "$MAC_LSM_REGISTRY" ]]; then
        tr -d '\n' < "$MAC_LSM_REGISTRY"
        return 0
    fi
    [[ -n "$RUN_LSM" ]] || return 1
    printf '%s' "$RUN_LSM"
}

# Which MAC system the registry names, or nothing.
#
# Matched between commas rather than as a substring. The registry is a
# comma-separated list and a bare match would let a future LSM whose name
# CONTAINS one of these read as that one.
mac_lsm_names_system() {
    local reading="$1" name
    for name in selinux apparmor; do
        case ",$reading," in
            *",$name,"*)
                printf '%s' "$name"
                return 0
                ;;
        esac
    done
    return 1
}

# The MAC configuration paths that exist here, named for the log.
mac_config_present() {
    local path present=""
    for path in "${MAC_CONFIG_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            present+="${present:+, }$path"
        fi
    done
    printf '%s' "$present"
}

# Whether this fixture can be asked the no-op question at all. Decided before
# any check runs and read by expected_check_total, exactly as SHADOW_MIN_DAYS is,
# so the arithmetic and the rows cannot come to disagree about the size of a run.
#
# Three ways it cannot be asked, and each is a different fact. The registry may
# be unreadable, which is a fixture where securityfs was never mounted. The
# registry may NAME a MAC system, which is the host this oracle does not cover.
# Or the configuration tree may be absent entirely, in which case an untouched
# tree compares one absence with another and passes without asking anything,
# which is the vacuity issue #47 exists to remove.
MAC_ASKABLE=0
MAC_UNASKABLE_REASON=""
detect_mac_askable() {
    local reading named path
    if ! reading="$(mac_lsm_reading)"; then
        MAC_ASKABLE=0
        MAC_LSM_SOURCE=""
        MAC_UNASKABLE_REASON="$MAC_LSM_REGISTRY cannot be read here and the runner declared no reading of the host's, so nothing independent of the tool can say whether this kernel has a MAC system"
        return 0
    fi
    # Decided here rather than in the reader, which runs in a command
    # substitution and could not report it back.
    if [[ -r "$MAC_LSM_REGISTRY" ]]; then
        MAC_LSM_SOURCE="$MAC_LSM_REGISTRY, read in this container"
    else
        MAC_LSM_SOURCE="the runner's reading of the host's $MAC_LSM_REGISTRY, because securityfs is not mounted here"
    fi
    MAC_LSM_READING="$reading"
    if named="$(mac_lsm_names_system "$reading")"; then
        MAC_ASKABLE=0
        MAC_UNASKABLE_REASON="the kernel's LSM registry names $named, so this is a host the plugin is expected to ACT on and a no-op oracle would assert the opposite of the requirement (issue #18)"
        return 0
    fi
    for path in "${MAC_CONFIG_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            MAC_ASKABLE=1
            MAC_UNASKABLE_REASON=""
            return 0
        fi
    done
    MAC_ASKABLE=0
    MAC_UNASKABLE_REASON="none of ${MAC_CONFIG_PATHS[*]} exists here, so an untouched tree would be one absence compared with another"
}

# The pre-apply reading, which is half of what the check below compares.
preapply_mac_init() {
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply MAC capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        return 1
    fi
    MAC_CONFIG_BEFORE="$(mac_config_digest)"
}

run_mac_preapply_control() {
    if (( MAC_ASKABLE != 1 )); then
        record_unaskable "mac-hardening pre-apply control: $MAC_UNASKABLE_REASON"
        return 0
    fi
    record_pass "mac-hardening: the kernel's LSM registry reads '$MAC_LSM_READING' from $MAC_LSM_SOURCE and names neither selinux nor apparmor, and $(mac_config_present) is present, so the row below is asking whether a host the plugin must leave alone was left alone"
}

run_mac_checks() {
    local key after delta
    for key in "${MAC_CHECKS[@]}"; do
        if (( MAC_ASKABLE != 1 )); then
            record_unaskable "mac $key: $MAC_UNASKABLE_REASON"
            continue
        fi
        case "$key" in
            config-untouched)
                after="$(mac_config_digest)"
                if [[ "$after" == "$MAC_CONFIG_BEFORE" ]]; then
                    record_pass "mac $key: everything under $(mac_config_present) holds the content, mode and size it held before apply, so the plugin wrote nothing on a kernel with no MAC system to configure"
                else
                    delta="$(diff <(printf '%s\n' "$MAC_CONFIG_BEFORE") <(printf '%s\n' "$after") | grep '^[<>]' | head -5 | tr '\n' ';' || true)"
                    record_fail "mac $key: the MAC configuration tree changed across an apply on a kernel whose LSM registry names no MAC system, so the plugin wrote a configuration nothing on this host will ever read: $delta"
                fi
                ;;
            *)
                record_fail "mac $key: no probe is defined for this key, so the table and the checks have come apart"
                ;;
        esac
    done
}

KERNEL_BEFORE=""

# The pre-apply reading, which is half of what the checks below compare.
preapply_kernel_init() {
    local entry name
    KERNEL_BEFORE=""
    if ! run_has_netns; then
        return 0
    fi
    for entry in "${KERNEL_CHECKS[@]}"; do
        IFS='|' read -r name _ _ <<<"$entry"
        KERNEL_BEFORE+="$name=$(kernel_reading "$name")"$'\n'
    done
}

# Doing nothing must never exit 0. This asserts at least one managed parameter
# was AWAY from its target before the apply, so the checks below cannot pass
# against a host that was already compliant.
#
# The names below are what this suite read before the WHOLE apply, which is not
# the same as what the kernel plugin saw when its turn came, and the two can
# disagree honestly. Measured 2026-07-30 on arch and debian: the firewall plugin
# runs first and enables ufw, whose start applies /etc/ufw/sysctl.conf
# (IPT_SYSCTL in /etc/default/ufw), and that file sets log_martians to 0 while
# the tool's target is 1. So the kernel plugin then reports writing a parameter
# this capture had recorded as compliant. Both readings are correct; they were
# taken either side of another plugin. The three firewalld distributions show no
# such disagreement, which is what identified the cause.
run_kernel_preapply_control() {
    local entry name target direction reading away=0 away_names="" note
    # A seeded row this capture finds already at its target. The seed's own
    # read-back cannot see it: that proves what the kernel reported at seed
    # time, and this is a capture taken afterwards. Without this the control
    # would pass on the rows that did arrive loosened while the one that did not
    # went into the run exactly as vacuous as it was before it was seeded.
    local seeded_at_target=""
    if ! run_has_netns; then
        record_unaskable "kernel-hardening pre-apply control: this run has no network namespace of its own, so /proc/sys/net is the host's and read-only"
        return 0
    fi
    for entry in "${KERNEL_CHECKS[@]}"; do
        IFS='|' read -r name target direction <<<"$entry"
        # Guarded rather than assigned outright. A parameter the capture has no
        # line for fails the grep, and under `set -euo pipefail` a bare
        # assignment from a failing pipeline ends the whole run from here: exit
        # 1 with not one check printed, which reads as a finding and is not.
        # The capture is built from this same table, so the two coming apart is
        # a fault in the suite rather than in the host, and it is reported as
        # one instead of being counted as a parameter away from target. Counting
        # it away would be worse than aborting: the control would then pass on
        # the strength of a reading nobody took.
        if ! reading="$(grep -m1 "^$name=" <<<"$KERNEL_BEFORE" | cut -d= -f2-)"; then
            record_fail "kernel-hardening pre-apply control: the pre-apply capture holds no reading for $name, so the capture and the table have come apart and this control cannot be asked"
            return 0
        fi
        if ! kernel_satisfies "$reading" "$target" "$direction"; then
            away=$((away + 1))
            # Named, not just counted. A bare count cannot be reconciled against
            # the tool's own list of what it wrote, and the first container run
            # of this oracle produced exactly that: the tool reported writing two
            # parameters on arch and three on debian where this control found one
            # away on each. One of the two readings is wrong and a number alone
            # cannot say which.
            note=""
            if kernel_seeded_looser "$name"; then
                note=", seeded by this suite"
            fi
            away_names+="${away_names:+, }$name was '$reading' against a target of '$target'$note"
        elif kernel_seeded_looser "$name"; then
            seeded_at_target+="${seeded_at_target:+, }$name reads '$reading'"
        fi
    done
    if (( away == 0 )); then
        record_fail "kernel-hardening: every managed parameter already met its target before apply, so the checks below would pass without the tool having done anything"
        return 0
    fi
    if [[ -n "$seeded_at_target" ]]; then
        record_fail "kernel-hardening: this suite loosened a parameter before apply and the pre-apply capture finds it already at its target ($seeded_at_target), so the seed and the capture describe different hosts and that row would pass below without the tool having done anything"
        return 0
    fi
    record_pass "kernel-hardening: $away of the ${#KERNEL_CHECKS[@]} managed parameters were away from target before apply, so the checks below are asking a real question ($away_names)"
}

# One assertion per parameter: does the kernel enforce what the tool reported.
run_kernel_checks() {
    local entry name target direction reading reason
    if ! run_has_netns; then
        for entry in "${KERNEL_CHECKS[@]}"; do
            IFS='|' read -r name _ _ <<<"$entry"
            record_unaskable "kernel $name: this run has no network namespace of its own, so /proc/sys/net is the host's and read-only"
        done
    else
        for entry in "${KERNEL_CHECKS[@]}"; do
            IFS='|' read -r name target direction <<<"$entry"
            reading="$(kernel_reading "$name")"
            if [[ "$reading" == "unreadable" ]]; then
                record_fail "kernel $name: sysctl could not be read, so this parameter is unproven"
            elif kernel_satisfies "$reading" "$target" "$direction"; then
                record_pass "kernel $name: the kernel enforces '$reading', which meets the target '$target' by $direction"
            else
                record_fail "kernel $name: the kernel enforces '$reading', which does NOT meet the target '$target' by $direction, so the hardening the tool reported is not what the kernel will apply"
            fi
        done
    fi
    for entry in "${KERNEL_UNASKABLE[@]}"; do
        IFS='|' read -r name reason <<<"$entry"
        record_unaskable "kernel $name: $reason"
    done
}

# The one kernel row that asks whether the apply LOOSENED anything.
#
# The value read here is the seed rather than the tool's target, so this row
# cannot pass by agreeing with the tool: an oracle that compared for equality
# with the target would fail it, and so would a tool that stopped clamping its
# target up to what the host already runs.
run_seeded_kernel_check() {
    local entry name seed target reading
    if ! run_has_netns; then
        for entry in "${SEEDED_KERNEL_CHECKS[@]}"; do
            IFS='|' read -r name _ _ <<<"$entry"
            record_unaskable "seeded kernel $name: this run has no network namespace of its own, so /proc/sys/net is the host's and the seed could not be written"
        done
        return 0
    fi
    for entry in "${SEEDED_KERNEL_CHECKS[@]}"; do
        IFS='|' read -r name seed target <<<"$entry"
        reading="$(kernel_reading "$name")"
        if [[ "$reading" == "$seed" ]]; then
            record_pass "seeded kernel $name: still '$reading' after apply, so the tool left a host stricter than its own target of '$target' alone"
        elif [[ "$reading" == "unreadable" ]]; then
            record_fail "seeded kernel $name: was seeded '$seed' before apply and cannot be read now, so nothing here shows whether the apply left the seed standing"
        else
            record_fail "seeded kernel $name: was seeded '$seed' before apply and now reads '$reading', against a tool target of '$target', so the apply LOOSENED a parameter that was already stricter than its target"
        fi
    done
}

# === Services systemd will not start at boot ===
#
# The oracle is systemd, asked with `is-enabled` and `is-active`, and the
# filesystem, asked with `readlink`. Both are consumers of what this plugin
# writes: `systemctl disable` removes a wants/ symlink and `systemctl mask`
# creates a link to /dev/null, and systemd reads both at the next boot.
#
# WHAT THIS ORACLE CANNOT SEE, and it is the limit issue #47 names as the rule
# any new oracle must follow: both readers ask about a unit NAME, and it is the
# name the tool asks about. A tool managing the wrong unit would be agreed with
# here and both would be wrong. The permissions oracle carries the same limit
# for the same reason, and closing it would need a second source for the name.
#
# The unit is chosen by the fixture rather than by this file.
# scripts/containers/create-container.sh installs bluez on all five images and
# ENABLES bluetooth.service, explicitly so this plugin has subject matter: it
# raises a finding only for a unit that is enabled or active, and every image
# shipped with none of the five units it assesses.
SERVICES_UNIT="bluetooth"

# The unit file `systemctl` resolves the bare name to, and therefore the
# basename `systemctl mask` gives its link. Suffixed for the reason
# crates/hardener-plugins/src/services/mod.rs:371 records: `list-unit-files`
# matches patterns literally, and an unsuffixed pattern matches nothing, which
# once made every service look absent.
SERVICES_MASK_LINK="/etc/systemd/system/${SERVICES_UNIT}.service"

# Unit-file states the services plugin counts as enabled, copied from
# ENABLED_STATES in crates/hardener-plugins/src/services/mod.rs:407 rather than
# restated in this file's own words. It mirrors the exit-code semantics of
# `systemctl is-enabled`, which exits 0 for more states than `enabled`.
#
# Deliberately NOT the firewall oracle's NOT_AT_BOOT_STATES, which shares the
# word `enabled-runtime` and means the opposite by it. That list answers "will
# this survive a reboot"; this one answers "does this plugin raise a finding",
# and an oracle must fail on exactly the set the plugin it judges repairs.
SERVICES_ENABLED_STATES=(enabled enabled-runtime alias static indirect generated transient)

# Is this word one the plugin treats as enabled?
#
# An empty word is not, so a systemctl that answered nothing fails toward "not
# verified" rather than reading as a unit that was already disabled. That is the
# admitting direction and it is the one this file refuses everywhere.
services_unit_is_enabled() {
    local word="$1" state
    for state in "${SERVICES_ENABLED_STATES[@]}"; do
        [[ "$word" == "$state" ]] && return 0
    done
    return 1
}

# What `systemctl is-active` printed, with the status discarded, for the reason
# systemd_unit_boot_word gives: `is-active` prints `inactive` while exiting 3,
# so a reading taken from the status throws the word away.
systemd_unit_active_word() {
    local word=""
    word="$(systemctl is-active "$1" 2>/dev/null)" || true
    printf '%s' "${word//[[:space:]]/}"
}

# What sits at the mask link, as `<kind>|<target>`, with three kinds and never
# two meanings sharing one value.
#
# `absent` and `notlink` are deliberately distinct. A readlink-only reading
# gives the empty string for both, and they are not the same host: a regular
# file at that path is an administrator's own override unit, `systemctl mask`
# will not replace it, and a control reading that as "absent" would admit a host
# where the apply cannot do the thing this oracle is about to check.
#
# `-L` is asked before `-e` because a dangling symlink answers no to `-e` and
# yes to `-L`. The limit, stated where it bites: `-e` is a stat, so a path this
# run may not stat reads as absent. This suite runs as root inside a container,
# where that cannot happen; anywhere else the reading would be wrong in the
# admitting direction.
services_mask_link_reading() {
    if [[ -L "$SERVICES_MASK_LINK" ]]; then
        printf 'link|%s' "$(readlink "$SERVICES_MASK_LINK")"
    elif [[ -e "$SERVICES_MASK_LINK" ]]; then
        printf 'notlink|'
    else
        printf 'absent|'
    fi
}

# Whether the unit exists at all, asked of `list-unit-files` the way the plugin
# asks it (services/mod.rs:534). The listing is captured and then matched, never
# matched through a pipe, because `$?` after a pipe is the last stage's status
# and the read this cares about is the first.
services_unit_installed() {
    local listing=""
    listing="$(systemctl list-unit-files "${SERVICES_UNIT}.service" 2>/dev/null)" || true
    if grep -q "^${SERVICES_UNIT}\.service" <<<"$listing"; then
        printf 'yes'
    else
        printf 'no'
    fi
}

# The three questions this oracle asks, in the order they are reported.
SERVICES_CHECKS=(
    "not-at-boot"
    "mask-link"
    "not-running"
)

# The readings, one set either side of the apply. Initialised here so a run that
# never reaches the capture has empty strings rather than unset names: this file
# runs under `set -u`, and the arithmetic below reads one of them.
SERVICES_INSTALLED_BEFORE=""
SERVICES_BOOT_BEFORE=""
SERVICES_ACTIVE_BEFORE=""
SERVICES_MASK_BEFORE=""
SERVICES_BOOT_AFTER=""
SERVICES_ACTIVE_AFTER=""
SERVICES_MASK_AFTER=""

# The readings taken while the container is still unhardened.
#
# Guarded on the generation for the reason preapply_firewall_init gives: these
# are half of what the checks below compare, so one taken after an apply would
# agree with itself. An unbooted run takes no readings at all and leaves the
# empty strings above standing, which is what the rows read when they declare
# themselves unaskable.
preapply_services_init() {
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply services capture was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It is half of what these checks compare, so it has to be taken" >&2
        echo "  while the container is still unhardened." >&2
        return 1
    fi
    run_is_booted || return 0
    SERVICES_INSTALLED_BEFORE="$(services_unit_installed)"
    SERVICES_BOOT_BEFORE="$(systemd_unit_boot_word "$SERVICES_UNIT")"
    SERVICES_ACTIVE_BEFORE="$(systemd_unit_active_word "$SERVICES_UNIT")"
    SERVICES_MASK_BEFORE="$(services_mask_link_reading)"
}

services_oracle_init() {
    if (( APPLY_GENERATION == 0 )); then
        echo "FATAL: the post-apply services capture was asked for before any apply." >&2
        return 1
    fi
    run_is_booted || return 0
    SERVICES_BOOT_AFTER="$(systemd_unit_boot_word "$SERVICES_UNIT")"
    SERVICES_ACTIVE_AFTER="$(systemd_unit_active_word "$SERVICES_UNIT")"
    SERVICES_MASK_AFTER="$(services_mask_link_reading)"
}

# One check, refusing three ways, and each refusal names a host on which every
# row below would report a pass the tool had not earned.
run_services_preapply_control() {
    if ! run_is_booted; then
        record_unaskable "services-hardening pre-apply control: this run is not booted, so systemd is not PID 1 and systemctl cannot be asked"
        return 0
    fi
    if [[ "$SERVICES_INSTALLED_BEFORE" != "yes" ]]; then
        record_fail "services-hardening: ${SERVICES_UNIT}.service is not installed, so this plugin manages nothing here; create-container.sh installs bluez on all five images, so that is a broken image and not a host these checks do not apply to"
    elif ! services_unit_is_enabled "$SERVICES_BOOT_BEFORE"; then
        record_fail "services-hardening: systemd read '$SERVICES_BOOT_BEFORE' for $SERVICES_UNIT before apply, which this plugin does not count as enabled, so it raises no finding and every check below would pass without the tool having acted"
    elif [[ "$SERVICES_MASK_BEFORE" != "absent|" ]]; then
        record_fail "services-hardening: $SERVICES_MASK_LINK already reads '$SERVICES_MASK_BEFORE' before apply, so the mask check below cannot show that the apply created it; recreate the container first"
    else
        record_pass "services-hardening: $SERVICES_UNIT was installed, read '$SERVICES_BOOT_BEFORE' at boot and had no mask link before apply, so the checks below are asking a real question"
    fi
}

run_services_checks() {
    local key
    for key in "${SERVICES_CHECKS[@]}"; do
        if ! run_is_booted; then
            record_unaskable "services $key: this run is not booted, so systemd is not PID 1 and systemctl cannot be asked"
            continue
        fi
        case "$key" in
            not-at-boot)
                # What the plugin is FOR. It cannot tell a mask from a plain
                # disable, because systemd counts neither as enabled, and that
                # is what the row below is for. The two are separate checks so
                # that a tool which stopped disabling fails this one alone.
                if services_unit_is_enabled "$SERVICES_BOOT_AFTER"; then
                    record_fail "services $key: systemd reads '$SERVICES_BOOT_AFTER' for $SERVICES_UNIT after apply, which this plugin counts as enabled, so the unit it reported disabling will still start at the next boot"
                else
                    record_pass "services $key: systemd reads '$SERVICES_BOOT_AFTER' for $SERVICES_UNIT after apply, having read '$SERVICES_BOOT_BEFORE' before apply, so it will not start at the next boot"
                fi
                ;;
            mask-link)
                # The only row that survives somebody re-enabling the unit, and
                # the only one that separates `systemctl mask` from `systemctl
                # disable`. Judged by the link's TARGET: a link pointing
                # anywhere else is a unit, not a mask.
                if [[ "$SERVICES_MASK_AFTER" == "link|/dev/null" ]]; then
                    record_pass "services $key: $SERVICES_MASK_LINK is a link to /dev/null after apply, where it read '$SERVICES_MASK_BEFORE' before, so the unit is masked and not merely disabled"
                else
                    record_fail "services $key: $SERVICES_MASK_LINK reads '$SERVICES_MASK_AFTER' after apply, so the unit is not masked and can be started or re-enabled by hand"
                fi
                ;;
            not-running)
                # Unaskable rather than passed on a host where the unit was
                # never running. bluetooth.service does not start in every
                # container, and a row reporting a pass on all five
                # distributions without the tool having stopped anything is the
                # vacuity issue #47 exists to remove. expected_check_total
                # subtracts this row on exactly this condition, so the two have
                # to keep agreeing about what "was not running" means.
                if [[ "$SERVICES_ACTIVE_BEFORE" != "active" ]]; then
                    record_unaskable "services $key: $SERVICES_UNIT read '$SERVICES_ACTIVE_BEFORE' before apply, so it was not running and nothing here could show the tool stopped it"
                elif [[ "$SERVICES_ACTIVE_AFTER" == "active" ]]; then
                    record_fail "services $key: $SERVICES_UNIT was running before apply and reads '$SERVICES_ACTIVE_AFTER' after it, so the tool reported stopping a service that is still running"
                else
                    record_pass "services $key: $SERVICES_UNIT read 'active' before apply and reads '$SERVICES_ACTIVE_AFTER' after it, so the tool stopped what it reported stopping"
                fi
                ;;
        esac
    done
}

SSH_CHECKS_EXPECTED=7
SEEDED_SSH_CHECKS_EXPECTED=2
LOGIN_DEFS_CHECKS_EXPECTED=3
VENDOR_SURVIVAL_CHECKS_EXPECTED=3
IDEMPOTENCE_CHECKS_EXPECTED=4
# The plugins compared in EVERY run. Services is the eighth and joins only a
# booted one, which is why this stays a literal and the count below is a
# function.
DIFF_PLUGINS_EXPECTED=7
PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED=2
PERMISSION_CHECKS_EXPECTED=9
FIREWALL_CHECKS_EXPECTED=3
AUDIT_CHECKS_EXPECTED=3
# One row, and it stays a table for the reason every other table here is one:
# the guard below refuses a length that moved without this number moving with
# it, and a second MAC row added on a machine that grows an LSM must meet a
# reviewer in the diff rather than arrive silently.
MAC_CHECKS_EXPECTED=1
SERVICES_CHECKS_EXPECTED=3
KERNEL_CHECKS_EXPECTED=11
# Pinned for the same reason as every table above, and one more that is specific
# to this pair: the failure mode here is a red row being "fixed" by moving it
# from KERNEL_CHECKS into KERNEL_UNASKABLE. Both sizes are pinned, so that move
# fails the guard twice rather than passing quietly.
KERNEL_UNASKABLE_EXPECTED=7
SEEDED_KERNEL_CHECKS_EXPECTED=1
# No total is counted off this one. It records no check of its own: the row it
# loosens is already in KERNEL_CHECKS, and what the seed changes is whether the
# pre-apply control can be satisfied, not how many assertions a run makes.
SEEDED_LOOSER_KERNEL_CHECKS_EXPECTED=10
# Pinned for a reason of its own, and it is the KERNEL_UNASKABLE one inverted.
# No total below is counted off this table's length. What pinning it buys is
# that a red introduced-finding row cannot be quieted by appending an entry:
# doing so fails this guard until the number beside the table moves as well, and
# that number is what a reviewer meets in the diff.
INTRODUCED_FINDING_ALLOWANCES_EXPECTED=2

require_check_tables() {
    local entry name got want refused=0
    for entry in \
        "SSH_CHECKS ${#SSH_CHECKS[@]} $SSH_CHECKS_EXPECTED" \
        "SEEDED_SSH_CHECKS ${#SEEDED_SSH_CHECKS[@]} $SEEDED_SSH_CHECKS_EXPECTED" \
        "LOGIN_DEFS_CHECKS ${#LOGIN_DEFS_CHECKS[@]} $LOGIN_DEFS_CHECKS_EXPECTED" \
        "VENDOR_SURVIVAL_CHECKS ${#VENDOR_SURVIVAL_CHECKS[@]} $VENDOR_SURVIVAL_CHECKS_EXPECTED" \
        "IDEMPOTENCE_CHECKS ${#IDEMPOTENCE_CHECKS[@]} $IDEMPOTENCE_CHECKS_EXPECTED" \
        "DIFF_PLUGINS ${#DIFF_PLUGINS[@]} $(diff_plugin_count)" \
        "PWQUALITY_ENFORCEMENT_CHECKS ${#PWQUALITY_ENFORCEMENT_CHECKS[@]} $PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED" \
        "PERMISSION_CHECKS ${#PERMISSION_CHECKS[@]} $PERMISSION_CHECKS_EXPECTED" \
        "FIREWALL_CHECKS ${#FIREWALL_CHECKS[@]} $FIREWALL_CHECKS_EXPECTED" \
        "AUDIT_CHECKS ${#AUDIT_CHECKS[@]} $AUDIT_CHECKS_EXPECTED" \
        "MAC_CHECKS ${#MAC_CHECKS[@]} $MAC_CHECKS_EXPECTED" \
        "SERVICES_CHECKS ${#SERVICES_CHECKS[@]} $SERVICES_CHECKS_EXPECTED" \
        "KERNEL_CHECKS ${#KERNEL_CHECKS[@]} $KERNEL_CHECKS_EXPECTED" \
        "KERNEL_UNASKABLE ${#KERNEL_UNASKABLE[@]} $KERNEL_UNASKABLE_EXPECTED" \
        "SEEDED_KERNEL_CHECKS ${#SEEDED_KERNEL_CHECKS[@]} $SEEDED_KERNEL_CHECKS_EXPECTED" \
        "SEEDED_LOOSER_KERNEL_CHECKS ${#SEEDED_LOOSER_KERNEL_CHECKS[@]} $SEEDED_LOOSER_KERNEL_CHECKS_EXPECTED" \
        "INTRODUCED_FINDING_ALLOWANCES ${#INTRODUCED_FINDING_ALLOWANCES[@]} $INTRODUCED_FINDING_ALLOWANCES_EXPECTED"; do
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

# Two assertions per compared directive, plus one pre-apply control per plugin,
# plus one per unmanaged setting. print_summary refuses a run whose totals do
# not come to this: a loop that skipped a directive, or a check that recorded
# nothing at all, would otherwise leave a partial run reading as a complete one.
#
# The vendor survival and idempotency checks are one assertion each, not two:
# there is no tool-reported counterpart to compare against, because the tool
# claims nothing about settings it does not manage and nothing about what a
# second run of itself would do. Vendor survival took the per-distribution total
# from 22 to 25 and the five-distribution total from 110 to 125; idempotency
# takes them to 28 and 140. The pwquality enforcement pair takes them to 30
# and 150: also one assertion each, because the stack reading is compared
# against the tool and the password verdict against the stack reading, and
# neither has a second tool claim to hold it to.
#
# The nine permission paths are two each, like the ssh and login.defs
# directives, because each has both a reading and a tool verdict. With the third
# plugin's own pre-apply control that takes the per-distribution total from 30 to
# 51 and the five-distribution total from 150 to 255. The permission-modes
# idempotency reading takes them to 52 and 260: one assertion, like the other
# three readings, because the tool claims nothing about what a second run of
# itself would do.
#
# The preview-agreement oracle adds one row per compared plugin and one control
# over both of the parses those rows are read through, taking the unbooted total
# from 56 to 62 and the booted one from 69 to 75. It is the one block the mode
# makes no difference to: the dry run and the apply both happen whether or not
# the fixture is booted, so the same six are asked either way.
#
# The introduced-finding registry is shaped the same and sized the same, one row
# per compared plugin and one control over the two documents those rows are read
# through, taking the unbooted total from 62 to 68 and the booted one from 75 to
# 81. The mode makes no difference to it either: both scan documents are
# captured whether or not the fixture is booted, and the finding ids in them are
# the tool's own report rather than a reading off /proc/sys.
#
# The rollback-reload check (Task 7, issue #67) adds a flat two: the positive
# control and the restoration assertion, neither counted off a table because
# the check is not table-driven, it runs its own apply-then-rollback cycle once.
# Both modes get the same two, taking the unbooted total from 68 to 70 and the
# booted one from 81 to 83: sshd -T needs neither the kernel oracle nor a
# booted network namespace, so the mode makes no difference to it either.
#
# Counted off the pinned lengths above, never off the tables themselves. Read
# from ${#SSH_CHECKS[@]} the expectation would follow the table it exists to
# police: emptying that table would drop the number from 28 to 14 and
# print_summary would then accept the shorter run, which is the guard asking the
# tables whether the tables are right.
expected_check_total() {
    # PASS_MIN_DAYS contributes two of the login.defs assertions, and on a host
    # whose shadow has no minimum-password-age field both are declared unaskable
    # rather than asked. Subtracted from both arms below, because the mode above
    # is a fact about /proc/sys and this one is a fact about shadow: a run can
    # be in either, both or neither.
    local min_days_rows=0
    if [[ "$SHADOW_MIN_DAYS" != "1" ]]; then
        min_days_rows=2
    fi
    # How many plugins this run compares, and therefore how many pre-apply
    # controls, preview-agreement rows and introduced-finding rows it makes.
    # Seven in a booted run and six otherwise, because the services plugin is
    # only in the compared set where systemctl can be asked anything.
    local plugins
    plugins="$(diff_plugin_count)"
    # The services `not-running` row is unaskable on a host where the unit was
    # never running, and that is a fact about the HOST rather than about the
    # invocation, so it is read back from the pre-apply capture rather than
    # declared by the runner. SHADOW_MIN_DAYS above is the same shape, probed
    # before the run and subtracted the same way.
    local services_rows=0
    if run_is_booted; then
        services_rows=$SERVICES_CHECKS_EXPECTED
        if [[ "$SERVICES_ACTIVE_BEFORE" != "active" ]]; then
            services_rows=$(( services_rows - 1 ))
        fi
    fi
    # The kernel rows and the kernel plugin's own pre-apply control, which a run
    # without its own network namespace declares unaskable and therefore does
    # not ask for either. The seeded kernel row goes with them, its seed having
    # been unwritable.
    #
    # Gated on the namespace and not on the booted signal, which is #137: the
    # two were one variable, so a --pipe run gave up 13 rows to a condition only
    # the services rows have. One expression rather than an arm per mode, so
    # that the four combinations of the two signals cannot each need their own
    # copy of the arithmetic to be kept in step.
    local kernel_rows=0 kernel_control=0
    if run_has_netns; then
        kernel_rows=$(( KERNEL_CHECKS_EXPECTED + SEEDED_KERNEL_CHECKS_EXPECTED ))
        kernel_control=1
    fi
    # The MAC rows and the MAC plugin's own pre-apply control, which go together
    # because they are unaskable for one reason and it disqualifies both. This is
    # a fact about the KERNEL rather than about the invocation, so it is
    # subtracted the way SHADOW_MIN_DAYS is and not gated on a mode signal: a
    # host carrying selinux or apparmor is one this oracle does not cover, and it
    # can be booted or not, with a namespace or without.
    local mac_rows=0
    if (( MAC_ASKABLE != 1 )); then
        mac_rows=$(( MAC_CHECKS_EXPECTED + 1 ))
    fi
    printf '%s' "$(( 2 * (SSH_CHECKS_EXPECTED + LOGIN_DEFS_CHECKS_EXPECTED \
        + PERMISSION_CHECKS_EXPECTED) \
        + VENDOR_SURVIVAL_CHECKS_EXPECTED + IDEMPOTENCE_CHECKS_EXPECTED \
        + PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED + plugins - 1 + kernel_control \
        + SEEDED_SSH_CHECKS_EXPECTED + FIREWALL_CHECKS_EXPECTED \
        + AUDIT_CHECKS_EXPECTED + MAC_CHECKS_EXPECTED \
        + kernel_rows \
        + services_rows \
        + plugins + 1 \
        + plugins + 1 \
        + 2 - min_days_rows - mac_rows ))"
}

# The three plugins spell their finding ids differently, and a filter written for
# one convention matches NOTHING under the others. Matching nothing returns an
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
# produce that same zero, and only the last of the three is nameable from the
# document itself. `scan --format json` serialises scan_success and scan_error
# beside plugin_id, plugin_name, findings and unchecked, and
# validate_scan_document refuses a plugin that reports its own scan as failed.
# The other two leave the document looking entirely healthy: a plugin can report
# scan_success true while the filter reading it names an id, or a plugin_id, the
# tool does not emit. A capture taken while the container is known to be
# unhardened is the only thing in reach that tells those apart.
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
    local document="$1" label="$2" plugin count reason
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
        # And whether the scan ran at all, which no shape above can say. Every
        # rule up to here asks whether the document can be read; this one asks
        # whether it is a reading. A plugin whose scan failed reports no
        # finding, and no finding for every compared directive is exactly this
        # suite's pass condition.
        #
        # True is not by itself a statement that anything was measured: the ssh
        # plugin reports a successful scan while putting every one of its
        # directives into `unchecked` when sshd_config cannot be read for want
        # of root. That case is what the two rules above answer, and this one is
        # deliberately not made to carry it.
        if ! jq --exit-status --arg p "$plugin" \
            '[.[] | select(.plugin_id == $p) | has("scan_success")] == [true]' \
            >/dev/null <<<"$document"; then
            echo "FATAL: the $label object for plugin '$plugin' has no 'scan_success' key." >&2
            echo "  It is the only thing that tells a scan that ran and found nothing" >&2
            echo "  from one that never ran, and both report no finding, which is this" >&2
            echo "  suite's pass condition. Rebuild the CLI from this tree, or set" >&2
            echo "  BINARY to a build that carries the key." >&2
            return 1
        fi
        # Present and false is a different fault, and no rebuild fixes it: the
        # tool is stating that this plugin's scan did not complete on this host.
        # The reason it gave travels into the refusal, because a check that
        # refuses has to say what it refused over. scan_error is an Option, so
        # the null it may hold is answered here rather than printed at a reader
        # as though it were the explanation.
        if ! jq --exit-status --arg p "$plugin" \
            '[.[] | select(.plugin_id == $p) | .scan_success] == [true]' \
            >/dev/null <<<"$document"; then
            reason="$(jq -r --arg p "$plugin" \
                '.[] | select(.plugin_id == $p) | .scan_error // "none reported"' \
                <<<"$document")"
            echo "FATAL: the $label object for plugin '$plugin' reports scan_success false." >&2
            echo "  Its scan did not complete, so what it lists is not a reading of" >&2
            echo "  this host: every compared directive under that plugin would count" >&2
            echo "  zero findings, which is this suite's pass condition." >&2
            echo "  The reason the tool gave: $reason" >&2
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

# Whether a reading satisfies what this run requires of it.
#
# `exact` is string equality, which is what every check in this suite meant while
# there was only one comparison: sshd -T prints one value, the table names one
# value, and anything else is a disagreement.
#
# `mask` exists for a mode compared against an allowed-bits mask, where a
# STRICTER mode is compliant and equality would fail a correctly hardened host.
# /etc/shadow at 0600 sets no bit the 0640 mask disallows, and the tool
# deliberately leaves it alone, so an equality oracle would report a defect
# against the tool behaving exactly as designed. The product side spells the same
# asymmetry out in crates/hardener-plugins/src/permissions/mod.rs, and this is
# the reason the question has to carry a direction rather than being `==`.
#
# An unknown comparison is fatal rather than defaulting to equality. A typo would
# otherwise score every mask directive by the wrong rule while the run still
# printed a complete summary, which is the exact failure this suite exists to
# refuse. Fatal here means "not satisfied", so the check fails loudly rather than
# passing on a comparison nobody implemented.
requirement_satisfied() {
    local system="$1" target="$2" comparison="$3" octal='^[0-7]{1,4}$'
    case "$comparison" in
        exact)
            [[ "$system" == "$target" ]]
            ;;
        mask)
            # Both sides are checked before any arithmetic runs, and what that
            # buys is the message rather than the status. `8#absent` fails on its
            # own, so an unguarded comparison would also refuse the reading, but
            # it would refuse it as `8#absent: value too great for base` with a
            # bash line number, and a check that reports a refusal has to report
            # the rule that refused. The self-test asserts this wording for that
            # reason, not the exit status, which is identical either way.
            #
            # One to four digits, not three: `stat -c %a` prints `0` for mode
            # 0000, which /etc/shadow legitimately holds on some distributions,
            # and four for a mode carrying a setuid, setgid or sticky bit. Both
            # are real readings, and a special bit sits outside every mask this
            # table uses, so it must reach the comparison rather than the
            # refusal.
            if [[ ! "$system" =~ $octal || ! "$target" =~ $octal ]]; then
                echo "FATAL: a mask comparison needs two octal modes, and was" \
                    "given '$system' against '$target'" >&2
                return 1
            fi
            (( (8#$system & ~8#$target) == 0 ))
            ;;
        *)
            echo "FATAL: no such comparison '$comparison'" >&2
            return 1
            ;;
    esac
}

# How a requirement reads inside a message.
#
# `exact` names the value. `mask` names the rule, because "requires '640'" is
# false of a directive that also accepts 600, and a message that asserts
# something false about the requirement is the same defect as a message that
# names the wrong cause.
requirement_wording() {
    local target="$1" comparison="$2"
    case "$comparison" in
        exact) printf "'%s'" "$target" ;;
        mask) printf "no bit outside '%s'" "$target" ;;
        *) printf "an unknown requirement against '%s'" "$target" ;;
    esac
}

# The second assertion, on its own so it can be pinned in all four directions.
# scan's verdict agrees with the system when a system that does not satisfy what
# this run requires produces at least one finding, and one that satisfies it
# produces none.
#
# It is given the satisfaction rather than the two values, because whether a
# reading satisfies a requirement is no longer always string equality. Deciding
# that here as well would put a second copy of the comparison behind this
# question, and the two copies would answer differently for exactly the readings
# a mask exists for. Anything other than yes or no is fatal, for the same reason
# an unknown comparison is.
verdict_agrees() {
    local satisfied="$1" findings="$2"
    case "$satisfied" in
        yes) (( findings == 0 )) ;;
        no) (( findings > 0 )) ;;
        *)
            echo "FATAL: verdict_agrees was asked about satisfaction '$satisfied'," \
                "which is neither yes nor no" >&2
            return 1
            ;;
    esac
}

# Per-check bookkeeping. The summary vocabulary below is the one that
# scripts/test/run-cross-distro-tests.sh already parses out of a suite's log,
# so the host-side runner reports this suite through the machinery it has. No
# line printed before the summary may repeat those labels.
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_UNASKABLE=0

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

# A check this fixture cannot answer, declared in advance as a property of the
# fixture rather than discovered at runtime.
#
# The suite's rule is that an undeterminable value is a FAILURE, never a skip,
# so that a probe which quietly fails to read cannot pass. This does not weaken
# it. The distinction is when unaskability is decided: a container has no
# writable /proc/sys, which is known before the run and stated in a table, while
# "I asked and got nothing" is a property of the run and stays a failure.
#
# Deliberately outside CHECKS_TOTAL. The three counters above are what the
# host-side runner parses, and a gap that was never asked is not a check that
# ran. print_summary names the count so a green run can never be read as full
# coverage.
record_unaskable() {
    CHECKS_UNASKABLE=$((CHECKS_UNASKABLE + 1))
    printf '  ----   %s\n' "$1"
}

# The two assertions for one directive, given the value its oracle reported.
# Both are always recorded, so every directive contributes the same two checks
# whatever happens and one cannot quietly contribute fewer by going wrong.
# `target` is what this run requires, which is the tool's own target for an
# unseeded directive and the SEEDED value for the two in SEEDED_SSH_CHECKS. The
# messages below therefore say "this run requires" rather than "the tool
# targets", which reads more naturally and would be false for the seeded pair.
#
# For the same reason no message here names a cause. A disagreement used to be
# reported as "apply did not take effect", and on a seeded directive the truth
# is the opposite: apply took effect and overwrote a value stricter than its
# own target. Stating the two values and leaving the cause to the reader is the
# only wording true of both.
compare_directive() {
    local plugin="$1" directive="$2" system="$3" target="$4" finding_id="$5" comparison="$6"
    local satisfied=no requirement
    requirement="$(requirement_wording "$target" "$comparison")"

    if requirement_satisfied "$system" "$target" "$comparison"; then
        satisfied=yes
        record_pass "$plugin $directive: the system holds '$system', which is what this run requires ($requirement)"
    else
        record_fail "$plugin $directive: the system holds '$system' but this run requires $requirement"
    fi

    compare_reported_verdict "$plugin" "$directive" "$satisfied" "$finding_id" \
        "the system holds '$system' and this run requires $requirement"
}

# The second assertion for one compared id: whether the tool's own verdict agrees
# with what the system was just read to hold.
#
# Split out of compare_directive because a permission directive whose PATH is
# absent has no mode to compare and still has a verdict worth checking, and a
# second copy of this body is the shape that has produced a defect in eleven
# consecutive sessions. `state` is the caller's description of what was read, so
# no wording here has to be true of both callers.
compare_reported_verdict() {
    local plugin="$1" label="$2" satisfied="$3" finding_id="$4" state="$5" reported unchecked

    # Asked before the findings are counted, because it decides whether that
    # count means anything: the tool reports no finding for a check it never
    # ran, and no finding is the pass condition here.
    if ! unchecked="$(scan_unchecked_count "$plugin" "$finding_id")"; then
        record_fail "$plugin $label: the tool's unchecked list could not be read for '$finding_id'"
        return 0
    fi
    if (( unchecked > 0 )); then
        record_fail "$plugin $label: the tool did not check '$finding_id'; it lists the id as unchecked, which is neither agreement with the system nor a contradiction of it"
        return 0
    fi
    if ! reported="$(scan_finding_count "$plugin" "$finding_id")"; then
        record_fail "$plugin $label: the tool's verdict for '$finding_id' could not be read"
        return 0
    fi
    if verdict_agrees "$satisfied" "$reported"; then
        record_pass "$plugin $label: the tool agrees with the system ($reported finding(s) for '$finding_id')"
    elif [[ "$satisfied" == yes ]]; then
        record_fail "$plugin $label: the tool reports $reported finding(s) for '$finding_id' while $state"
    else
        record_fail "$plugin $label: the tool claims a compliance the system does not have: no finding for '$finding_id' while $state"
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
    for entry in "${PERMISSION_CHECKS[@]}"; do
        IFS='|' read -r directive _ <<<"$entry"
        printf '%s %s\n' permissions-hardening "$(permission_finding_id "$directive")"
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
# Per plugin rather than in total, because each of those faults lands on one
# plugin at a time. The third of them is answered before this runs: the JSON
# carries scan_success, and validate_scan_document refuses a plugin that reports
# its own scan as failed. The first two never touch that key. A plugin whose
# scan succeeded emits the same empty arrays a fully compliant host does the
# moment the filter reading it is written under the wrong id convention, and
# only a control scoped to that plugin, counted through the very filter the
# comparison uses, can see it.
run_preapply_control() {
    local plugin entry_plugin id count matched total unreadable
    for plugin in "${DIFF_PLUGINS[@]}"; do
        # firewall, kernel and services have no per-directive finding ids this
        # suite compares, and each carries a control of its own instead. firewall's
        # only scan finding is `{backend}-disabled`, and firewalld is already
        # active in three of the five containers, so a finding-count control
        # would fail there against a tool behaving correctly. The kernel rows
        # are scored against sysctl rather than against a reported finding at
        # all, so this loop would find nothing to count for them and read that
        # emptiness as a broken filter. Their controls are
        # run_firewall_preapply_control and run_kernel_preapply_control, which
        # ask whether the property under test was already true before the apply.
        # services is skipped for the same reason and carries
        # run_services_preapply_control: this loop would count zero compared
        # directives for it and read that emptiness as a broken filter, failing
        # a plugin that had behaved correctly.
        #
        # audit is the fourth of exactly the same kind and was missed when it
        # joined the compared set: its rows are scored against what augenrules
        # compiled rather than against a reported finding, so this loop finds
        # nothing to count and fails a plugin that behaved correctly. Its own
        # control is run_audit_preapply_control.
        #
        # mac is the fifth, and it is the clearest case of all: on a kernel with
        # no MAC system the plugin correctly reports NOTHING, so a control built
        # on counting its findings would fail it for behaving exactly as
        # required. Its own control is run_mac_preapply_control, which asks the
        # kernel rather than the tool.
        case "$plugin" in
            firewall-hardening|kernel-hardening|audit-hardening|mac-hardening|"$SERVICES_PLUGIN_ID") continue ;;
        esac
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

# Findings the hardening is EXPECTED to introduce, and the reason each one is
# correct: "<plugin id>|<finding id>|<why it is right>".
#
# The obvious rule, "hardening introduces no new finding", is false, and a check
# asserting it would fail a tool behaving exactly as designed. Measured
# 2026-07-31 against the arch and debian containers this suite had just
# hardened: the firewall plugin runs first and enables ufw, ufw applies its own
# sysctl file when its unit starts, that unit is ordered AFTER systemd-sysctl,
# and the file sets log_martians to 0 against the tool's target of 1. So the
# parameter genuinely stops surviving a reboot and the tool is right to report
# it, only after the apply. The three firewalld distributions reported none of
# this.
#
# Which makes this a registry rather than a prohibition. An introduced finding
# passes when it is declared here with a written reason and fails naming itself
# when it is not, so the decision gets forced at the moment the finding first
# appears rather than the day it misleads someone. Same shape, and the same
# reason, as scripts/validate/validate_write_sites.py.
#
# Matched on the whole id, never on a prefix. `kernel_boot_override_` reads as
# one mechanism but covers every parameter that mechanism ever reaches,
# including ones nobody has looked at, and a bare `kernel_` would cover the
# plugin. What is being declared is a decision about one finding, and a pattern
# written before the decision cannot carry it.
INTRODUCED_FINDING_ALLOWANCES=(
    "kernel-hardening|kernel_boot_override_net_ipv4_conf_all_log_martians|ufw's sysctl file sets this to 0 and ufw.service is ordered after systemd-sysctl, so once the firewall plugin enables ufw the parameter stops surviving a reboot; measured 2026-07-31 on arch and debian, current 0 against a want of 1"
    "kernel-hardening|kernel_boot_override_net_ipv4_conf_default_log_martians|the default scope of the same ufw file, introduced by the same enable and measured beside it on the same two containers"
)

# Every finding id one plugin reported in one of the two scan documents, sorted
# and one per line.
#
# Prints nothing for a plugin that reported no finding, which is what a hardened
# host looks like, and returns non-zero when the document holds no readable
# findings array for it at all. Both print nothing and only one of them is a
# reading: an absent plugin object would otherwise contribute an empty set, an
# empty set introduces nothing, and nothing introduced is the pass condition of
# every row below.
#
# has_scan_array is what draws that line, and it is reused rather than restated:
# it already requires exactly one object for the plugin and a findings key that
# is genuinely an array.
#
# An entry whose finding_id is not a string is dropped rather than printed as
# jq's `null`. A renamed key then empties BOTH sides at once, which introduces
# nothing and resolves nothing, and the control below is what turns that into a
# red row.
scan_finding_ids() {
    local document="$1" plugin="$2"
    has_scan_array "$document" "$plugin" findings || return 1
    jq -r --arg p "$plugin" \
        '.[] | select(.plugin_id == $p) | .findings[]
             | select((.finding_id | type) == "string") | .finding_id' \
        <<<"$document" | sort -u
}

# The ids in $2 that $1 does not hold, one per line. One function for both
# directions: introduced is "after minus before" and resolved is "before minus
# after", and writing the difference twice is how the two come to disagree.
#
# Both arguments arrive as the lists scan_finding_ids prints, where an empty
# list means an empty set. A here-string built from an empty variable still
# carries one blank line, so both loops skip blanks rather than treating that
# line as an id.
ids_absent_from() {
    local held="$1" candidates="$2" id
    local -A seen=()
    while IFS= read -r id; do
        if [[ -n "$id" ]]; then
            seen["$id"]=1
        fi
    done <<<"$held"
    while IFS= read -r id; do
        if [[ -n "$id" && -z "${seen[$id]:-}" ]]; then
            printf '%s\n' "$id"
        fi
    done <<<"$candidates"
}

# The declared reason for one introduced finding, non-zero when no entry
# declares it. Keyed on the plugin AND the id together, so an id declared under
# one plugin does not excuse the same id appearing under another.
introduced_finding_reason() {
    local plugin="$1" id="$2" entry entry_plugin entry_id reason
    for entry in "${INTRODUCED_FINDING_ALLOWANCES[@]}"; do
        IFS='|' read -r entry_plugin entry_id reason <<<"$entry"
        if [[ "$entry_plugin" == "$plugin" && "$entry_id" == "$id" ]]; then
            printf '%s' "$reason"
            return 0
        fi
    done
    return 1
}

# One row per compared plugin: is every finding the apply introduced declared?
#
# Both documents are captured on every run and, until this existed, only parts
# of each were ever interrogated: the finding-id comparisons cover ssh, pam and
# permissions directives, and nothing asked either document anything about
# firewall or kernel ids. 373dd7c added a kernel finding that appears only after
# apply, a full run passed 75/75, and the run said nothing whatever about the
# commit it was run for.
#
# The freshness of both documents is not re-checked here. Every ssh, pam and
# permissions row above reads SCAN_JSON through require_fresh_capture and
# run_preapply_control reads PRE_APPLY_SCAN_JSON through
# require_preapply_capture, so a stale stamp on either has already gone red
# nineteen times over before this block runs.
#
# One thing a reader meeting a red permissions row should check first, and it is
# unmeasured rather than expected: scan_oracle_init runs BELOW the two inits that
# create and remove the probe account, so the post-apply document describes
# /etc/passwd and /etc/shadow as useradd and userdel left them. That ordering is
# deliberate and permissions_oracle_init is taken above them for exactly this
# reason, but nothing has yet measured whether it can introduce a finding of its
# own. If it can, the honest repair is the capture order, not an entry here.
run_introduced_finding_checks() {
    local plugin before after id reason declared undeclared
    for plugin in "${DIFF_PLUGINS[@]}"; do
        if ! before="$(scan_finding_ids "$PRE_APPLY_SCAN_JSON" "$plugin")"; then
            record_fail "introduced findings $plugin: the pre-apply scan document holds no readable findings array for the plugin, so nothing here can say which of its findings are new"
            continue
        fi
        if ! after="$(scan_finding_ids "$SCAN_JSON" "$plugin")"; then
            record_fail "introduced findings $plugin: the post-apply scan document holds no readable findings array for the plugin, so nothing here can say which of its findings are new"
            continue
        fi
        declared=""
        undeclared=""
        while IFS= read -r id; do
            [[ -n "$id" ]] || continue
            if reason="$(introduced_finding_reason "$plugin" "$id")"; then
                declared+="${declared:+; }$id ($reason)"
            else
                undeclared+="${undeclared:+, }$id"
            fi
        done < <(ids_absent_from "$before" "$after")
        if [[ -n "$undeclared" ]]; then
            record_fail "introduced findings $plugin: the apply introduced finding(s) no INTRODUCED_FINDING_ALLOWANCES entry declares: $undeclared. Hardening a host can correctly introduce a finding, so this is a decision and not yet a defect: measure what the tool is reporting, then either fix the tool or declare the id beside the reason it is right."
        elif [[ -n "$declared" ]]; then
            record_pass "introduced findings $plugin: every finding the apply introduced is declared: $declared"
        else
            record_pass "introduced findings $plugin: the apply introduced no finding the plugin was not already reporting"
        fi
    done
}

# The control over the comparison those rows are read through, and it is the
# half that discriminates on every distribution.
#
# Each row above passes when nothing was introduced, and nothing is what an
# empty set introduces: a renamed finding_id key, a plugin_id the document no
# longer carries, and a capture that never happened all produce five quiet
# passes. So this asks the opposite question. At least one finding the tool
# reported BEFORE the apply must be absent AFTER it, because hardening fixes
# things on all five containers. Nothing resolved means the two documents are
# the same one, or the extraction reads nothing, or the apply did nothing, and
# all three have to be red.
#
# Coverage is reported alongside, naming the side a plugin was missing from: a
# document that never carried the plugin and one whose capture failed are fixed
# in different places. Both sides are asked of every plugin before the skip, so
# a plugin missing from both is named twice rather than once.
#
# One pass over the plugins rather than a coverage loop and a counting loop.
# Read twice, the second loop's assignments would be safe only because the first
# had already returned, and under `set -euo pipefail` a reader that failed there
# would end the run with no summary at all instead of recording a red row.
run_introduced_finding_control() {
    local plugin gaps="" before after id names resolved="" total=0 readable
    for plugin in "${DIFF_PLUGINS[@]}"; do
        readable=1
        if ! before="$(scan_finding_ids "$PRE_APPLY_SCAN_JSON" "$plugin")"; then
            gaps+="${gaps:+, }$plugin is missing from the pre-apply scan document"
            readable=0
        fi
        if ! after="$(scan_finding_ids "$SCAN_JSON" "$plugin")"; then
            gaps+="${gaps:+, }$plugin is missing from the post-apply scan document"
            readable=0
        fi
        (( readable == 1 )) || continue
        names=""
        while IFS= read -r id; do
            [[ -n "$id" ]] || continue
            total=$((total + 1))
            names+="${names:+, }$id"
        done < <(ids_absent_from "$after" "$before")
        if [[ -n "$names" ]]; then
            resolved+="${resolved:+; }$plugin resolved $names"
        fi
    done
    if [[ -n "$gaps" ]]; then
        record_fail "introduced findings control: the two documents do not cover all ${#DIFF_PLUGINS[@]} compared plugins, so a row above can pass on a set that was empty because nothing was read: $gaps"
        return 0
    fi
    if (( total == 0 )); then
        record_fail "introduced findings control: not one finding the tool reported before apply is absent after it, on a container this run has hardened twice; either the two documents are the same one, or the id extraction reads nothing, or the apply did nothing, and every row above passes on all three"
        return 0
    fi
    record_pass "introduced findings control: the apply resolved $total finding(s), so the comparison the rows above are read through is live: $resolved"
}

# The positive control for the seeded pair, and the only thing that separates
# "the tool left the seed alone" from "the seed never landed and the tool set
# its own target, which happens to be what we are reading".
#
# It is the seed itself rather than a separate probe, which is what makes it
# unable to pass by matching nothing: the values asserted here exist only
# because the write took effect, and a run where it did not reads sshd's
# default and fails loudly instead of quietly agreeing with itself.
run_seeded_checks() {
    local entry directive seed before
    for entry in "${SEEDED_SSH_CHECKS[@]}"; do
        IFS='|' read -r directive seed _ <<<"$entry"
        if ! before="$(seeded_baseline_value "$directive")"; then
            record_fail "seeded $directive: the pre-apply reading could not be taken, so nothing shows the seed took effect and the post-apply check below proves nothing"
            continue
        fi
        if [[ "$before" == "$seed" ]]; then
            record_pass "seeded $directive: before apply sshd enforced '$before', stricter than the tool's own target, so the check below is asking a real question"
        else
            record_fail "seeded $directive: before apply sshd enforced '$before' but the seed wrote '$seed'; the seed did not take effect, so the post-apply reading would agree with the tool by accident"
        fi
    done
    # No silent caps: these two directives buy the no-loosen check by giving up
    # the "arrived unset, the tool set it" coverage, which the other five keep.
    echo "  note| ${#SEEDED_SSH_CHECKS[@]} of ${#SSH_CHECKS[@]} ssh directives are seeded stricter than the baseline and no longer cover the unset path"
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
            "$(ssh_finding_id "$directive")" exact
    done
}

run_login_defs_checks() {
    local entry directive target system
    for entry in "${LOGIN_DEFS_CHECKS[@]}"; do
        # Four names for four columns. `read` gives the last name every field
        # that is left, so a three-name unpack would have read the target as
        # "90|5" the moment the passwd -S column was added.
        IFS='|' read -r directive _ target _ <<<"$entry"
        # Two rows, matching record_unresolved's shape for the same reason: a
        # directive costs two assertions either way, so the totals stay
        # comparable between a host that could be asked and one that could not.
        if [[ "$directive" == "$MIN_DAYS_DIRECTIVE" && "$SHADOW_MIN_DAYS" != "1" ]]; then
            record_unaskable "pam-hardening $directive: this host's shadow has no minimum-password-age field, so no account can carry the value and there is nothing to compare"
            record_unaskable "pam-hardening $directive: the tool's verdict is not compared either, because there is no system value to hold it to"
            continue
        fi
        if ! system="$(login_defs_system_value "$directive")"; then
            record_unresolved pam-hardening "$directive" "shadow reported no value for the probe account"
            continue
        fi
        compare_directive pam-hardening "$directive" "$system" "$target" \
            "$(pam_finding_id "$directive")" exact
    done
}

# One check per unmanaged setting: it holds what it held before apply.
#
# A reading that could not be taken on either side is a failure, never a skip,
# and costs that setting its single check. Recording exactly one either way
# keeps the totals comparable between a run where the probe answered and one
# where it did not.
run_vendor_survival_checks() {
    local key before after
    for key in "${VENDOR_SURVIVAL_CHECKS[@]}"; do
        if ! before="$(vendor_survival_baseline_value "$key")"; then
            record_fail "vendor survival $key: the value before apply could not be read, so nothing can be shown to have survived"
            continue
        fi
        if ! after="$(vendor_survival_system_value "$key")"; then
            record_fail "vendor survival $key: the value after apply could not be read"
            continue
        fi
        if vendor_survival_agrees "$before" "$after"; then
            record_pass "vendor survival $key: still '$after', the value the system held before apply"
        else
            record_fail "vendor survival $key: was '$before' before apply and is '$after' now; this tool does not manage $key, so the change is damage whatever the new value is"
        fi
    done
}

# One check per reading: the second apply left it exactly as the first one did.
#
# A reading that cannot be taken on either side is a failure, never a skip, and
# costs that key its single check, so the totals stay comparable between a run
# where every reading answered and one where some did not.
run_idempotence_checks() {
    local key before after
    for key in "${IDEMPOTENCE_CHECKS[@]}"; do
        if ! before="$(idempotence_baseline "$key")"; then
            record_fail "idempotency $key: the reading taken after the first apply could not be used, so nothing can be shown to be unchanged"
            continue
        fi
        if ! after="$(idempotence_reading "$key")"; then
            record_fail "idempotency $key: the reading after the second apply could not be taken"
            continue
        fi
        if [[ "$before" == "$after" ]]; then
            record_pass "idempotency $key: the second apply left this exactly as the first one did"
        else
            record_fail "idempotency $key: this reading moved between the two applies, so applying on a cadence does not hold the host where one apply put it"
            idempotence_report_difference "$key" "$before" "$after"
        fi
    done
}

# The preview an operator approves, and the apply that follows it.
#
# Uniquely in this file the subject is the tool's own output, on both sides,
# and that is not the shortcut it looks like. Everywhere else reading the tool
# back is the defect this suite exists to catch: the reader and the writer
# agree with each other and disagree with Linux. Here the property IS that the
# tool's two accounts of itself agree, and no reading of the host can supply
# it, because a preview describes a future and leaves nothing behind to
# measure. 420a52b fixed exactly this shape of defect, a firewall dry run that
# did not preview the boot enable its apply then made, and only the mock tests
# noticed: no container run asked the question at all.
PRE_APPLY_DRY_RUN_JSON=""

# The display names the apply's own output names plugins by. `apply` renders
# its per-plugin line from metadata.plugin_name and never from the plugin id
# (apply_results in crates/hardener-cli/src/output.rs), so the two have to be
# joined somewhere. Asked of the tool rather than written out by hand here: a
# hand-written pair that drifted from what the tool prints would take the join
# with it, and a join that matches nothing is this suite's pass condition.
DIFF_PLUGIN_NAMES=""

# The output of the FIRST apply, which is the only one the preview above
# describes. run_full_suite applies twice; the second runs on a host the first
# has already hardened and reports applying almost nothing, so a global that
# followed the latest apply would leave every row below passing for free.
FIRST_APPLY_OUTPUT=""

# That choice is a function of its own rather than three lines inside
# apply_hardening, which shells out and so cannot be driven by --self-test.
# Keeping the first apply's output rather than the latest is the difference
# between this oracle asking a question and asking none, which is not a
# property to leave unasserted.
retain_first_apply_output() {
    if (( APPLY_GENERATION == 1 )); then
        FIRST_APPLY_OUTPUT="$1"
    fi
}

# Both halves of the join, captured while the container is still unhardened.
#
# The dry run has to be taken before the apply for the same reason as every
# other pre-apply capture: taken afterwards it would preview a host that is
# already hardened and agree with itself.
#
# Its exit status is deliberately not a refusal, unlike capture_scan_json's.
# Measured against this tree's binary at 420a52b, when the compared set held
# five plugins rather than today's six: `--format json apply
# --dry-run` over that set exits 1 on an ordinary host,
# because the pam plugin reports a blocking validation issue, and the document
# is printed all the same (output::validation_reports runs ahead of the bail).
# A capture that refused on non-zero would refuse most runs.
preapply_preview_init() {
    local args=() plugin out status=0
    if (( APPLY_GENERATION != 0 )); then
        echo "FATAL: the pre-apply dry run was asked for at generation" \
            "$APPLY_GENERATION, after apply had run." >&2
        echo "  It is the preview the checks below hold the apply to, so it has to be" >&2
        echo "  taken while the container is still unhardened." >&2
        return 1
    fi
    if ! out="$("$BINARY" --format json plugins)"; then
        echo "FATAL: plugins --format json failed, so the apply's output cannot be joined" >&2
        return 1
    fi
    if ! DIFF_PLUGIN_NAMES="$(jq -r '.[] | "\(.plugin_id)|\(.plugin_name)"' <<<"$out")"; then
        echo "FATAL: the tool's plugin listing could not be read as JSON" >&2
        return 1
    fi
    for plugin in "${DIFF_PLUGINS[@]}"; do
        # Refused here rather than left to the control below, because the two
        # faults send a reader to different files: a name the tool never
        # supplied is a listing that has changed, while a name that supplied no
        # line is an apply that did not run the plugin.
        if ! apply_plugin_display_name "$plugin" >/dev/null; then
            echo "FATAL: the tool's plugin listing does not name '$plugin'." >&2
            echo "  Its apply output is read by that name, and a name nothing supplies" >&2
            echo "  matches no line, which is this suite's pass condition." >&2
            return 1
        fi
        # The same --plugin list apply_hardening builds, so the preview and the
        # run cover the same set by construction rather than by two lists
        # agreeing.
        args+=(--plugin "$plugin")
    done
    out="$("$BINARY" --format json apply --dry-run "${args[@]}")" || status=$?
    echo "dry run exit status $status (non-zero is expected when a plugin reports a blocking validation issue)"
    PRE_APPLY_DRY_RUN_JSON="$out"
}

# What the preview said about one plugin: "<estimated changes>|<issues>".
# Non-zero when the document holds no report this can read for it.
#
# The two counts stay apart rather than summed. A plugin that previewed a
# limitation instead of a change has spoken, and the row below must not call
# that silence: measured against this tree's binary at 420a52b, the firewall
# plugin's dry run on an ordinary host reports 0 estimated changes and 1 issue.
#
# Both keys are required to be arrays rather than defaulted, for the reason
# every filter in this file is: `length` counts an absent or retyped key as 0,
# "0|0" is this file's word for a preview that said nothing, and a preview that
# said nothing is what every row below passes on.
dry_run_preview_reading() {
    local plugin="$1" out
    if ! out="$(jq -r --arg p "$plugin" \
        '[.[] | select(.validation_report_plugin_id == $p)
              | select((.validation_report_estimated_changes | type) == "array"
                       and (.validation_report_issues | type) == "array")
              | "\(.validation_report_estimated_changes | length)|\(.validation_report_issues | length)"]
         | first // empty' <<<"$PRE_APPLY_DRY_RUN_JSON")"; then
        return 1
    fi
    [[ -n "$out" ]] || return 1
    printf '%s' "$out"
}

# The name the apply's output names one plugin by, non-zero when the tool's own
# listing does not cover it. Non-zero rather than an empty name for the reason
# firewall_boot_word_before is: an empty name would match the space in every
# line of the output.
apply_plugin_display_name() {
    local plugin="$1" pair
    while IFS= read -r pair; do
        if [[ "${pair%%|*}" == "$plugin" ]]; then
            printf '%s' "${pair#*|}"
            return 0
        fi
    done <<<"$DIFF_PLUGIN_NAMES"
    return 1
}

# How many changes the apply reported APPLYING for one plugin. Non-zero when no
# count could be read at all, which covers an output holding no result line for
# the plugin and a line carrying an error message where the summary would be.
#
# Fail-closed on that second shape rather than reading it as 0: output.rs
# prints `{icon} {name} - {err}` for a plugin that carries an apply_error AND
# recorded no change at all, and that branch prints no count whatever, so
# calling it 0 would guess in the one direction that passes the row below. The
# firewall plugin's "No firewall backend" is that shape.
#
# A plugin that failed part way now prints `{summary}: {err}`, which the
# counting pattern below reads as any other summary. It did not always: the
# error alone replaced the whole phrase, and the first container run of the
# audit oracle failed on all six distributions because the audit plugin writes
# its rules file, fails the reload under nspawn, and had its count discarded.
# That was an operator-facing loss before it was an oracle's, and the fix is in
# output.rs rather than in a wider pattern here.
apply_applied_count() {
    local plugin="$1" name line summary
    name="$(apply_plugin_display_name "$plugin")" || return 1
    # Matched inside the line rather than from its start. The icon ahead of the
    # name is what this would have to anchor on, and the icon is colour-escaped
    # whenever the `colored` crate decides it is writing to a terminal, which
    # is a property of the process rather than of this file.
    line="$(grep -m1 -F -- " $name - " <<<"$FIRST_APPLY_OUTPUT")" || return 1
    summary="${line#*" $name - "}"
    case "$summary" in
        "no changes needed"*)
            printf '0'
            ;;
        # Both counting wordings apply_summary builds: "N change(s) applied[, M
        # skipped]" and "N of M change(s) applied, K failed[, M skipped]". The
        # leading number counts successes alone in both, which is what makes one
        # pattern enough for the pair.
        [0-9]*" change(s) applied"*)
            printf '%s' "${summary%%" "*}"
            ;;
        *)
            return 1
            ;;
    esac
}

# One row per compared plugin: did the apply apply changes the preview never
# mentioned?
#
# Only that direction. The reverse, a preview naming work the apply then did
# not do, is not a failure here: a plugin can fail partway on a container and
# several do, so making that red would fail correct runs. The direction kept is
# the one with no confound and the one that costs an operator something. The
# preview is what they approve, and a run longer than its preview applied
# something nobody was shown.
#
# Silence is "no estimated changes AND no issues". A plugin that previewed a
# limitation rather than a change has told the operator something, so what it
# then applies is not unannounced.
run_preview_agreement_checks() {
    local plugin reading changes issues applied
    for plugin in "${DIFF_PLUGINS[@]}"; do
        if ! reading="$(dry_run_preview_reading "$plugin")"; then
            record_fail "preview agreement $plugin: the dry run's document holds no report this can read for the plugin, so there is no preview to hold its apply to"
            continue
        fi
        IFS='|' read -r changes issues <<<"$reading"
        if ! applied="$(apply_applied_count "$plugin")"; then
            record_fail "preview agreement $plugin: the apply's output yields no applied-change count for the plugin, so what it did cannot be compared with what was previewed"
            continue
        fi
        if (( changes > 0 || issues > 0 )); then
            record_pass "preview agreement $plugin: the preview named $changes estimated change(s) and $issues issue(s), so the apply's $applied applied change(s) followed something the operator was shown"
        elif (( applied == 0 )); then
            record_pass "preview agreement $plugin: the preview was silent and the apply applied nothing, so nothing here was approved unseen"
        else
            record_fail "preview agreement $plugin: the preview named no estimated change and no issue, and the apply then reported $applied applied change(s); the operator approved a preview shorter than the run"
        fi
    done
}

# The control over both parses, and it is not optional.
#
# Every row above passes when the preview said nothing to contradict, and a
# filter that matches nothing says nothing: a mistyped key, a renamed plugin
# id, a display name the apply prints differently, each of them produces five
# quiet passes over a tool nobody checked. So both sides are required to have
# answered for EVERY compared plugin rather than for at least one, and the
# refusal names the plugin and the side it was missing from, because a reading
# the preview never carried and a reading the apply never printed are fixed in
# different places.
run_preview_agreement_control() {
    local plugin gaps=""
    for plugin in "${DIFF_PLUGINS[@]}"; do
        dry_run_preview_reading "$plugin" >/dev/null \
            || gaps+="${gaps:+, }$plugin is missing from the dry run's document"
    done
    for plugin in "${DIFF_PLUGINS[@]}"; do
        apply_applied_count "$plugin" >/dev/null \
            || gaps+="${gaps:+, }$plugin is missing from the apply's output"
    done
    if [[ -n "$gaps" ]]; then
        record_fail "preview agreement control: the two readings do not cover all ${#DIFF_PLUGINS[@]} compared plugins, so a row above can pass on a parse that matched nothing: $gaps"
        return 0
    fi
    record_pass "preview agreement control: the dry run's document and the apply's output both answered for all ${#DIFF_PLUGINS[@]} compared plugins, so no row above passed on an empty reading"
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
    # Kept for the preview comparison above, and only from the first apply: the
    # preview it is held against was taken before this one, and the second runs
    # on a host this one has already hardened.
    retain_first_apply_output "$out"
    echo "apply exit status $status (non-zero is expected when a plugin reports a manual action)"
    # Prefixed, so no line of the tool's own output can be mistaken for one of
    # this suite's summary counters by whatever parses the log.
    while IFS= read -r line; do
        printf '  apply| %s\n' "$line"
    done <<<"$out"
}

# The run's own summary. The four labels match full-test-suite.sh so the
# host-side runner parses this log with the machinery it already has. Skipped
# stays 0: a check that could not be DETERMINED is recorded as a failure, which
# is the whole point. A check the fixture cannot be ASKED is a different thing,
# declared in advance, and it is reported on its own line below rather than
# folded into any of the four.
print_summary() {
    local expected
    expected="$(expected_check_total)"
    echo ""
    echo "  Total Tests:  $CHECKS_TOTAL"
    echo "  Passed:       $CHECKS_PASSED"
    echo "  Failed:       $CHECKS_FAILED"
    echo "  Skipped:      0"
    if (( CHECKS_UNASKABLE > 0 )); then
        echo "  Unaskable:    $CHECKS_UNASKABLE (declared above, not asked on this fixture)"
    fi
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
        echo "the value the system holds and the value this run requires."
        return 1
    fi
    echo "The system agrees with what the tool reported."
}

self_test() {
    local failures=0
    # The mode this function runs in is PINNED rather than inherited.
    #
    # Every scan fixture below carries five plugin objects, and
    # validate_scan_document requires each compared plugin to appear in the
    # document, so a booted load would fail these assertions on their
    # fixtures instead of on any behaviour. Each assertion that cares about
    # the mode sets it for the one call it makes, which is how both arms get
    # exercised from either environment. Measured: without this,
    # `HARDENER_DIFF_BOOTED=1 --self-test` reported ten failures, none of
    # which was about the code under test.
    #
    # Both signals, since #137 split them. Pinning only one would leave the
    # other inherited, which is the whole of what this paragraph refuses.
    RUN_NETNS=0
    RUN_BOOTED=0
    DIFF_PLUGINS=("${DIFF_PLUGINS_BASE[@]}")
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

    # The passwd -S reader, which exists because one supported distribution's
    # shadow cannot report the minimum at all. Arch builds chage without the
    # field: `chage -l` prints no 'Minimum number of days' line, `chage --help`
    # offers no -m, and `strings` finds the word nowhere in the binary. That
    # rules out a translated label and a privilege difference alike, so no way
    # of invoking chage there can answer PASS_MIN_DAYS. passwd -S reports the
    # same /etc/shadow row and does carry the field, on shadow 4.20.0.arch1-1
    # as elsewhere.
    #
    # The field count is asserted rather than assumed. passwd(1) documents
    # exactly seven fields, and the only one that could ever gain a space is the
    # date, which shadow has printed both as 2024-12-24 and as 12/24/2024. A
    # reader that indexed blindly would answer a spacey date with the neighbour
    # of the field it was asked for, and a wrong value that looks like a reading
    # is the one failure this suite must never produce.
    local passwd_status_fixture="hardenerdiffprobe P 2024-12-24 5 42 11 -1"
    check_eq "$(extract_passwd_status_value "$passwd_status_fixture" 4)" "5" "passwd -S min"
    check_eq "$(extract_passwd_status_value "$passwd_status_fixture" 5)" "42" "passwd -S max"
    check_eq "$(extract_passwd_status_value "$passwd_status_fixture" 6)" "11" "passwd -S warn"
    check_status 1 "a passwd -S line of the wrong width is refused rather than indexed" \
        extract_passwd_status_value "hardenerdiffprobe P Dec 24, 2024 5 42 11 -1" 4
    check_status 1 "a truncated passwd -S line returns non-zero" \
        extract_passwd_status_value "hardenerdiffprobe P" 4
    check_status 1 "empty passwd -S output returns non-zero" \
        extract_passwd_status_value "" 4

    # The subscript itself, which is the sharper hazard of the two. A row that
    # lost its fourth column hands this an empty string, and an empty subscript
    # is arithmetic 0, which bash reads as -1 and answers from the END of the
    # line. Unchecked, that returns the inactivity period as though it were the
    # directive's value.
    check_eq "$(extract_passwd_status_value "$passwd_status_fixture" "" 2>/dev/null)" "" \
        "an absent field index yields no value, rather than the last field counted backwards"
    check_status 1 "an absent field index is refused" \
        extract_passwd_status_value "$passwd_status_fixture" ""
    check_status 1 "a non-numeric field index is refused rather than read as zero" \
        extract_passwd_status_value "$passwd_status_fixture" "min"
    check_status 1 "a field index past the seven documented fields is refused" \
        extract_passwd_status_value "$passwd_status_fixture" 8

    # The banner that lets a log name the binary that produced it. All three
    # branches, because the dangerous one is the quiet one: a --version that
    # fails, or that succeeds while printing nothing, must not reach the log as
    # an empty string beside a path that looks authoritative.
    check_eq "$(binary_version "$(command -v bash)")" "$(bash --version | head -1)" \
        "a multi-line --version is reduced to its first line"
    check_eq "$(binary_version /nonexistent/hardener | cut -d' ' -f1)" "UNAVAILABLE" \
        "a binary that cannot be run is named, not blank"

    # A stub rather than a temporary file, because /tmp is mounted noexec often
    # enough that writing one there would make this assertion the flakiest in
    # the suite. Invoked once directly as well: a static analyser cannot follow
    # a function name passed as an argument, so without this the stub reads as
    # dead code, exactly as the comment further down describes.
    silent_binary() { :; }
    silent_binary
    check_eq "$(binary_version silent_binary | cut -d' ' -f1)" "UNAVAILABLE" \
        "a binary that prints no version is named, not blank"

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

    # The rollback-reload check (Task 7, issue #67). What is proven first is
    # that its two recording functions actually distinguish agreement from
    # disagreement, because a check that always passes is the exact defect
    # this repository keeps finding in this file; the gate around them is
    # driven at the end of the block, over stubs.
    local rr_fixture="PermitRootLogin no
PasswordAuthentication yes
X11Forwarding no"
    check_eq "$(rollback_reload_snapshot "$rr_fixture")" \
        "PermitRootLogin=no PasswordAuthentication=yes" \
        "rollback_reload_snapshot joins both watched directives into one string"
    check_status 1 "rollback_reload_snapshot fails when a watched directive is absent" \
        rollback_reload_snapshot "PermitRootLogin no"

    # rollback_reload_capture's own plumbing: ensure_host_keys and
    # capture_sshd_effective stubbed the same way ssh_oracle_init's proof
    # above stubs them, so this runs with no root and no container.
    local rr_capture="$rr_fixture"
    ensure_host_keys() { :; }
    capture_sshd_effective() { printf '%s' "$rr_capture"; }
    check_eq "$(rollback_reload_capture)" "PermitRootLogin=no PasswordAuthentication=yes" \
        "rollback_reload_capture joins ensure_host_keys and capture_sshd_effective through the snapshot"
    capture_sshd_effective() { return 1; }
    check_status 1 "rollback_reload_capture fails when sshd -T itself fails" \
        rollback_reload_capture
    unset -f ensure_host_keys capture_sshd_effective

    # rollback_reload_assert_changed and rollback_reload_assert_restored both
    # call record_pass/record_fail directly, like compare_directive above, so
    # they are proven the same way: the delta in the three counters around one
    # call, with the totals restored immediately after so this proof cannot
    # move the run's own count.
    local rr_before_total=$CHECKS_TOTAL rr_before_passed=$CHECKS_PASSED rr_before_failed=$CHECKS_FAILED

    rollback_reload_assert_changed "PermitRootLogin=yes PasswordAuthentication=yes" \
        "PermitRootLogin=no PasswordAuthentication=no" >/dev/null
    check_eq "$((CHECKS_TOTAL - rr_before_total))" "1" \
        "the positive control contributes exactly one check"
    check_eq "$((CHECKS_PASSED - rr_before_passed))" "1" \
        "and passes when the apply moved sshd's answer away from the baseline"
    CHECKS_TOTAL=$rr_before_total CHECKS_PASSED=$rr_before_passed CHECKS_FAILED=$rr_before_failed

    rollback_reload_assert_changed "PermitRootLogin=no PasswordAuthentication=no" \
        "PermitRootLogin=no PasswordAuthentication=no" >/dev/null
    check_eq "$((CHECKS_FAILED - rr_before_failed))" "1" \
        "the positive control fails when apply left sshd's answer exactly where it started, which would let the restoration check below pass by accident"
    CHECKS_TOTAL=$rr_before_total CHECKS_PASSED=$rr_before_passed CHECKS_FAILED=$rr_before_failed

    # The case Task 7 asks for by name: a recorded baseline and a
    # post-rollback reading that disagree must fail this check. A rollback
    # that silently restored files sshd was never told to re-read would
    # otherwise report success here, which is the shipped defect issue #67
    # describes, so a section that cannot fail this way is not proving
    # anything.
    rollback_reload_assert_restored "PermitRootLogin=yes PasswordAuthentication=yes" \
        "PermitRootLogin=no PasswordAuthentication=no" >/dev/null
    check_eq "$((CHECKS_FAILED - rr_before_failed))" "1" \
        "a post-rollback reading that disagrees with the pre-apply baseline fails the restoration check"
    check_eq "$((CHECKS_PASSED - rr_before_passed))" "0" \
        "and records no pass alongside that failure"
    CHECKS_TOTAL=$rr_before_total CHECKS_PASSED=$rr_before_passed CHECKS_FAILED=$rr_before_failed

    rollback_reload_assert_restored "PermitRootLogin=yes PasswordAuthentication=yes" \
        "PermitRootLogin=yes PasswordAuthentication=yes" >/dev/null
    check_eq "$((CHECKS_PASSED - rr_before_passed))" "1" \
        "and passes when the post-rollback reading matches the pre-apply baseline"
    check_eq "$((CHECKS_FAILED - rr_before_failed))" "0" \
        "with no failure recorded alongside that pass"
    CHECKS_TOTAL=$rr_before_total CHECKS_PASSED=$rr_before_passed CHECKS_FAILED=$rr_before_failed

    # The gate around the cycle, driven whole. sshd -T and $BINARY are stubbed,
    # the same way ssh_oracle_init's proof above stubs its capture, so the real
    # orchestrator runs here with no root, no container and no tool.
    #
    # What this pins is the bookkeeping the cycle cannot be trusted without.
    # The cycle applies, so it bumps APPLY_GENERATION, and everything below it
    # in run_full_suite requires that counter to read 0: without the hand-back
    # seed_stricter_than_baseline refuses outright and the whole run reports no
    # checks at all, which is what happened on all five distributions the first
    # time this section shipped. Without the refusal to hand it back on
    # failure, a container left hardened by a rollback that never reached sshd
    # would be measured by every check below as though it were pristine.
    local rr_readings rr_saved_binary rr_rollback_reaches_sshd=1
    rr_readings="$(mktemp)"
    ensure_host_keys() { :; }
    # The reading index advances through a file rather than a variable: every
    # caller reads this through a command substitution, and a counter bumped
    # inside that subshell would be back to its old value by the next reading.
    capture_sshd_effective() {
        local nth
        nth="$(cat "$rr_readings")"
        printf '%s' "$((nth + 1))" >"$rr_readings"
        # Reading 0 is the pre-apply baseline, 1 is post-apply and 2 is
        # post-rollback: hardened at 1 always, and back at the baseline at 2
        # only when the rollback is meant to have reached the daemon.
        if (( nth == 1 || (nth == 2 && rr_rollback_reaches_sshd == 0) )); then
            printf 'PermitRootLogin no\nPasswordAuthentication no\n'
        else
            printf 'PermitRootLogin prohibit-password\nPasswordAuthentication yes\n'
        fi
    }
    # One checkpoint row under the name the cycle looks for, and nothing else to
    # do: what a real apply and rollback would have moved is exactly what the
    # stubbed readings above describe.
    rr_stub_binary() {
        if [[ "$1" == "--format" ]]; then
            printf '[{"checkpoint_name":"ssh-hardening-pre-apply","checkpoint_id":"cp-1"}]'
        fi
    }
    rr_saved_binary="$BINARY"
    BINARY=rr_stub_binary

    printf '0' >"$rr_readings"
    APPLY_GENERATION=0
    check_status 0 "run_rollback_reload_check succeeds when sshd is back at its pre-apply answer" \
        run_rollback_reload_check
    check_eq "$APPLY_GENERATION" "0" \
        "and hands the apply generation back, because its own passing assertion is that the container is standing where it started"
    check_eq "$((CHECKS_PASSED - rr_before_passed))" "2" \
        "recording its two checks, both passed"
    CHECKS_TOTAL=$rr_before_total CHECKS_PASSED=$rr_before_passed CHECKS_FAILED=$rr_before_failed

    printf '0' >"$rr_readings"
    rr_rollback_reaches_sshd=0
    APPLY_GENERATION=0
    check_status 1 "run_rollback_reload_check ends the run when sshd still enforces the hardening after rollback" \
        run_rollback_reload_check
    check_eq "$APPLY_GENERATION" "1" \
        "and keeps the generation it bumped, so nothing below it can read a hardened container as a pristine one"
    check_eq "$((CHECKS_FAILED - rr_before_failed))" "1" \
        "with the restoration assertion recorded as that failure"
    CHECKS_TOTAL=$rr_before_total CHECKS_PASSED=$rr_before_passed CHECKS_FAILED=$rr_before_failed

    BINARY="$rr_saved_binary"
    APPLY_GENERATION=0
    rm -f "$rr_readings"
    unset -f ensure_host_keys capture_sshd_effective rr_stub_binary

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

    # The Arch reading, where chage reports no minimum and the second reader has
    # to answer for that directive alone. The passwd -S fixture disagrees with
    # the chage one on max and warn on purpose: a fallback that had quietly
    # started answering every directive would read 99 and 88 here, and a fixture
    # that agreed with chage could not tell the two readers apart.
    local archless_fixture="Last password change					: Dec 24, 2024
Maximum number of days between password change		: 42
Number of days of warning before password expires	: 11"
    LOGIN_DEFS_CHAGE="$archless_fixture"
    LOGIN_DEFS_PASSWD_STATUS="hardenerdiffprobe P 2024-12-24 5 99 88 -1"
    check_eq "$(login_defs_system_value PASS_MIN_DAYS)" "5" \
        "a chage that reports no minimum falls back to passwd -S"
    check_eq "$(login_defs_system_value PASS_MAX_DAYS)" "42" \
        "a directive chage does report is still read from chage"
    check_eq "$(login_defs_system_value PASS_WARN_AGE)" "11" \
        "and so is the warn age, which passwd -S could also have answered"

    # Neither reader has it, which is the case the FATAL exists for. The message
    # has to carry the output it rejected: the arch run that raised this said
    # only that the label was missing, so the log could not say what chage had
    # actually printed and the cause needed a container to find.
    LOGIN_DEFS_PASSWD_STATUS=""
    check_status 1 "a directive neither reader reports returns non-zero" \
        login_defs_system_value PASS_MIN_DAYS
    local unreadable_message
    unreadable_message="$(login_defs_system_value PASS_MIN_DAYS 2>&1 >/dev/null)" || true
    check_eq "$(grep -c 'Maximum number of days between password change' <<<"$unreadable_message")" "1" \
        "the message carries the output it could not parse"

    # The runner unpacks this table positionally, so its unpack and the table's
    # width have to move together: a three-name unpack against four columns
    # reads PASS_MAX_DAYS' target as "90|5", because `read` gives the last name
    # everything that is left. Driven through the runner rather than asserted
    # off the table, because the defect lives in the runner's own line and a
    # test that unpacked the row itself would only be pinning its own arithmetic.
    #
    # The absence claim is worth nothing without the positive one beside it, so
    # both are made: the run must produce a row for the directive at all, and
    # that row must not carry the fourth column. The scan document is deliberately
    # absent here, which costs each directive its second assertion and changes
    # nothing about the first.
    # No counters are saved around this: the runner is driven inside a command
    # substitution, so record_pass and record_fail increment in a subshell and
    # the totals here never move. Restoring them would be restoring nothing.
    local ld_runner_output
    LOGIN_DEFS_CHAGE="Last password change					: Dec 24, 2024
Minimum number of days between password change		: 1
Maximum number of days between password change		: 90
Number of days of warning before password expires	: 7"
    LOGIN_DEFS_CHAGE_GENERATION="$APPLY_GENERATION"
    LOGIN_DEFS_PASSWD_STATUS=""
    ld_runner_output="$(run_login_defs_checks)"
    check_eq "$(grep -c "PASS_MAX_DAYS: the system holds '90'" <<<"$ld_runner_output")" "1" \
        "the login.defs runner records a row for the directive it read"
    check_eq "$(grep -c '90|5' <<<"$ld_runner_output")" "0" \
        "and reads its target without the passwd -S column glued on"

    LOGIN_DEFS_CHAGE=""
    LOGIN_DEFS_PASSWD_STATUS=""
    LOGIN_DEFS_CHAGE_GENERATION=""

    # The probe creates a real account, so its two safety properties are pinned
    # here rather than only by hand: it never deletes a user it did not create,
    # and it never leaves one behind. useradd, userdel, chage and id are stubbed
    # against a variable standing in for the account database, which keeps
    # --self-test runnable with no root and no container.
    # Field 4 is 3, which appears in neither chage fixture, so a PASS_MIN_DAYS
    # of 3 can only have come from the second reader.
    local probe_passwd_fixture="hardenerdiffprobe P 2024-12-24 3 42 11 -1"
    local probe_restore_fixture="$probe_fixture"
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
    # Stubbed for the same reason chage is, and its absence hid a defect: with
    # the real binary reached instead, `passwd -S` failed against an account
    # that does not exist, the capture came back empty, and the assertions below
    # could not tell that apart from a capture that never propagated. It also
    # made --self-test, documented as safe anywhere, shell out to the setuid
    # passwd on a maintainer's own machine.
    passwd() { printf '%s\n' "$probe_passwd_fixture"; }

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

    # BOTH readings have to survive the call, and this is the assertion the
    # first version of the fallback did not have. The capture was being made
    # inside a function every caller invoked as `$(...)`, so it was published
    # into a subshell and the parent kept an empty string: on Arch, the only
    # host that needs the second reader, the fallback could never fire and the
    # run stayed exactly as broken as before. Everything else was green,
    # because every other assertion planted the globals by hand.
    check_eq "$LOGIN_DEFS_PASSWD_STATUS" "$probe_passwd_fixture" \
        "the probe's passwd -S reading survives the call that took it"
    # And the whole Arch path, end to end through the probe rather than planted:
    # a chage that reports no minimum, and a value that can only have come from
    # the second reader.
    probe_fixture="$archless_fixture"
    init_status=0
    login_defs_oracle_init || init_status=$?
    check_eq "$init_status" "0" "the oracle initialises against a chage with no minimum"
    check_eq "$(login_defs_system_value PASS_MIN_DAYS)" "3" \
        "and PASS_MIN_DAYS is answered from the probe's own passwd -S reading"
    probe_fixture="$probe_restore_fixture"
    login_defs_oracle_init || true

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
    unset -f useradd userdel id chage passwd

    # The vendor survival family. Its whole job is to notice a value changing,
    # so the assertions that matter are the ones where something changed and
    # the ones where a reading could not be taken at all.
    #
    # The scheme extraction first. A yescrypt field and a sha512 field must
    # yield different answers, or a comparison between them would agree; and a
    # field that carries no password at all must be refused, because "!" is
    # stable across an apply and would otherwise pass as a setting that
    # survived while proving nothing.
    # Named once, because every one of them is a literal crypt string that must
    # reach the function exactly as written.
    # shellcheck disable=SC2016  # crypt prefixes are data, not expressions
    local scheme_yescrypt='$y$' scheme_sha512='$6$' scheme_bcrypt='$2b$' \
        field_yescrypt='$y$j9T$LdI4nQ7$3xKq' field_sha512='$6$rounds=5000$abc$def' \
        field_bcrypt='$2b$10$abcdef' field_locked_hash='!$6$abc$def'

    check_eq "$(shadow_hash_scheme "$field_yescrypt")" "$scheme_yescrypt" \
        "yescrypt reads as its own scheme"
    check_eq "$(shadow_hash_scheme "$field_sha512")" "$scheme_sha512" \
        "sha512 reads as its own scheme"
    check_eq "$(shadow_hash_scheme "$field_bcrypt")" "$scheme_bcrypt" \
        "bcrypt reads as its own scheme"
    check_eq "$(shadow_hash_scheme 'K3vY8qP1sT.xU')" "descrypt" \
        "a field with no scheme prefix is legacy descrypt, not an absent value"
    check_status 1 "an empty shadow field is refused" shadow_hash_scheme ""
    check_status 1 "a locked account is refused rather than read" shadow_hash_scheme "!"
    check_status 1 "an account with no password is refused" shadow_hash_scheme "*"
    check_status 1 "a locked account that keeps its hash is still refused" \
        shadow_hash_scheme "$field_locked_hash"

    # The account row reader, against a file rather than the real /etc. The
    # decoy row is an account whose name starts with the probe's: a prefix
    # match would read its fields and report another account's settings as the
    # probe's, and both of its fields are values the assertions would notice.
    local account_root="${TMPDIR:-/tmp}/diffsuite-accounts-$$"
    mkdir -p "$account_root"
    printf '%s\n' \
        "root:x:0:0:root:/root:/bin/bash" \
        "${DIFF_PROBE_USER}extra:x:1001:1001::/home/decoy:/bin/sh" \
        "${DIFF_PROBE_USER}:x:1002:1002::/home/${DIFF_PROBE_USER}:/bin/sh" \
        >"$account_root/passwd"
    check_eq "$(probe_account_field "$account_root/passwd" 6)" "/home/$DIFF_PROBE_USER" \
        "the account reader takes the probe's own row, not one that merely starts the same"
    check_eq "$(probe_account_field "$account_root/passwd" 1)" "$DIFF_PROBE_USER" \
        "the account reader counts fields from one"
    printf '%s\n' "root:!:20000:0:99999:7:::" >"$account_root/noprobe"
    check_status 1 "a file with no row for the probe account returns non-zero" \
        probe_account_field "$account_root/noprobe" 2
    rm -rf "$account_root"

    # The capture is written in the KEY value shape sshd -T prints, so the ssh
    # extractor reads it. Pinned here so that reuse cannot quietly stop being
    # true: a capture format that drifted would leave every reading absent, and
    # an absent reading on both sides of the comparison is two silences
    # agreeing.
    local survival_fixture
    survival_fixture="$(printf 'ENCRYPT_METHOD %s\nHOME_MODE 750\nUMASK 0027\n' "$scheme_yescrypt")"
    check_eq "$(vendor_survival_reading "$survival_fixture" HOME_MODE)" "750" \
        "a vendor survival reading is read out of the capture by key"
    check_eq "$(vendor_survival_reading "$survival_fixture" ENCRYPT_METHOD)" "$scheme_yescrypt" \
        "a reading whose value looks like a shell variable survives the capture"
    check_status 1 "a key absent from the capture returns non-zero" \
        vendor_survival_reading "$survival_fixture" NO_SUCH_KEY
    check_status 1 "a key present with no value returns non-zero" \
        vendor_survival_reading "$(printf 'HOME_MODE \n')" HOME_MODE

    # The comparison itself, in every direction. The third is the defect this
    # family exists to catch: a setting the tool does not manage holding a
    # different value after the run than before it.
    check_status 0 "an unchanged value agrees" vendor_survival_agrees 750 750
    check_status 1 "a changed value does not agree" vendor_survival_agrees 750 700
    check_status 1 "a missing before value does not agree" vendor_survival_agrees "" 750
    check_status 1 "a missing after value does not agree" vendor_survival_agrees 750 ""

    # The two freshness rules, which are mirror images: the after capture is
    # refused unless it followed the last apply, the before capture unless it
    # predates every apply.
    APPLY_GENERATION=0
    VENDOR_SURVIVAL_AFTER=""
    VENDOR_SURVIVAL_AFTER_GENERATION=""
    VENDOR_SURVIVAL_BEFORE=""
    VENDOR_SURVIVAL_BEFORE_GENERATION=""
    check_status 1 "uninitialised vendor survival oracle returns non-zero" \
        vendor_survival_system_value HOME_MODE
    check_status 1 "uninitialised vendor survival baseline returns non-zero" \
        vendor_survival_baseline_value HOME_MODE

    VENDOR_SURVIVAL_BEFORE="$survival_fixture"
    VENDOR_SURVIVAL_BEFORE_GENERATION=0
    check_eq "$(vendor_survival_baseline_value UMASK)" "0027" \
        "a baseline stamped before any apply reads"
    VENDOR_SURVIVAL_AFTER="$survival_fixture"
    VENDOR_SURVIVAL_AFTER_GENERATION=0
    check_status 1 "a vendor survival capture with no apply recorded returns non-zero" \
        vendor_survival_system_value UMASK
    bump_apply_generation
    check_status 1 "a vendor survival capture older than the last apply returns non-zero" \
        vendor_survival_system_value UMASK
    VENDOR_SURVIVAL_AFTER_GENERATION="$APPLY_GENERATION"
    check_eq "$(vendor_survival_system_value UMASK)" "0027" \
        "a capture taken after apply reads"
    VENDOR_SURVIVAL_BEFORE_GENERATION="$APPLY_GENERATION"
    check_status 1 "a baseline stamped after an apply returns non-zero" \
        vendor_survival_baseline_value UMASK
    VENDOR_SURVIVAL_BEFORE_GENERATION=0

    # The checks as the run records them. One per setting whatever happens, and
    # a damaged setting must cost a failure rather than a silence.
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_vendor_survival_checks >/dev/null
    check_eq "$((CHECKS_TOTAL - before_total))" "3" \
        "the vendor survival family records one check per setting"
    check_eq "$((CHECKS_PASSED - before_passed))" "3" \
        "settings that survived the run pass"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    VENDOR_SURVIVAL_AFTER="$(printf 'ENCRYPT_METHOD %s\nHOME_MODE 750\nUMASK 0027\n' "$scheme_sha512")"
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_vendor_survival_checks >/dev/null
    check_eq "$((CHECKS_FAILED - before_failed))" "1" \
        "a setting the run changed fails its check"
    check_eq "$((CHECKS_PASSED - before_passed))" "2" \
        "the settings that did survive still pass"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    # A reading missing from the after capture is a failure, not a skip, and
    # not a pass by comparison with a silence.
    VENDOR_SURVIVAL_AFTER="$(printf 'HOME_MODE 750\nUMASK 0027\n')"
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_vendor_survival_checks >/dev/null
    check_eq "$((CHECKS_FAILED - before_failed))" "1" \
        "a reading that could not be taken fails its check"
    check_eq "$((CHECKS_TOTAL - before_total))" "3" \
        "a failed reading still costs exactly one check"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    APPLY_GENERATION=0
    VENDOR_SURVIVAL_AFTER=""
    VENDOR_SURVIVAL_AFTER_GENERATION=""
    VENDOR_SURVIVAL_BEFORE=""
    VENDOR_SURVIVAL_BEFORE_GENERATION=""

    # An unaskable row is reported and counted, and it must NOT move the
    # pass/fail arithmetic: the host-side runner parses those three numbers and
    # a declared gap is not a check that ran.
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    before_unaskable=$CHECKS_UNASKABLE
    record_unaskable "self-test: a row the fixture cannot answer" >/dev/null
    check_eq "$((CHECKS_UNASKABLE - before_unaskable))" "1" \
        "an unaskable row increments its own counter"
    check_eq "$((CHECKS_TOTAL - before_total))" "0" \
        "an unaskable row does not count as a check that ran"
    check_eq "$((CHECKS_PASSED - before_passed))" "0" \
        "an unaskable row is not a pass"
    check_eq "$((CHECKS_FAILED - before_failed))" "0" \
        "an unaskable row is not a failure"
    CHECKS_UNASKABLE=$before_unaskable

    # The probe's two safety properties, the same pair the login.defs probe has
    # and for the same reason: it creates a real account. The account database
    # stubs from that block are gone by here, so they are rebuilt around the
    # readings, which are stubbed as a unit because chpasswd, su and stat all
    # want a real account to talk about.
    local survival_stub_exists=0 survival_stub_readings=0
    useradd() { survival_stub_exists=1; }
    userdel() { survival_stub_exists=0; }
    id() { [[ "$survival_stub_exists" == 1 ]]; }
    vendor_survival_probe_readings() {
        if (( survival_stub_readings != 0 )); then
            return "$survival_stub_readings"
        fi
        printf '%s' "$survival_fixture"
    }

    survival_stub_exists=1
    check_status 1 "the survival probe refuses when the probe user already exists" \
        vendor_survival_values
    check_eq "$survival_stub_exists" "1" "the survival probe leaves a pre-existing user alone"

    survival_stub_exists=0
    survival_stub_readings=1
    check_status 1 "the survival probe returns non-zero when a reading fails" \
        vendor_survival_values
    check_eq "$survival_stub_exists" "0" "the survival probe removes the user after a failed reading"

    survival_stub_readings=0
    check_eq "$(vendor_survival_values)" "$survival_fixture" \
        "the survival probe prints its readings on the success path"
    check_eq "$survival_stub_exists" "0" "the survival probe removes the user on the success path"

    # The before capture is taken above apply, and refused below it.
    APPLY_GENERATION=0
    init_status=0
    preapply_vendor_survival_init || init_status=$?
    check_eq "$init_status" "0" "preapply_vendor_survival_init succeeds before any apply"
    check_eq "$(vendor_survival_baseline_value HOME_MODE)" "750" \
        "the baseline capture feeds the accessor"
    bump_apply_generation
    init_status=0
    preapply_vendor_survival_init || init_status=$?
    check_eq "$init_status" "1" \
        "preapply_vendor_survival_init refuses to capture once apply has run"
    init_status=0
    vendor_survival_oracle_init || init_status=$?
    check_eq "$init_status" "0" "vendor_survival_oracle_init captures after apply"
    check_eq "$(vendor_survival_system_value HOME_MODE)" "750" \
        "the after capture feeds the accessor"

    APPLY_GENERATION=0
    VENDOR_SURVIVAL_AFTER=""
    VENDOR_SURVIVAL_AFTER_GENERATION=""
    VENDOR_SURVIVAL_BEFORE=""
    VENDOR_SURVIVAL_BEFORE_GENERATION=""
    unset -f useradd userdel id vendor_survival_probe_readings

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
    check_eq "${#VENDOR_SURVIVAL_CHECKS[@]}" "3" "the vendor survival table holds three settings"
    check_eq "${#IDEMPOTENCE_CHECKS[@]}" "4" "the idempotency table holds four readings"
    check_eq "${IDEMPOTENCE_CHECKS[0]}" "permission-modes" \
        "the permission reading is taken first, ahead of the probe account login-defs creates"
    check_eq "${#DIFF_PLUGINS[@]}" "7" "seven plugins are compared"
    check_eq "${#SEEDED_SSH_CHECKS[@]}" "2" "the seeded table holds two directives"
    check_eq "${#PERMISSION_CHECKS[@]}" "9" "the permissions table holds nine paths"
    check_eq "${#KERNEL_CHECKS[@]}" "11" \
        "the kernel table holds every net.ipv4 parameter the plugin manages"
    check_eq "${#KERNEL_UNASKABLE[@]}" "7" \
        "and names every parameter a container cannot be asked about"
    check_eq "$(printf '%s\n' "${KERNEL_CHECKS[@]}" | grep -c '^net\.ipv4\.')" "11" \
        "every askable kernel row is a net.ipv4 parameter, which is the only family a container namespace exposes"
    check_eq "$(printf '%s\n' "${KERNEL_UNASKABLE[@]}" | grep -cE '^(kernel|fs)\.')" "7" \
        "and every unaskable row is a kernel. or fs. parameter"

    # The comparison each kernel row is scored by, in all three of its
    # directions.
    check_eq "$(kernel_satisfies 1 1 at-least && echo yes || echo no)" "yes" \
        "an at-least parameter is satisfied by its target"
    check_eq "$(kernel_satisfies 2 1 at-least && echo yes || echo no)" "yes" \
        "and by a stricter value, which is the whole reason the comparison has a direction"
    check_eq "$(kernel_satisfies 0 1 at-least && echo yes || echo no)" "no" \
        "and not by a looser one"
    check_eq "$(kernel_satisfies 0 0 at-most && echo yes || echo no)" "yes" \
        "an at-most parameter is satisfied by its target"
    check_eq "$(kernel_satisfies 1 0 at-most && echo yes || echo no)" "no" \
        "and not by a looser one"
    check_eq "$(kernel_satisfies 0 1 at-most && echo yes || echo no)" "yes" \
        "an at-most parameter is satisfied by a stricter value, which is what makes at-most a direction and not an equality in disguise"
    # The ranked rows are what prove a direction cannot be arithmetic at all.
    # rp_filter's strictness is not its integer order: 0 is off, 2 is loose mode
    # and 1 is strict mode, so at-least would score loose mode 2 as satisfying a
    # target of strict mode 1, and at-most would score it the wrong way round on
    # the other pair. Only a listed value space places these readings correctly.
    check_eq "$(kernel_satisfies 2 1 ranked:0,2,1 && echo yes || echo no)" "no" \
        "a ranked value below the target does not satisfy it"
    check_eq "$(kernel_satisfies 1 2 ranked:0,2,1 && echo yes || echo no)" "yes" \
        "and rp_filter 1 satisfies a target of 2 because it ranks above it"
    check_eq "$(kernel_satisfies 3 1 ranked:0,2,1 && echo yes || echo no)" "no" \
        "a reading outside the declared value space satisfies nothing, because a value that cannot be placed is not evidence of compliance"
    check_eq "$(kernel_satisfies 1 3 ranked:0,2,1 && echo yes || echo no)" "no" \
        "and a target outside it satisfies nothing either, so a mistyped table row goes red rather than scoring every reading green forever"
    check_eq "$(kernel_satisfies unreadable 1 at-least && echo yes || echo no)" "no" \
        "an unreadable value satisfies nothing: discovered at runtime is a failure, never a declared gap"
    check_eq "$(kernel_reading net.ipv4.no_such_parameter_at_all)" "unreadable" \
        "a parameter the kernel does not have reads as a token the comparison rejects, not as an empty string"
    sysctl() { printf '4096\t131072\t33554432\n'; }
    check_eq "$(kernel_reading net.ipv4.tcp_rmem)" "unreadable" \
        "a multi-value parameter is unreadable, not a plausible integer assembled by deleting its separators"
    sysctl() { printf '  1  \n'; }
    check_eq "$(kernel_reading net.ipv4.conf.all.rp_filter)" "1" \
        "and a scalar arriving with surrounding whitespace is trimmed to the value itself"
    unset -f sysctl

    # No namespace of its own is not a failure and not a pass: the fixture
    # cannot be asked.
    before_unaskable=$CHECKS_UNASKABLE
    before_total=$CHECKS_TOTAL
    RUN_NETNS=0 run_kernel_checks >/dev/null
    check_eq "$((CHECKS_UNASKABLE - before_unaskable))" "18" \
        "a run without its own network namespace declares all 18 kernel parameters unaskable, the 11 for the mode and the 7 for the mount"
    check_eq "$((CHECKS_TOTAL - before_total))" "0" \
        "and records no checks at all, so the total the tables ask for still adds up"
    CHECKS_UNASKABLE=$before_unaskable

    # The booted branch, which is the entire oracle, driven here without root
    # and without a container. Asserting that an unbooted run makes no claim is
    # not the same as asserting a booted one makes the right one, and only the
    # branch below is what a real run scores.
    #
    # sysctl is stubbed rather than kernel_reading, so the reader under test
    # stays in the path and the `unreadable` token is produced by the failure it
    # really comes from rather than injected past it.
    #
    # The reading is chosen from the row being asked, because no constant is
    # compliant in every direction: an at-least row wants its target, an at-most
    # row wants its target too but is violated upward, and rp_filter's ranked
    # space is violated by 2, which is loose mode and ranks BELOW strict mode 1.
    local kernel_stub_mode=compliant
    sysctl() {
        local wanted="${2:-}" entry name target direction
        for entry in "${KERNEL_CHECKS[@]}"; do
            IFS='|' read -r name target direction <<<"$entry"
            [[ "$name" == "$wanted" ]] || continue
            case "$kernel_stub_mode:$direction" in
                unreadable:*) return 1 ;;
                compliant:ranked:*) printf '1\n' ;;
                violating:ranked:*) printf '2\n' ;;
                compliant:*) printf '%s\n' "$target" ;;
                violating:at-least) printf '%s\n' "$((target - 1))" ;;
                violating:at-most) printf '%s\n' "$((target + 1))" ;;
                *) return 1 ;;
            esac
            return 0
        done
        return 1
    }

    local kernel_saved_total=$CHECKS_TOTAL kernel_saved_passed=$CHECKS_PASSED
    local kernel_saved_failed=$CHECKS_FAILED kernel_saved_unaskable=$CHECKS_UNASKABLE
    local kernel_saved_before="$KERNEL_BEFORE"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    kernel_stub_mode=compliant
    RUN_NETNS=1 run_kernel_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "11/0" \
        "a booted run whose every parameter meets its target records one pass per askable row"
    check_eq "$CHECKS_UNASKABLE" "7" \
        "and still declares the 7 rows the mount puts out of reach, because being booted does not make /proc/sys writable"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    kernel_stub_mode=violating
    RUN_NETNS=1 run_kernel_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/11" \
        "a parameter the kernel enforces against its own direction fails, on every row"

    # The undeterminable-is-a-failure rule, holding inside the oracle itself.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    kernel_stub_mode=unreadable
    local kernel_unreadable_out
    kernel_unreadable_out="$(mktemp)"
    RUN_NETNS=1 run_kernel_checks > "$kernel_unreadable_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/11" \
        "a parameter that cannot be read is a failure, never an unaskable row: unaskability is declared in advance and this was discovered at runtime"
    check_status 0 "and it fails with its own message rather than the one about a value that disagrees" \
        grep -q "sysctl could not be read" "$kernel_unreadable_out"
    rm -f "$kernel_unreadable_out"

    # The pre-apply control. Doing nothing must never exit 0, so a container
    # that already met every target before the apply has to fail it.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    kernel_stub_mode=compliant
    RUN_NETNS=1 preapply_kernel_init
    check_eq "$(grep -c '=' <<<"$KERNEL_BEFORE")" "11" \
        "the pre-apply capture holds one reading per askable parameter"
    RUN_NETNS=1 run_kernel_preapply_control >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a container already at every kernel target before apply fails the control, because the checks below would then pass without the tool having done anything"

    # One parameter away from target used to be enough to make the checks below
    # a real question, and since #47 it is not. tcp_syncookies is the one row
    # this suite does not loosen, so a capture away on that row alone describes
    # a host where all ten seeded parameters came back at their targets, and
    # ten of the eleven checks below would pass whether or not the tool ran.
    # The count in the message is proven to be counted rather than to be the
    # table's length by the looser-seed block further down, which reaches the
    # pass this case no longer can.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    KERNEL_BEFORE="${KERNEL_BEFORE/net.ipv4.tcp_syncookies=1/net.ipv4.tcp_syncookies=0}"
    local kernel_control_out
    kernel_control_out="$(mktemp)"
    RUN_NETNS=1 run_kernel_preapply_control > "$kernel_control_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a container away only on the row this suite does not seed fails the control, because every row it does seed came back at its target"
    check_status 0 "and it fails for that reason rather than for the empty-count one, which is the older rule and would be the wrong diagnosis" \
        grep -q "the pre-apply capture finds it already at its target" "$kernel_control_out"
    rm -f "$kernel_control_out"

    # A capture missing a row the table declares. Before this was guarded the
    # grep below failed, `set -euo pipefail` ended the self-test from the
    # assignment, and the run exited 1 having printed nothing: a status where a
    # failure should have been. It is a failure rather than a parameter counted
    # away, because no reading was taken for it at all.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    local kernel_torn_out kernel_torn_before
    kernel_torn_before="$KERNEL_BEFORE"
    # Guarded, and then checked, for the reason the case itself exists: `grep
    # -v` exits 1 when it emits no lines, so the assignment that arranges a
    # torn capture could end the run from an assignment. The guard alone would
    # be worse than the abort, because an empty capture is missing every row
    # and the assertion below would still pass, for a reason that has nothing
    # to do with what it claims. The count says which of the two happened.
    KERNEL_BEFORE="$(grep -v "^net.ipv4.tcp_syncookies=" <<<"$KERNEL_BEFORE" || true)"
    check_eq "$(grep -c '=' <<<"$KERNEL_BEFORE")" "10" \
        "the torn capture holds every declared parameter but the one removed, so an empty capture cannot stand in for it"
    kernel_torn_out="$(mktemp)"
    RUN_NETNS=1 run_kernel_preapply_control > "$kernel_torn_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a pre-apply capture missing a row the kernel table declares fails the control rather than ending the run from an assignment"
    check_status 0 "and the failure names the parameter the capture had no reading for, which an abort could never have said" \
        grep -q "holds no reading for net.ipv4.tcp_syncookies" "$kernel_torn_out"
    rm -f "$kernel_torn_out"
    KERNEL_BEFORE="$kernel_torn_before"

    unset -f sysctl
    CHECKS_TOTAL=$kernel_saved_total
    CHECKS_PASSED=$kernel_saved_passed
    CHECKS_FAILED=$kernel_saved_failed
    CHECKS_UNASKABLE=$kernel_saved_unaskable
    KERNEL_BEFORE="$kernel_saved_before"

    # The seeded kernel row. Every other kernel row can only prove the tool
    # hardened a host that was below its target; this one is the only one that
    # can prove it declined to un-harden a host that was already above it.
    local seeded_kernel_name seeded_kernel_seed seeded_kernel_target
    local seeded_kernel_direction
    IFS='|' read -r seeded_kernel_name seeded_kernel_seed seeded_kernel_target \
        <<<"${SEEDED_KERNEL_CHECKS[0]}"
    seeded_kernel_direction="$(printf '%s\n' "${KERNEL_CHECKS[@]}" \
        | grep -m1 "^$seeded_kernel_name|" | cut -d'|' -f3 || true)"
    check_eq "$seeded_kernel_direction" "at-least" \
        "the seeded parameter is a row of the kernel table and carries the direction that scores it, so the seed cannot be written into a parameter nothing checks"
    # tcp_syncookies 2 sends SYN cookies unconditionally rather than only under
    # pressure, which is not weaker than the tool's target of 1. The plugin
    # clamps its own target up to what the host already runs, so a correct apply
    # leaves the seed standing in the runtime and in the persistent file.
    check_eq "$(kernel_satisfies "$seeded_kernel_seed" "$seeded_kernel_target" "$seeded_kernel_direction" && echo yes || echo no)" "yes" \
        "the seeded value satisfies the tool's own target in that row's direction, so a correct apply has nothing to write and the seed survives it"
    check_eq "$(kernel_satisfies "$seeded_kernel_target" "$seeded_kernel_seed" "$seeded_kernel_direction" && echo yes || echo no)" "no" \
        "and the tool's own target does NOT satisfy the seed, which is the property that makes this row catch a loosening rather than restate the seed"
    check_eq "${SEEDED_KERNEL_CHECKS_EXPECTED}" "1" \
        "one seeded kernel row, pinned like every other table"

    # And the row's discrimination, driven without root and without a container.
    # A seeded row that only ever reads its seed proves nothing: these three
    # readings are what separate "the tool left the seed alone" from "the tool
    # wrote its own target over it" and from "nothing could be read at all".
    local seeded_kernel_stub=seed seeded_kernel_out
    sysctl() {
        case "$seeded_kernel_stub" in
            seed) printf '%s\n' "$seeded_kernel_seed" ;;
            target) printf '%s\n' "$seeded_kernel_target" ;;
            *) return 1 ;;
        esac
    }

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    RUN_NETNS=1 run_seeded_kernel_check >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "a host still reading the seed after apply passes the seeded row"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    seeded_kernel_stub=target
    seeded_kernel_out="$(mktemp)"
    RUN_NETNS=1 run_seeded_kernel_check > "$seeded_kernel_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a host reading the tool's own target instead fails it, which is the loosening this row exists to catch and the one an equality oracle would score green"
    check_status 0 "and it says the apply loosened the parameter, rather than reporting a value that merely disagrees" \
        grep -q "LOOSENED" "$seeded_kernel_out"
    rm -f "$seeded_kernel_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    seeded_kernel_stub=unreadable
    RUN_NETNS=1 run_seeded_kernel_check >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "and a reading that could not be taken at all is a failure too, never a declared gap"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    RUN_NETNS=0 run_seeded_kernel_check >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/0/1" \
        "a run without its own network namespace declares the seeded row unaskable and records no check, so that mode's total is unmoved by it"

    unset -f sysctl
    CHECKS_TOTAL=$kernel_saved_total
    CHECKS_PASSED=$kernel_saved_passed
    CHECKS_FAILED=$kernel_saved_failed
    CHECKS_UNASKABLE=$kernel_saved_unaskable

    # The looser kernel seed, which is what lets the pre-apply control above be
    # satisfied on a container that arrives already at every target. The RHEL
    # container is that container, and the control was correctly refusing to
    # certify checks that would have passed whether or not the tool ran.
    local looser_saved_netns="$RUN_NETNS"
    local le le_name le_seed le_target le_direction
    local looser_unlisted="" looser_satisfied="" looser_collides=""
    for le in "${SEEDED_LOOSER_KERNEL_CHECKS[@]}"; do
        IFS='|' read -r le_name le_seed le_target <<<"$le"
        # `|| true` so that a seeded parameter absent from KERNEL_CHECKS is
        # REPORTED. Without it the empty grep fails the pipeline, `set -euo
        # pipefail` aborts the self-test from an assignment, and the run ends on
        # exit 1 having printed no failure at all. The assertions below are the
        # evidence; an abort is only a status.
        le_direction="$(printf '%s\n' "${KERNEL_CHECKS[@]}" \
            | grep -m1 "^$le_name|" | cut -d'|' -f3 || true)"
        if [[ -z "$le_direction" ]]; then
            looser_unlisted+="${looser_unlisted:+, }$le_name"
        fi
        if kernel_satisfies "$le_seed" "$le_target" "$le_direction"; then
            looser_satisfied+="${looser_satisfied:+, }$le_name"
        fi
        if printf '%s\n' "${SEEDED_KERNEL_CHECKS[@]}" | grep -q "^$le_name|"; then
            looser_collides+="${looser_collides:+, }$le_name"
        fi
    done
    # Named rather than counted, in all three, because a count cannot say which
    # row broke the property and every one of these is a table-authoring
    # mistake somebody has to find in a diff.
    check_eq "$looser_unlisted" "" \
        "every loosened parameter is a row of the kernel table and carries the direction that scores it, so no seed can be written into a parameter the control never counts"
    check_eq "$looser_satisfied" "" \
        "and no seeded value satisfies its own row's target, which is the whole point: a seed the target already satisfied would leave that row as vacuous as it was unseeded"
    # The two seed tables ask opposite questions of the same host, so one
    # parameter cannot serve both: a row seeded stricter and then looser would
    # arrive at whichever write landed second, and the check that lost would be
    # scoring the other one's seed.
    check_eq "$looser_collides" "" \
        "and no parameter is seeded in both directions"
    check_eq "${SEEDED_LOOSER_KERNEL_CHECKS_EXPECTED}" "10" \
        "ten loosened kernel rows, pinned like every other table"
    # The anti-vacuity property itself, and the reason it is arithmetic rather
    # than a literal: every askable row is seeded away from its target by one
    # table or the other, so a row added to KERNEL_CHECKS without a seed fails
    # here instead of joining the run as a check that passes on an
    # already-compliant host whether or not the tool ran.
    check_eq "$(( ${#SEEDED_LOOSER_KERNEL_CHECKS[@]} + ${#SEEDED_KERNEL_CHECKS[@]} ))" \
        "${#KERNEL_CHECKS[@]}" \
        "and between the two seed tables every askable kernel row arrives away from its target"

    # The seed itself, driven with no root and no writable /proc/sys. The
    # read-back is the assertion that matters: unlike the stricter seed this one
    # has no check of its own after apply, so a write the kernel accepted and
    # then ignored would leave the control measuring what the container shipped
    # while the log said a seed had been placed.
    # The read-back is per parameter rather than one value for the whole table,
    # so a seed loop that wrote every row and then read only the first cannot
    # pass this. `target` is the mode that stands for "the kernel ignored the
    # write", because the target is what the container was already holding.
    local looser_written="" looser_readback=seed looser_expected=""
    sysctl() {
        if [[ "$1" == "-w" ]]; then
            looser_written+="${looser_written:+ }$2"
            return 0
        fi
        local wanted="${2:-}" entry name seed target
        for entry in "${SEEDED_LOOSER_KERNEL_CHECKS[@]}"; do
            IFS='|' read -r name seed target <<<"$entry"
            [[ "$name" == "$wanted" ]] || continue
            case "$looser_readback" in
                seed) printf '%s\n' "$seed" ;;
                *) printf '%s\n' "$target" ;;
            esac
            return 0
        done
        return 1
    }
    for le in "${SEEDED_LOOSER_KERNEL_CHECKS[@]}"; do
        IFS='|' read -r le_name le_seed _ <<<"$le"
        looser_expected+="${looser_expected:+ }$le_name=$le_seed"
    done

    RUN_NETNS=1
    check_status 0 "the looser seed is written on a booted run" \
        seed_kernel_looser_than_baseline
    check_eq "$looser_written" "$looser_expected" \
        "into every parameter the table names, at the value each declares"

    looser_readback=target
    check_status 1 "a seed the kernel did not take is refused rather than believed" \
        seed_kernel_looser_than_baseline
    looser_readback=seed

    bump_apply_generation
    check_status 1 "the looser seed refuses to run after an apply" \
        seed_kernel_looser_than_baseline
    APPLY_GENERATION=0

    looser_written=""
    RUN_NETNS=0
    check_status 0 "an unbooted run is not an error" seed_kernel_looser_than_baseline
    check_eq "$looser_written" "" \
        "and writes no seed, because /proc/sys/net is the host's and read-only there"

    # The control's evidence. Every run now arrives holding ten loosened
    # parameters, so a message that read the same for a seeded row and a
    # naturally away one would let a log claim a container was non-compliant
    # when this suite had made it so.
    local looser_saved_before="$KERNEL_BEFORE" looser_control_out ke ke_name ke_target
    KERNEL_BEFORE=""
    for ke in "${KERNEL_CHECKS[@]}"; do
        IFS='|' read -r ke_name ke_target _ <<<"$ke"
        if kernel_seeded_looser "$ke_name"; then
            KERNEL_BEFORE+="$ke_name=$(kernel_reading "$ke_name")"$'\n'
        else
            KERNEL_BEFORE+="$ke_name=$ke_target"$'\n'
        fi
    done
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    looser_control_out="$(mktemp)"
    RUN_NETNS=1 run_kernel_preapply_control > "$looser_control_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "a container at every target except the seeded ones passes the control, which is the run RHEL could not previously reach"
    check_status 0 "and the pass says which parameters this suite loosened, so the log cannot read as a container that arrived that way" \
        grep -q "seeded by this suite" "$looser_control_out"
    check_status 0 "and it counts the seeded rows rather than the table's length, so a seed that reached nothing cannot read as one that reached everything" \
        grep -q "10 of the 11 managed parameters were away from target" "$looser_control_out"
    rm -f "$looser_control_out"

    # A seeded row the capture finds already at its target. The seed's own
    # read-back cannot see this: it proves what the kernel reported at seed
    # time, and the control scores a capture taken afterwards. Left unchecked
    # the control would still pass on the nine rows that did arrive loosened,
    # while the tenth went into the run as vacuous as it was before #47.
    KERNEL_BEFORE="$(printf '%s\n' "${KERNEL_BEFORE%$'\n'}" \
        | sed 's/^net\.ipv4\.conf\.all\.accept_redirects=.*/net.ipv4.conf.all.accept_redirects=0/')"
    check_eq "$(grep -c '=' <<<"$KERNEL_BEFORE")" "11" \
        "the amended capture still holds one reading per askable parameter, so a capture emptied by the edit cannot stand in for one that disagrees"
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    looser_control_out="$(mktemp)"
    RUN_NETNS=1 run_kernel_preapply_control > "$looser_control_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a capture that finds a seeded parameter already at its target fails the control, because that row would then pass whether or not the tool ran"
    check_status 0 "and the failure names the row, which a count of the ones that did arrive loosened could never have said" \
        grep -q "net.ipv4.conf.all.accept_redirects" "$looser_control_out"
    rm -f "$looser_control_out"

    unset -f sysctl
    KERNEL_BEFORE="$looser_saved_before"
    RUN_NETNS="$looser_saved_netns"
    CHECKS_TOTAL=$kernel_saved_total
    CHECKS_PASSED=$kernel_saved_passed
    CHECKS_FAILED=$kernel_saved_failed
    CHECKS_UNASKABLE=$kernel_saved_unaskable

    # === The shadow minimum-password-age mode (issue #69) ===
    #
    # Arch builds shadow without the field, so PASS_MIN_DAYS can never be
    # carried by an account there and the oracle has nothing to compare. The
    # rows are declared unaskable rather than failed, the way the kernel rows
    # are when /proc/sys is the host's, and the expected total moves with them.
    local md_saved_mode="$SHADOW_MIN_DAYS"
    local md_with="Usage: chage [options] LOGIN
  -m, --mindays MIN_DAYS        set minimum number of days
  -M, --maxdays MAX_DAYS        set maximum number of days"
    local md_without="Usage: chage [options] LOGIN
  -M, --maxdays MAX_DAYS        set maximum number of days
  -W, --warndays WARN_DAYS      set expiration warning days"
    local md_stub="$md_with"
    chage() { printf '%s\n' "$md_stub"; }

    SHADOW_MIN_DAYS=0
    check_status 0 "the shadow probe runs against a usage it can read" detect_shadow_min_days
    check_eq "$SHADOW_MIN_DAYS" "1" "a chage offering --mindays is read as supported"

    md_stub="$md_without"
    detect_shadow_min_days
    check_eq "$SHADOW_MIN_DAYS" "0" "and one that does not is read as unsupported"

    # A usage printed on stderr by a chage that exits non-zero is still a usage.
    md_stub=""
    chage() { printf '%s\n' "$md_with" >&2; return 1; }
    SHADOW_MIN_DAYS=0
    detect_shadow_min_days
    check_eq "$SHADOW_MIN_DAYS" "1" \
        "a usage printed on stderr by a failing chage is still read, because builds differ on both"

    # And a probe that printed nothing is refused, never assumed either way:
    # this decides which totals the run expects.
    chage() { return 1; }
    check_status 1 "a chage that printed nothing is fatal rather than a guess" \
        detect_shadow_min_days
    unset -f chage

    # The totals move with the mode, both arms.
    local md_saved_booted="$RUN_BOOTED" md_saved_netns="$RUN_NETNS"
    local md_saved_mac="$MAC_ASKABLE"
    SHADOW_MIN_DAYS=1
    MAC_ASKABLE=1
    local md_full_booted md_full_unbooted
    md_full_booted="$(RUN_NETNS=1 RUN_BOOTED=1 expected_check_total)"
    md_full_unbooted="$(RUN_NETNS=0 RUN_BOOTED=0 expected_check_total)"
    SHADOW_MIN_DAYS=0
    check_eq "$(RUN_NETNS=1 RUN_BOOTED=1 expected_check_total)" "$(( md_full_booted - 2 ))" \
        "a host without the shadow field asks for two fewer checks when booted"
    check_eq "$(RUN_NETNS=0 RUN_BOOTED=0 expected_check_total)" "$(( md_full_unbooted - 2 ))" \
        "and two fewer when not, because the two modes are independent facts"
    # The third signal, subtracted on top of the second rather than instead of
    # it, which is the property worth asserting: three independent facts about a
    # host, each costing its own rows. A kernel carrying a MAC system gives up
    # the MAC row and the MAC plugin's own pre-apply control together, because
    # one reason disqualifies both.
    MAC_ASKABLE=0
    check_eq "$(RUN_NETNS=1 RUN_BOOTED=1 expected_check_total)" "$(( md_full_booted - 4 ))" \
        "a kernel this no-op oracle does not cover gives up two more, and the shadow subtraction still stands beside it"
    check_eq "$(RUN_NETNS=0 RUN_BOOTED=0 expected_check_total)" "$(( md_full_unbooted - 4 ))" \
        "and the same two when unbooted, because whether a kernel has a MAC system is a fact about the kernel and not about the invocation"
    MAC_ASKABLE="$md_saved_mac"

    # The runner declares them rather than asking. Driven without a command
    # substitution, so the counters it moves are the ones read here.
    local md_before_total=$CHECKS_TOTAL md_before_unaskable=$CHECKS_UNASKABLE
    local md_before_failed=$CHECKS_FAILED md_saved_chage="$LOGIN_DEFS_CHAGE"
    local md_saved_gen="$LOGIN_DEFS_CHAGE_GENERATION"
    LOGIN_DEFS_CHAGE="Maximum number of days between password change		: 90
Number of days of warning before password expires	: 7"
    LOGIN_DEFS_CHAGE_GENERATION="$APPLY_GENERATION"
    LOGIN_DEFS_PASSWD_STATUS=""
    # Redirected to a file rather than captured with $(...): a command
    # substitution would move the counters in a subshell and the deltas read
    # here would all be zero, which is the mistake this suite has made before.
    local md_log
    md_log="$(mktemp)"
    run_login_defs_checks > "$md_log"
    check_eq "$((CHECKS_UNASKABLE - md_before_unaskable))" "2" \
        "an unsupported host declares both PASS_MIN_DAYS rows unaskable"
    # Asserted against the directive by name rather than against the failure
    # count, which the other two directives move for reasons of their own.
    check_eq "$(grep -c "FAIL.*$MIN_DAYS_DIRECTIVE" "$md_log")" "0" \
        "and fails neither of them, because an absent field is a property of the build and not a defect in the host"
    check_eq "$(grep -c "no minimum-password-age field" "$md_log")" "1" \
        "with the reason on the log, so a reader meets it where the row would have been"
    rm -f "$md_log"

    CHECKS_TOTAL=$md_before_total
    CHECKS_UNASKABLE=$md_before_unaskable
    CHECKS_FAILED=$md_before_failed
    LOGIN_DEFS_CHAGE="$md_saved_chage"
    LOGIN_DEFS_CHAGE_GENERATION="$md_saved_gen"
    LOGIN_DEFS_PASSWD_STATUS=""
    RUN_BOOTED="$md_saved_booted"
    RUN_NETNS="$md_saved_netns"
    SHADOW_MIN_DAYS="$md_saved_mode"

    local pinned_total
    # Asked in an explicit mode, both here and below: the totals these
    # assertions pin are properties of the tables, and reading them in
    # whatever mode the environment happened to ask for would make the
    # self-test go red on a maintainer who exported the runner's signal.
    #
    # Both signals named at every call, never one of them. A call that set only
    # the namespace would take the boot from the environment, which is the
    # inheritance the paragraph above refuses.
    #
    # The MAC signal is set here for the same reason, and it is not inherited
    # either: the totals below are properties of the tables, and a maintainer
    # running this on a Fedora laptop whose kernel carries selinux would
    # otherwise read four different numbers than one running it here.
    MAC_ASKABLE=1
    pinned_total="$(RUN_NETNS=0 RUN_BOOTED=0 expected_check_total)"
    check_eq "$pinned_total" "80" \
        "the run is sized at two checks per directive, one per unmanaged setting, one per idempotency reading, one per pwquality enforcement reading, one control per plugin, one preview-agreement row per plugin and its own control, one introduced-finding row per plugin and its own control, plus one pre-apply control per seeded directive, plus the rollback-reload check's own two"
    # The kernel rows against the namespace ALONE, which is the configuration
    # #137 exists for: `--pipe --private-network` holds no systemd and asks
    # every kernel row regardless. Thirteen more than the bare total, and none
    # of them a services row.
    check_eq "$(RUN_NETNS=1 RUN_BOOTED=0 expected_check_total)" "93" \
        "a run holding its own network namespace and no systemd is sized for eleven kernel rows, the seeded kernel row and the kernel plugin's own control, and for no services row at all"
    # The services rows, and the one of them whose askability is a property of
    # the HOST rather than of the invocation. Six more in a booted run: three
    # rows, the plugin's own pre-apply control, and one row in each of the two
    # generic per-plugin blocks, which follow the plugin count.
    local svc_saved_active="$SERVICES_ACTIVE_BEFORE"
    SERVICES_ACTIVE_BEFORE="active"
    check_eq "$(RUN_NETNS=1 RUN_BOOTED=1 expected_check_total)" "99" \
        "a booted run is sized for eleven kernel rows, the seeded kernel row, the kernel plugin's own control, and the six a services plugin with a running unit brings with it"
    SERVICES_ACTIVE_BEFORE="inactive"
    check_eq "$(RUN_NETNS=1 RUN_BOOTED=1 expected_check_total)" "98" \
        "and one fewer where it was never running, because that row is declared unaskable rather than passed"
    check_eq "$(RUN_NETNS=0 RUN_BOOTED=0 expected_check_total)" "$pinned_total" \
        "an unbooted run is unmoved by services entirely, because the plugin is not in the compared set there"
    # The fourth combination, and the only one no runner produces: a boot
    # declared without the namespace. It is asked because the safe direction has
    # to be arithmetic as well as a predicate, and because a future runner that
    # forgets one --setenv lands here rather than on a red total.
    SERVICES_ACTIVE_BEFORE="active"
    check_eq "$(RUN_NETNS=0 RUN_BOOTED=1 expected_check_total)" "86" \
        "a boot declared without the namespace asks for the services rows and for no kernel row, so a missing flag costs coverage rather than producing a total nothing can meet"
    SERVICES_ACTIVE_BEFORE="$svc_saved_active"

    check_status 0 "require_check_tables accepts the tables as they stand" \
        require_check_tables

    local saved_ssh_checks=("${SSH_CHECKS[@]}")
    SSH_CHECKS=("PermitRootLogin|no")
    check_status 1 "require_check_tables refuses a table edited down" require_check_tables
    SSH_CHECKS=("${saved_ssh_checks[@]}")
    # The seeded table is the newest and therefore the one most likely to be
    # edited down by someone who does not know it is counted.
    local saved_seeded=("${SEEDED_SSH_CHECKS[@]}")
    SEEDED_SSH_CHECKS=("MaxAuthTries|2|6")
    check_status 1 "require_check_tables refuses a seeded table edited down" \
        require_check_tables
    SEEDED_SSH_CHECKS=("${saved_seeded[@]}")
    # The newest table of all, and the guard row for it is one line in a list of
    # fourteen. Without this, deleting that line costs nothing and the services
    # rows could then be edited down in silence.
    local saved_services=("${SERVICES_CHECKS[@]}")
    SERVICES_CHECKS=("not-at-boot")
    check_status 1 "require_check_tables refuses the services table edited down" \
        require_check_tables
    SERVICES_CHECKS=("${saved_services[@]}")
    SSH_CHECKS=("PermitRootLogin|no")
    # And the size the run is measured against does not follow the table down.
    # Counted off ${#SSH_CHECKS[@]} it would, and print_summary would then accept
    # a run that skipped six directives as a complete one. Compared against the
    # value taken while the tables were whole, which the literal above pins.
    check_eq "$(RUN_NETNS=0 RUN_BOOTED=0 expected_check_total)" "$pinned_total" \
        "the expected total does not move when a table is edited down"
    SSH_CHECKS=("${saved_ssh_checks[@]}")
    check_status 0 "require_check_tables accepts the table once it is restored" \
        require_check_tables

    # The introduced-finding registry, and it is the one table here whose length
    # no total is counted off, so nothing else in this file would notice it
    # moving.
    local saved_allowances=("${INTRODUCED_FINDING_ALLOWANCES[@]}")
    INTRODUCED_FINDING_ALLOWANCES=("${saved_allowances[0]}")
    check_status 1 "require_check_tables refuses the introduced-finding registry edited down" \
        require_check_tables
    # The direction that matters more in this table than in any other: appending
    # an entry is how a red introduced-finding row gets quieted, and doing so
    # fails this guard until the number beside the table moves as well, which is
    # what puts the decision in front of a reviewer.
    INTRODUCED_FINDING_ALLOWANCES=("${saved_allowances[@]}" "kernel-hardening|kernel_invented|declared with no measurement behind it")
    check_status 1 "and refuses it grown, which is the direction that would quiet a red row" \
        require_check_tables
    INTRODUCED_FINDING_ALLOWANCES=("${saved_allowances[@]}")
    check_status 0 "and accepts the registry once it is restored" require_check_tables

    # The seeded pair. Its failure mode is the quiet one: if the seed never
    # lands, the post-apply reading is the tool's own target, the tool put it
    # there, and the check agrees with the tool about a value neither of them
    # was asked about. Only the pre-apply control separates those, so its own
    # refusals are pinned here.
    local seeded_fixture
    seeded_fixture=$'maxauthtries 2\nclientaliveinterval 60\nemptydirective \n'

    APPLY_GENERATION=0
    SEEDED_BEFORE=""
    SEEDED_BEFORE_GENERATION=""
    check_status 1 "a seeded reading is refused before the capture is taken" \
        seeded_baseline_value MaxAuthTries

    SEEDED_BEFORE="$seeded_fixture"
    SEEDED_BEFORE_GENERATION=1
    check_status 1 "a seeded capture stamped after an apply is refused" \
        seeded_baseline_value MaxAuthTries

    SEEDED_BEFORE_GENERATION=0
    check_eq "$(seeded_baseline_value MaxAuthTries)" "2" \
        "a seeded reading comes back from the pre-apply capture"
    check_status 1 "a directive absent from the seeded capture is refused" \
        seeded_baseline_value NoSuchDirective
    check_status 1 "a directive present with no value is refused" \
        seeded_baseline_value EmptyDirective

    APPLY_GENERATION=1
    check_status 1 "the seeded capture refuses to be taken once apply has run" \
        preapply_seeded_init
    check_status 1 "the seed refuses to be written once apply has run" \
        seed_stricter_than_baseline
    APPLY_GENERATION=0

    # What the seed actually writes, against a scratch file. Appended and not
    # prepended is the property that makes this an oracle rather than a
    # restatement of itself, so the content is asserted rather than assumed.
    local seed_scratch seed_written
    seed_scratch="$(mktemp)"
    printf '# existing config\nInclude /etc/ssh/sshd_config.d/*.conf\n' >"$seed_scratch"
    SEED_TARGET_FILE="$seed_scratch"
    check_status 0 "the seed writes when no apply has happened" \
        seed_stricter_than_baseline
    seed_written="$(cat "$seed_scratch")"
    SEED_TARGET_FILE="/etc/ssh/sshd_config"
    rm -f "$seed_scratch"
    check_eq "$(printf '%s' "$seed_written" | tail -2)" \
        "$(printf 'MaxAuthTries 2\nClientAliveInterval 60')" \
        "the seed is appended, so a fragment written later still beats it"
    check_eq "$(printf '%s' "$seed_written" | head -2)" \
        "$(printf '# existing config\nInclude /etc/ssh/sshd_config.d/*.conf')" \
        "the seed leaves the Include above it, which is what lets a fragment win"

    # And the checks themselves: one per seeded directive whichever way each
    # goes, so a failed reading cannot quietly shrink the run.
    local before_total before_passed before_failed
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_seeded_checks >/dev/null
    check_eq "$((CHECKS_TOTAL - before_total))" "2" \
        "the seeded pair records one check each"
    check_eq "$((CHECKS_FAILED - before_failed))" "0" \
        "a capture holding both seeds passes both"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    # The discriminating case: sshd enforcing its own default rather than the
    # seed means the write never took effect, and every later reading of that
    # directive would be describing the tool agreeing with itself.
    SEEDED_BEFORE=$'maxauthtries 6\nclientaliveinterval 60\n'
    before_total=$CHECKS_TOTAL
    before_failed=$CHECKS_FAILED
    run_seeded_checks >/dev/null
    check_eq "$((CHECKS_FAILED - before_failed))" "1" \
        "a seed that did not take effect fails its control instead of passing quietly"
    check_eq "$((CHECKS_TOTAL - before_total))" "2" \
        "a failed seed still costs exactly one check"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed
    SEEDED_BEFORE=""
    SEEDED_BEFORE_GENERATION=""

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
    # carrying plugin_id, plugin_name, findings, unchecked, scan_success and
    # scan_error, which is the whole key set output.rs builds. One finding under
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
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "ssh-hardening",
    "plugin_name": "SSH Hardening",
    "findings": [
      { "finding_id": "ssh-permitrootlogin", "finding_current_value": "yes" }
    ],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "permissions-hardening",
    "plugin_name": "File Permissions Hardening",
    "findings": [
      { "finding_id": "perm--boot", "finding_current_value": "755" }
    ],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "firewall-hardening",
    "plugin_name": "Firewall Hardening",
    "findings": [
      { "finding_id": "ufw-disabled", "finding_current_value": "disabled" }
    ],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "kernel-hardening",
    "plugin_name": "Kernel Hardening",
    "findings": [
      { "finding_id": "kernel_net_ipv4_conf_all_rp_filter", "finding_current_value": "0" }
    ],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null

  },
  {
    "plugin_id": "audit-hardening",
    "plugin_name": "Audit Rules Hardening",
    "findings": [
      { "finding_id": "audit_rules_missing", "finding_current_value": "absent" }
    ],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "mac-hardening",
    "plugin_name": "MAC System Hardening",
    "findings": [],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
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
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
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

    # The key that says the scan ran at all, which the loop above cannot infer:
    # after apply every compared directive is expected to report no finding, and
    # a plugin whose scan never completed reports no finding either. The two
    # faults are told apart the way `findings` and `unchecked` are, because an
    # absent key is a stale binary and a false one is a genuine failure here.
    #
    # Status and message together, in the idiom the preview capture's refusal
    # uses. The status alone could not tell these two arms apart: both refuse,
    # and an absent key would still be refused by the arm written for a false
    # one, silently taking the rebuild advice out of the log.
    local ss_out
    ss_out="$(mktemp)"
    scan_capture="$(jq 'map(if .plugin_id == "permissions-hardening" then del(.scan_success) else . end)' <<<"$scan_fixture")"
    init_status=0
    scan_oracle_init 2>"$ss_out" >/dev/null || init_status=$?
    check_eq "$init_status/$(grep -c "has no 'scan_success' key" "$ss_out" || true)" "1/1" \
        "scan_oracle_init refuses a plugin object with no scan_success key, named as the absent key a rebuild supplies rather than as a scan that failed"

    scan_capture="$(jq 'map(if .plugin_id == "kernel-hardening" then .scan_success = false | .scan_error = "sysctl -a exited 1" else . end)' <<<"$scan_fixture")"
    init_status=0
    scan_oracle_init || init_status=$?
    check_eq "$init_status" "1" "scan_oracle_init refuses a plugin that reported its own scan as failed"

    # The reason the tool gave has to reach the log, or a maintainer is told a
    # plugin failed and left to rediscover why.
    init_status=0
    scan_oracle_init 2>"$ss_out" >/dev/null || init_status=$?
    check_eq "$init_status/$(grep -c 'sysctl -a exited 1' "$ss_out" || true)" "1/1" \
        "and the refusal carries the scan_error the tool reported, because a check that refuses has to say what it refused over"

    # A failed scan that named no reason. scan_error is an Option, so null is a
    # shape the tool genuinely emits, and the refusal has to stay a refusal
    # without printing jq's 'null' at the reader as the explanation.
    scan_capture="$(jq 'map(if .plugin_id == "kernel-hardening" then .scan_success = false else . end)' <<<"$scan_fixture")"
    init_status=0
    scan_oracle_init 2>"$ss_out" >/dev/null || init_status=$?
    check_eq "$init_status/$(grep -c 'null' "$ss_out" || true)" "1/0" \
        "a failed scan that reported no reason is refused as well, and the refusal does not offer jq's 'null' as one"
    rm -f "$ss_out"

    # The tool's own "I could not check this". The ids in `unchecked` are
    # identical to the finding ids by design, so an unchecked directive has no
    # finding, and no finding is what this suite scores as agreement. The ssh
    # plugin puts every one of its directives here at once when sshd_config
    # cannot be read for want of root, and still reports the scan as successful,
    # which is why every object below carries scan_success true and is accepted.
    local unchecked_fixture='[
  {
    "plugin_id": "pam-hardening",
    "plugin_name": "PAM Hardening",
    "findings": [],
    "unchecked": [
      { "unchecked_check_id": "pam-PASS_MAX_DAYS", "unchecked_reason": "reading /etc/login.defs requires root" }
    ],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "ssh-hardening",
    "plugin_name": "SSH Hardening",
    "findings": [],
    "unchecked": [
      { "unchecked_check_id": "ssh-permitrootlogin", "unchecked_reason": "reading /etc/ssh/sshd_config requires root" }
    ],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "permissions-hardening",
    "plugin_name": "File Permissions Hardening",
    "findings": [],
    "unchecked": [
      { "unchecked_check_id": "perm--boot", "unchecked_reason": "could not determine whether /boot exists" }
    ],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "firewall-hardening",
    "plugin_name": "Firewall Hardening",
    "findings": [],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "kernel-hardening",
    "plugin_name": "Kernel Hardening",
    "findings": [],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null

  },
  {
    "plugin_id": "audit-hardening",
    "plugin_name": "Audit Rules Hardening",
    "findings": [
      { "finding_id": "audit_rules_missing", "finding_current_value": "absent" }
    ],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
  },
  {
    "plugin_id": "mac-hardening",
    "plugin_name": "MAC System Hardening",
    "findings": [],
    "unchecked": [],
    "scan_success": true,
    "scan_error": null
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
    compare_directive ssh-hardening PermitRootLogin no no "$(ssh_finding_id PermitRootLogin)" exact >/dev/null
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
    compare_directive ssh-hardening MaxAuthTries 3 3 "$(ssh_finding_id MaxAuthTries)" exact >/dev/null
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
    check_eq "${#compared_ids[@]}" "19" "the control covers every compared directive"
    check_eq "${compared_ids[0]}" "ssh-hardening ssh-permitrootlogin" \
        "the control names each directive by the id its own plugin emits"

    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_preapply_control >/dev/null
    check_eq "$((CHECKS_TOTAL - before_total))" "3" "the control records one check per plugin"
    check_eq "$((CHECKS_PASSED - before_passed))" "3" \
        "a plugin that reported a finding before apply passes its control"
    CHECKS_TOTAL=$before_total
    CHECKS_PASSED=$before_passed
    CHECKS_FAILED=$before_failed

    # A plugin with nothing to report before apply. A failed scan looks like
    # this and so does a filter that matches nothing, and the two are separated
    # elsewhere: the JSON does carry scan_success, so validate_scan_document has
    # already refused the first before this control runs. The second is what
    # only this control sees, because a filter naming an id the tool never emits
    # returns nothing out of a scan that reported itself entirely successful.
    # Neither may pass.
    PRE_APPLY_SCAN_JSON="$(jq 'map(if .plugin_id == "ssh-hardening" then .findings = [] else . end)' <<<"$scan_fixture")"
    before_total=$CHECKS_TOTAL
    before_passed=$CHECKS_PASSED
    before_failed=$CHECKS_FAILED
    run_preapply_control >/dev/null
    check_eq "$((CHECKS_PASSED - before_passed))" "2" \
        "the plugins that did report findings still pass their controls"
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

    # The comparison the verdict rests on, in both of its directions.
    #
    # `exact` is the one every check used while there was only one. `mask` is the
    # one a permission directive needs, and the third and fourth assertions below
    # are the whole reason it exists: /etc/shadow at 0600 and at 0000 sets no bit
    # the 0640 mask disallows, and an equality comparison would report the tool as
    # defective for leaving a correctly hardened path alone.
    check_status 0 "an exact comparison is satisfied by the same value" \
        requirement_satisfied 644 644 exact
    check_status 1 "an exact comparison is not satisfied by a different value" \
        requirement_satisfied 640 644 exact
    check_status 0 "a mask comparison is satisfied by the mask itself" \
        requirement_satisfied 640 640 mask
    check_status 0 "a mask comparison is satisfied by a stricter mode" \
        requirement_satisfied 600 640 mask
    check_status 0 "a mask comparison is satisfied by a mode that sets nothing" \
        requirement_satisfied 0 640 mask
    check_status 1 "a mask comparison is not satisfied by a bit outside the mask" \
        requirement_satisfied 644 640 mask
    check_status 1 "a mask comparison is not satisfied by a special bit outside the mask" \
        requirement_satisfied 4640 640 mask
    # A reading that is not an octal mode must not be compared arithmetically.
    # `8#` on a non-octal word is a bash syntax error inside the arithmetic, which
    # would abort the run under set -e rather than fail one check.
    # These three assert the MESSAGE, not the status, and the difference matters.
    # `8#absent` fails arithmetically on its own and an unmatched `case` returns
    # 0, so a status assertion here passed identically with the guard removed and
    # with the unknown-comparison branch deleted. Watched failing under both, once
    # the wording became the assertion.
    check_status 1 "a mask comparison refuses a reading that is not an octal mode" \
        requirement_satisfied absent 640 mask
    check_eq "$(requirement_satisfied absent 640 mask 2>&1 >/dev/null; :)" \
        "FATAL: a mask comparison needs two octal modes, and was given 'absent' against '640'" \
        "and names the reading it refused rather than leaving bash to describe it"
    check_eq "$(requirement_satisfied 640 rw-r----- mask 2>&1 >/dev/null; :)" \
        "FATAL: a mask comparison needs two octal modes, and was given '640' against 'rw-r-----'" \
        "a mask comparison refuses a target that is not an octal mode, and names it"
    check_eq "$(requirement_satisfied 640 640 stricter 2>&1 >/dev/null; :)" \
        "FATAL: no such comparison 'stricter'" \
        "an unknown comparison is refused by name rather than treated as equality"
    check_eq "$(requirement_wording 700 exact)" "'700'" \
        "an exact requirement is worded as the value it names"
    check_eq "$(requirement_wording 640 mask)" "no bit outside '640'" \
        "a mask requirement is worded as the rule, because it also accepts 600"

    # The verdict rule itself, in all four directions. The last one is the shape
    # of the defect this harness exists to catch: the system holds something
    # other than the target and the tool reports nothing wrong.
    check_status 0 "verdict agrees when the system satisfies the requirement and nothing is reported" \
        verdict_agrees yes 0
    check_status 1 "verdict disagrees when the system satisfies the requirement and a finding is reported" \
        verdict_agrees yes 1
    check_status 0 "verdict agrees when the system does not satisfy it and a finding is reported" \
        verdict_agrees no 1
    check_status 1 "verdict disagrees when the system does not satisfy it and nothing is reported" \
        verdict_agrees no 0
    # Neither yes nor no is fatal rather than silently one of them: read as "no"
    # it would demand a finding for a reading nobody classified, and read as
    # "yes" it would accept the tool reporting nothing about it.
    check_status 1 "verdict_agrees refuses a satisfaction that is neither yes nor no" \
        verdict_agrees maybe 0

    # The idempotency checks. Their readings want root and a container, so what
    # is pinned here is everything around them: the fragment listing, the
    # dispatch, every refusal that keeps the baseline from becoming a reading
    # against itself, and the comparison driven through a stub so it is watched
    # both passing and failing.
    #
    # The permission reading dispatches to the same capture the permissions oracle
    # uses, driven over a fixture table so it reads nothing of the developer's own.
    # One capture, two questions: does the system agree with the tool, and did the
    # second apply move anything. A second reader would have been a second thing to
    # keep in step with the table.
    local idem_fixture idem_saved_table=("${PERMISSION_CHECKS[@]}")
    idem_fixture="$(mktemp -d)"
    printf 'x\n' >"$idem_fixture/mode-640"
    chmod 640 "$idem_fixture/mode-640"
    PERMISSION_CHECKS=("$idem_fixture/mode-640|640|exact" "$idem_fixture/gone|700|exact")
    check_eq "$(idempotence_reading permission-modes)" \
        "$idem_fixture/mode-640 640
$idem_fixture/gone absent" \
        "the permission idempotency reading is the whole capture, absences included"
    PERMISSION_CHECKS=("${idem_saved_table[@]}")
    rm -rf "$idem_fixture"

    local dropin_fixture
    dropin_fixture="$(mktemp -d)"
    check_eq "$(sshd_dropin_listing "$dropin_fixture/missing")" "directory absent" \
        "a missing fragment directory reads as absent rather than as nothing"
    check_eq "$(sshd_dropin_listing "$dropin_fixture")" "directory empty" \
        "an empty fragment directory reads as empty rather than as nothing"
    printf 'X11Forwarding no\n' >"$dropin_fixture/00-hardener.conf"
    printf 'X11Forwarding yes\n' >"$dropin_fixture/50-redhat.conf"
    check_eq "$(sshd_dropin_listing "$dropin_fixture")" \
        "=== $dropin_fixture/00-hardener.conf
X11Forwarding no
=== $dropin_fixture/50-redhat.conf
X11Forwarding yes" \
        "the fragment listing names every file and carries its contents"
    rm -rf "$dropin_fixture"

    check_status 1 "an unknown idempotency key is refused, never read as an empty reading" \
        idempotence_reading no-such-reading

    # The stub publishes through the global the probe publishes through, rather
    # than printing: a probe that printed its reading could not return two of
    # them, which is what put the second one in a subshell in the first place.
    login_defs_system_values() {
        LOGIN_DEFS_PROBE_CHAGE='Last password change : Jul 28, 2026
Minimum number of days : 1'
    }
    check_eq "$(idempotence_reading login-defs)" "Minimum number of days : 1" \
        "the login.defs reading drops the probe account's own creation date"
    # shellcheck disable=SC2329  # called indirectly, through idempotence_reading
    login_defs_system_values() { return 1; }
    check_status 1 "a probe that failed is not filtered down to an empty reading" \
        idempotence_reading login-defs
    unset -f login_defs_system_values

    check_eq "$(idempotence_report_difference sshd-dropins "kept
gone" "kept
added")" \
        "  diff| sshd-dropins only after the first apply: gone
  diff| sshd-dropins only after the second apply: added" \
        "the difference report names the line each side has and the other does not"

    local saved_generation=$APPLY_GENERATION
    IDEMPOTENCE_BEFORE=()
    IDEMPOTENCE_BEFORE_GENERATION=""
    APPLY_GENERATION=0
    check_status 1 "the idempotency baseline refuses to be taken before any apply" \
        first_apply_idempotence_init
    APPLY_GENERATION=2
    check_status 1 "the idempotency baseline refuses to be taken after the second apply" \
        first_apply_idempotence_init
    check_status 1 "an uncaptured idempotency baseline is refused" \
        idempotence_baseline sshd-effective
    IDEMPOTENCE_BEFORE[sshd-effective]="a reading"
    IDEMPOTENCE_BEFORE_GENERATION=2
    check_status 1 "a baseline stamped after the second apply is refused" \
        idempotence_baseline sshd-effective
    IDEMPOTENCE_BEFORE_GENERATION=1
    check_status 1 "a baseline for a key that was never captured is refused" \
        idempotence_baseline no-such-reading
    APPLY_GENERATION=1
    check_status 1 "the comparison is refused until a second apply has happened" \
        idempotence_baseline sshd-effective
    APPLY_GENERATION=2
    check_eq "$(idempotence_baseline sshd-effective)" "a reading" \
        "a baseline taken between the two applies is returned"

    # Watched failing, which is the only thing that makes it evidence: a
    # comparison of one reading against itself passes whatever the tool did.
    # The stub replaces the reading for the rest of this function, so nothing
    # below may use the real one.
    local idempotence_saved_total=$CHECKS_TOTAL
    local idempotence_saved_passed=$CHECKS_PASSED
    local idempotence_saved_failed=$CHECKS_FAILED
    local idempotence_key
    IDEMPOTENCE_BEFORE=()
    IDEMPOTENCE_BEFORE_GENERATION=1
    for idempotence_key in "${IDEMPOTENCE_CHECKS[@]}"; do
        IDEMPOTENCE_BEFORE["$idempotence_key"]="what one apply produced"
    done
    idempotence_reading() { printf 'what one apply produced'; }
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_idempotence_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "$IDEMPOTENCE_CHECKS_EXPECTED/0" \
        "a second apply that changes nothing passes every idempotency check"
    idempotence_reading() { printf 'something the second apply moved'; }
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_idempotence_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/$IDEMPOTENCE_CHECKS_EXPECTED" \
        "a second apply that moves a reading fails every idempotency check"
    unset -f idempotence_reading
    CHECKS_TOTAL=$idempotence_saved_total
    CHECKS_PASSED=$idempotence_saved_passed
    CHECKS_FAILED=$idempotence_saved_failed
    APPLY_GENERATION=$saved_generation

    # === Password quality enforcement ===

    check_status 0 "a loaded module line is read as loaded" \
        pwquality_module_loaded_in "password required pam_pwquality.so retry=3"
    check_status 1 "a commented module line is not a loaded module" \
        pwquality_module_loaded_in "#password required pam_pwquality.so retry=3"
    check_status 1 "an indented commented module line is not a loaded module either" \
        pwquality_module_loaded_in "    # password required pam_pwquality.so"
    check_status 1 "a stack loading other modules only is read as absent" \
        pwquality_module_loaded_in "auth required pam_faillock.so preauth
password required pam_unix.so sha512 shadow"
    check_status 0 "one loaded line among many is enough" \
        pwquality_module_loaded_in "auth required pam_faillock.so preauth
password required pam_pwquality.so
password required pam_unix.so"

    # All four directions, because either alone passes on a harness that always
    # says the same thing.
    check_status 0 "a loaded module and no finding agree" \
        pwquality_enforcement_agrees loaded 0
    check_status 1 "a loaded module and a finding disagree" \
        pwquality_enforcement_agrees loaded 1
    check_status 0 "an absent module and a finding agree" \
        pwquality_enforcement_agrees absent 1
    check_status 1 "an absent module and no finding disagree, which is the defect" \
        pwquality_enforcement_agrees absent 0
    check_status 1 "a reading that is neither is refused rather than read as agreement" \
        pwquality_enforcement_agrees "" 0

    # A stack directory with nothing in it must refuse rather than answer
    # 'absent': absence concluded from nothing is how a host this run never
    # looked at comes to be scored.
    local pwquality_saved_files=("${PWQUALITY_STACK_FILES[@]}")
    local pwquality_fixture
    pwquality_fixture="$(mktemp -d)"
    PWQUALITY_STACK_FILES=("$pwquality_fixture/system-auth")
    check_status 1 "a stack with no readable file is refused, never read as no module" \
        pwquality_stack_reading
    printf 'password required pam_unix.so\n' >"$pwquality_fixture/system-auth"
    check_eq "$(pwquality_stack_reading)" "absent" \
        "a stack that was read and loads no pwquality reads as absent"
    printf 'password required pam_pwquality.so\n' >>"$pwquality_fixture/system-auth"
    check_eq "$(pwquality_stack_reading)" "loaded" \
        "a stack that loads it reads as loaded"

    # Watched failing, the only thing that makes the family evidence: the pair
    # must be able to record two failures, not merely two checks.
    local pwquality_saved_total=$CHECKS_TOTAL
    local pwquality_saved_passed=$CHECKS_PASSED
    local pwquality_saved_failed=$CHECKS_FAILED
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '1'; }
    # shellcheck disable=SC2329  # called indirectly, through the family below
    pwquality_verdict() { printf 'refused'; }
    run_pwquality_enforcement_checks >/dev/null
    check_eq "$CHECKS_TOTAL" "$PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED" \
        "the pwquality family records one check per reading"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/$PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED" \
        "a host whose stack loads the module, whose tool still reports minlen failing, and whose libpwquality refuses even the probe password fails both readings"
    unset -f scan_finding_count
    unset -f pwquality_verdict
    CHECKS_TOTAL=$pwquality_saved_total
    CHECKS_PASSED=$pwquality_saved_passed
    CHECKS_FAILED=$pwquality_saved_failed
    rm -rf "$pwquality_fixture"
    PWQUALITY_STACK_FILES=("${pwquality_saved_files[@]}")

    # === The permissions oracle ===
    #
    # The id derivation first, pinned to literals. permissions builds its ids off
    # the path, so the leading slash becomes a dash of its own and every id
    # carries a doubled dash. A filter written without it matches nothing, and
    # matching nothing is this suite's pass condition.
    check_eq "$(permission_finding_id /root)" "perm--root" \
        "the leading slash becomes a dash, so the id carries a doubled dash"
    check_eq "$(permission_finding_id /etc/shadow)" "perm--etc-shadow" \
        "every separator becomes a dash"
    check_eq "$(permission_finding_id /etc/sudoers.d)" "perm--etc-sudoers.d" \
        "a dot in a path is left alone, because the id derivation does not touch it"

    # The reader is a string compare, not a pattern match, and this is the
    # assertion that says why: two of the table's paths contain a dot, and the
    # grep-based reader the ssh capture uses would answer this row from a
    # different path entirely.
    local permission_fixture_capture="/etc/sudoersXd 750
/etc/sudoers.d 700
/etc/shadow 0"
    check_eq "$(permission_capture_reading "$permission_fixture_capture" /etc/sudoers.d)" "700" \
        "a path is read by exact match, not by a pattern its dot would widen"
    check_eq "$(permission_capture_reading "$permission_fixture_capture" /etc/shadow)" "0" \
        "a mode of 0 is a reading, not an empty answer"
    check_status 1 "a path the capture holds no row for is refused" \
        permission_capture_reading "$permission_fixture_capture" /etc/passwd

    # The capture itself, driven over a fixture table rather than the real one:
    # the nine paths are absolute, and a self-test that read the developer's own
    # /etc/shadow would prove whatever that machine happens to hold.
    local permission_saved_table=("${PERMISSION_CHECKS[@]}")
    local permission_fixture
    permission_fixture="$(mktemp -d)"
    printf 'x\n' >"$permission_fixture/exact"
    chmod 640 "$permission_fixture/exact"
    printf 'x\n' >"$permission_fixture/nothing"
    chmod 000 "$permission_fixture/nothing"
    PERMISSION_CHECKS=(
        "$permission_fixture/exact|640|exact"
        "$permission_fixture/nothing|640|mask"
        "$permission_fixture/missing|700|exact"
    )
    # The status is captured rather than left to set -e. A capture that refuses
    # aborts the whole self-test from an assignment, and an aborted run prints no
    # verdict for the assertions below, so the failure that reaches a reader is a
    # FATAL line rather than the named expectation that was broken.
    local permission_capture_out permission_capture_status=0
    permission_capture_out="$(permission_modes_capture)" || permission_capture_status=$?
    check_eq "$permission_capture_status" "0" \
        "the capture succeeds over a table whose third path does not exist"
    check_eq "$(permission_capture_reading "$permission_capture_out" "$permission_fixture/exact")" "640" \
        "the capture reports the mode the filesystem holds"
    check_eq "$(permission_capture_reading "$permission_capture_out" "$permission_fixture/nothing")" "0" \
        "a file with no bits set reports 0, which is why the octal pattern accepts one digit"
    check_eq "$(permission_capture_reading "$permission_capture_out" "$permission_fixture/missing")" "absent" \
        "a path that is not there is a determinate answer rather than a failure"

    # A path that exists and cannot be read is the third outcome, and it must be
    # fatal rather than joining either of the other two. Driven through a stub,
    # because as an ordinary user a file inside an unreadable directory fails the
    # existence test as well and would arrive as `absent`.
    # shellcheck disable=SC2329  # called indirectly, by the capture below
    stat() { echo "stat: cannot statx: Permission denied" >&2; return 1; }
    check_status 1 "a path that exists and cannot be statted is fatal, never absent" \
        permission_modes_capture
    unset -f stat

    # The freshness lifecycle, the same one every other oracle here has, and for
    # the same reason: a capture taken before apply describes the container as it
    # was found.
    PERMISSION_MODES=""
    PERMISSION_MODES_GENERATION=""
    check_status 1 "uninitialised permissions oracle returns non-zero" \
        permission_system_value "$permission_fixture/exact"
    local permission_saved_generation=$APPLY_GENERATION
    APPLY_GENERATION=1
    init_status=0
    permissions_oracle_init || init_status=$?
    check_eq "$init_status" "0" "permissions_oracle_init captures at the current generation"
    check_eq "$(permission_system_value "$permission_fixture/exact")" "640" \
        "and the reading is then readable by path"
    APPLY_GENERATION=2
    check_status 1 "a capture taken before the last apply is refused" \
        permission_system_value "$permission_fixture/exact"
    APPLY_GENERATION=1
    check_status 1 "a path the capture holds no row for is refused rather than read as absent" \
        permission_system_value /etc/nowhere

    # The family end to end, through stubbed verdicts. Three shapes, each
    # contributing exactly two checks, and the second is the one an equality
    # comparison would have failed: 000 is stricter than the 640 mask, the tool
    # correctly reports nothing, and this must be two passes rather than a defect
    # reported against a tool behaving as designed.
    local permission_saved_total=$CHECKS_TOTAL
    local permission_saved_passed=$CHECKS_PASSED
    local permission_saved_failed=$CHECKS_FAILED
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_unchecked_count() { printf '0'; }
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '0'; }
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_TOTAL" "6" "each path contributes two checks, absent or not"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "6/0" \
        "a mode equal to an exact target, a mode stricter than a mask, and an absent path all agree with a tool reporting nothing"

    # And the same three with the tool reporting a finding for each. The absent
    # row is the interesting one: a finding for a path that is not there is the
    # tool claiming something about a file it cannot have looked at.
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '1'; }
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/3" \
        "the three readings still pass and all three tool verdicts fail"

    # A mode that violates its target, with the tool reporting nothing: the shape
    # this whole suite exists to catch, on a permission rather than a directive.
    chmod 644 "$permission_fixture/exact"
    PERMISSION_CHECKS=("$permission_fixture/exact|640|exact")
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '0'; }
    permissions_oracle_init
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/2" \
        "a mode that violates its target while the tool reports nothing fails both assertions"

    unset -f scan_unchecked_count
    unset -f scan_finding_count
    CHECKS_TOTAL=$permission_saved_total
    CHECKS_PASSED=$permission_saved_passed
    CHECKS_FAILED=$permission_saved_failed
    APPLY_GENERATION=$permission_saved_generation
    PERMISSION_CHECKS=("${permission_saved_table[@]}")
    PERMISSION_MODES=""
    PERMISSION_MODES_GENERATION=""
    rm -rf "$permission_fixture"

    # === The vendor layer ===
    #
    # openSUSE keeps sudoers at /usr/etc/sudoers and nothing at /etc/sudoers, so
    # an oracle that stopped at the first absence agreed with a tool that could
    # not see the file either: two silences comparing equal, which is the shape
    # this suite exists to refuse.
    check_eq "$(permission_vendor_path /etc/sudoers)" "/usr/etc/sudoers" \
        "an /etc path has a vendor counterpart"
    check_status 1 "a path outside /etc has none, so none is invented for it" \
        permission_vendor_path /root
    check_status 1 "and /etc with nothing after it has none either" \
        permission_vendor_path /etc/

    local vendor_fixture vendor_saved_table=("${PERMISSION_CHECKS[@]}")
    local vendor_saved_total=$CHECKS_TOTAL vendor_saved_passed=$CHECKS_PASSED
    local vendor_saved_failed=$CHECKS_FAILED vendor_saved_generation=$APPLY_GENERATION
    vendor_fixture="$(mktemp -d)"
    install -d "$vendor_fixture/etc"
    printf 'x\n' >"$vendor_fixture/vendor-copy"
    chmod 444 "$vendor_fixture/vendor-copy"
    # The path derivation is stubbed, because the real one names an absolute
    # /usr/etc path this self-test must not depend on the developer having. What
    # the stub leaves under test is the capture's use of it; the derivation itself
    # is pinned by the three assertions above.
    # shellcheck disable=SC2329  # called indirectly, by the capture and the family
    permission_vendor_path() { printf '%s' "$vendor_fixture/vendor-copy"; }
    PERMISSION_CHECKS=("$vendor_fixture/etc/absent-here|440|exact")
    local vendor_capture vendor_status=0
    vendor_capture="$(permission_modes_capture)" || vendor_status=$?
    check_eq "$vendor_status" "0" "the capture succeeds when /etc holds nothing and the vendor copy does"
    check_eq "$(permission_capture_reading "$vendor_capture" "$vendor_fixture/etc/absent-here")" \
        "vendor:444" \
        "a path absent from /etc is read at the vendor layer rather than called absent"

    # The verdict is the assertion that can fail here, and both directions are
    # watched. 444 sets o+r where an exact 440 does not allow it, so the tool is
    # required to have reported a finding: reporting one agrees, reporting none is
    # the openSUSE defect and fails.
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_unchecked_count() { printf '0'; }
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '1'; }
    APPLY_GENERATION=1
    permissions_oracle_init
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/0" \
        "a violating vendor mode the tool reported agrees, and still costs two checks"
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '0'; }
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/1" \
        "a violating vendor mode the tool said nothing about fails the verdict, which is the openSUSE defect"

    # And the compliant direction, so the verdict is pinned all four ways: a
    # vendor mode that satisfies the target requires silence, and a finding
    # against it is the tool contradicting a system that is fine.
    chmod 440 "$vendor_fixture/vendor-copy"
    permissions_oracle_init
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/0" \
        "a compliant vendor mode with nothing reported agrees"
    # shellcheck disable=SC2329  # called indirectly, through the family below
    scan_finding_count() { printf '1'; }
    CHECKS_TOTAL=0
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    run_permission_checks >/dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/1" \
        "a compliant vendor mode the tool reported a finding for fails the verdict"

    unset -f scan_unchecked_count
    unset -f scan_finding_count
    unset -f permission_vendor_path
    CHECKS_TOTAL=$vendor_saved_total
    CHECKS_PASSED=$vendor_saved_passed
    CHECKS_FAILED=$vendor_saved_failed
    APPLY_GENERATION=$vendor_saved_generation
    PERMISSION_CHECKS=("${vendor_saved_table[@]}")
    PERMISSION_MODES=""
    PERMISSION_MODES_GENERATION=""
    rm -rf "$vendor_fixture"

    # --- the two mode predicates ---
    #
    # Both arms of each, and a third for a value that is not the literal 1: the
    # flags are signals from the runner, and anything else arriving in one must
    # leave the oracle it gates off rather than half on.
    #
    # And the pair asserted against each other, which is #137: they were one
    # variable, and a suite that reunited them would answer both questions from
    # whichever signal it read. A run holding the namespace and not booted is
    # exactly the `--pipe --private-network` configuration the runner now uses,
    # so it is asked for here rather than left to the containers to discover.
    local booted_saved="$RUN_BOOTED" netns_saved="$RUN_NETNS"
    RUN_BOOTED=1
    check_status 0 "a booted run answers the booted predicate affirmatively" run_is_booted
    RUN_BOOTED=0
    check_status 1 "an unbooted run answers it negatively" run_is_booted
    RUN_BOOTED=2
    check_status 1 "and a value that is not the literal 1 is not booted either" run_is_booted
    RUN_NETNS=1
    check_status 0 "a run with its own network namespace answers the namespace predicate affirmatively" run_has_netns
    RUN_NETNS=0
    check_status 1 "a run without one answers it negatively" run_has_netns
    RUN_NETNS=2
    check_status 1 "and a value that is not the literal 1 is not a namespace either" run_has_netns
    RUN_NETNS=1
    RUN_BOOTED=0
    check_status 0 "a namespace without a boot is a namespace, which is what --pipe --private-network is" run_has_netns
    check_status 1 "and is still not booted, so the services rows stay unaskable there" run_is_booted
    RUN_NETNS=0
    RUN_BOOTED=1
    check_status 1 "a boot the runner declared without the namespace leaves the kernel rows unaskable, which is the safe direction" run_has_netns
    RUN_BOOTED="$booted_saved"
    RUN_NETNS="$netns_saved"

    # --- firewall oracle ---
    #
    # Fixtures are trimmed from real `nft list ruleset` output taken on the arch
    # and fedora containers 2026-07-30. The firewalld spelling in particular was
    # measured rather than guessed: a zone's DROP target renders as a bare
    # `drop` replacing the trailing `reject with icmpx admin-prohibited`, and a
    # pattern written for "policy drop" matches firewalld never.
    local fw_ufw_after='table ip filter {
        chain ufw-before-input {
                iifname "lo" accept
                jump ufw-user-input
        }

        chain ufw-user-input {
                tcp dport 22 accept
        }
}
=== iptables policies ===
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT'

    local fw_ufw_before='=== iptables policies ===
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT'

    local fw_firewalld_before='table inet firewalld {
        chain filter_INPUT {
                ct state { established, related } accept
                iifname "lo" accept
                jump filter_INPUT_POLICIES
                reject with icmpx admin-prohibited
        }

        chain filter_IN_public {
                tcp dport 22 accept
                reject with icmpx admin-prohibited
        }
}
=== iptables policies ===
-P INPUT ACCEPT'

    local fw_firewalld_after='table inet firewalld {
        chain filter_INPUT {
                ct state { established, related } accept
                iifname "lo" accept
                jump filter_INPUT_POLICIES
                drop
        }

        chain filter_IN_public {
                tcp dport 22 accept
                drop
        }
}
=== iptables policies ===
-P INPUT ACCEPT'

    check_eq "$(firewall_backend_kind "$fw_ufw_after")" "ufw" \
        "a ufw ruleset is recognised by its own chains"
    check_eq "$(firewall_backend_kind "$fw_firewalld_after")" "firewalld" \
        "a firewalld ruleset is recognised by its table"
    check_eq "$(firewall_backend_kind "")" "none" \
        "an empty ruleset names no backend rather than guessing one"

    # The two spellings of one property. Each backend's AFTER must satisfy it
    # and each backend's BEFORE must not, or the post-apply check would pass
    # without the tool having done anything.
    check_status 0 "ufw after apply drops inbound by default" \
        firewall_default_is_drop "$fw_ufw_after"
    check_status 1 "ufw before apply does not" \
        firewall_default_is_drop "$fw_ufw_before"
    check_status 0 "firewalld after apply drops inbound by default" \
        firewall_default_is_drop "$fw_firewalld_after"
    check_status 1 "firewalld before apply rejects rather than drops, which is not the target" \
        firewall_default_is_drop "$fw_firewalld_before"

    # The measured trap: firewalld's BEFORE holds every rule its AFTER holds
    # except the target, so a check reading presence rather than the target
    # cannot tell them apart. This pins that the discriminator is the target.
    check_status 1 "a firewalld ruleset carrying ufw's policy line is still judged by its own target" \
        firewall_default_is_drop "$fw_firewalld_before
-P INPUT DROP"

    check_status 0 "ssh stays accepted in a ufw ruleset" \
        firewall_ssh_accepted "$fw_ufw_after"
    check_status 0 "ssh stays accepted in a firewalld ruleset" \
        firewall_ssh_accepted "$fw_firewalld_after"
    check_status 1 "a ruleset with no ssh rule fails the lockout check" \
        firewall_ssh_accepted "$fw_ufw_before"

    # The boot question, which no ruleset can answer. Driven through a stubbed
    # systemctl, because the real one would answer about the maintainer's own
    # host and give a different reading on every machine this is run on.
    local fw_systemctl_word="disabled" fw_systemctl_rc=1
    systemctl() {
        printf '%s\n' "$fw_systemctl_word"
        return "$fw_systemctl_rc"
    }

    # `is-enabled` prints `disabled` on stdout while exiting 1, so a reading
    # taken from the status would throw the word away and report that nothing
    # was read. That is the defect 7fd250e repaired in the plugin, and it would
    # be worth nothing to repair it there and rebuild it here.
    check_eq "$(firewall_boot_reading "$fw_ufw_after")" "ufw|disabled" \
        "a non-zero is-enabled still yields the word it printed"

    fw_systemctl_word="  enabled  "
    fw_systemctl_rc=0
    check_eq "$(firewall_boot_reading "$fw_firewalld_after")" "firewalld|enabled" \
        "the unit asked about is the one the backend kind names, and padding round the answer is trimmed"

    fw_systemctl_word=""
    fw_systemctl_rc=4
    check_eq "$(firewall_boot_reading "$fw_ufw_after")" "ufw|" \
        "a systemctl answering nothing leaves the word empty rather than inventing one"

    # The short-circuit, proved with the stub answering `enabled`: a capture
    # holding no backend must not report a unit as enabled at boot, and without
    # the short-circuit this reading would carry the stub's word.
    fw_systemctl_word="enabled"
    fw_systemctl_rc=0
    check_eq "$(firewall_boot_reading "$fw_ufw_before")" "none|" \
        "a capture holding no backend names no unit and does not ask systemd about one"
    unset -f systemctl

    # The before reading, which asks every candidate unit instead of the one a
    # ruleset names. This stub answers per unit, because one answering the same
    # word for all of them could not tell "asked each" apart from "asked one and
    # copied the answer along the list".
    systemctl() {
        case "$2" in
            firewalld) printf 'not-found\n'; return 1 ;;
            ufw) printf '  disabled \n'; return 1 ;;
            *) printf 'unexpected-unit\n'; return 1 ;;
        esac
    }
    check_eq "$(firewall_boot_readings_before)" "firewalld|not-found ufw|disabled" \
        "the before reading asks every candidate unit and pairs each answer with the unit it came from"
    unset -f systemctl

    # The candidate list and firewall_backend_kind name the same two backends,
    # and each is written out by hand. Read the kinds back out of that
    # function's own body so the two cannot drift apart in silence: a third
    # backend taught to it alone would otherwise get no before reading at all,
    # and no row would go red for the absence. This reads `printf '<kind>'` and
    # would not see a kind spelled some other way, which is what the run-time
    # branch in run_firewall_checks covers.
    local fw_kinds
    fw_kinds="$(declare -f firewall_backend_kind | sed -nE "s/.*printf '([a-z]+)'.*/\1/p" | tr '\n' ' ')"
    check_eq "${FIREWALL_UNIT_CANDIDATES[*]}" "firewalld ufw" \
        "the units asked before apply are pinned to their two literals"
    check_eq "${fw_kinds% }" "${FIREWALL_UNIT_CANDIDATES[*]} none" \
        "and they are exactly the backends firewall_backend_kind can name, plus its no-backend case"

    check_status 0 "the six words for a unit that will not start at boot are refused" \
        firewall_not_at_boot disabled
    check_status 0 "including the one that exits zero" \
        firewall_not_at_boot enabled-runtime
    check_status 1 "and 'enabled' itself is not among them" \
        firewall_not_at_boot enabled
    check_status 1 "nor is a state with no [Install] section, which is undeterminable rather than a known failure" \
        firewall_not_at_boot static

    local fw_saved_total=$CHECKS_TOTAL fw_saved_passed=$CHECKS_PASSED fw_saved_failed=$CHECKS_FAILED
    local fw_saved_before="$FIREWALL_BEFORE" fw_saved_after="$FIREWALL_AFTER"
    local fw_saved_boot_before="$FIREWALL_BOOT_BEFORE" fw_saved_boot_after="$FIREWALL_BOOT_AFTER"

    # The lookup, on the shape the reading above produces. `ufw` is deliberately
    # the second pair: a lookup reading the first pair rather than matching the
    # name would answer `not-found` here and the boot row would then report a
    # state the ufw unit was never in.
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|disabled"
    check_eq "$(firewall_boot_word_before ufw)" "disabled" \
        "the before word is looked up by unit name rather than by position in the list"
    check_eq "$(firewall_boot_word_before firewalld)" "not-found" \
        "and each unit gets back the answer that was recorded against it"
    check_status 1 "a unit the list does not cover is refused rather than answered with an empty word" \
        firewall_boot_word_before nftables

    # Redirected to a file rather than captured with $(...): a command
    # substitution is a subshell, so every counter run_firewall_checks
    # increments would be discarded and the assertions below would read 0/0
    # whatever happened. Each `>` truncates, so one file serves every block.
    local fw_out
    fw_out="$(mktemp)"

    # The control has to fail when the property was already true, or every
    # firewalld run would report a pass it did not earn.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_BEFORE="$fw_firewalld_after"
    run_firewall_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a container already dropping inbound before apply fails the firewall control"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_BEFORE="$fw_firewalld_before"
    run_firewall_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "a container not yet dropping inbound passes the firewall control"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_BEFORE=""
    run_firewall_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "an empty pre-apply capture fails the control rather than passing quietly"

    # The state arch and debian are actually in before the apply: ufw installed,
    # not enabled, so its chains do not exist and only the iptables policies are
    # readable. Measured on arch 2026-07-30, where an earlier version of this
    # control called it an error and failed a correct run.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_BEFORE="$fw_ufw_before"
    run_firewall_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "a container whose backend is installed but not yet enabled passes the control"

    # arch, and the only load-bearing row of the five distributions: its ufw
    # unit had no multi-user.target.wants symlink before the apply, so the unit
    # itself reads a not-at-boot word and the apply is what changed it.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|enabled"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|disabled"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/0" \
        "a hardened ufw ruleset whose unit is enabled at boot passes all three firewall checks"
    check_status 0 "and the boot row finds its own unit in the pair list and carries the word that unit read before apply" \
        grep -q "the ufw unit read 'disabled' before apply, so the apply is what enabled it" "$fw_out"

    # debian, and the row the pair format exists for. Its after reading is
    # arch's byte for byte, and the wording still has to differ: debian's ufw
    # package enables the unit at install, so the apply is not what put it at
    # boot. Taken off the pre-apply ruleset the before reading was `none` on
    # debian too, because ufw's chains do not exist until the unit starts, and
    # this row then printed arch's evidence a second time.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|enabled"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|enabled"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/0" \
        "a ufw unit already enabled at boot before the apply passes all three"
    check_status 0 "and its boot row asserts agreement rather than crediting the apply, on an after reading identical to arch's" \
        grep -q "the ufw unit already read 'enabled' before apply, so this row asserts agreement" "$fw_out"

    # fedora, rhel and openSUSE: firewalld is already enabled at boot in the
    # container, so this row can assert agreement and nothing more. Saying so is
    # what keeps one row of evidence from reading as five.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_firewalld_after"
    FIREWALL_BOOT_AFTER="firewalld|enabled"
    FIREWALL_BOOT_BEFORE="firewalld|enabled ufw|not-found"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/0" \
        "a hardened firewalld ruleset whose unit was already enabled at boot passes all three"
    check_status 0 "and the boot row says it asserts agreement rather than claiming the apply acted" \
        grep -q "asserts agreement rather than proving the apply acted" "$fw_out"

    # A unit the before reading did ask and got nothing back from. The row still
    # passes, because the after reading is what it checks, but it may not fill
    # the gap with the wording that credits the apply. Reaching for that wording
    # when the before state is unknown is exactly the defect this pair format
    # repairs, and rebuilding it one branch over would be worth nothing.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|enabled"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/0" \
        "a unit whose before state could not be read still passes the boot row on its after reading"
    check_status 0 "and that row says it cannot tell whether the apply is what did it" \
        grep -q "the ufw unit read 'nothing at all' before apply, which is neither 'enabled' nor a state this can name, so this row cannot say" "$fw_out"
    check_status 1 "and claims the apply acted nowhere in the run" \
        grep -q "so the apply is what" "$fw_out"

    # The before reading missing altogether, with an after reading present. A
    # capture that was never taken is not a unit that answered nothing, and the
    # two send a reader to different places.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|enabled"
    FIREWALL_BOOT_BEFORE=""
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/0" \
        "an after reading with no before reading at all still passes the boot row"
    check_status 0 "and says no reading was taken before apply rather than naming a unit nothing ever asked about" \
        grep -q "no reading was taken before apply, so this row cannot say" "$fw_out"

    # The candidate list and firewall_backend_kind coming apart during a run:
    # the after reading names a unit no before reading covers. The row has to
    # say that rather than borrow a wording that reads like an ordinary result,
    # because a third backend reaching one of the two lists and not the other is
    # a fault in this file and not a finding about the container.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="nftables|enabled"
    FIREWALL_BOOT_BEFORE="firewalld|disabled ufw|disabled"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "3/0" \
        "an after unit that no before reading covers still passes on its after word"
    check_status 0 "and its row names the two lists that have come apart rather than reading as a normal result" \
        grep -q "do not include 'nftables', so the candidate list and firewall_backend_kind have come apart" "$fw_out"

    # A hardened ruleset whose unit will not come back. This is the state arch
    # shipped in before 61a33f9, and the two rows above it pass against it,
    # which is why this one exists.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|disabled"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|disabled"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/1" \
        "a hardened ruleset whose unit will not start at boot fails the boot row alone"
    check_status 0 "and the boot failure carries the word systemd answered with" \
        grep -q "the ufw unit is 'disabled'" "$fw_out"

    # The state this whole row exists for: `enabled-runtime` exits ZERO, so an
    # oracle judging on the status reads it as a pass, and the enablement it
    # describes is discarded by the next reboot.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_firewalld_after"
    FIREWALL_BOOT_AFTER="firewalld|enabled-runtime"
    FIREWALL_BOOT_BEFORE="firewalld|disabled ufw|not-found"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/1" \
        "a unit enabled for this boot only fails the boot row, though systemctl exits zero for it"
    check_status 0 "and that failure names enabled-runtime rather than any other way of not starting at boot" \
        grep -q "the firewalld unit is 'enabled-runtime'" "$fw_out"

    # An undeterminable value discovered at runtime is a FAILURE, never a skip.
    # record_unaskable is for unaskability declared in advance as a property of
    # the fixture; "I asked and got nothing back" is a property of the run.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|disabled"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/1" \
        "a unit systemd answered nothing about fails the boot row rather than being skipped"
    check_status 0 "and the failure says nothing was answered rather than naming a state" \
        grep -q "systemd answered 'nothing at all' about the ufw unit" "$fw_out"

    # A word that is neither `enabled` nor one of the six. `static` exits zero
    # and cannot be enabled at all, so it is not a pass and not one of the
    # failures the tool knows how to repair either.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER="ufw|static"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|disabled"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/1" \
        "a state with no [Install] section fails the boot row despite exiting zero"
    check_status 0 "and that failure carries the word rather than a guess at what it meant" \
        grep -q "systemd answered 'static' about the ufw unit" "$fw_out"

    # A capture that was never taken. It must not borrow the message for a unit
    # that was asked and answered nothing: those send a reader to different
    # places, one to the harness and one to the host.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_ufw_after"
    FIREWALL_BOOT_AFTER=""
    FIREWALL_BOOT_BEFORE=""
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/1" \
        "a boot reading that was never taken fails the row rather than passing quietly"
    check_status 0 "and says the reading is missing rather than naming a unit it never asked about" \
        grep -q "no boot-persistence reading was taken after apply" "$fw_out"

    # An unhardened ruleset must fail the drop check and still pass the lockout
    # check, because ssh being reachable is not what the apply was for.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER="$fw_firewalld_before"
    FIREWALL_BOOT_AFTER="firewalld|enabled"
    FIREWALL_BOOT_BEFORE="firewalld|enabled ufw|not-found"
    run_firewall_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "2/1" \
        "an unhardened firewalld ruleset fails the drop check and passes the lockout and boot checks"

    # A ruleset holding neither backend after a successful-looking apply, which
    # is what debian produced on the first real run. It must fail, and it must
    # fail with its own message rather than the one about a backend that is
    # present and misconfigured, because those two send a reader to different
    # places.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    FIREWALL_AFTER='=== iptables policies ===
-P INPUT ACCEPT'
    FIREWALL_BOOT_AFTER="none|"
    FIREWALL_BOOT_BEFORE="firewalld|not-found ufw|not-found"
    run_firewall_checks > "$fw_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/3" \
        "a ruleset holding no backend at all fails all three firewall checks"
    check_status 0 "and the no-backend failure carries the capture that produced it" \
        grep -q "the kernel holds no ufw or firewalld ruleset at all" "$fw_out"
    check_status 0 "and the boot row refuses it in its own words rather than the ruleset row's" \
        grep -q "there is no unit whose boot persistence could be asked about" "$fw_out"
    rm -f "$fw_out"

    CHECKS_TOTAL=$fw_saved_total
    CHECKS_PASSED=$fw_saved_passed
    CHECKS_FAILED=$fw_saved_failed
    FIREWALL_BEFORE="$fw_saved_before"
    FIREWALL_AFTER="$fw_saved_after"
    FIREWALL_BOOT_BEFORE="$fw_saved_boot_before"
    FIREWALL_BOOT_AFTER="$fw_saved_boot_after"

    # --- services oracle ---
    #
    # The word list is the services plugin's own, not the firewall oracle's
    # above. The two disagree about `enabled-runtime`: the firewall counts it as
    # not-at-boot and services counts it as enabled, because they answer
    # different questions with the same word. An oracle has to fail on exactly
    # the set the plugin it judges repairs, so neither list may be reused for
    # the other.
    check_status 0 "the plain enabled state counts as enabled" \
        services_unit_is_enabled enabled
    check_status 0 "and so does the runtime one, which this plugin treats as enabled where the firewall oracle does not" \
        services_unit_is_enabled enabled-runtime
    check_status 0 "a unit with no [Install] section is still counted enabled, because is-enabled exits zero for it" \
        services_unit_is_enabled static
    check_status 1 "a disabled unit is not" \
        services_unit_is_enabled disabled
    check_status 1 "nor is a masked one, which is what the apply leaves behind" \
        services_unit_is_enabled masked
    check_status 1 "and an empty word is not enabled, so a systemctl that answered nothing cannot read as a unit already disabled" \
        services_unit_is_enabled ""

    # The three-valued mask reading, driven against a real temporary tree rather
    # than a stub. This function asks the filesystem, and a stubbed filesystem
    # would prove only that the stub answers.
    local svc_saved_link="$SERVICES_MASK_LINK" svc_tmp
    svc_tmp="$(mktemp -d)"

    SERVICES_MASK_LINK="$svc_tmp/absent.service"
    check_eq "$(services_mask_link_reading)" "absent|" \
        "a path with nothing at it reads absent"

    SERVICES_MASK_LINK="$svc_tmp/masked.service"
    ln -s /dev/null "$SERVICES_MASK_LINK"
    check_eq "$(services_mask_link_reading)" "link|/dev/null" \
        "a mask link reads as a link and carries its target"

    SERVICES_MASK_LINK="$svc_tmp/override.service"
    printf '[Unit]\n' > "$SERVICES_MASK_LINK"
    check_eq "$(services_mask_link_reading)" "notlink|" \
        "an administrator's own unit file at that path is NOT reported as absent, because systemctl mask will not replace it"

    SERVICES_MASK_LINK="$svc_tmp/dangling.service"
    ln -s "$svc_tmp/nothing-here" "$SERVICES_MASK_LINK"
    check_eq "$(services_mask_link_reading)" "link|$svc_tmp/nothing-here" \
        "a dangling link is still a link, which is why -L is asked before -e"

    rm -rf "$svc_tmp"
    SERVICES_MASK_LINK="$svc_saved_link"

    # The installed probe, through a stubbed systemctl, because the real one
    # would answer about whichever host this self-test happens to run on.
    local svc_listing=""
    systemctl() {
        printf '%s\n' "$svc_listing"
    }
    svc_listing="UNIT FILE            STATE
bluetooth.service    enabled"
    check_eq "$(services_unit_installed)" "yes" \
        "a listing naming the unit reports it installed"
    svc_listing="0 unit files listed."
    check_eq "$(services_unit_installed)" "no" \
        "a listing that names no unit reports it absent rather than assuming it is there"
    svc_listing="bluetooth.socket    enabled"
    check_eq "$(services_unit_installed)" "no" \
        "and a unit of the same name that is not the service does not count as one"
    unset -f systemctl

    # The load-time decision itself, read back by sourcing this file in a
    # subshell under each mode.
    #
    # It cannot be read from the ambient DIFF_PLUGINS, because the pin at the
    # top of this function replaces that list with the base five. Without these
    # two, an append that lost its condition would go unnoticed and every
    # `--pipe` run would then compare a plugin it has no systemd to ask about,
    # failing rows on a fixture rather than on the tool. Measured: dropping the
    # condition survived the whole suite until these were added.
    local svc_suite="$DIFF_SCRIPT_DIR/differential-suite.sh" svc_loaded
    svc_loaded="$(HARDENER_DIFF_BOOTED=1 bash -c 'source "$1"; printf "%s" "${DIFF_PLUGINS[*]}"' _ "$svc_suite")"
    check_eq "${svc_loaded##* }" "$SERVICES_PLUGIN_ID" \
        "a booted load appends the services plugin, last, so it is applied after the plugins that were already compared"
    check_eq "$(wc -w <<<"$svc_loaded")" "8" \
        "and compares eight plugins in that mode"
    svc_loaded="$(HARDENER_DIFF_BOOTED=0 bash -c 'source "$1"; printf "%s" "${DIFF_PLUGINS[*]}"' _ "$svc_suite")"
    check_status 1 "an unbooted load does not compare the services plugin at all" \
        grep -qF "$SERVICES_PLUGIN_ID" <<<"$svc_loaded"
    check_eq "$(wc -w <<<"$svc_loaded")" "7" \
        "and compares the seven that need no systemd to ask"
    # The third load, and the one #137 created: the namespace signal must move
    # this list not at all. The two signals were one variable, so a suite that
    # read the wrong one here would put the services plugin into every
    # `--pipe --private-network` run, where systemd is not PID 1 and every row
    # it brings fails on the fixture rather than on the tool.
    svc_loaded="$(HARDENER_DIFF_NETNS=1 HARDENER_DIFF_BOOTED=0 bash -c 'source "$1"; printf "%s" "${DIFF_PLUGINS[*]}"' _ "$svc_suite")"
    check_status 1 "a namespace without a boot does not compare the services plugin either, because the namespace says nothing about PID 1" \
        grep -qF "$SERVICES_PLUGIN_ID" <<<"$svc_loaded"
    check_eq "$(wc -w <<<"$svc_loaded")" "7" \
        "and still compares seven, so the kernel oracle is bought without the services rows coming with it"

    # Every plugin this suite can compare must be a plugin that EXISTS. These
    # strings do two jobs: they are passed to `--plugin`, which refuses an id
    # naming nothing, and they are matched against `.plugin_id` in the scan
    # document, where an id naming nothing matches no object and every finding
    # filter over it counts zero, which reads as a clean plugin.
    #
    # Read back out of the plugin sources rather than restated here, which is
    # how the firewall self-test pins its backend kinds. `services-hardening`
    # was written into this file first and is not a plugin: the id is
    # `service-minimisation`, and nothing in a green self-test noticed.
    local svc_declared_ids svc_plugin
    svc_declared_ids="$(grep -rhoE 'PluginId::(new|from)\("[a-z-]+"\)' \
        "$DIFF_PROJECT_DIR"/crates/hardener-plugins/src/*/mod.rs \
        | grep -oE '"[a-z-]+"' | tr -d '"' | sort -u)"
    check_status 1 "the plugin sources were readable, so the ids below are compared against something" \
        test -z "$svc_declared_ids"
    for svc_plugin in "${DIFF_PLUGINS[@]}" "$SERVICES_PLUGIN_ID"; do
        check_eq "$(grep -cx "$svc_plugin" <<<"$svc_declared_ids" || true)" "1" \
            "the compared plugin '$svc_plugin' is an id the plugin sources actually declare"
    done

    # The generic finding-count control must skip services exactly as it skips
    # firewall and kernel. Services has no compared directives, so that loop
    # counts zero for it and reads the emptiness as a broken filter, failing a
    # plugin that behaved correctly.
    local svc_saved_plugins=("${DIFF_PLUGINS[@]}")
    local svc_control_total=$CHECKS_TOTAL svc_control_passed=$CHECKS_PASSED
    local svc_control_failed=$CHECKS_FAILED
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    DIFF_PLUGINS=("$SERVICES_PLUGIN_ID")
    run_preapply_control > /dev/null
    check_eq "$CHECKS_TOTAL" "0" \
        "the generic finding-count control records nothing for services, which carries a control of its own"
    DIFF_PLUGINS=("${svc_saved_plugins[@]}")
    CHECKS_TOTAL=$svc_control_total CHECKS_PASSED=$svc_control_passed
    CHECKS_FAILED=$svc_control_failed

    # The runtime word, and the same exit-status rule the boot word follows:
    # `is-active` prints `inactive` while exiting 3, so a reading taken from the
    # status throws away the only answer there was.
    local svc_active_word="" svc_active_rc=0
    systemctl() {
        printf '%s\n' "$svc_active_word"
        return "$svc_active_rc"
    }
    svc_active_word="  inactive  "
    svc_active_rc=3
    check_eq "$(systemd_unit_active_word bluetooth)" "inactive" \
        "a non-zero is-active still yields the word it printed, with the padding trimmed"
    svc_active_word=""
    svc_active_rc=4
    check_eq "$(systemd_unit_active_word bluetooth)" "" \
        "and a systemctl answering nothing leaves the word empty rather than inventing one"
    unset -f systemctl

    # The generation guards. A capture taken on the wrong side of an apply is
    # the defect these exist for: the pre-apply reading is half of what the rows
    # compare, so one taken afterwards would agree with itself, and a post-apply
    # reading taken before any apply describes the container the run started on.
    local svc_saved_generation=$APPLY_GENERATION
    APPLY_GENERATION=1
    check_status 1 "the pre-apply services capture refuses to run after an apply" \
        preapply_services_init
    APPLY_GENERATION=0
    check_status 1 "and the post-apply capture refuses to run before one" \
        services_oracle_init
    APPLY_GENERATION=$svc_saved_generation

    # The control, driven on each host it can meet. Redirected to a file rather
    # than captured with $(...), for the reason the firewall block gives above:
    # a command substitution is a subshell, so every counter the function
    # increments would be discarded and the assertions would read 0/0 whatever
    # happened.
    local svc_out
    svc_out="$(mktemp)"
    local svc_saved_total=$CHECKS_TOTAL svc_saved_passed=$CHECKS_PASSED
    local svc_saved_failed=$CHECKS_FAILED svc_saved_unaskable=$CHECKS_UNASKABLE
    local svc_saved_booted="$RUN_BOOTED"
    local svc_saved_installed="$SERVICES_INSTALLED_BEFORE"
    local svc_saved_boot_before="$SERVICES_BOOT_BEFORE" svc_saved_boot_after="$SERVICES_BOOT_AFTER"
    local svc_saved_mask_before="$SERVICES_MASK_BEFORE" svc_saved_mask_after="$SERVICES_MASK_AFTER"
    local svc_saved_active_after="$SERVICES_ACTIVE_AFTER"
    RUN_BOOTED=1

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SERVICES_INSTALLED_BEFORE="yes"
    SERVICES_BOOT_BEFORE="enabled"
    SERVICES_MASK_BEFORE="absent|"
    run_services_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "an installed, enabled, unmasked unit is the host these rows need"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SERVICES_INSTALLED_BEFORE="no"
    run_services_preapply_control > "$svc_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a missing unit fails the control, because create-container.sh installs bluez on all five images"
    check_status 0 "and the message calls the image broken rather than calling the check inapplicable" \
        grep -q "broken image" "$svc_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SERVICES_INSTALLED_BEFORE="yes"
    SERVICES_BOOT_BEFORE="disabled"
    run_services_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a unit that was already disabled fails the control, because the plugin raises no finding and every row below would then pass without it acting"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SERVICES_BOOT_BEFORE="enabled"
    SERVICES_MASK_BEFORE="link|/dev/null"
    run_services_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a mask link left behind by an earlier run voids the reading and fails the control"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SERVICES_MASK_BEFORE="notlink|"
    run_services_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "and so does an administrator's own unit file at that path, which is not the same host as an empty one"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    RUN_BOOTED=0
    SERVICES_INSTALLED_BEFORE="yes"
    SERVICES_BOOT_BEFORE="enabled"
    SERVICES_MASK_BEFORE="absent|"
    run_services_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/0/1" \
        "an unbooted run declares the control unaskable rather than passing or failing it"
    RUN_BOOTED=1

    # The rows. The hardened host first, which is the only shape all three pass.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    SERVICES_BOOT_BEFORE="enabled"
    SERVICES_BOOT_AFTER="masked"
    SERVICES_MASK_BEFORE="absent|"
    SERVICES_MASK_AFTER="link|/dev/null"
    SERVICES_ACTIVE_BEFORE="active"
    SERVICES_ACTIVE_AFTER="inactive"
    run_services_checks > "$svc_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "3/0/0" \
        "a unit that was enabled and running and is now masked and stopped passes all three rows"
    check_status 0 "and the not-at-boot row carries the word systemd read BEFORE apply, not only the one it reads now" \
        grep -q "having read 'enabled' before apply" "$svc_out"

    # The shape mask-link exists for. systemd reports a disabled unit and a
    # masked one the same way, so not-at-boot cannot tell them apart and passes
    # here; only the link can fail.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    SERVICES_BOOT_AFTER="disabled"
    SERVICES_MASK_AFTER="absent|"
    run_services_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "2/1/0" \
        "a unit disabled but not masked passes not-at-boot and fails mask-link, which is the only thing that tells the two apart"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    SERVICES_BOOT_AFTER="enabled"
    SERVICES_MASK_AFTER="link|/dev/null"
    run_services_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "2/1/0" \
        "a unit systemd still starts at boot fails not-at-boot however the link reads"

    # The link is judged by its TARGET and not by being a link. The vendor unit
    # file is what /etc/systemd/system holds on a host where somebody dropped an
    # override in, and it is not a mask.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    SERVICES_BOOT_AFTER="masked"
    SERVICES_MASK_AFTER="link|/usr/lib/systemd/system/bluetooth.service"
    run_services_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "2/1/0" \
        "a link pointing anywhere but /dev/null is not a mask"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    SERVICES_MASK_AFTER="link|/dev/null"
    SERVICES_ACTIVE_BEFORE="inactive"
    SERVICES_ACTIVE_AFTER="inactive"
    run_services_checks > "$svc_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "2/0/1" \
        "a unit that was never running leaves not-running unaskable rather than passing it"
    check_status 0 "and says so with the word it read before apply rather than with a verdict" \
        grep -q "read 'inactive' before apply" "$svc_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    SERVICES_ACTIVE_BEFORE="active"
    SERVICES_ACTIVE_AFTER="active"
    run_services_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "2/1/0" \
        "a unit still running after apply fails not-running"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    RUN_BOOTED=0
    run_services_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/0/3" \
        "an unbooted run declares all three rows unaskable rather than reading systemctl on a host that has no systemd to ask"
    RUN_BOOTED=1

    rm -f "$svc_out"
    CHECKS_TOTAL=$svc_saved_total CHECKS_PASSED=$svc_saved_passed
    CHECKS_FAILED=$svc_saved_failed CHECKS_UNASKABLE=$svc_saved_unaskable
    RUN_BOOTED="$svc_saved_booted"
    SERVICES_INSTALLED_BEFORE="$svc_saved_installed"
    SERVICES_BOOT_BEFORE="$svc_saved_boot_before"
    SERVICES_BOOT_AFTER="$svc_saved_boot_after"
    SERVICES_MASK_BEFORE="$svc_saved_mask_before"
    SERVICES_MASK_AFTER="$svc_saved_mask_after"
    SERVICES_ACTIVE_AFTER="$svc_saved_active_after"

    # === The audit oracle ===
    #
    # Its three rows read absolute paths on the live host, so those belong to a
    # container run and not to this. What is driven here is everything the rows
    # are read THROUGH: the three constants, which are copies of values the
    # plugin owns, and the pre-apply control, which is the only thing standing
    # between the compiled-file row and a container that shipped the rule.
    #
    # The constants were pinned in prose alone. AUDIT_PROBE_RULE's comment said
    # the self-test read it back out of audit/mod.rs "so the two cannot drift",
    # and no such check had been written: a rule the plugin renamed would have
    # left the row asking whether the tool wrote what this suite imagined, which
    # is a question about this suite. No validator reads prose.
    local au_source="$DIFF_PROJECT_DIR/crates/hardener-plugins/src/audit/mod.rs"
    check_status 0 "the audit plugin's source is readable, so the constants below are compared against something" \
        test -r "$au_source"
    check_eq "$(grep -cF -- "\"$AUDIT_PROBE_RULE\"" "$au_source" || true)" "1" \
        "the probe rule is one of the plugin's own, read back out of its AUDIT_RULES table rather than restated here"
    check_eq "$(grep -cF -- "\"$AUDIT_RULES_FILE\"" "$au_source" || true)" "1" \
        "and the rules file this suite stats is the path the plugin declares it writes"
    # The plugin does name the compiled file, at AUDIT_COMPILED_RULES, and this
    # assertion was written expecting it not to. It names it to capture it into
    # the checkpoint, and nothing writes it: augenrules produces the content.
    # The independence this oracle rests on is over who WRITES that file, not
    # over who knows its path, and asserting the stronger thing would have made
    # a correct rollback capture fail a test about the oracle.
    check_eq "$(grep -cF -- "\"$AUDIT_COMPILED_FILE\"" "$au_source" || true)" "1" \
        "and the compiled file both read is one path, though what this suite reads there is augenrules' output and the plugin only captures it for rollback"

    local au_saved_before="$AUDIT_COMPILED_BEFORE" au_saved_generation=$APPLY_GENERATION
    local au_saved_total=$CHECKS_TOTAL au_saved_passed=$CHECKS_PASSED
    local au_saved_failed=$CHECKS_FAILED au_saved_unaskable=$CHECKS_UNASKABLE
    local au_out
    au_out="$(mktemp)"

    APPLY_GENERATION=1
    check_status 1 "the pre-apply capture refuses to run after an apply, because a reading taken then describes the host the apply produced" \
        preapply_audit_init
    APPLY_GENERATION=0

    # augenrules is a container property and this runs on the host, so the
    # answer is injected exactly as the services words are. Both sides of it
    # matter: the unaskable branch is what a fixture without the audit package
    # gets, and reading it as a pass would be the whole oracle bought for free.
    audit_askable() { return "$au_askable_rc"; }
    local au_askable_rc=1
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    AUDIT_COMPILED_BEFORE="absent"
    run_audit_preapply_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/0/1" \
        "a fixture without augenrules declares the control unaskable rather than passing it, because a tool that cannot be asked has agreed with nothing"

    au_askable_rc=0
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    run_audit_preapply_control > "$au_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "1/0/0" \
        "a compiled file that did not exist before apply is the state the rows below ask a real question against"
    check_status 0 "and the control says which state it read, so the log carries the evidence rather than the verdict" \
        grep -q "was absent before apply" "$au_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    AUDIT_COMPILED_BEFORE="-w /etc/passwd -p wa -k identity"
    run_audit_preapply_control > "$au_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "1/0/0" \
        "a compiled file already naming OTHER rules passes, because the row below asks about one rule and not about an empty file"

    # The one this control exists for, and the shape a second differential run
    # on an unrecreated container produces.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    AUDIT_COMPILED_BEFORE="-w /etc/passwd -p wa -k identity
$AUDIT_PROBE_RULE"
    run_audit_preapply_control > "$au_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/1/0" \
        "a compiled file that already named the probe rule fails the control, because the row below would then pass whether or not the apply wrote anything"
    check_status 0 "and says to recreate the container, which is the fix rather than a rerun" \
        grep -q "recreate the container first" "$au_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    AUDIT_COMPILED_BEFORE="unreadable"
    run_audit_preapply_control > "$au_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/1/0" \
        "and a compiled file that existed and could not be read fails too, rather than being read as the absence that passes"

    unset -f audit_askable
    audit_askable() {
        command -v augenrules >/dev/null 2>&1
    }
    rm -f "$au_out"
    AUDIT_COMPILED_BEFORE="$au_saved_before"
    APPLY_GENERATION=$au_saved_generation
    CHECKS_TOTAL=$au_saved_total CHECKS_PASSED=$au_saved_passed
    CHECKS_FAILED=$au_saved_failed CHECKS_UNASKABLE=$au_saved_unaskable

    # === The MAC no-op oracle ===
    #
    # Every input here is injected. The kernel's LSM registry is a property of
    # the machine this runs on and the configuration tree is a property of the
    # container, so neither is read live, and every state that declares a row
    # unaskable is driven: an unaskable branch nobody exercises is the whole
    # oracle bought for free.
    check_eq "$(mac_lsm_names_system "capability,landlock,lockdown,yama,bpf" || echo NONE)" "NONE" \
        "a registry naming no MAC system names none, which is the host this oracle covers"
    check_eq "$(mac_lsm_names_system "capability,selinux,bpf")" "selinux" \
        "and one that names selinux says so"
    check_eq "$(mac_lsm_names_system "apparmor,capability")" "apparmor" \
        "and apparmor at the head of the list is found, because the match is between commas rather than anchored to the start"
    # Why the match is between commas rather than a substring. This suite has
    # been bitten by substring matching in two languages already.
    check_eq "$(mac_lsm_names_system "capability,selinuxfs-shim,bpf" || echo NONE)" "NONE" \
        "an LSM whose name merely CONTAINS 'selinux' is not selinux"

    # The reader itself, before it is stubbed below. Three states, because the
    # runner fallback exists to rescue exactly one of them and must not quietly
    # take over the other two.
    local mac_saved_registry="$MAC_LSM_REGISTRY" mac_saved_run_lsm="$RUN_LSM"
    local mac_reg_file
    mac_reg_file="$(mktemp)"
    printf 'capability,yama\n' > "$mac_reg_file"
    MAC_LSM_REGISTRY="$mac_reg_file"
    RUN_LSM="capability,selinux"
    check_eq "$(mac_lsm_reading)" "capability,yama" \
        "a registry readable in the container is read there, and the runner's declaration does not override it"
    MAC_LSM_REGISTRY="$mac_reg_file.absent"
    check_eq "$(mac_lsm_reading)" "capability,selinux" \
        "a registry that is not mounted falls back to the runner's reading of the host's, which is the same kernel"
    RUN_LSM=""
    check_status 1 "and with neither, the reader refuses rather than answering 'no MAC system', because those are different facts" \
        mac_lsm_reading
    # The fallback's provenance reaches the log, which is what the cost of
    # depending on the runner is paid with.
    RUN_LSM="capability,yama"
    detect_mac_askable
    check_status 0 "the control names the runner as the source when the fallback answered" \
        grep -q "runner's reading of the host's" <<<"$MAC_LSM_SOURCE"
    MAC_LSM_REGISTRY="$mac_reg_file"
    detect_mac_askable
    check_status 0 "and names the container's own registry when that answered" \
        grep -q "read in this container" <<<"$MAC_LSM_SOURCE"
    rm -f "$mac_reg_file"
    MAC_LSM_REGISTRY="$mac_saved_registry"
    RUN_LSM="$mac_saved_run_lsm"

    local mac_saved_paths=("${MAC_CONFIG_PATHS[@]}")
    local mac_saved_askable="$MAC_ASKABLE" mac_saved_reason="$MAC_UNASKABLE_REASON"
    local mac_saved_before="$MAC_CONFIG_BEFORE" mac_saved_reading="$MAC_LSM_READING"
    local mac_saved_generation=$APPLY_GENERATION
    local mac_saved_total=$CHECKS_TOTAL mac_saved_passed=$CHECKS_PASSED
    local mac_saved_failed=$CHECKS_FAILED mac_saved_unaskable=$CHECKS_UNASKABLE
    local mac_root mac_out
    mac_root="$(mktemp -d)"
    mac_out="$(mktemp)"
    mkdir -p "$mac_root/selinux"
    printf 'SELINUX=disabled\n' > "$mac_root/selinux/config"
    # Set rather than inherited from the umask, because a mode row below
    # restores this file to it and an inherited value would make that assertion
    # depend on the environment the self-test was started from.
    chmod 644 "$mac_root/selinux/config"
    MAC_CONFIG_PATHS=("$mac_root/selinux")

    local mac_reading_rc=0 mac_reading_out="capability,landlock,bpf"
    mac_lsm_reading() {
        (( mac_reading_rc == 0 )) || return "$mac_reading_rc"
        printf '%s' "$mac_reading_out"
    }

    detect_mac_askable
    check_eq "$MAC_ASKABLE" "1" \
        "a kernel naming no MAC system, with a configuration tree present, is a host this oracle can ask about"

    mac_reading_rc=1
    detect_mac_askable
    check_eq "$MAC_ASKABLE" "0" \
        "a registry that cannot be read is unaskable rather than folded into 'this kernel has no MAC system'"
    check_status 0 "and says which of the two it was, because they are different facts and are fixed in different places" \
        grep -q "cannot be read here" <<<"$MAC_UNASKABLE_REASON"

    mac_reading_rc=0
    mac_reading_out="capability,selinux,bpf"
    detect_mac_askable
    check_eq "$MAC_ASKABLE" "0" \
        "a kernel that DOES carry a MAC system is unaskable, because a no-op oracle asserted there would assert the opposite of what that host requires"
    check_status 0 "and names issue #18, which is what covering that host actually needs" \
        grep -q "issue #18" <<<"$MAC_UNASKABLE_REASON"

    mac_reading_out="capability,landlock,bpf"
    MAC_CONFIG_PATHS=("$mac_root/absent")
    detect_mac_askable
    check_eq "$MAC_ASKABLE" "0" \
        "and a configuration tree that does not exist is unaskable, because an untouched absence is one absence compared with another"

    MAC_CONFIG_PATHS=("$mac_root/selinux")
    detect_mac_askable

    APPLY_GENERATION=1
    check_status 1 "the pre-apply capture refuses to run after an apply, because a tree read then is the one the apply produced" \
        preapply_mac_init
    APPLY_GENERATION=0
    preapply_mac_init

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    run_mac_preapply_control > "$mac_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "1/0/0" \
        "the control passes on a kernel with no MAC system and a tree there to compare"
    check_status 0 "and puts the registry's own words on the log, so a reader meets the evidence and not the verdict" \
        grep -q "capability,landlock,bpf" "$mac_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    run_mac_checks > "$mac_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "1/0/0" \
        "an untouched tree passes the row this oracle exists for"

    # The row going red, which is the case the oracle is FOR: a plugin writing
    # an SELinux configuration onto a host that has no SELinux.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    printf 'SELINUX=enforcing\n' > "$mac_root/selinux/config"
    run_mac_checks > "$mac_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/1/0" \
        "a tree the apply rewrote fails, which is the whole of what this oracle is for"

    # Content is not the only way to write to a file. A mode change moves no
    # bytes and is still the plugin having touched something it must not.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    printf 'SELINUX=disabled\n' > "$mac_root/selinux/config"
    chmod 600 "$mac_root/selinux/config"
    run_mac_checks > "$mac_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/1/0" \
        "and a mode changed with the content put back fails too, because the digest carries the mode"

    # A file ADDED under the tree, which no comparison of the files that were
    # already there could see.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    chmod 644 "$mac_root/selinux/config"
    printf 'x\n' > "$mac_root/selinux/added.conf"
    run_mac_checks > "$mac_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/1/0" \
        "and a file the apply added fails, because the digest names every path under the tree rather than the ones it started with"
    rm -f "$mac_root/selinux/added.conf"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0 CHECKS_UNASKABLE=0
    MAC_ASKABLE=0
    MAC_UNASKABLE_REASON="driven from the self-test"
    run_mac_preapply_control > /dev/null
    run_mac_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED/$CHECKS_UNASKABLE" "0/0/2" \
        "an unaskable kernel declares the control and the row unaskable together, which is the pair expected_check_total subtracts as one"

    unset -f mac_lsm_reading
    mac_lsm_reading() {
        [[ -r "$MAC_LSM_REGISTRY" ]] || return 1
        tr -d '\n' < "$MAC_LSM_REGISTRY"
    }
    rm -rf "$mac_root"
    rm -f "$mac_out"
    MAC_CONFIG_PATHS=("${mac_saved_paths[@]}")
    MAC_ASKABLE="$mac_saved_askable"
    MAC_UNASKABLE_REASON="$mac_saved_reason"
    MAC_CONFIG_BEFORE="$mac_saved_before"
    MAC_LSM_READING="$mac_saved_reading"
    APPLY_GENERATION=$mac_saved_generation
    CHECKS_TOTAL=$mac_saved_total CHECKS_PASSED=$mac_saved_passed
    CHECKS_FAILED=$mac_saved_failed CHECKS_UNASKABLE=$mac_saved_unaskable

    # The absence several assertions above have as their SUBJECT, made
    # structural rather than borrowed from whichever plugin happened to be
    # uncompared that month. Twice now that borrowing has quietly expired.
    local ncp_hit=0 ncp_plugin
    for ncp_plugin in "${DIFF_PLUGINS[@]}"; do
        if [[ "$ncp_plugin" == "$NEVER_COMPARED_PLUGIN" ]]; then
            ncp_hit=1
        fi
    done
    check_eq "$ncp_hit" "0" \
        "the never-compared id is in no compared set, which is what stops a third absence assertion losing its subject to a plugin that joined"

    # The preview an operator approves, held against the apply that followed.
    # Both sides are injected here exactly as the firewall boot readings are: a
    # check that shells out live cannot be driven, and an assertion nothing
    # proves is not an oracle.
    local pa_saved_dry="$PRE_APPLY_DRY_RUN_JSON" pa_saved_names="$DIFF_PLUGIN_NAMES"
    local pa_saved_apply="$FIRST_APPLY_OUTPUT" pa_saved_generation=$APPLY_GENERATION
    local pa_saved_total=$CHECKS_TOTAL pa_saved_passed=$CHECKS_PASSED pa_saved_failed=$CHECKS_FAILED

    # The tool's own glyphs, written as escapes so this file stays ASCII. The
    # renderer prints one ahead of every plugin name and the ESC run is what
    # `colored` adds around it, so a fixture without them would not exercise the
    # one thing the parse has to tolerate.
    local pa_tick=$'\u2713' pa_cross=$'\u2717' pa_arrow=$'\u2192'
    local pa_green=$'\033[32m' pa_plain=$'\033[0m'

    DIFF_PLUGIN_NAMES="ssh-hardening|SSH Hardening
pam-hardening|PAM Authentication Hardening
permissions-hardening|File Permissions Hardening
firewall-hardening|Firewall Hardening
kernel-hardening|Kernel Hardening
audit-hardening|Audit Rules Hardening
mac-hardening|MAC System Hardening"

    # The shape `--format json apply --dry-run` prints, reduced to the keys the
    # rows read. Taken from a live run of this tree's binary at 420a52b, where
    # ssh and kernel previewed nothing at all and pam previewed issues and no
    # change.
    local pa_dry_fixture pa_apply_fixture pa_out
    pa_dry_fixture='[
  {"validation_report_plugin_id":"ssh-hardening","validation_report_issues":[],"validation_report_estimated_changes":[]},
  {"validation_report_plugin_id":"pam-hardening","validation_report_issues":[{"validation_issue_severity":"High"}],"validation_report_estimated_changes":[]},
  {"validation_report_plugin_id":"permissions-hardening","validation_report_issues":[],"validation_report_estimated_changes":["chmod 0600 /etc/shadow"]},
  {"validation_report_plugin_id":"firewall-hardening","validation_report_issues":[],"validation_report_estimated_changes":[]},
  {"validation_report_plugin_id":"kernel-hardening","validation_report_issues":[],"validation_report_estimated_changes":[]},
  {"validation_report_plugin_id":"audit-hardening","validation_report_issues":[],"validation_report_estimated_changes":[]},
  {"validation_report_plugin_id":"mac-hardening","validation_report_issues":[],"validation_report_estimated_changes":[]}
]'
    # And the shape apply_results prints, with every summary wording in it. The
    # firewall line carries the colour escapes, so the assertions below run over
    # the one line whose icon this parse could not have anchored on.
    pa_apply_fixture="$pa_arrow Applying: SSH Hardening
$pa_arrow Applying: Firewall Hardening
$pa_tick SSH Hardening - no changes needed
$pa_cross PAM Authentication Hardening - 1 of 3 change(s) applied, 2 failed
$pa_tick File Permissions Hardening - 2 change(s) applied, 1 skipped
$pa_green$pa_tick$pa_plain Firewall Hardening - 3 change(s) applied
$pa_tick Kernel Hardening - no changes needed
$pa_tick Audit Rules Hardening - no changes needed
$pa_tick MAC System Hardening - no changes needed"

    pa_out="$(mktemp)"
    PRE_APPLY_DRY_RUN_JSON="$pa_dry_fixture"
    FIRST_APPLY_OUTPUT="$pa_apply_fixture"

    check_eq "$(dry_run_preview_reading pam-hardening)" "0|1" \
        "a preview reading keeps its changes and its issues apart, so a plugin that previewed a limitation is not read as silent"
    # NEVER_COMPARED_PLUGIN, whose absence is structural rather than borrowed.
    # This assertion named audit-hardening until audit joined the compared set,
    # then mac-hardening until mac joined it here. Each time, the fixture gained
    # the plugin and the absence the assertion was built on quietly ceased to
    # exist. A test whose subject is an ABSENCE has to name something the
    # fixtures cannot start carrying, and the guard below is what makes that
    # true of this id rather than merely true today.
    check_status 1 "a plugin the document does not cover is refused rather than answered as silent" \
        dry_run_preview_reading "$NEVER_COMPARED_PLUGIN"

    check_eq "$(apply_plugin_display_name permissions-hardening)" "File Permissions Hardening" \
        "the apply's output is joined to a plugin id by the name the tool itself prints"
    check_status 1 "and an id the tool's listing does not name is refused, because an empty name would match the space in every line" \
        apply_plugin_display_name "$NEVER_COMPARED_PLUGIN"

    # The fixture above stands in for the tool's live listing, and a live run is
    # guarded: capture_plugin_names refuses outright when the listing does not
    # name a compared plugin. Nothing guarded the fixture, and its drift was not
    # quiet. When audit joined DIFF_PLUGINS the name was not added here, so three
    # assertions below went red on their counts, which reads as the rows being
    # wrong rather than as the fixture being short one line.
    local pa_missing="" pa_plugin
    for pa_plugin in "${DIFF_PLUGINS[@]}"; do
        apply_plugin_display_name "$pa_plugin" >/dev/null \
            || pa_missing+="${pa_missing:+, }$pa_plugin"
    done
    check_eq "$pa_missing" "" \
        "the stand-in listing names every compared plugin, so a plugin added to DIFF_PLUGINS is refused here by name rather than three rows below by arithmetic"

    check_eq "$(apply_applied_count firewall-hardening)" "3" \
        "the applied count comes off the plugin's own result line, colour escapes and all"
    check_eq "$(apply_applied_count ssh-hardening)" "0" \
        "a plugin that needed nothing reads 0 rather than nothing at all"
    check_eq "$(apply_applied_count pam-hardening)" "1" \
        "a partly failed apply reads its successes alone, which is the number before 'change(s) applied' in both wordings"
    check_eq "$(apply_applied_count permissions-hardening)" "2" \
        "and a skipped tail does not move the count"

    FIRST_APPLY_OUTPUT="$pa_cross Firewall Hardening - No firewall backend: nothing installed"
    check_status 1 "a result line carrying an error where the summary would be is refused: that branch prints no count, so reading it as 0 would guess in the direction that passes" \
        apply_applied_count firewall-hardening

    # The shape the first container run of the audit oracle actually produced,
    # taken verbatim from the arch log of 2026-08-09 with its counts. The audit
    # plugin writes its rules file and fails the reload under nspawn, so its
    # result line carries an error AND a summary. output.rs printed the error
    # alone until that run, which is why this reads as a regression test rather
    # than as a shape somebody imagined: two of the six distributions could not
    # have been told apart from a plugin that applied nothing.
    FIRST_APPLY_OUTPUT="$pa_cross Audit Rules Hardening - 2 of 4 change(s) applied, 2 failed: Some changes failed"
    check_eq "$(apply_applied_count audit-hardening)" "2" \
        "a plugin that failed part way still yields the successes it did apply, because the error follows the summary rather than replacing it"

    FIRST_APPLY_OUTPUT="$(grep -v "Firewall Hardening - " <<<"$pa_apply_fixture")"
    check_status 1 "and a plugin the output holds no result line for is refused" \
        apply_applied_count firewall-hardening

    # Redirected to a file rather than captured with $(...), for the reason the
    # firewall block above gives: a command substitution is a subshell, so every
    # counter these functions increment would be discarded.
    FIRST_APPLY_OUTPUT="$pa_apply_fixture"
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    run_preview_agreement_checks > "$pa_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "6/1" \
        "the one plugin the preview was silent about and the apply then applied changes for is the one row that fails"
    check_status 0 "and the failure carries both numbers, so a reader is not sent back to the tool to find out how far apart they were" \
        grep -q "preview agreement firewall-hardening: the preview named no estimated change and no issue, and the apply then reported 3 applied change(s)" "$pa_out"
    check_status 0 "a plugin silent on both sides passes, which is the whole reason the control below has to exist" \
        grep -q "preview agreement ssh-hardening: the preview was silent and the apply applied nothing" "$pa_out"
    check_status 0 "and a plugin that previewed an issue rather than a change has spoken, so the changes it then applied were not unannounced" \
        grep -q "preview agreement pam-hardening: the preview named 0 estimated change(s) and 1 issue(s)" "$pa_out"

    # The direction this deliberately does not fail. Every preview now names a
    # change and three of the six applies report none, which is what a plugin
    # that failed partway on a container looks like from here.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_DRY_RUN_JSON="$(jq 'map(.validation_report_estimated_changes = ["a change the apply may not reach"])' <<<"$pa_dry_fixture")"
    run_preview_agreement_checks > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "7/0" \
        "a preview that named work the apply then did not do passes, because plugins fail partway on containers and making that red would fail correct runs"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_DRY_RUN_JSON="$pa_dry_fixture"
    run_preview_agreement_control > "$pa_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "the control passes when both readings answered for every compared plugin"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_DRY_RUN_JSON="$(jq 'map(select(.validation_report_plugin_id != "kernel-hardening"))' <<<"$pa_dry_fixture")"
    run_preview_agreement_control > "$pa_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a plugin the dry run never reported on fails the control, rather than leaving the other four to pass and the run to look complete"
    check_status 0 "and the control names that plugin and the side it was missing from" \
        grep -q "kernel-hardening is missing from the dry run's document" "$pa_out"

    # The vacuity a key rename produces, which is the likeliest of the three and
    # the only one that leaves the document looking entirely healthy.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_DRY_RUN_JSON="$(jq 'map(.estimated_changes = .validation_report_estimated_changes | del(.validation_report_estimated_changes))' <<<"$pa_dry_fixture")"
    run_preview_agreement_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a renamed estimated-changes key fails the control, because jq counts an absent key as nothing and nothing is exactly what a silent preview reads as"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_DRY_RUN_JSON="$pa_dry_fixture"
    FIRST_APPLY_OUTPUT="$(grep -v "Firewall Hardening - " <<<"$pa_apply_fixture")"
    run_preview_agreement_control > "$pa_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "an apply output holding no result line for a compared plugin fails the control too, on the other side of the same join"
    check_status 0 "and names that plugin against the apply's side of it" \
        grep -q "firewall-hardening is missing from the apply's output" "$pa_out"

    # Which apply the comparison is held to, and the one property here that
    # decides whether it asks anything at all: run_full_suite applies twice, and
    # the second runs on a host the first has already hardened.
    APPLY_GENERATION=1
    FIRST_APPLY_OUTPUT=""
    retain_first_apply_output "the first apply's output"
    APPLY_GENERATION=2
    retain_first_apply_output "the second apply's output"
    check_eq "$FIRST_APPLY_OUTPUT" "the first apply's output" \
        "a later apply's output does not replace the first one's, which is the only one the preview was taken ahead of"

    # Status and refusal together in one assertion, deliberately. Asked for the
    # status alone this could not be shown to discriminate: with the guard
    # removed the function falls through to a binary that is absent under
    # --self-test and returns non-zero anyway, so it would stay green over a
    # capture that no longer refuses anything.
    local pa_status=0
    APPLY_GENERATION=1
    preapply_preview_init 2>"$pa_out" >/dev/null || pa_status=$?
    check_eq "$pa_status/$(grep -c 'the pre-apply dry run was asked for at generation 1' "$pa_out")" "1/1" \
        "the preview capture refuses to be taken once apply has run, and says so before it reaches the binary, because a preview of an already hardened host agrees with itself"

    rm -f "$pa_out"
    APPLY_GENERATION=$pa_saved_generation
    PRE_APPLY_DRY_RUN_JSON="$pa_saved_dry"
    DIFF_PLUGIN_NAMES="$pa_saved_names"
    FIRST_APPLY_OUTPUT="$pa_saved_apply"
    CHECKS_TOTAL=$pa_saved_total
    CHECKS_PASSED=$pa_saved_passed
    CHECKS_FAILED=$pa_saved_failed

    # The two scan documents held against each other. Both are injected here
    # rather than captured, exactly as the firewall boot readings and the dry
    # run are: a check that shells out cannot be driven, and an assertion
    # nothing proves is not an oracle.
    local if_saved_scan="$SCAN_JSON" if_saved_pre="$PRE_APPLY_SCAN_JSON"
    local if_saved_total=$CHECKS_TOTAL if_saved_passed=$CHECKS_PASSED if_saved_failed=$CHECKS_FAILED
    local if_saved_allowances=("${INTRODUCED_FINDING_ALLOWANCES[@]}")
    local if_out if_before if_after
    if_out="$(mktemp)"

    # What a hardened host produces, derived from the same fixture so that what
    # is being tested is visible as the mutation. Four plugins resolve the one
    # finding they reported; the kernel plugin resolves its own and reports the
    # two boot-override ids measured on arch and debian on 2026-07-31, which
    # appear only after the firewall plugin has enabled ufw.
    if_before="$scan_fixture"
    if_after="$(jq 'map(.findings = (if .plugin_id == "kernel-hardening" then
            [{"finding_id": "kernel_boot_override_net_ipv4_conf_all_log_martians"},
             {"finding_id": "kernel_boot_override_net_ipv4_conf_default_log_martians"}]
          else [] end))' <<<"$scan_fixture")"
    PRE_APPLY_SCAN_JSON="$if_before"
    SCAN_JSON="$if_after"

    check_eq "$(scan_finding_ids "$if_before" kernel-hardening)" "kernel_net_ipv4_conf_all_rp_filter" \
        "the id extraction reads a plugin's findings by the key the tool emits them under"
    # Status and value in one assertion: asked for the value alone this could
    # not discriminate, because a refusal prints nothing as well and nothing is
    # what a compliant plugin correctly reads as.
    check_eq "$(scan_finding_ids "$if_after" ssh-hardening || echo REFUSED)" "" \
        "a plugin that reported no finding reads as an empty set rather than as a refusal, because that is what a hardened host looks like"
    # NEVER_COMPARED_PLUGIN for the reason given at the preview refusal above:
    # every real plugin is now in every fixture, so none of them can stand for
    # one that is not.
    check_status 1 "and a plugin the document holds no object for is refused, because an empty set introduces nothing and nothing introduced is the pass condition below" \
        scan_finding_ids "$if_before" "$NEVER_COMPARED_PLUGIN"
    check_eq "$(scan_finding_ids "$(jq 'map(.findings = (.findings | map({id: .finding_id})))' <<<"$if_before")" ssh-hardening || echo REFUSED)" "" \
        "an entry carrying no string finding_id contributes no id rather than jq's 'null', which the registry could then be made to declare"

    check_eq "$(ids_absent_from "kept" "$(printf 'kept\nnew')")" "new" \
        "the difference names what the second set holds and the first does not"
    check_eq "$(ids_absent_from "kept" "" | wc -l)" "0" \
        "and an empty candidate list is an empty set rather than one blank id, which a here-string built from an empty variable would otherwise supply"

    check_status 1 "an id no entry declares is refused by the registry" \
        introduced_finding_reason kernel-hardening kernel_boot_override_net_ipv4_conf_all_rp_filter
    check_status 1 "and an id declared under one plugin does not excuse the same id under another, because the registry is keyed on the pair" \
        introduced_finding_reason firewall-hardening kernel_boot_override_net_ipv4_conf_all_log_martians

    # Redirected to a file rather than captured with $(...), for the reason the
    # two blocks above give: a command substitution is a subshell, so every
    # counter these functions increment would be discarded.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    run_introduced_finding_checks > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "7/0" \
        "every row passes when the only findings the apply introduced are declared ones"
    check_status 0 "and the declared row carries the reason the entry gives, so a reader meets it in the log rather than being sent to the table" \
        grep -q "introduced findings kernel-hardening: every finding the apply introduced is declared: kernel_boot_override_net_ipv4_conf_all_log_martians (ufw's sysctl file sets this to 0" "$if_out"
    check_status 0 "a plugin that introduced nothing says so, rather than saying nothing" \
        grep -q "introduced findings ssh-hardening: the apply introduced no finding the plugin was not already reporting" "$if_out"

    # The registry doing the thing it exists for. With the second entry removed,
    # the second boot-override finding is exactly what 373dd7c's new finding was
    # on the run that reported 75/75 and said nothing about it.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    INTRODUCED_FINDING_ALLOWANCES=("${if_saved_allowances[0]}")
    run_introduced_finding_checks > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "6/1" \
        "an introduced finding no entry declares fails its plugin's row, and only that plugin's"
    check_status 0 "and the row names the id, because the maintainer's next move is to decide what that one finding is" \
        grep -q "no INTRODUCED_FINDING_ALLOWANCES entry declares: kernel_boot_override_net_ipv4_conf_default_log_martians" "$if_out"
    INTRODUCED_FINDING_ALLOWANCES=("${if_saved_allowances[@]}")

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SCAN_JSON="$(jq 'map(select(.plugin_id != "firewall-hardening"))' <<<"$if_after")"
    run_introduced_finding_checks > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "6/1" \
        "a plugin the post-apply document never covered fails its own row rather than reading as one that introduced nothing"
    check_status 0 "named against the document it was missing from" \
        grep -q "introduced findings firewall-hardening: the post-apply scan document holds no readable findings array" "$if_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SCAN_JSON="$if_after"
    PRE_APPLY_SCAN_JSON="$(jq 'map(select(.plugin_id != "pam-hardening"))' <<<"$if_before")"
    run_introduced_finding_checks > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "6/1" \
        "and a plugin the pre-apply document never covered fails too, on the other side of the same comparison"
    check_status 0 "named against that side, because the two absences are fixed in different places" \
        grep -q "introduced findings pam-hardening: the pre-apply scan document holds no readable findings array" "$if_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_SCAN_JSON="$if_before"
    run_introduced_finding_control > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "1/0" \
        "the control passes when the apply resolved at least one finding"
    check_status 0 "and names which plugin resolved what, so the log shows the comparison ran rather than asserting that it did" \
        grep -q "introduced findings control: the apply resolved 6 finding(s)" "$if_out"
    check_status 0 "including the plugin that resolved one finding and introduced two in the same apply" \
        grep -q "kernel-hardening resolved kernel_net_ipv4_conf_all_rp_filter" "$if_out"
    # The newest compared plugin named on the same line, so the count above is
    # not the only thing that would notice audit dropping back out of the set.
    check_status 0 "and the plugin this oracle was added for, so the count above is not the only reading that covers it" \
        grep -q "audit-hardening resolved audit_rules_missing" "$if_out"

    # The vacuity every row above passes on, and the reason this control is not
    # optional: nothing introduced is the pass condition, and a document nobody
    # can read introduces nothing.
    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SCAN_JSON="$if_before"
    run_introduced_finding_control > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "two identical documents fail the control, because an apply that resolved nothing leaves the rows above nothing to be read off"
    check_status 0 "and the refusal names all three things that produce it, rather than one" \
        grep -q "either the two documents are the same one, or the id extraction reads nothing, or the apply did nothing" "$if_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_SCAN_JSON="$(jq 'map(.findings = (.findings | map({id: .finding_id})))' <<<"$if_before")"
    SCAN_JSON="$(jq 'map(.findings = (.findings | map({id: .finding_id})))' <<<"$if_after")"
    run_introduced_finding_control > /dev/null
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a renamed finding_id key fails the control, because it empties both sides at once and validate_scan_document does not require that key the way it requires unchecked_check_id"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    PRE_APPLY_SCAN_JSON="$if_before"
    SCAN_JSON="$(jq 'map(select(.plugin_id != "kernel-hardening"))' <<<"$if_after")"
    run_introduced_finding_control > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "a plugin missing from the post-apply document fails the control even though the other four resolved findings, so coverage is not bought off by resolution"
    check_status 0 "and the control names that plugin and the side it was missing from" \
        grep -q "kernel-hardening is missing from the post-apply scan document" "$if_out"

    CHECKS_TOTAL=0 CHECKS_PASSED=0 CHECKS_FAILED=0
    SCAN_JSON="$if_after"
    PRE_APPLY_SCAN_JSON="$(jq 'map(select(.plugin_id != "ssh-hardening"))' <<<"$if_before")"
    run_introduced_finding_control > "$if_out"
    check_eq "$CHECKS_PASSED/$CHECKS_FAILED" "0/1" \
        "and one missing from the pre-apply document fails it on the other side"
    check_status 0 "named against that side" \
        grep -q "ssh-hardening is missing from the pre-apply scan document" "$if_out"

    rm -f "$if_out"
    SCAN_JSON="$if_saved_scan"
    PRE_APPLY_SCAN_JSON="$if_saved_pre"
    INTRODUCED_FINDING_ALLOWANCES=("${if_saved_allowances[@]}")
    CHECKS_TOTAL=$if_saved_total
    CHECKS_PASSED=$if_saved_passed
    CHECKS_FAILED=$if_saved_failed

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
    echo "Binary version: $(binary_version "$BINARY")"
    echo "Plugins: ${DIFF_PLUGINS[*]}"
    # Which arithmetic applied, printed where the reader of a log meets it. Two
    # lines rather than one, because they are two facts: a 0 on the first is why
    # 11 kernel rows below read as unaskable rather than missing, and a 0 on the
    # second is why the services rows do.
    echo "Own network namespace (kernel oracle): $RUN_NETNS"
    echo "Booted, systemd as PID 1 (services oracle): $RUN_BOOTED"
    detect_shadow_min_days || return 1
    echo "Shadow minimum password age: $SHADOW_MIN_DAYS"
    # The third mode signal, and it works like the two above: probed before any
    # check runs, printed where a reader of the log meets it, and subtracted from
    # the arithmetic rather than left to a row to discover. Printed with its
    # reason when it is 0, because "MAC oracle: 0" alone would send a reader
    # looking for a broken probe on a host where the answer is that this kernel
    # has a MAC system and the oracle deliberately does not cover it.
    detect_mac_askable
    if (( MAC_ASKABLE == 1 )); then
        echo "MAC no-op oracle (kernel LSM registry): 1 ($MAC_LSM_READING, from $MAC_LSM_SOURCE)"
    else
        echo "MAC no-op oracle (kernel LSM registry): 0, $MAC_UNASKABLE_REASON"
    fi

    # Task 7's acceptance criterion, and it runs first, above every seed and
    # every capture below: its own baseline is "whatever this container
    # shipped", which is only true while nothing else here has touched
    # sshd_config yet. It applies and rolls that apply back, and hands the
    # generation counter back only once its own assertion has proved the
    # container is standing where it started, so the seed below still meets
    # the generation 0 it requires. A failure leaves the container hardened
    # and therefore ends the run: see the gate above the function.
    run_rollback_reload_check || return 1

    # Before every capture below, because all of them describe a container that
    # has to already be holding the seed.
    seed_stricter_than_baseline || return 1
    # Above preapply_kernel_init, so the capture below sees the seeded value
    # rather than what the container shipped. Taken the other way round the
    # pre-apply control would score the seeded parameter against a reading the
    # seed had already replaced.
    seed_kernel_stricter_than_baseline || return 1
    # Above the same capture, and for the same reason. This one is what gives
    # the pre-apply control something to measure on a container that arrives
    # already at every target, which is the run RHEL could not otherwise reach.
    seed_kernel_looser_than_baseline || return 1
    preapply_seeded_init || return 1
    preapply_scan_oracle_init || return 1
    # The other capture that must be taken above apply, and for a second
    # reason: it is not a control over the checks below, it is half of what
    # they compare. Taken after apply it would agree with itself.
    preapply_vendor_survival_init || return 1
    preapply_firewall_init || return 1
    preapply_services_init || return 1
    preapply_kernel_init || return 1
    preapply_audit_init || return 1
    preapply_mac_init || return 1
    # Last of the pre-apply captures, deliberately. It previews the host the
    # apply below is about to meet, so every seed written above has to be in
    # place first or the preview and the run describe different hosts.
    preapply_preview_init || return 1

    apply_hardening

    # Between the two applies: what one apply produced, which is what the second
    # must not move.
    first_apply_idempotence_init || return 1

    apply_hardening

    # Every capture below is therefore taken after TWO applies, which is
    # deliberate and strengthens the checks that were already here: they now
    # assert that the hardening holds on the run after the one that established
    # it, not merely that one apply reached its targets. A directive a second
    # apply un-hardens now fails its own check as well as the idempotency one.
    # First of the post-apply captures, deliberately. The two below it create and
    # remove a probe account, and useradd and userdel rewrite /etc/passwd and
    # /etc/shadow: a mode captured after them describes what those tools left
    # behind as much as what the apply set, and this suite exists to measure the
    # apply. Taken here it is the closest reading to the apply available.
    permissions_oracle_init || return 1
    ssh_oracle_init || return 1
    login_defs_oracle_init || return 1
    vendor_survival_oracle_init || return 1
    scan_oracle_init || return 1
    firewall_oracle_init || return 1
    services_oracle_init || return 1

    run_preapply_control
    run_firewall_preapply_control
    run_services_preapply_control
    run_kernel_preapply_control
    run_audit_preapply_control
    run_mac_preapply_control
    run_seeded_checks
    run_ssh_checks
    run_login_defs_checks
    run_permission_checks
    run_vendor_survival_checks
    run_idempotence_checks
    run_pwquality_enforcement_checks
    run_firewall_checks
    run_audit_checks
    run_mac_checks
    run_services_checks
    run_kernel_checks
    run_seeded_kernel_check
    # Its control sits here beside its rows rather than up with the three
    # pre-apply controls, because what it guards is not a property the container
    # held before the apply but the two parses these rows are read through.
    run_preview_agreement_control
    run_preview_agreement_checks
    # Beside its own rows for the same reason, and last because it is the only
    # block that holds the two scan documents against each other: everything
    # above interrogates one of them at a time.
    run_introduced_finding_control
    run_introduced_finding_checks
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
