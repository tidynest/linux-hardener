#!/usr/bin/env bash
# =============================================================================
# RELEASE READINESS ROOT BATCH - Linux Hardener
# =============================================================================
# Every suite this machine cannot run from an unprivileged agent session, in
# one invocation, so that one root prompt buys all of them.
#
# The suites batched here are the ones that need systemd-nspawn, and therefore
# root: the cross-distro suite, the differential suite, the packaging install
# tests, the Web UI GUI suite and the rollback readback. The polkit matrix is
# a host check rather than a container one and is run first, because it is
# cheap and a failure there is worth knowing before an hour of container work.
#
# Usage:
#   ./scripts/test/release-readiness-root.sh --dry-run   # unprivileged pre-check
#   sudo ./scripts/test/release-readiness-root.sh        # the real run
#   sudo ./scripts/test/release-readiness-root.sh --only differential
#
# Run --dry-run as your normal user FIRST. It performs every read-only
# pre-flight check (binary freshness, host tooling, GUI build artefacts) and
# prints the plan without touching a container, so a run that was going to
# abort in the first minute of a root session aborts before that session
# starts instead.
#
# Output:
#   test-results/release-readiness/00-preflight.log       binary identity, captured first
#   test-results/release-readiness/<suite>.log            each suite's own output
#   test-results/release-readiness/<suite>-containers.log that suite's container rebuild
#   test-results/release-readiness/<suite>/               the suite runner's own artefacts
#   test-results/release-readiness/summary.txt            the table this script prints
#
# Two properties this script is built around, both of them scars:
#
#   1. A suite that did not run must never read as a suite that passed. Every
#      suite ends as PASS, FAIL or NOTRUN, the three are printed distinctly,
#      and the process exit code is zero only when every suite reached PASS.
#
#   2. A container must never be reused between suites. A completed
#      differential run leaves its own container hardened, and the next run
#      against it fails a rotating subset that reads as a regression when every
#      one of those failures is really a pre-apply control doing its job. So
#      every container in DISTRO_ORDER is destroyed and rebuilt immediately
#      before each suite that runs inside one. The rule is uniform on purpose:
#      there is no per-suite exception for a reader to get wrong, and it is what
#      lets --only run any single suite on its own and still be trustworthy.
#
# The cost of that rule is time, not attention. Expect several hours unattended,
# most of it in container creation, and a working network throughout: the
# bootstraps fetch from pacman, apt and podman registries, and the GUI suite
# installs Playwright inside each container.
#
# NOTE FOR THE FIRST RUNNER: this script was written and reviewed but never
# executed, because the session that wrote it could not become root. Its
# argument parsing, its version gate and its plan output were exercised through
# --dry-run; nothing below the pre-flight section has been run even once.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

RESULTS_DIR="$PROJECT_DIR/test-results"
RR_DIR="$RESULTS_DIR/release-readiness"
CREATE_CONTAINER="$PROJECT_DIR/scripts/containers/create-container.sh"

# The suites, in execution order. Also the vocabulary --only accepts.
SUITE_ORDER=(polkit cross-distro differential package gui rollback)

DRY_RUN=false
ONLY_SUITE=""

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $1"; }
section()   { echo ""; echo -e "${CYAN}=== $1 ===${NC}"; echo ""; }

usage() {
    cat << EOF
Release Readiness Root Batch for Linux Hardener

Usage:
  ./scripts/test/release-readiness-root.sh --dry-run   Unprivileged pre-check
  sudo ./scripts/test/release-readiness-root.sh        Run every suite
  sudo ./scripts/test/release-readiness-root.sh --only NAME

Options:
  --dry-run     Run the read-only pre-flight checks, print the plan, write
                nothing and touch no container. Needs no privileges. Run this
                first: it fails for the same reasons the real run would.
  --only NAME   Run one suite. Valid: ${SUITE_ORDER[*]}
  --help        Show usage

Every suite that runs inside a container destroys and rebuilds all six
containers first, so --only is safe to use on its own.

Results are written under test-results/release-readiness/. The exit code is
zero only when every selected suite passed; a suite that could not run is
reported as NOTRUN and is not treated as a pass.
EOF
}

# =============================================================================
# Argument parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --only)
            if [[ $# -lt 2 ]]; then
                log_error "--only needs a suite name. Valid: ${SUITE_ORDER[*]}"
                exit 1
            fi
            ONLY_SUITE="$2"
            # Validated here rather than at dispatch, so a typo costs a second
            # rather than an hour of container rebuilds followed by nothing.
            if [[ " ${SUITE_ORDER[*]} " != *" $ONLY_SUITE "* ]]; then
                log_error "Unknown suite: $ONLY_SUITE"
                log_error "Valid: ${SUITE_ORDER[*]}"
                exit 1
            fi
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

SELECTED_SUITES=("${SUITE_ORDER[@]}")
[[ -n "$ONLY_SUITE" ]] && SELECTED_SUITES=("$ONLY_SUITE")

# =============================================================================
# Result bookkeeping
# =============================================================================
#
# Three states, never two. FAIL means the suite ran and something in it did not
# pass; NOTRUN means the suite never got to say anything, which is a different
# fact and is printed as one. Collapsing them is how a suite that never ran
# comes to read as a green line.

declare -A SUITE_STATUS SUITE_DETAIL

record_result() {
    local suite="$1" status="$2" detail="$3"
    SUITE_STATUS[$suite]="$status"
    SUITE_DETAIL[$suite]="$detail"
    case "$status" in
        PASS)   echo -e "  ${GREEN}[PASS]${NC}   $suite: $detail" ;;
        FAIL)   echo -e "  ${RED}[FAIL]${NC}   $suite: $detail" ;;
        NOTRUN) echo -e "  ${YELLOW}[NOTRUN]${NC} $suite: $detail" ;;
    esac
}

# =============================================================================
# Pure helpers
# =============================================================================
#
# Everything in this block reads state and returns a string. They are the only
# parts of this script that can be exercised without root, and they are kept
# free of side effects so that stays true.

# The version the working tree declares, read from the [workspace.package]
# block. Cargo.toml holds many `version =` lines (every dependency has one), so
# the section header is tracked rather than the first match taken.
workspace_version() {
    awk '
        /^\[/    { in_workspace_package = ($0 == "[workspace.package]"); next }
        in_workspace_package && /^version[[:space:]]*=/ {
            line = $0
            sub(/^version[[:space:]]*=[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
    ' "$PROJECT_DIR/Cargo.toml"
}

# The first line of a binary's --version, or the empty string if it will not
# answer. Kept to one line: a multi-line answer would break every comparison
# below into a shape no reader can attribute to the path printed beside it.
binary_version_line() {
    local binary="$1" output
    if ! output="$("$binary" --version 2>&1)" || [[ -z "$output" ]]; then
        return 1
    fi
    printf '%s' "${output%%$'\n'*}"
}

# The first tracked source file that is newer than the binary, or nothing.
#
# The commit check below cannot see an uncommitted edit: the binary carries the
# commit it was built at, and an edit on top of that commit leaves the identity
# string untouched while making the binary stale. This is what notices.
first_source_newer_than() {
    local binary="$1"
    find "$PROJECT_DIR/crates" "$PROJECT_DIR/src-tauri" \
        "$PROJECT_DIR/Cargo.toml" "$PROJECT_DIR/Cargo.lock" \
        -newer "$binary" \
        \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
        -print -quit 2>/dev/null
}

# =============================================================================
# Pre-flight
# =============================================================================
#
# Nothing below this section is allowed to run until all of it passes. Under
# --dry-run this is the whole script.

TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
MUSL_BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"

# A redirected target dir sits outside the /project bind, so the in-container
# scripts would not find ./target. Mounted where they expect it, exactly as
# run-cross-distro-tests.sh and run-package-tests.sh do. Only this script's own
# nspawn call (the rollback readback) needs it; the runners build their own.
TARGET_BIND=()
[[ "$TARGET_DIR" != "$PROJECT_DIR/target" ]] && TARGET_BIND=("--bind-ro=$TARGET_DIR:/project/target")

# Filled by check_binary_identity, read by the per-distro readback below.
EXPECTED_VERSION_LINE=""
# Whether the GUI suite has anything to test. Set by check_gui_artefacts.
GUI_ARTEFACTS_PRESENT=false

PREFLIGHT_FAILED=false
preflight_fail() {
    log_error "$1"
    PREFLIGHT_FAILED=true
}

check_host_commands() {
    local missing=() command_name
    for command_name in systemd-nspawn machinectl systemd-run git find stat awk; do
        command -v "$command_name" &> /dev/null || missing+=("$command_name")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        preflight_fail "Missing host commands: ${missing[*]}"
        return
    fi
    log_info "Host tooling present"
}

# The gate this whole script is built around.
#
# A container run once attributed a failure to the code when what the container
# actually held was a musl binary from an older commit. The runners check that
# a binary EXISTS; none of them checks that it is the one the tree describes.
# So three questions are asked here, and any one of them says no is an abort:
#
#   1. Does the binary's semantic version match [workspace.package]?
#   2. Was it built at the commit that is checked out?
#   3. Is any tracked source newer than the binary itself?
#
# The third is what catches an uncommitted edit, which the second cannot see.
# There is deliberately no override: an override here reintroduces exactly the
# failure this exists to prevent.
check_binary_identity() {
    local expected_version actual_line actual_version actual_commit head_commit stale_file
    local _name _rest

    if [[ ! -x "$MUSL_BINARY" ]]; then
        preflight_fail "No musl binary at $MUSL_BINARY"
        log_error "  Build it as your normal user, NOT under sudo:"
        log_error "    cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli"
        return
    fi

    if ! actual_line="$(binary_version_line "$MUSL_BINARY")"; then
        preflight_fail "$MUSL_BINARY would not report a version"
        return
    fi

    # "hardener 1.5.1 (44e20f9 2026-08-06)". The date is absent when the build
    # script could not read one, and the commit reads "release" for a tarball
    # build with no git directory; both fall through to the comparisons below
    # and are reported as the mismatches they are.
    read -r _name actual_version actual_commit _rest <<< "$actual_line"
    actual_commit="${actual_commit#(}"
    actual_commit="${actual_commit%)}"

    expected_version="$(workspace_version)"
    if [[ -z "$expected_version" ]]; then
        preflight_fail "Could not read the version from Cargo.toml [workspace.package]"
        return
    fi

    head_commit="$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo "")"
    if [[ -z "$head_commit" ]]; then
        preflight_fail "Could not read HEAD; this must run inside the git working tree"
        return
    fi

    log_info "Binary:           $MUSL_BINARY"
    log_info "Binary version:   $actual_line"
    log_info "Tree version:     $expected_version"
    log_info "Tree commit:      $head_commit"

    local mismatch=false
    if [[ "$actual_version" != "$expected_version" ]]; then
        preflight_fail "Version mismatch: binary says $actual_version, tree says $expected_version"
        mismatch=true
    fi
    if [[ "$actual_commit" != "$head_commit" ]]; then
        preflight_fail "Commit mismatch: binary built at $actual_commit, HEAD is $head_commit"
        mismatch=true
    fi

    stale_file="$(first_source_newer_than "$MUSL_BINARY")"
    if [[ -n "$stale_file" ]]; then
        preflight_fail "Source newer than the binary: $stale_file"
        mismatch=true
    fi

    if [[ "$mismatch" == "true" ]]; then
        log_error "  Every container in this run would execute that binary and every"
        log_error "  failure would be attributed to code it does not contain. Rebuild"
        log_error "  as your normal user, NOT under sudo (a root build leaves"
        log_error "  root-owned artefacts in your cargo target directory):"
        log_error "    cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli"
        return
    fi

    EXPECTED_VERSION_LINE="$actual_line"
    log_info "Binary identity verified against the working tree"
}

# The Web UI suite serves crates/hardener-ui/dist, which is gitignored and only
# exists after a trunk build. Reported here rather than discovered an hour in,
# and it is not fatal to the run: the other five suites are still worth having,
# and the GUI suite is recorded NOTRUN rather than skipped quietly.
check_gui_artefacts() {
    if [[ -f "$PROJECT_DIR/crates/hardener-ui/dist/index.html" ]]; then
        GUI_ARTEFACTS_PRESENT=true
        log_info "GUI artefacts present (crates/hardener-ui/dist/index.html)"
        return
    fi
    GUI_ARTEFACTS_PRESENT=false
    log_warn "No crates/hardener-ui/dist/index.html: the GUI suite will be recorded NOTRUN"
    log_warn "  Build it as your normal user first:"
    log_warn "    cd crates/hardener-ui && trunk build --release"
}

run_preflight() {
    section "Pre-flight"
    check_host_commands
    check_binary_identity
    check_gui_artefacts

    if [[ ! -x "$CREATE_CONTAINER" ]]; then
        preflight_fail "Not executable: $CREATE_CONTAINER"
    fi

    if [[ "$PREFLIGHT_FAILED" == "true" ]]; then
        echo ""
        log_error "Pre-flight failed. Nothing was run."
        return 1
    fi
    log_info "Pre-flight passed"
    return 0
}

# =============================================================================
# Plan
# =============================================================================

# The distro count is read from DISTRO_ORDER rather than written out, so a
# distribution added to the shared table cannot leave this plan describing a
# smaller run than the one that follows it.
describe_suite() {
    local all="all ${#DISTRO_ORDER[@]} distros (${DISTRO_ORDER[*]})"
    case "$1" in
        polkit)       echo "polkit matrix on this host (no container, non-interactive)" ;;
        cross-distro) echo "run-cross-distro-tests.sh --apply --booted, $all" ;;
        differential) echo "run-cross-distro-tests.sh --differential --booted, $all" ;;
        package)      echo "run-package-tests.sh --apply, $all" ;;
        gui)          echo "gui/run-gui-tests.sh, $all" ;;
        rollback)     echo "verify-rollback.sh inside the arch container" ;;
    esac
}

print_plan() {
    section "Plan"
    local suite index=0
    for suite in "${SELECTED_SUITES[@]}"; do
        index=$((index + 1))
        local rebuild="rebuilds all ${#DISTRO_ORDER[@]} containers first"
        [[ "$suite" == "polkit" ]] && rebuild="no container"
        [[ "$suite" == "rollback" ]] && rebuild="rebuilds the arch container first"
        echo "  $index. $suite: $(describe_suite "$suite")"
        echo "     ($rebuild)"
    done
    echo ""
    echo "  Results: $RR_DIR/"
}

# =============================================================================
# Containers
# =============================================================================

# Destroy and rebuild the named containers, checking BOTH the exit status of
# each step and the container directory itself. Neither signal is sufficient on
# its own, and each catches what the other cannot.
#
# The directory check after the clean is what proves the removal took: a clean
# that silently did nothing would leave the previous run's hardened container in
# place, and every failure the suite then reported against it would be a
# pre-apply control working rather than a defect. create-container.sh now
# refuses such a container rather than reporting success for one it did not
# build (it exits 3), so the two signals agree instead of disagreeing; the check
# is kept because it names which step went wrong, and because a create that
# exits 3 here means the clean above it failed rather than the bootstrap.
#
# The exit status is needed because bootstrap_arch does `mkdir -p` on the
# container path before pacstrap runs (create-container.sh:361) and the
# debootstrap path does the same (:402), so a bootstrap that dies halfway (a
# mirror error, a network drop during a several-hour unattended run) leaves the
# directory behind. A directory-only check would hand a half-built container to
# the suite and every failure it produced would be recorded against the code
# under test, which is the same poisoned-container scar wearing a different hat.
# The podman-based distros remove the directory themselves when their export
# fails (create-container.sh:340 and :349); arch, debian and ubuntu do not.
recreate_containers() {
    local logfile="$1"; shift
    local distros=("$@")
    local distro container container_path create_status

    # Truncated once here, then appended to, so this log describes this run
    # only. Opened for append throughout, an earlier run's FATAL lines would sit
    # above this run's with no separator and read as current. The per-suite
    # logs are opened the same way.
    : > "$logfile"

    for distro in "${distros[@]}"; do
        container="${CONTAINERS[$distro]}"
        container_path="/var/lib/machines/$container"
        log_step "Rebuilding container: $distro ($container)"

        # A machine left registered by an interrupted run holds the directory
        # and makes the removal below look like a permissions problem.
        machinectl terminate "$container" > /dev/null 2>&1 || true

        {
            echo "=== $distro: clean ==="
            "$CREATE_CONTAINER" "$distro" clean --no-confirm 2>&1 || true
        } >> "$logfile" 2>&1

        if [[ -d "$container_path" ]]; then
            log_error "Container survived clean: $container_path"
            echo "FATAL: clean left $container_path in place" >> "$logfile"
            return 1
        fi

        create_status=0
        {
            echo "=== $distro: create ==="
            "$CREATE_CONTAINER" "$distro" 2>&1 || create_status=$?
        } >> "$logfile" 2>&1

        if [[ $create_status -ne 0 ]]; then
            log_error "Container create failed: $distro (exit $create_status)"
            echo "FATAL: create exited $create_status for $distro" >> "$logfile"
            return 1
        fi

        if [[ ! -d "$container_path" ]]; then
            log_error "Container was not created: $container_path"
            echo "FATAL: create did not produce $container_path" >> "$logfile"
            return 1
        fi
    done
    return 0
}

# =============================================================================
# Artefact handling
# =============================================================================

# The fixed names each runner writes into test-results/.
#
# Named explicitly rather than matched with a glob, because a glob cannot tell
# this run's output from a file an unrelated run left behind months ago. That
# distinction is the whole point of the two functions below: everything is
# removed before the runner starts, so anything present afterwards was produced
# by the run being reported.
#
# The two run-cross-distro-tests.sh suites are listed separately because they no
# longer write the same names: the differential suite prefixes its per-distro
# logs and its summary, so the two are archived and cleared independently. The
# prefixes below are the ONLY place this script knows those names; they must
# match run-cross-distro-tests.sh's LOG_PREFIX and run-package-tests.sh's pkg-.
runner_artefacts() {
    local distro
    case "$1" in
        cross-distro)
            for distro in "${DISTRO_ORDER[@]}"; do echo "$RESULTS_DIR/$distro.log"; done
            echo "$RESULTS_DIR/summary.txt"
            ;;
        differential)
            for distro in "${DISTRO_ORDER[@]}"; do echo "$RESULTS_DIR/differential-$distro.log"; done
            echo "$RESULTS_DIR/differential-summary.txt"
            ;;
        package)
            for distro in "${DISTRO_ORDER[@]}"; do echo "$RESULTS_DIR/pkg-$distro.log"; done
            echo "$RESULTS_DIR/pkg-summary.txt"
            ;;
        gui)
            echo "$RESULTS_DIR/gui"
            ;;
    esac
}

# Every removal in this script goes through here. A guard, not a formality:
# each target is assembled from variables and this script runs as root, so it
# is proved to sit inside the project's own results tree before it is removed.
remove_results_path() {
    local path="$1"
    if [[ -z "$RESULTS_DIR" || "$RESULTS_DIR" != "$PROJECT_DIR/"* || "$path" != "$RESULTS_DIR/"* ]]; then
        log_error "Refusing to remove a path outside the results tree: $path"
        return 1
    fi
    rm -rf "$path"
}

clear_runner_artefacts() {
    local path
    while read -r path; do
        remove_results_path "$path" || return 1
    done < <(runner_artefacts "$1")
    return 0
}

# The sub-runners write to fixed names in a shared results directory, so each
# suite's artefacts are copied aside under its own directory here as soon as it
# finishes. That is what keeps a suite's evidence attributable to it after the
# next suite has run: the copy is per suite even where the names are not.
archive_artefacts() {
    local suite="$1" path source
    local destination="$RR_DIR/$suite"

    # Cleared rather than merged into, so the promise made above holds here too:
    # what is in this directory afterwards came from the run being reported. A
    # second run into the same results tree would otherwise leave the first
    # run's per-distro logs sitting beside this one's.
    if ! remove_results_path "$destination"; then
        # Not fatal, and deliberately not an early exit that would throw away
        # the suites still to run. The version readback below finds no logs and
        # records the suite as a failure, which is the fail-closed direction.
        log_error "Not archiving $suite: $destination could not be cleared"
        return 0
    fi

    mkdir -p "$destination"
    while read -r path; do
        [[ -e "$path" ]] || continue
        # An artefact can be a directory: the GUI suite writes a whole
        # test-results/gui tree. Copying the directory itself would land it at
        # <suite>/<name>/, a level deeper than the <suite>/ layout scripts
        # README documents, so its contents are copied instead.
        source="$path"
        [[ -d "$path" ]] && source="$path/."
        cp -a "$source" "$destination/" || log_warn "Could not copy $path"
    done < <(runner_artefacts "$suite")
}

# Read the binary version back out of what the container actually reported.
#
# Pre-flight proved the binary on this host is current. This proves the binary
# the container executed is the same one, which is a different claim: the
# container reaches it through a bind mount that could have been pointed
# somewhere else, and the runner would not notice. Both the full suite and the
# differential suite print the version string; grepping for the exact string
# works for either, whatever label or colour precedes it.
#
# A log that does not carry the line at all fails this check rather than
# passing it, and so does a log that is not there. That is the whole point:
# silence is not agreement. Iterating the distros by name rather than
# globbing whatever landed in the directory is what makes an absent log
# visible; a glob would simply have nothing to loop over and report success.
assert_container_binary_version() {
    local suite="$1" prefix="${2:-}" distro logfile
    local missing=() mismatched=()

    # An empty needle makes grep -qF match every line of every log, so the one
    # function whose purpose is to refuse silence would become a guaranteed
    # pass. No path currently reaches here with the version line unset, which is
    # precisely why the invariant is asserted rather than assumed.
    if [[ -z "$EXPECTED_VERSION_LINE" ]]; then
        log_error "No verified binary version to read back for suite $suite"
        return 1
    fi

    for distro in "${DISTRO_ORDER[@]}"; do
        logfile="$RR_DIR/$suite/${prefix}${distro}.log"
        if [[ ! -f "$logfile" ]]; then
            missing+=("$distro")
        elif ! grep -qF "$EXPECTED_VERSION_LINE" "$logfile"; then
            mismatched+=("$distro")
        fi
    done

    if [[ ${#missing[@]} -eq 0 && ${#mismatched[@]} -eq 0 ]]; then
        return 0
    fi

    log_error "Binary version readback failed for suite $suite"
    log_error "  expected: $EXPECTED_VERSION_LINE"
    [[ ${#missing[@]} -gt 0 ]] && log_error "  no log at all: ${missing[*]}"
    [[ ${#mismatched[@]} -gt 0 ]] && log_error "  reported a different binary: ${mismatched[*]}"
    return 1
}

# =============================================================================
# Suites
# =============================================================================
#
# Every suite here is EXPECTED to be able to exit non-zero, so each invocation
# ends in `|| exit_code=$?`, which is what keeps `set -e` from ending the run
# at the first failing suite. Output is redirected to a file and the exit code
# read straight afterwards, never through a pipeline: this project's shell is
# zsh, where ${PIPESTATUS[0]} is empty, and a gate read that way reports a pass
# for a suite that never ran.

# The polkit matrix asks about this host: is polkitd running, is the policy file
# installed under /usr/share/polkit-1/actions, does pkaction parse it, is there
# an authentication agent. It needs the package installed on the host, and it
# needs no container.
#
# Run as root, deliberately, and left that way. Nothing in the matrix requires
# root, and its desktop detection reads XDG_CURRENT_DESKTOP which sudo does not
# forward; but the detection falls back to a system-wide pgrep for the
# compositor, so the answer is the same either way, and its agent detection is
# a system-wide pgrep to begin with. Dropping back to the invoking user would
# mean forwarding a graphical session into a root shell, which is more moving
# parts for no change in the result.
#
# --interactive is deliberately NOT passed: it blocks on a human at an
# authentication dialog. Its three tests are reported as skips by the matrix
# itself and must be run by hand.
suite_polkit() {
    local logfile="$RR_DIR/polkit.log" exit_code=0
    log_step "Polkit matrix (host)"
    "$PROJECT_DIR/scripts/test/polkit/test-polkit-matrix.sh" > "$logfile" 2>&1 || exit_code=$?

    # Exit 2 is the matrix's "could not ask" state: a precondition was absent, so
    # checks were skipped rather than failed. That is NOTRUN here, not FAIL. Folding
    # it into FAIL would report a host without the package installed as a defect in
    # the code, which is the conflation the matrix was fixed to stop making.
    case $exit_code in
        0) record_result polkit PASS "all automated checks passed (3 interactive tests skipped)" ;;
        2) record_result polkit NOTRUN "a precondition was absent, see $logfile" ;;
        *) record_result polkit FAIL "exit $exit_code, see $logfile" ;;
    esac
}

# The full suite, across every distro in DISTRO_ORDER, booted and applying.
#
# --booted and --apply together are what make this the deepest run the suite
# has: full-test-suite.sh declares its own expected size from those two flags,
# and an unbooted run declares six fewer checks because the services rollback
# rows cannot be asked without a service manager as PID 1.
#
# Note that this runner's own --rebuild flag is NOT used. See the comment on
# suite_package for why.
suite_cross_distro() {
    local logfile="$RR_DIR/cross-distro.log" exit_code=0
    recreate_containers "$RR_DIR/cross-distro-containers.log" "${DISTRO_ORDER[@]}" || {
        record_result cross-distro NOTRUN "container rebuild failed, see cross-distro-containers.log"
        return
    }

    clear_runner_artefacts cross-distro || {
        record_result cross-distro NOTRUN "could not clear stale runner output"
        return
    }

    log_step "Cross-distro full suite (--apply --booted)"
    "$PROJECT_DIR/scripts/test/run-cross-distro-tests.sh" --apply --booted \
        > "$logfile" 2>&1 || exit_code=$?

    archive_artefacts cross-distro

    if [[ $exit_code -ne 0 ]]; then
        record_result cross-distro FAIL "exit $exit_code, see $logfile"
        return
    fi
    if ! assert_container_binary_version cross-distro; then
        record_result cross-distro FAIL "a container ran an unverified binary, see cross-distro/"
        return
    fi
    record_result cross-distro PASS "${#DISTRO_ORDER[@]} distros, booted, apply"
}

# The differential suite, across every distro in DISTRO_ORDER, booted.
#
# It replaces the full suite rather than following it: it applies hardening
# unconditionally, so it is never the read-only run that --apply gates. Note
# that --apply is not passed alongside it and must not be read as optional here:
# the runner does not refuse the combination, it silently ignores --apply
# (run-cross-distro-tests.sh:560-565 selects the differential suite in an if and
# reaches --apply only in the elif), so a reader who added it would get no
# warning and no change. --booted is what sets HARDENER_DIFF_BOOTED=1
# inside the container, which is the only thing that makes the eleven kernel
# rows askable; without it they are declared unaskable rather than measured
# against the host's own kernel.
suite_differential() {
    local logfile="$RR_DIR/differential.log" exit_code=0
    recreate_containers "$RR_DIR/differential-containers.log" "${DISTRO_ORDER[@]}" || {
        record_result differential NOTRUN "container rebuild failed, see differential-containers.log"
        return
    }

    clear_runner_artefacts differential || {
        record_result differential NOTRUN "could not clear stale runner output"
        return
    }

    log_step "Differential suite (--differential --booted)"
    "$PROJECT_DIR/scripts/test/run-cross-distro-tests.sh" --differential --booted \
        > "$logfile" 2>&1 || exit_code=$?

    archive_artefacts differential

    if [[ $exit_code -ne 0 ]]; then
        record_result differential FAIL "exit $exit_code, see $logfile"
        return
    fi
    if ! assert_container_binary_version differential "differential-"; then
        record_result differential FAIL "a container ran an unverified binary, see differential/"
        return
    fi
    record_result differential PASS "${#DISTRO_ORDER[@]} distros, booted"
}

# The packaging install tests: mirror the PKGBUILD package() function inside
# each container, then check the file layout, the permissions, the functional
# behaviour of the installed binary, and a clean uninstall. --apply adds the
# apply, checkpoint and rollback checks through the INSTALLED binary rather
# than the one in the tree, which is the part a packaged release actually ships.
#
# --rebuild is not used here either. It would run cargo as root, and this
# machine's cargo target directory lives under the invoking user's home
# (~/.cache/cargo-target), so a root build leaves root-owned artefacts there
# and breaks the user's next unprivileged build. Pre-flight requires the binary
# instead and refuses to start without a current one.
suite_package() {
    local logfile="$RR_DIR/package.log" exit_code=0
    recreate_containers "$RR_DIR/package-containers.log" "${DISTRO_ORDER[@]}" || {
        record_result package NOTRUN "container rebuild failed, see package-containers.log"
        return
    }

    clear_runner_artefacts package || {
        record_result package NOTRUN "could not clear stale runner output"
        return
    }

    log_step "Package install tests (--apply)"
    "$PROJECT_DIR/scripts/test/run-package-tests.sh" --apply > "$logfile" 2>&1 || exit_code=$?

    archive_artefacts package

    if [[ $exit_code -ne 0 ]]; then
        record_result package FAIL "exit $exit_code, see $logfile"
        return
    fi
    # Worth asking here even though pre-flight already verified the binary:
    # this suite runs /usr/bin/hardener, installed by the package() mirror,
    # rather than the one reached through the bind mount. If the install
    # picked up the host glibc build because the musl one was not visible,
    # this is what says so.
    if ! assert_container_binary_version package "pkg-"; then
        record_result package FAIL "the installed binary was not the verified one, see package/"
        return
    fi
    record_result package PASS "${#DISTRO_ORDER[@]} distros, installed binary applied and rolled back"
}

# The Web UI suite: Playwright against the built WASM frontend with a Tauri IPC
# mock, headless inside each container. The container installs its own browser
# and Node at run time, so this one needs the network from inside the container
# as well as outside.
#
# The Tauri desktop GUI suite (gui/run-tauri-gui-tests.sh) is NOT run here. It
# wants a debug build of linux-hardener-desktop, which pre-flight does not
# verify and this script will not build for the reason given on suite_package.
suite_gui() {
    local logfile="$RR_DIR/gui.log" exit_code=0

    if [[ "$GUI_ARTEFACTS_PRESENT" != "true" ]]; then
        record_result gui NOTRUN "crates/hardener-ui/dist/index.html absent; run trunk build --release"
        return
    fi

    recreate_containers "$RR_DIR/gui-containers.log" "${DISTRO_ORDER[@]}" || {
        record_result gui NOTRUN "container rebuild failed, see gui-containers.log"
        return
    }

    clear_runner_artefacts gui || {
        record_result gui NOTRUN "could not clear stale runner output"
        return
    }

    log_step "Web UI GUI suite"
    "$PROJECT_DIR/scripts/test/gui/run-gui-tests.sh" > "$logfile" 2>&1 || exit_code=$?

    archive_artefacts gui

    if [[ $exit_code -eq 0 ]]; then
        record_result gui PASS "${#DISTRO_ORDER[@]} distros, Playwright against the built frontend"
    else
        record_result gui FAIL "exit $exit_code, see $logfile"
    fi
}

# The rollback readback. Included here because it had nowhere else to live: no
# CI job calls verify-rollback.sh, and before this script no runner called it
# either (issue #125), yet it is the only check that reads a rolled-back kernel
# parameter, sshd_config and directory mode back off the system rather than
# trusting the tool's own report.
# It needs root and a container, which is exactly the class of work this script
# exists to batch, so it costs one arch container to give it a home.
#
# It has no host-side runner to copy an invocation from, so the invocation is
# the one its own header documents, with two additions this machine needs:
# --pipe, so it cannot wait on a console that an unattended run does not have,
# and the target bind, so /project/target resolves when the cargo target
# directory is redirected out of the tree.
#
# A failure here is NOT by itself a regression in the release candidate: no
# dated run of this script exists, so its first result is a baseline. Read the
# log before drawing a conclusion from it.
suite_rollback() {
    local logfile="$RR_DIR/rollback.log" exit_code=0
    local container_path="/var/lib/machines/${CONTAINERS[arch]}"

    recreate_containers "$RR_DIR/rollback-containers.log" arch || {
        record_result rollback NOTRUN "container rebuild failed, see rollback-containers.log"
        return
    }

    log_step "Rollback readback (arch container)"
    # --private-network is what makes the runtime sysctl arm askable at all.
    # nspawn remounts /proc/sys/net read-write only for a container holding its
    # own network namespace; without it /proc/sys is the host's and read-only,
    # so that arm skipped on every run this script has ever made and the
    # capability existed without ever being exercised (issue #131).
    #
    # Measured on 2026-08-08 rather than assumed: --private-network alone is
    # enough under --pipe, and --boot is NOT required, which is what the code
    # and three documents had said. Nothing here needs the network: the script
    # runs a local binary, writes files and reads them back.
    systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --private-network \
        --pipe \
        /bin/bash /project/scripts/test/verify-rollback.sh \
        > "$logfile" 2>&1 || exit_code=$?

    # Exit 2 is "passed, and something was not asked". It is reported as its own
    # sentence rather than folded into the PASS above, because the detail line
    # is the part that gets read: the previous wording claimed kernel, ssh and
    # permissions had been read back whether or not the runtime sysctl arm had
    # run, and under --pipe it never ran. Still a PASS, because nothing failed
    # and a skip is not a regression.
    #
    # The 2 branch deliberately names no arm. There are now two that can skip,
    # the runtime sysctl one and pam where login.defs is absent, and a sentence
    # listing what was read has to be corrected every time another is added or
    # it starts overstating again. Pointing at the log cannot rot.
    case $exit_code in
        0) record_result rollback PASS \
            "kernel (file and runtime), ssh, permissions and pam read back after rollback" ;;
        2) record_result rollback PASS \
            "passed, but at least one arm was not asked, see $logfile" ;;
        *) record_result rollback FAIL \
            "exit $exit_code, see $logfile (first ever run: baseline, not a regression)" ;;
    esac
}

run_suite() {
    case "$1" in
        polkit)       suite_polkit ;;
        cross-distro) suite_cross_distro ;;
        differential) suite_differential ;;
        package)      suite_package ;;
        gui)          suite_gui ;;
        rollback)     suite_rollback ;;
        *)
            record_result "$1" NOTRUN "no dispatch for this suite name"
            ;;
    esac
}

# =============================================================================
# Summary
# =============================================================================

write_summary() {
    local summary_file="$RR_DIR/summary.txt" suite failed=0 notrun=0

    {
        echo "Release Readiness Root Batch"
        echo "============================"
        echo "Date:    $(date)"
        echo "Host:    $(uname -srm)"
        echo "Binary:  $EXPECTED_VERSION_LINE"
        echo "Suites:  ${SELECTED_SUITES[*]}"
        echo ""
        printf "%-14s %-8s %s\n" "Suite" "Status" "Detail"
        printf "%-14s %-8s %s\n" "-----" "------" "------"
        for suite in "${SELECTED_SUITES[@]}"; do
            printf "%-14s %-8s %s\n" "$suite" \
                "${SUITE_STATUS[$suite]:-NOTRUN}" \
                "${SUITE_DETAIL[$suite]:-never reached}"
        done
        echo ""
        echo "Logs: $RR_DIR/<suite>.log"
    } > "$summary_file"

    echo ""
    BOX_W=74
    echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
    print_boxline "   RELEASE READINESS SUMMARY"
    echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
    echo ""
    printf "  ${BOLD}%-14s %-8s${NC} %s\n" "Suite" "Status" "Detail"
    printf "  %-14s %-8s %s\n" "-----" "------" "------"

    for suite in "${SELECTED_SUITES[@]}"; do
        local status="${SUITE_STATUS[$suite]:-NOTRUN}"
        local detail="${SUITE_DETAIL[$suite]:-never reached}"
        local colour="$GREEN"
        case "$status" in
            FAIL)   colour="$RED";    failed=$((failed + 1)) ;;
            NOTRUN) colour="$YELLOW"; notrun=$((notrun + 1)) ;;
        esac
        printf "  ${colour}%-14s %-8s${NC} %s\n" "$suite" "$status" "$detail"
    done

    echo ""
    echo -e "  Summary:  ${CYAN}$summary_file${NC}"
    echo -e "  Logs:     ${CYAN}$RR_DIR/${NC}"
    echo ""

    # A suite that did not run is not a suite that passed, and the exit code
    # says so. Anything other than all-PASS is a non-zero exit.
    if [[ $failed -eq 0 && $notrun -eq 0 ]]; then
        echo -e "${GREEN}Every suite passed.${NC}"
        return 0
    fi
    if [[ $failed -gt 0 ]]; then
        echo -e "${RED}$failed suite(s) failed.${NC}"
    fi
    if [[ $notrun -gt 0 ]]; then
        echo -e "${YELLOW}$notrun suite(s) never ran. Read the detail column before"
        echo -e "treating the rest of this table as a complete result.${NC}"
    fi
    return 1
}

# The whole results tree is written by root, inside the user's repository.
# Handed back so the next unprivileged run is not blocked by root-owned files.
restore_results_ownership() {
    [[ -n "${SUDO_USER:-}" ]] || return 0
    [[ -d "$RESULTS_DIR" ]] || return 0
    # The trailing colon hands the group back too; without it the tree stays
    # group-root and a later unprivileged run can still be blocked by it.
    chown -R "$SUDO_USER:" "$RESULTS_DIR" 2>/dev/null \
        || log_warn "Could not hand $RESULTS_DIR back to $SUDO_USER"
}

# =============================================================================
# Main
# =============================================================================

BOX_W=74
echo ""
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
print_boxline "   RELEASE READINESS ROOT BATCH"
print_boxline "   Suites: ${#SELECTED_SUITES[@]}  |  Dry run: $DRY_RUN"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"

if ! run_preflight; then
    exit 1
fi

print_plan

if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    log_info "Dry run: nothing was written and no container was touched."
    log_info "Pre-flight is green, so the real run will get past this point:"
    log_info "  sudo $0${ONLY_SUITE:+ --only $ONLY_SUITE}"
    exit 0
fi

# Checked after the plan, so --dry-run stays usable by an unprivileged user.
if [[ $EUID -ne 0 ]]; then
    echo ""
    log_error "Must run as root (systemd-nspawn requires it)."
    log_error "  sudo $0${ONLY_SUITE:+ --only $ONLY_SUITE}"
    exit 1
fi

mkdir -p "$RR_DIR"

# summary.txt is written only when a traversal completes, so a run interrupted
# at hour three would otherwise leave the PREVIOUS run's summary sitting beside
# this run's fresh 00-preflight.log and partial suite logs, for a later reader
# to take as this run's result. Removed before anything else is written.
rm -f "$RR_DIR/summary.txt"

# Written before any suite runs, so the identity every result below is
# attributed to is on disk even if the run is interrupted a minute later.
{
    echo "Release readiness pre-flight"
    echo "Date:           $(date)"
    echo "Binary path:    $MUSL_BINARY"
    echo "Binary version: $EXPECTED_VERSION_LINE"
    echo "Tree version:   $(workspace_version)"
    echo "Tree commit:    $(git -C "$PROJECT_DIR" rev-parse --short HEAD)"
    echo "Tree status:    $(git -C "$PROJECT_DIR" status --porcelain | wc -l) modified path(s)"
    echo "GUI artefacts:  $GUI_ARTEFACTS_PRESENT"
    echo "Suites:         ${SELECTED_SUITES[*]}"
} > "$RR_DIR/00-preflight.log"

log_info "Binary identity recorded: $RR_DIR/00-preflight.log"

for suite_name in "${SELECTED_SUITES[@]}"; do
    section "Suite: $suite_name"
    run_suite "$suite_name"
done

SUMMARY_STATUS=0
write_summary || SUMMARY_STATUS=$?

# After write_summary, so summary.txt is handed over with everything else.
restore_results_ownership

exit "$SUMMARY_STATUS"
