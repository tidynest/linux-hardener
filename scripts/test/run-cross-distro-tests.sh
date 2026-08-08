#!/bin/bash
# =============================================================================
# CROSS-DISTRO TEST RUNNER - Linux Hardener
# =============================================================================
# Runs full-test-suite.sh, or differential-suite.sh with --differential, across
# all supported distributions using systemd-nspawn --pipe (non-interactive, no
# boot/login needed), or with --booted under the container's own systemd.
# Serial by default; --parallel tests multiple distros simultaneously with
# background processes, up to --jobs of them at a time.
#
# Usage: sudo ./scripts/test/run-cross-distro-tests.sh [OPTIONS]
#
# Options:
#   --apply           Enable destructive tests (apply + rollback)
#   --booted          Boot under systemd rather than --pipe (services, audit,
#                     firewall need PID 1 to be a service manager)
#   --differential    Run differential-suite.sh instead of full-test-suite.sh
#   --distro NAME     Run only one distro (arch|debian|ubuntu|fedora|rhel|opensuse)
#   --gui             Run GUI tests (Playwright Web UI) after CLI tests
#   --parallel        Run distros in parallel instead of serially
#   --jobs N          Max parallel jobs (with --parallel; default: 3)
#   --rebuild         Build musl binary before testing
#   --self-test       Assert this runner's own reporting, then exit
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results"

# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"
# shellcheck source=../lib/parallel.sh
source "$SCRIPT_DIR/../lib/parallel.sh"

TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
MUSL_BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"

# Options
DO_APPLY=false
DO_BOOTED=false
DO_DIFFERENTIAL=false
SINGLE_DISTRO=""
DO_GUI=false
DO_REBUILD=false
PARALLEL=false
MAX_JOBS=3
DO_SELF_TEST=false

# =============================================================================
# Argument parsing
# =============================================================================

# Kept because `--self-test` is the one flag that must arrive alone, and the
# parse loop below consumes the count it would be judged by.
ARGC_AT_START=$#

while [[ $# -gt 0 ]]; do
    case $1 in
        --apply)
            DO_APPLY=true
            shift
            ;;
        --booted)
            DO_BOOTED=true
            shift
            ;;
        --differential)
            DO_DIFFERENTIAL=true
            shift
            ;;
        --distro)
            SINGLE_DISTRO="$2"
            if [[ -z "${CONTAINERS[$SINGLE_DISTRO]+_}" ]]; then
                echo "Unknown distro: $SINGLE_DISTRO"
                echo "Valid: ${!CONTAINERS[*]}"
                exit 1
            fi
            shift 2
            ;;
        --gui)
            DO_GUI=true
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --rebuild)
            DO_REBUILD=true
            shift
            ;;
        --self-test)
            DO_SELF_TEST=true
            shift
            ;;
        --help|-h)
            cat << EOF
Cross-Distro Test Runner for Linux Hardener

Usage: sudo $0 [OPTIONS]

Options:
  --apply           Enable destructive tests (apply + rollback)
  --booted          Boot the container under systemd instead of --pipe, so
                    systemd is PID 1 and services/audit/firewall are testable.
                    Leaves a machine running if interrupted: clear it with
                    'machinectl terminate <container-name>'
  --differential    Run differential-suite.sh instead of full-test-suite.sh
  --distro NAME     Run only one distro (arch|debian|ubuntu|fedora|rhel|opensuse)
  --gui             Run GUI tests (Playwright Web UI) after CLI tests
  --parallel        Run distros in parallel instead of serially, up to --jobs
                    of them at a time
  --jobs N          Max parallel jobs (with --parallel; default: 3)
  --rebuild         Build musl binary before testing
  --self-test       Assert this runner's own count parsing and reporting and
                    exit. Needs no root, no container and no binary
  --help            Show usage

--differential asks each setting's real consumer what the system is enforcing
and compares that against what the tool reported. It ALWAYS applies hardening,
whether or not --apply is given, and it creates and removes a probe account, so
it replaces the full suite for that run rather than running alongside it. A
failure means the system disagrees with the tool: a product defect, not a
flaky test.

Output, with the differential suite writing under a prefix of its own so that
running both suites leaves both results rather than only the second:
  test-results/<distro>.log                Per-distro full output
  test-results/summary.txt                 Aggregated results table
  test-results/differential-<distro>.log   The same, for --differential
  test-results/differential-summary.txt

Containers must exist at /var/lib/machines/<name>.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# Reading and reporting one distribution's counts
#
# Everything in this block is pure: it reads a log or four numbers and returns
# text. It sits above the pre-flight so `--self-test` can exercise it without
# root and without a container, which is the whole reason this runner had no
# self-test before and its reporting could not be fixed with evidence.
# =============================================================================

# Parse pass/fail/skip/total counts from a log (strips ANSI escape codes);
# echoes "passed failed skipped total unaskable" on one line.
#
# `Unaskable` is written by differential-suite.sh alone, and only when the
# count is above zero, so a full-suite log reads it as the zero it is. It is a
# fifth number rather than a kind of skip: those rows are declared in advance
# as ones this fixture cannot be asked, they never enter the suite's total, and
# a differential run that reports nothing about them reconciles trivially while
# saying nothing about the part of the run that did not happen.
parse_log_counts() {
    local stripped
    stripped=$(sed 's/\x1b\[[0-9;]*m//g' "$1")
    local passed failed skipped total unaskable
    passed=$(echo "$stripped" | grep -oP 'Passed:\s+\K\d+' 2>/dev/null || echo "0")
    failed=$(echo "$stripped" | grep -oP 'Failed:\s+\K\d+' 2>/dev/null || echo "0")
    skipped=$(echo "$stripped" | grep -oP 'Skipped:\s+\K\d+' 2>/dev/null || echo "0")
    total=$(echo "$stripped" | grep -oP 'Total Tests:\s+\K\d+' 2>/dev/null || echo "0")
    unaskable=$(echo "$stripped" | grep -oP 'Unaskable:\s+\K\d+' 2>/dev/null || echo "0")
    echo "$passed $failed $skipped $total $unaskable"
}

# Splits a run's skips into the ones its total already holds and the ones it
# never saw. Echoes "counted uncounted".
#
# The first number is derived as declared-minus-resolved, so it is precisely
# "announced and never given a verdict" rather than "skipped". Those are the
# same thing only while every announcement ends in a pass, a failure or a skip.
# The wording at the print sites says what is measured rather than what it is
# believed to mean, because a check that fell out of its section without a
# verdict would otherwise be reported confidently as a skip.
#
# Both suites count `log_test` announcements into TESTS_TOTAL. A skip taken
# after such an announcement occupies a slot that never becomes a pass; a skip
# taken before one never enters the total at all. So passed + failed is
# routinely short of total, and the difference is not a count of silent
# failures however much it reads like one: on the 2026-08-02 sweep it was
# "146/149 passed, 9 skipped", which is a complete and correct run, and it was
# read as three failures.
#
# Numbers that cannot be reconciled echo "? ?" rather than a negative. That is
# a parse that went wrong rather than a run that did, and a negative count
# dressed up as a total would be a third thing for a reader to misread.
reconcile_skips() {
    local passed="$1" failed="$2" skipped="$3" total="$4" counted uncounted
    counted=$(( total - passed - failed ))
    uncounted=$(( skipped - counted ))
    if (( counted < 0 || uncounted < 0 )); then
        echo "? ?"
        return
    fi
    echo "$counted $uncounted"
}

# One distribution's counts as one line, used by both result-line paths. The
# two summary tables are columnar and share `distro_table_fields` instead.
#
# Shared because the green and the red path had come to say different things
# about the same four numbers: the green one never printed the failure count at
# all, so a reader had to infer it from the arithmetic, and the arithmetic does
# not work without the split above. One formatter means a clean run and a
# failed one are read the same way.
format_distro_counts() {
    local passed="$1" failed="$2" skipped="$3" total="$4" unaskable="${5:-0}"
    local counted uncounted line
    read -r counted uncounted <<< "$(reconcile_skips "$passed" "$failed" "$skipped" "$total")"
    line="$(printf '%s declared, %s passed, %s failed, %s skipped' \
        "$total" "$passed" "$failed" "$skipped")"

    # The split is printed only where there is something to reconcile. A run
    # whose passes and failures account for everything it declared needs no
    # parenthetical, and a differential run is that run by construction.
    if [[ "$counted" != "0" || "$skipped" != "0" ]]; then
        line+="$(printf ' (%s declared without a verdict, %s never declared)' \
            "$counted" "$uncounted")"
    fi

    # Unaskable rows are the differential suite's own axis and never enter its
    # total, so a run reporting only the reconciled quadruple says nothing at
    # all about the checks it declined to ask. That count is the one compared
    # between distributions, and a move in it is the finding.
    if [[ "$unaskable" != "0" ]]; then
        line+="$(printf ', %s unaskable and never asked' "$unaskable")"
    fi

    printf '%s' "$line"
}

# One distribution's whole result line, prefix and colour included.
#
# Both execution modes call this rather than choosing a branch each: the four
# branches they used to hold had drifted into saying four different things. The
# parallel failure line named only the failure count, the serial one named
# passes and failures but not what was declared, and neither green line
# mentioned failures at all. `$3` is the parallel flag, which changes the
# decoration and nothing about the counts.
#
# The flag sits ahead of the counts so that everything after it is a number and
# can be checked as one. Nothing binds the single call site to this signature,
# and the transposition that would cost the most is silent: `$1` and `$2`
# swapped makes `[[ "$exit_code" -eq 0 ]]` evaluate a distribution's name as an
# unset arithmetic name, which is zero, which is PASS on every distribution.
# Two of the counts swapped with each other still cannot be detected here, and
# no assertion in this file can see the call site either.
distro_result_line() {
    local distro="$1" exit_code="$2" parallel="$3"
    local passed="$4" failed="$5" skipped="$6" total="$7" unaskable="${8:-0}"
    local counts

    if [[ ! "$exit_code$passed$failed$skipped$total$unaskable" =~ ^[0-9]+$ ]] \
        || [[ "$parallel" != "true" && "$parallel" != "false" ]]; then
        echo "distro_result_line: refusing a call it cannot read: ($*)" >&2
        return 2
    fi

    counts="$(format_distro_counts "$passed" "$failed" "$skipped" "$total" "$unaskable")"

    # A run that produced no parsable counts is its own outcome: printing zeroes
    # for it would be a reconciled-looking line about a run that never reported.
    if [[ "$total" -eq 0 ]]; then
        if [[ "$parallel" == "true" ]]; then
            echo -e "[$distro] ${RED}ERR${NC}: no results parsed (exit: $exit_code)"
        else
            echo -e "  ${RED}[ERR]${NC}  No test results parsed (exit code: $exit_code)"
        fi
        return
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        if [[ "$parallel" == "true" ]]; then
            echo -e "[$distro] ${GREEN}PASS${NC}: $counts"
        else
            echo -e "  ${GREEN}[DONE]${NC} $counts"
        fi
        return
    fi

    if [[ "$parallel" == "true" ]]; then
        echo -e "[$distro] ${RED}FAIL${NC}: $counts (exit: $exit_code)"
    else
        echo -e "  ${RED}[FAIL]${NC} $counts (exit: $exit_code)"
    fi
}

# One distribution's row in the two summary tables, which are the same table
# printed twice: once into summary.txt and once to stdout with colour.
#
# The skips are split here for the reason they are split in the result line. A
# row reading `149 146 0 9` does not add up, and summary.txt is the file
# `full-test-suite.sh` itself calls the one most likely to be looked at first,
# so leaving the reconciliation out of it would have left issue #65 half open.
# Echoes eight fields: the distribution, the four the log reported, the two the
# reconciliation derives, and the unaskable count, which is zero for the full
# suite and is the number a differential sweep is compared on. The caller
# supplies the format string, the colour and which of them it has room for.
distro_table_fields() {
    local distro="$1" total="$2" passed="$3" failed="$4" skipped="$5" unaskable="${6:-0}"
    local counted uncounted
    read -r counted uncounted <<< "$(reconcile_skips "$passed" "$failed" "$skipped" "$total")"
    echo "$distro $total $passed $failed $skipped $counted $uncounted $unaskable"
}

# Asserts the block above. No root, no container, no binary.
self_test() {
    local failures=0 workdir
    workdir="$(mktemp -d)"

    check_eq() {
        local got="$1" want="$2" what="$3"
        if [[ "$got" == "$want" ]]; then
            echo "  ok   $what"
            return 0
        fi
        echo "  FAIL $what"
        echo "         expected: $want"
        echo "         got:      $got"
        failures=$((failures + 1))
    }

    check_contains() {
        local haystack="$1" needle="$2" what="$3"
        case "$haystack" in
            *"$needle"*) echo "  ok   $what" ;;
            *)
                echo "  FAIL $what"
                echo "         '$haystack' does not contain '$needle'"
                failures=$((failures + 1))
                ;;
        esac
    }

    # The parser, against a log shaped like the one a suite writes, colour and
    # all. The positive control for everything below: a reconciliation built on
    # a parser that had stopped parsing would report "0 declared" and look calm.
    printf 'Total Tests:  149\n\033[0;32mPassed:\033[0m       146\nFailed:       0\nSkipped:      9\n' \
        > "$workdir/coloured.log"
    check_eq "$(parse_log_counts "$workdir/coloured.log")" "146 0 9 149 0" \
        "the parser reads each count by its own label, through the colour escapes"

    : > "$workdir/empty.log"
    check_eq "$(parse_log_counts "$workdir/empty.log")" "0 0 0 0 0" \
        "a log carrying no counts reads as five zeroes rather than as empty fields"

    # The differential suite's own shape: no skips at all, and a count of rows
    # it declared unaskable on a line the parser did not read until now.
    printf 'Total Tests:  81\nPassed:       81\nFailed:       0\nSkipped:      0\nUnaskable:    9 (declared above, not asked on this fixture)\n' \
        > "$workdir/differential.log"
    check_eq "$(parse_log_counts "$workdir/differential.log")" "81 0 0 81 9" \
        "the unaskable count is read as a fifth number, not folded into the skips it is not"

    # The arithmetic the whole issue is about.
    check_eq "$(reconcile_skips 146 0 9 149)" "3 6" \
        "146 passed and 0 failed against 149 declared is three skips inside the total and six outside it"
    check_eq "$(reconcile_skips 149 0 0 149)" "0 0" \
        "a run with nothing skipped reconciles to no skips on either side"
    check_eq "$(reconcile_skips 146 0 1 149)" "? ?" \
        "counts that cannot be reconciled are refused rather than printed as a negative"
    check_eq "$(reconcile_skips 200 0 0 149)" "? ?" \
        "and so are counts where more passed than were ever declared"

    # The defect itself: the green path used to omit the failure count, so a
    # clean run and a failed one could not be read the same way.
    local green red
    green="$(format_distro_counts 146 0 9 149)"
    red="$(format_distro_counts 140 6 9 149)"
    check_contains "$green" "0 failed" \
        "a clean run states its failure count rather than leaving it to be inferred"
    check_eq "$green" "149 declared, 146 passed, 0 failed, 9 skipped (3 declared without a verdict, 6 never declared)" \
        "and the clean run's line reconciles: 146 + 0 + 3 is the 149 it declared"
    for field in declared passed failed skipped "declared without a verdict"; do
        check_contains "$red" "$field" \
            "the failed run names '$field' too, so both paths carry the same fields"
    done

    # The two modes this runner has, said in the line rather than left to the
    # reader. A differential run reconciles by construction, so the split it
    # would print is nothing but zeroes, and the count that does move between
    # fixtures is the one it never mentioned.
    check_eq "$(format_distro_counts 81 0 0 81 9)" \
        "81 declared, 81 passed, 0 failed, 0 skipped, 9 unaskable and never asked" \
        "a differential run names the rows it declined to ask instead of a split of no skips"
    check_eq "$(format_distro_counts 81 0 0 81 0)" \
        "81 declared, 81 passed, 0 failed, 0 skipped" \
        "and a run with nothing skipped and nothing unaskable says neither"

    # The branch selection, which is the half a formatter test cannot reach. A
    # formatter nothing calls would pass every assertion above.
    local serial_green parallel_green serial_red parallel_red serial_err
    serial_green="$(NC='' GREEN='' RED='' distro_result_line arch 0 false 146 0 9 149)"
    parallel_green="$(NC='' GREEN='' RED='' distro_result_line arch 0 true 146 0 9 149)"
    serial_red="$(NC='' GREEN='' RED='' distro_result_line arch 1 false 140 6 9 149)"
    parallel_red="$(NC='' GREEN='' RED='' distro_result_line arch 1 true 140 6 9 149)"
    serial_err="$(NC='' GREEN='' RED='' distro_result_line arch 2 false 0 0 0 0)"

    check_eq "$serial_green" \
        "  [DONE] 149 declared, 146 passed, 0 failed, 9 skipped (3 declared without a verdict, 6 never declared)" \
        "the serial clean line is the reconciled one, which is the line that was read as three failures"
    check_contains "$parallel_green" \
        "149 declared, 146 passed, 0 failed, 9 skipped (3 declared without a verdict, 6 never declared)" \
        "and the parallel clean line carries the identical counts, only the decoration differs"
    check_contains "$serial_red" \
        "149 declared, 140 passed, 6 failed, 9 skipped (3 declared without a verdict, 6 never declared)" \
        "the serial failure line carries the same fields as the clean one"
    check_contains "$parallel_red" \
        "149 declared, 140 passed, 6 failed, 9 skipped (3 declared without a verdict, 6 never declared)" \
        "and so does the parallel failure line, which used to name the failure count alone"
    check_contains "$serial_red" "(exit: 1)" \
        "a failure still reports the status the suite exited with, which the serial path did not print at all"
    check_contains "$parallel_green" "PASS" \
        "a clean run is still labelled a pass"
    check_contains "$serial_red" "[FAIL]" \
        "and a failed one a failure, so the reconciliation did not cost the verdict"
    check_contains "$serial_err" "No test results parsed" \
        "a run that parsed no counts says so rather than reconciling four zeroes into a calm line"
    check_contains "$(NC='' GREEN='' RED='' distro_result_line arch 0 false 81 0 0 81 9)" \
        "9 unaskable and never asked" \
        "and the differential shape reaches the printed line, not only the formatter under it"

    # The call site is bound by nothing but the order of seven arguments, so
    # the function refuses a call it cannot read rather than reporting one. The
    # transposition below is the one that costs the most: with the name in the
    # exit code's place, the arithmetic test reads an unset name as zero and
    # every distribution reports a pass.
    local swapped_out swapped_status flag_out flag_status
    swapped_out="$(NC='' GREEN='' RED='' distro_result_line 0 arch false 146 0 9 149 2>&1)"
    swapped_status=$?
    check_eq "$swapped_status" "2" \
        "a call with the distribution and the exit code transposed is refused rather than read as a pass"
    check_contains "$swapped_out" "refusing a call it cannot read" \
        "and it says what it was given rather than failing silently"
    flag_out="$(NC='' GREEN='' RED='' distro_result_line arch 0 yes 146 0 9 149 2>&1)"
    flag_status=$?
    check_eq "$flag_status" "2" \
        "and so is a parallel flag that is neither true nor false, which would otherwise pick the serial layout"
    check_contains "$flag_out" "refusing a call it cannot read" \
        "with the same message, since it is the same kind of unreadable call"

    # The table row, which is the other half of the same reporting defect.
    check_eq "$(distro_table_fields arch 149 146 0 9)" "arch 149 146 0 9 3 6 0" \
        "the table row splits the skips too, so 146 + 0 + 3 is the 149 beside it"
    check_eq "$(distro_table_fields arch 0 0 0 0)" "arch 0 0 0 0 0 0 0" \
        "a distribution that reported nothing has a row of zeroes rather than a question mark"
    check_eq "$(distro_table_fields arch 149 146 0 1)" "arch 149 146 0 1 ? ? 0" \
        "and a row that cannot be reconciled says so in the table as well"
    check_eq "$(distro_table_fields arch 81 81 0 0 9)" "arch 81 81 0 0 0 0 9" \
        "a differential row carries its unaskable count into the summary tables rather than only into the log"

    rm -rf "$workdir"

    if (( failures > 0 )); then
        echo "self-test: $failures assertion(s) failed"
        return 1
    fi
    echo "self-test: all reporting checks passed"
}

if [[ "$DO_SELF_TEST" == "true" ]]; then
    # Any other argument is refused rather than ignored. This block sits above
    # the root check and above the line that creates the results directory, so
    # `--apply --booted --self-test` used to exit 0 in under a second having
    # entered no container, leaving the previous run's summary.txt in place for
    # a reader to take as this run's. differential-suite.sh refuses the same
    # shape at its own entry point, and this runner reintroduced it.
    if (( ARGC_AT_START != 1 )); then
        echo "--self-test takes no other arguments, and $ARGC_AT_START were given" >&2
        echo "Run it on its own, or drop it to run the suite." >&2
        exit 1
    fi
    self_test
    exit $?
fi

# =============================================================================
# Pre-flight
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root (systemd-nspawn requires root)${NC}"
    exit 1
fi

if [[ "$DO_REBUILD" == "true" ]]; then
    echo -e "${CYAN}Building musl binary...${NC}"
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    # -p hardener-cli, not the workspace. The workspace holds src-tauri, which
    # links against the host's GTK and WebKit stack, and hardener-ui, which is
    # built for wasm32; asking musl for either of them fails the build outright
    # and takes the only binary this runner needs down with it. Identical to
    # run-package-tests.sh, which had the flag and this did not.
    cargo build --release --target x86_64-unknown-linux-musl \
        --manifest-path "$PROJECT_DIR/Cargo.toml" -p hardener-cli || {
        echo -e "${RED}Build failed${NC}"
        exit 1
    }
    TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
    MUSL_BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"
    echo -e "${GREEN}Build complete: $MUSL_BINARY${NC}"
fi

if [[ ! -x "$MUSL_BINARY" ]] && [[ ! -x "$TARGET_DIR/release/hardener" ]]; then
    echo -e "${RED}ERROR: No binary found. Build first or use --rebuild${NC}"
    exit 1
fi

# A redirected target dir sits outside the /project bind; mount it where the
# in-container scripts expect ./target.
TARGET_BIND=()
[[ "$TARGET_DIR" != "$PROJECT_DIR/target" ]] && TARGET_BIND=("--bind-ro=$TARGET_DIR:/project/target")

mkdir -p "$RESULTS_DIR"

# =============================================================================
# Run tests per distro
# =============================================================================

# Build list of distros to test
if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

# Track results for summary
declare -A RESULT_PASSED RESULT_FAILED RESULT_SKIPPED RESULT_TOTAL RESULT_EXIT
declare -A RESULT_UNASKABLE

# The suite each container runs, and the arguments it takes. The differential
# suite replaces the full suite rather than following it: it applies hardening
# unconditionally, so a run of it is never the read-only run --apply gates.
# It takes no arguments, and refuses any it is given.
#
# LOG_PREFIX is what keeps the two suites' evidence apart on disk. Both wrote
# test-results/<distro>.log and test-results/summary.txt, so running one after
# the other left only the second one's logs, and release-readiness-root.sh runs
# both in the same batch. The full suite keeps the bare names, which the docs
# and the sibling runners already name; the differential suite takes a prefix of
# its own, exactly as run-package-tests.sh writes pkg-<distro>.log.
INNER_SUITE="/project/scripts/test/full-test-suite.sh"
INNER_ARGS=()
SUITE_LABEL="full"
LOG_PREFIX=""
if [[ "$DO_DIFFERENTIAL" == "true" ]]; then
    INNER_SUITE="/project/scripts/test/differential-suite.sh"
    SUITE_LABEL="differential"
    LOG_PREFIX="differential-"
elif [[ "$DO_APPLY" == "true" ]]; then
    INNER_ARGS=(--apply)
fi

# The network namespace, and the signal that declares it, for the unbooted path.
#
# Empty for the full suite and non-empty for the differential one, which is
# narrower than it looks: --private-network is what grants CAP_NET_ADMIN, so
# adding it to a run changes what that run's firewall apply can do. The
# differential suite is the one measured under it (#137); the full suite is not,
# and giving it the flag on the strength of the other suite's reading is the
# mistake this repository keeps making.
#
# What it buys the differential suite: /proc/sys/net becomes writable, which is
# the whole of what the kernel oracle needs, so an unbooted run asks its 11
# kernel rows instead of declaring them unaskable. Measured under --pipe on
# 2026-08-08; booting is one way of having been given a namespace and never the
# condition itself.
#
# --setenv reaches the suite here because under --pipe the payload process IS
# the suite. The booted path below cannot do the same and says why.
PIPE_NETNS=()
if [[ "$DO_DIFFERENTIAL" == "true" ]]; then
    PIPE_NETNS=(--private-network --setenv=HARDENER_DIFF_NETNS=1)
fi

# The default execution mode: systemd never runs, so anything that asks the
# service manager a question is untestable here.
nspawn_suite_pipe() {
    local container_path="$1"
    systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        "${PIPE_NETNS[@]}" \
        --pipe \
        /bin/bash "$INNER_SUITE" "${INNER_ARGS[@]}"
}

# Boot the container under its own systemd and run the suite as a child of it.
#
# --private-network rather than --network-veth, measured on arch 2026-07-30
# through `systemd-run --machine` (a real child of the container's systemd, not
# nsenter, which keeps the host's capabilities and reports them instead). Both
# give CapEff 00000000fdecbfff with CAP_NET_ADMIN set, a read-write
# /proc/sys/net, and `iptables -L` rc=0. --network-veth additionally creates a
# ve-* interface on the host and needs addressing at both ends, which this suite
# has no use for: it needs the namespace, not connectivity.
#
# The private namespace is a safety requirement, not a preference. nspawn grants
# CAP_NET_ADMIN only to a container that owns its network namespace, and that is
# exactly what makes the sharing case harmless. Never hand
# --capability=CAP_NET_ADMIN to a container on the host's namespace: this suite
# runs `hardener apply --plugin firewall-hardening`, and those rules would land
# in the host's own netfilter.
#
# /proc/sys stays read-only in both configurations, so the 7 fs.* and kernel.*
# parameters remain out of reach and full-test-suite.sh's
# `apply --plugin kernel-hardening` still cannot touch this workstation. Do not
# mount it writable to "fix" a kernel oracle. The 11 net.ipv4.* parameters do
# become writable, inside the container's namespace only (host tcp_fin_timeout
# read 60 before and after a container write of 47), so the kernel apply now
# half-succeeds here where it used to fail outright.
nspawn_suite_booted() {
    local container_path="$1"
    local machine unit rc=0
    machine="$(basename "$container_path")"
    unit="hardener-suite-$machine"

    # Idempotent: a machine left behind by an interrupted run would otherwise
    # hold the container and make this look like a container-in-use failure.
    machinectl terminate "$machine" > /dev/null 2>&1 || true
    systemctl reset-failed "$unit" > /dev/null 2>&1 || true
    sleep 1

    if ! systemd-run --unit="$unit" \
        systemd-nspawn --machine="$machine" --directory="$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --boot --private-network --console=passive > /dev/null; then
        echo "FATAL: could not launch $machine"
        return 1
    fi

    # Wait for the transport itself rather than for a proxy signal. Waiting on
    # `machinectl status` looks equivalent and is not: it succeeds as soon as
    # the machine registers, long before the container's bus is listening.
    local ready=""
    for _ in $(seq 1 60); do
        if systemd-run --machine="$machine" --wait --pipe --quiet /bin/true > /dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ -z "$ready" ]]; then
        echo "FATAL: $machine booted but never accepted a command."
        echo "  'systemd-run --machine' needs dbus INSIDE the container. Only"
        echo "  debian installs it explicitly (create-container.sh); openSUSE"
        echo "  installs systemd with --no-recommends and may not have it."
        echo "  Reported as a failure rather than skipped, deliberately: an"
        echo "  undeterminable result is a failure, never a skip."
        journalctl -u "$unit" -n 20 --no-pager 2>&1 || true
        machinectl terminate "$machine" > /dev/null 2>&1 || true
        return 1
    fi

    # The two mode signals the differential suite reads. They were one signal
    # until #137, under a name that said "booted" and a comment that claimed
    # booting was what made /proc/sys/net writable. It is not: the namespace is,
    # and --private-network grants one under --pipe as well, which is why the
    # branch above now declares the namespace without any of this.
    #
    # Both are set here because this configuration genuinely has both: the
    # nspawn line above passes --private-network, and the container runs its own
    # systemd as PID 1. Neither is inferred from the other in the suite, so a
    # runner that dropped one of these would lose that oracle and keep the
    # other, which is the direction a mistake here should fail in.
    #
    # Set here rather than on the --setenv of the nspawn line above, because it
    # is THIS process that becomes the suite. The container's PID 1 is a
    # different process, and reaching the suite from its environment would
    # depend on the manager passing it down to a transient unit.
    systemd-run --machine="$machine" --wait --pipe --quiet \
        --setenv=HARDENER_DIFF_BOOTED=1 \
        --setenv=HARDENER_DIFF_NETNS=1 \
        /bin/bash "$INNER_SUITE" "${INNER_ARGS[@]}" || rc=$?

    machinectl terminate "$machine" > /dev/null 2>&1 || true
    return "$rc"
}

# The invocation shared by both execution modes.
nspawn_suite() {
    if [[ "$DO_BOOTED" == "true" ]]; then
        nspawn_suite_booted "$1"
    else
        nspawn_suite_pipe "$1"
    fi
}

echo ""
BOX_W=74
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL CROSS-DISTRO TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Suite: $SUITE_LABEL  |  Apply: $DO_APPLY  |  Max jobs: $MAX_JOBS"
else
    print_boxline "   CROSS-DISTRO TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Suite: $SUITE_LABEL  |  Apply: $DO_APPLY  |  GUI: $DO_GUI"
fi
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

# Defined once, used by both serial (foreground) and parallel (backgrounded)
# execution. Runs the selected suite for one distro and prints an immediate
# one-line result. Result-array bookkeeping happens in the caller afterwards
# (a backgrounded run_single_distro cannot mutate the parent's associative
# arrays, so both modes re-derive counts from the persisted logfile there).
run_single_distro() {
    local distro="$1"
    local container="${CONTAINERS[$distro]}"
    local container_path="/var/lib/machines/$container"
    local logfile="$RESULTS_DIR/${LOG_PREFIX}${distro}.log"

    [[ "$PARALLEL" != "true" ]] && echo -e "${CYAN}━━━ Testing: $distro ($container) ━━━${NC}"

    if [[ ! -d "$container_path" ]]; then
        if [[ "$PARALLEL" == "true" ]]; then
            echo -e "[$distro] ${YELLOW}SKIP${NC}: container not found"
        else
            echo -e "  ${RED}[SKIP]${NC} Container not found: $container_path"
        fi
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        return 99
    fi

    if [[ "$PARALLEL" == "true" ]]; then
        echo -e "[$distro] ${CYAN}Starting...${NC}"
    else
        if [[ "$DO_BOOTED" == "true" ]]; then
            echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --boot --private-network -> $(basename "$INNER_SUITE") ${INNER_ARGS[*]}"
        elif (( ${#PIPE_NETNS[@]} > 0 )); then
            # The flags, not the mode name: this line is what a reader compares
            # against the suite's own two-line header, and "--pipe" alone would
            # not account for a kernel oracle that answered.
            echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe --private-network -> $(basename "$INNER_SUITE") ${INNER_ARGS[*]}"
        else
            echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> $(basename "$INNER_SUITE") ${INNER_ARGS[*]}"
        fi
    fi

    nspawn_suite "$container_path" > "$logfile" 2>&1
    local exit_code=$?

    local passed failed skipped total unaskable
    read -r passed failed skipped total unaskable <<< "$(parse_log_counts "$logfile")"

    distro_result_line "$distro" "$exit_code" "$PARALLEL" \
        "$passed" "$failed" "$skipped" "$total" "$unaskable"
    [[ "$PARALLEL" != "true" ]] && echo ""

    return "$exit_code"
}

# Record RESULT_* for one distro by re-parsing its persisted logfile. Shared
# by both execution modes so a distro's counts are always derived the same
# way, whether run_single_distro ran in the foreground or in a background job.
record_distro_result() {
    local distro="$1" exit_code="$2"
    RESULT_EXIT[$distro]=$exit_code
    local passed failed skipped total unaskable
    read -r passed failed skipped total unaskable \
        <<< "$(parse_log_counts "$RESULTS_DIR/${LOG_PREFIX}${distro}.log")"
    RESULT_PASSED[$distro]=$passed
    RESULT_FAILED[$distro]=$failed
    RESULT_SKIPPED[$distro]=$skipped
    RESULT_TOTAL[$distro]=$total
    RESULT_UNASKABLE[$distro]=$unaskable
}

if [[ "$PARALLEL" == "true" ]]; then
    echo -e "${CYAN}Launching parallel test jobs...${NC}"
    echo ""

    launch_job_pool "$MAX_JOBS" DISTROS

    for i in "${!PIDS[@]}"; do
        pid="${PIDS[$i]}"
        distro="${PID_DISTROS[$i]}"
        wait "$pid" 2>/dev/null
        record_distro_result "$distro" "$?"
    done
else
    for distro in "${DISTROS[@]}"; do
        run_single_distro "$distro"
        record_distro_result "$distro" "$?"
    done
fi

# =============================================================================
# Generate summary
# =============================================================================

SUMMARY_FILE="$RESULTS_DIR/${LOG_PREFIX}summary.txt"

{
    if [[ "$PARALLEL" == "true" ]]; then
        echo "Parallel Cross-Distro Test Results"
        echo "==================================="
        echo "Date: $(date)"
        echo "Suite: $SUITE_LABEL"
        echo "Apply mode: $DO_APPLY"
        echo "Max parallel jobs: $MAX_JOBS"
    else
        echo "Cross-Distro Test Results"
        echo "========================"
        echo "Date: $(date)"
        echo "Suite: $SUITE_LABEL"
        echo "Apply mode: $DO_APPLY"
    fi
    echo ""
    printf "%-12s %6s %6s %6s %6s %7s %7s %5s %8s\n" "Distro" "Total" "Pass" "Fail" "Skip" "NoVdt" "Unask" "Exit" "Status"
    printf "%-12s %6s %6s %6s %6s %7s %7s %5s %8s\n" "--------" "-----" "----" "----" "----" "-----" "-----" "----" "------"

    for distro in "${DISTROS[@]}"; do
        total="${RESULT_TOTAL[$distro]:-0}"
        passed="${RESULT_PASSED[$distro]:-0}"
        failed="${RESULT_FAILED[$distro]:-0}"
        skipped="${RESULT_SKIPPED[$distro]:-0}"
        unaskable="${RESULT_UNASKABLE[$distro]:-0}"
        exit_code="${RESULT_EXIT[$distro]:-1}"

        if [[ "$exit_code" -eq 99 ]]; then
            status="MISSING"
        elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
            status="PASS"
        else
            status="FAIL"
        fi

        read -r _ row_total row_passed row_failed row_skipped row_counted _ row_unaskable \
            <<< "$(distro_table_fields "$distro" "$total" "$passed" "$failed" "$skipped" "$unaskable")"
        printf "%-12s %6s %6s %6s %6s %7s %7s %5s %8s\n" "$distro" "$row_total" "$row_passed" \
            "$row_failed" "$row_skipped" "$row_counted" "$row_unaskable" "$exit_code" "$status"
    done

    echo ""
    echo "Total = Pass + Fail + NoVdt. NoVdt counts the checks this run declared"
    echo "and never gave a verdict to; on a clean run they are the skips taken"
    echo "after the check was announced, and Skip counts every skip, announced or"
    echo "not. Unask counts the rows a differential run declared unaskable on this"
    echo "fixture and never asked; they are outside Total by design."
    echo ""
    echo "Logs: $RESULTS_DIR/${LOG_PREFIX}<distro>.log"
} > "$SUMMARY_FILE"

# Print summary to stdout with colour
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL CROSS-DISTRO SUMMARY"
else
    print_boxline "   CROSS-DISTRO SUMMARY"
fi
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-12s %6s %6s %6s %6s %7s %7s %8s${NC}\n" "Distro" "Total" "Pass" "Fail" "Skip" "NoVdt" "Unask" "Status"
printf "  %-12s %6s %6s %6s %6s %7s %7s %8s\n" "--------" "-----" "----" "----" "----" "-----" "-----" "------"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    total="${RESULT_TOTAL[$distro]:-0}"
    passed="${RESULT_PASSED[$distro]:-0}"
    failed="${RESULT_FAILED[$distro]:-0}"
    skipped="${RESULT_SKIPPED[$distro]:-0}"
    unaskable="${RESULT_UNASKABLE[$distro]:-0}"
    exit_code="${RESULT_EXIT[$distro]:-1}"

    if [[ "$exit_code" -eq 99 ]]; then
        colour="$YELLOW"
        status="MISSING"
        overall_exit=1
    elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
        colour="$GREEN"
        status="PASS"
    else
        colour="$RED"
        status="FAIL"
        overall_exit=1
    fi

    read -r _ row_total row_passed row_failed row_skipped row_counted _ row_unaskable \
        <<< "$(distro_table_fields "$distro" "$total" "$passed" "$failed" "$skipped" "$unaskable")"
    printf "  ${colour}%-12s %6s %6s %6s %6s %7s %7s %8s${NC}\n" "$distro" "$row_total" "$row_passed" \
        "$row_failed" "$row_skipped" "$row_counted" "$row_unaskable" "$status"
done

echo ""
echo -e "  Summary:  ${CYAN}$SUMMARY_FILE${NC}"
echo -e "  Logs:     ${CYAN}$RESULTS_DIR/${LOG_PREFIX}<distro>.log${NC}"
echo ""

if [[ $overall_exit -eq 0 ]]; then
    echo -e "${GREEN}All distros passed.${NC}"
else
    echo -e "${RED}Some distros had failures: check logs.${NC}"
fi

# =============================================================================
# GUI Tests (optional)
# =============================================================================

if [[ "$DO_GUI" == "true" ]]; then
    echo ""
    echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
    print_boxline ""
    print_boxline "   GUI TESTS (Web UI: Playwright)"
    print_boxline ""
    echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
    echo ""

    gui_args=()
    [[ -n "$SINGLE_DISTRO" ]] && gui_args+=(--distro "$SINGLE_DISTRO")
    [[ "$PARALLEL" == "true" ]] && gui_args+=(--parallel --jobs "$MAX_JOBS")

    if "$SCRIPT_DIR/gui/run-gui-tests.sh" "${gui_args[@]}"; then
        echo -e "${GREEN}GUI tests passed.${NC}"
    else
        echo -e "${RED}GUI tests had failures: check test-results/gui/${NC}"
        overall_exit=1
    fi
fi

exit $overall_exit
