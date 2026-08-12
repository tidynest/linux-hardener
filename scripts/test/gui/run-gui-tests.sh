#!/bin/bash
# =============================================================================
# WEB UI GUI TEST ORCHESTRATOR: Linux Hardener
# =============================================================================
# Runs Playwright GUI tests inside systemd-nspawn containers.
# Serial by default; --parallel tests multiple distros simultaneously with
# background processes (~6x faster when testing all six distros).
#
# Usage: sudo ./scripts/test/gui/run-gui-tests.sh [OPTIONS]
#
# Options:
#   --distro NAME     Run only one distro (arch|debian|ubuntu|fedora|rhel|opensuse)
#   --parallel        Run distros in parallel instead of serially
#   --jobs N          Max parallel jobs (with --parallel; default: 5)
#   --grep PATTERN    Run only tests whose title matches PATTERN
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results/gui"

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/../../lib/common.sh"
# shellcheck source=../../lib/parallel.sh
source "$SCRIPT_DIR/../../lib/parallel.sh"

# Options
SINGLE_DISTRO=""
PARALLEL=false
MAX_JOBS=5
GREP_PATTERN=""

# =============================================================================
# Argument parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --distro)
            SINGLE_DISTRO="$2"
            if [[ -z "${CONTAINERS[$SINGLE_DISTRO]+_}" ]]; then
                echo "Unknown distro: $SINGLE_DISTRO"
                echo "Valid: ${!CONTAINERS[*]}"
                exit 1
            fi
            shift 2
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --grep)
            GREP_PATTERN="$2"
            shift 2
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --help|-h)
            cat << 'EOF'
Web UI GUI Test Orchestrator for Linux Hardener

Usage: sudo ./scripts/test/gui/run-gui-tests.sh [OPTIONS]

Options:
  --distro NAME     Run only one distro (arch|debian|ubuntu|fedora|rhel|opensuse)
  --parallel        Run distros in parallel instead of serially (~6x speedup)
  --jobs N          Max parallel jobs (with --parallel; default: 5)
  --grep PATTERN    Run only tests whose title matches PATTERN
  --help            Show usage

Runs Playwright tests against the WASM frontend served with a Tauri IPC mock
headless inside systemd-nspawn containers.

Output:
  test-results/gui/<distro>-webui.log    Per-distro test output
  test-results/gui/screenshots/webui/    Theme screenshots
  test-results/gui/gui-summary.txt       Aggregated results

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
# Pre-flight
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root (systemd-nspawn requires root)${NC}"
    exit 1
fi

# Verify dist directory exists
if [[ ! -f "$PROJECT_DIR/crates/hardener-ui/dist/index.html" ]]; then
    echo -e "${RED}ERROR: dist/ not found. Build WASM first: cd crates/hardener-ui && trunk build --release${NC}"
    exit 1
fi

# Refuse a dist older than the frontend it is meant to be a build of. Nothing
# here runs trunk, so a source edit reaches the containers only if someone
# rebuilt by hand, and a stale bundle does not announce itself: the suite runs
# green against the previous interface, and a test written for the change fails
# as though the change were wrong. Measured once, on the T-FIND-11 declined
# exception line, which was absent from the page because it was absent from the
# wasm. Same shape as the stale musl binary the cross-distro runner used to
# serve.
NEWER_SOURCE=$(find "$PROJECT_DIR/crates/hardener-ui/src" "$PROJECT_DIR/crates/hardener-ui/styles.css" \
    -newer "$PROJECT_DIR/crates/hardener-ui/dist/index.html" -print -quit 2>/dev/null)
if [[ -n "$NEWER_SOURCE" ]]; then
    echo -e "${RED}ERROR: dist/ is older than the frontend source (${NEWER_SOURCE#"$PROJECT_DIR/"}).${NC}"
    echo -e "${RED}       The containers would serve the previous build. Rebuild first:${NC}"
    echo -e "${RED}       cd crates/hardener-ui && trunk build --release${NC}"
    exit 1
fi

mkdir -p "$RESULTS_DIR/screenshots/webui"

if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

declare -A RESULT_EXIT

BOX_W=74

# The nspawn invocation shared by both execution modes.
nspawn_gui_tests() {
    local container_path="$1"
    local distro="$2"
    local -a env_args=(--setenv="HARDENER_DISTRO=$distro")
    [[ -n "$GREP_PATTERN" ]] && env_args+=(--setenv="PLAYWRIGHT_GREP=$GREP_PATTERN")
    timeout 600 systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${env_args[@]}" \
        --pipe \
        /bin/bash /project/scripts/test/gui/gui-test-inner.sh
}

# Files the suite's artefacts under the results directory the summary points at.
#
# Done here rather than inside the container because the 600 s ceiling kills the
# container outright, so a copy placed after the suite never runs for the run
# whose artefacts are most wanted. Playwright writes into the bind mount, so the
# files are already on this side of it and this only relocates them: the first
# timed-out run left fifteen populated directories under gui-tests/test-results
# and nothing at all where the summary said to look.
# Both the source and the destination are keyed by distro. The destination
# because six distros used to write one results tree and the last one won: a
# full six-distro run left 37 screenshots on disk, all rhel's, under a summary
# reporting six passes. The source because Playwright clears outputDir when it
# starts, so an un-namespaced source is deleted by the next container before the
# copy can matter, and under --parallel it is deleted mid-run.
collect_gui_artefacts() {
    local distro="$1"
    local source_dir="$PROJECT_DIR/gui-tests/test-results/$distro"
    local report_src="$PROJECT_DIR/gui-tests/test-reports/$distro.json"
    local dest="$RESULTS_DIR/$distro"
    local shots="$RESULTS_DIR/screenshots/webui/$distro"
    [[ -d "$source_dir" ]] || return 0

    # Cleared rather than merged: a partial run must look partial instead of
    # inheriting the previous run's files under the same names.
    rm -rf "$dest" "$shots"
    mkdir -p "$dest" "$shots"

    cp -r "$source_dir"/. "$dest/" 2>/dev/null || true
    # One copy of each screenshot, at the path the summary points at. The two cp
    # lines this replaces produced screenshots/ and screenshots/webui/
    # byte-for-byte identical.
    mv "$dest/screenshots"/*.png "$shots/" 2>/dev/null || true
    rmdir "$dest/screenshots" 2>/dev/null || true
    [[ -f "$report_src" ]] && cp "$report_src" "$dest/results.json"

    # Written by root inside the container. Handed back so the artefacts can be
    # read, and the analysis re-run, without sudo.
    [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$dest" "$shots"
    return 0
}

# A distro that passed while writing no screenshots is the signature of the
# collector losing them, which read as six green rows for as long as the summary
# printed only a status. Expect 37.
count_shots() {
    find "$RESULTS_DIR/screenshots/webui/$1" -name '*.png' 2>/dev/null | wc -l
}

echo ""
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL WEB UI GUI TEST RUNNER"
    print_boxline "   Distros: ${#DISTROS[@]}  |  Max jobs: $MAX_JOBS"
else
    print_boxline "   WEB UI GUI TEST RUNNER (Playwright)"
    print_boxline "   Distros: ${#DISTROS[@]}"
fi
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

# =============================================================================
# Run tests per distro (serial or parallel)
# =============================================================================

# Defined once, used by both serial (foreground, tees to the terminal) and
# parallel (backgrounded, redirects only -- concurrent tees would interleave
# raw output) execution.
run_single_distro() {
    local distro="$1"
    local container="${CONTAINERS[$distro]}"
    local container_path="/var/lib/machines/$container"
    local logfile="$RESULTS_DIR/${distro}-webui.log"

    [[ "$PARALLEL" != "true" ]] && echo -e "${CYAN}━━━ Web UI Testing: $distro ($container) ━━━${NC}"

    if [[ ! -d "$container_path" ]]; then
        if [[ "$PARALLEL" == "true" ]]; then
            echo -e "[$distro] ${YELLOW}SKIP${NC}: container not found"
        else
            echo -e "  ${YELLOW}[SKIP]${NC} Container not found: $container_path"
        fi
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        return 99
    fi

    local exit_code
    if [[ "$PARALLEL" == "true" ]]; then
        echo -e "[$distro] ${CYAN}Starting...${NC}"
        nspawn_gui_tests "$container_path" "$distro" > "$logfile" 2>&1
        exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            echo -e "[$distro] ${GREEN}PASS${NC}"
        else
            echo -e "[$distro] ${RED}FAIL${NC} (exit: $exit_code)"
        fi
    else
        echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> gui-test-inner.sh"
        echo -e "  ${CYAN}[LOG]${NC}  $logfile"
        nspawn_gui_tests "$container_path" "$distro" 2>&1 | tee "$logfile"
        exit_code=${PIPESTATUS[0]}
        if [[ $exit_code -eq 0 ]]; then
            echo -e "  ${GREEN}[PASS]${NC} All Playwright tests passed"
        else
            echo -e "  ${RED}[FAIL]${NC} Tests failed (exit code: $exit_code)"
        fi
        echo ""
    fi

    collect_gui_artefacts "$distro"

    return "$exit_code"
}

if [[ "$PARALLEL" == "true" ]]; then
    echo -e "${CYAN}Launching parallel test jobs...${NC}"
    echo ""

    launch_job_pool "$MAX_JOBS" DISTROS 10

    for i in "${!PIDS[@]}"; do
        pid="${PIDS[$i]}"
        distro="${PID_DISTROS[$i]}"
        wait "$pid" 2>/dev/null
        RESULT_EXIT[$distro]=$?
    done
else
    for distro in "${DISTROS[@]}"; do
        run_single_distro "$distro"
        RESULT_EXIT[$distro]=$?
    done
fi

# =============================================================================
# Generate summary
# =============================================================================

SUMMARY_FILE="$RESULTS_DIR/gui-summary.txt"

{
    if [[ "$PARALLEL" == "true" ]]; then
        echo "Parallel Web UI GUI Test Results"
        echo "================================="
        echo "Date: $(date)"
        echo "Max parallel jobs: $MAX_JOBS"
    else
        echo "Web UI GUI Test Results"
        echo "======================"
        echo "Date: $(date)"
    fi
    echo ""
    printf "%-12s %8s %6s\n" "Distro" "Status" "Shots"
    printf "%-12s %8s %6s\n" "--------" "------" "-----"

    for distro in "${DISTROS[@]}"; do
        exit_code="${RESULT_EXIT[$distro]:-1}"
        if [[ "$exit_code" -eq 0 ]]; then
            status="PASS"
        elif [[ "$exit_code" -eq 99 ]]; then
            status="MISSING"
        else
            status="FAIL"
        fi
        printf "%-12s %8s %6s\n" "$distro" "$status" "$(count_shots "$distro")"
    done

    echo ""
    echo "Logs: $RESULTS_DIR/<distro>-webui.log"
    echo "Screenshots: $RESULTS_DIR/screenshots/webui/<distro>/"
} > "$SUMMARY_FILE"

# The per-distro collector hands its own directories back, but the results root,
# the per-distro logs and this summary are written directly by the script as
# root and were left owned by it: a completed run produced ten root-owned
# entries that no unprivileged cleanup could remove.
[[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$RESULTS_DIR"

# Print summary
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
if [[ "$PARALLEL" == "true" ]]; then
    print_boxline "   PARALLEL WEB UI TEST SUMMARY"
else
    print_boxline "   WEB UI TEST SUMMARY"
fi
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-12s %8s %6s${NC}\n" "Distro" "Status" "Shots"
printf "  %-12s %8s %6s\n" "--------" "------" "-----"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    exit_code="${RESULT_EXIT[$distro]:-1}"
    if [[ "$exit_code" -eq 0 ]]; then
        colour="$GREEN"; status="PASS"
    elif [[ "$exit_code" -eq 99 ]]; then
        colour="$YELLOW"; status="MISSING"; overall_exit=1
    else
        colour="$RED"; status="FAIL"; overall_exit=1
    fi
    printf "  ${colour}%-12s %8s %6s${NC}\n" "$distro" "$status" "$(count_shots "$distro")"
done

echo ""
echo -e "  Summary:      ${CYAN}$SUMMARY_FILE${NC}"
echo -e "  Screenshots:  ${CYAN}$RESULTS_DIR/screenshots/webui/<distro>/${NC}"
echo ""

if [[ $overall_exit -eq 0 ]]; then
    echo -e "${GREEN}All Web UI tests passed.${NC}"
else
    echo -e "${RED}Some distros had failures: check logs.${NC}"
fi

exit $overall_exit
