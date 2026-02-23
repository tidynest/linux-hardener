#!/bin/bash
# =============================================================================
# CROSS-DISTRO TEST RUNNER - Linux System Hardener
# =============================================================================
# Runs full-test-suite.sh across all supported distributions using
# systemd-nspawn --pipe (non-interactive, no boot/login needed).
#
# Usage: sudo ./scripts/run-cross-distro-tests.sh [OPTIONS]
#
# Options:
#   --apply           Enable destructive tests (apply + rollback)
#   --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
#   --rebuild         Build musl binary before testing
#   --help            Show usage
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results"
MUSL_BINARY="$PROJECT_DIR/target/x86_64-unknown-linux-musl/release/hardener"

# Distro name -> container name mapping
declare -A CONTAINERS=(
    [arch]="hardener-test"
    [debian]="hardener-test-debian"
    [fedora]="hardener-test-fedora"
    [rhel]="hardener-test-rhel"
    [opensuse]="hardener-test-opensuse"
)

DISTRO_ORDER=(arch debian fedora rhel opensuse)

# Options
DO_APPLY=false
SINGLE_DISTRO=""
DO_REBUILD=false

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Argument parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --apply)
            DO_APPLY=true
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
        --rebuild)
            DO_REBUILD=true
            shift
            ;;
        --help|-h)
            cat << EOF
Cross-Distro Test Runner for Linux System Hardener

Usage: sudo $0 [OPTIONS]

Options:
  --apply           Enable destructive tests (apply + rollback)
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
  --rebuild         Build musl binary before testing
  --help            Show usage

Output:
  test-results/<distro>.log   Per-distro full output
  test-results/summary.txt    Aggregated results table

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

if [[ "$DO_REBUILD" == "true" ]]; then
    echo -e "${CYAN}Building musl binary...${NC}"
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    cargo build --release --target x86_64-unknown-linux-musl \
        --manifest-path "$PROJECT_DIR/Cargo.toml" || {
        echo -e "${RED}Build failed${NC}"
        exit 1
    }
    echo -e "${GREEN}Build complete: $MUSL_BINARY${NC}"
fi

if [[ ! -x "$MUSL_BINARY" ]] && [[ ! -x "$PROJECT_DIR/target/release/hardener" ]]; then
    echo -e "${RED}ERROR: No binary found. Build first or use --rebuild${NC}"
    exit 1
fi

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

APPLY_FLAG=""
[[ "$DO_APPLY" == "true" ]] && APPLY_FLAG="--apply"

echo ""
echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
echo -e "${MAGENTA}║${NC}   ${BOLD}CROSS-DISTRO TEST RUNNER${NC}                                              ${MAGENTA}║${NC}"
echo -e "${MAGENTA}║${NC}   Distros: ${#DISTROS[@]}  |  Apply: $DO_APPLY                                          ${MAGENTA}║${NC}"
echo -e "${MAGENTA}║${NC}                                                                          ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

for distro in "${DISTROS[@]}"; do
    container="${CONTAINERS[$distro]}"
    container_path="/var/lib/machines/$container"
    logfile="$RESULTS_DIR/${distro}.log"

    echo -e "${CYAN}━━━ Testing: $distro ($container) ━━━${NC}"

    # Check container exists
    if [[ ! -d "$container_path" ]]; then
        echo -e "  ${RED}[SKIP]${NC} Container not found: $container_path"
        RESULT_PASSED[$distro]=0
        RESULT_FAILED[$distro]=0
        RESULT_SKIPPED[$distro]=0
        RESULT_TOTAL[$distro]=0
        RESULT_EXIT[$distro]=99
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        continue
    fi

    # Run full-test-suite.sh inside the container via systemd-nspawn --pipe
    echo -e "  ${CYAN}[RUN]${NC}  systemd-nspawn --pipe -> full-test-suite.sh $APPLY_FLAG"

    systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        --pipe \
        /bin/bash /project/scripts/full-test-suite.sh $APPLY_FLAG \
        > "$logfile" 2>&1
    local_exit=$?
    RESULT_EXIT[$distro]=$local_exit

    # Parse results from log (strip ANSI escape codes first)
    stripped=$(sed 's/\x1b\[[0-9;]*m//g' "$logfile")
    RESULT_PASSED[$distro]=$(echo "$stripped" | grep -oP 'Passed:\s+\K\d+' 2>/dev/null || echo "0")
    RESULT_FAILED[$distro]=$(echo "$stripped" | grep -oP 'Failed:\s+\K\d+' 2>/dev/null || echo "0")
    RESULT_SKIPPED[$distro]=$(echo "$stripped" | grep -oP 'Skipped:\s+\K\d+' 2>/dev/null || echo "0")
    RESULT_TOTAL[$distro]=$(echo "$stripped" | grep -oP 'Total Tests:\s+\K\d+' 2>/dev/null || echo "0")

    # Print quick summary for this distro
    if [[ "${RESULT_FAILED[$distro]}" -eq 0 ]] && [[ "${RESULT_TOTAL[$distro]}" -gt 0 ]]; then
        echo -e "  ${GREEN}[DONE]${NC} ${RESULT_PASSED[$distro]}/${RESULT_TOTAL[$distro]} passed, ${RESULT_SKIPPED[$distro]} skipped"
    elif [[ "${RESULT_TOTAL[$distro]}" -eq 0 ]]; then
        echo -e "  ${RED}[ERR]${NC}  No test results parsed (exit code: $local_exit)"
    else
        echo -e "  ${RED}[FAIL]${NC} ${RESULT_PASSED[$distro]}/${RESULT_TOTAL[$distro]} passed, ${RESULT_FAILED[$distro]} failed, ${RESULT_SKIPPED[$distro]} skipped"
    fi
    echo ""
done

# =============================================================================
# Generate summary
# =============================================================================

SUMMARY_FILE="$RESULTS_DIR/summary.txt"

{
    echo "Cross-Distro Test Results"
    echo "========================"
    echo "Date: $(date)"
    echo "Apply mode: $DO_APPLY"
    echo ""
    printf "%-12s %6s %6s %6s %7s %5s %8s\n" "Distro" "Total" "Pass" "Fail" "Skip" "Exit" "Status"
    printf "%-12s %6s %6s %6s %7s %5s %8s\n" "--------" "-----" "----" "----" "----" "----" "------"

    any_failed=false
    for distro in "${DISTROS[@]}"; do
        total="${RESULT_TOTAL[$distro]}"
        passed="${RESULT_PASSED[$distro]}"
        failed="${RESULT_FAILED[$distro]}"
        skipped="${RESULT_SKIPPED[$distro]}"
        exit_code="${RESULT_EXIT[$distro]}"

        if [[ "$exit_code" -eq 99 ]]; then
            status="MISSING"
            any_failed=true
        elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
            status="PASS"
        else
            status="FAIL"
            any_failed=true
        fi

        printf "%-12s %6s %6s %6s %7s %5s %8s\n" "$distro" "$total" "$passed" "$failed" "$skipped" "$exit_code" "$status"
    done

    echo ""
    echo "Logs: $RESULTS_DIR/<distro>.log"
} > "$SUMMARY_FILE"

# Print summary to stdout with colour
echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${NC}   ${BOLD}CROSS-DISTRO SUMMARY${NC}                                                  ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
printf "  ${BOLD}%-12s %6s %6s %6s %7s %8s${NC}\n" "Distro" "Total" "Pass" "Fail" "Skip" "Status"
printf "  %-12s %6s %6s %6s %7s %8s\n" "--------" "-----" "----" "----" "----" "------"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    total="${RESULT_TOTAL[$distro]}"
    passed="${RESULT_PASSED[$distro]}"
    failed="${RESULT_FAILED[$distro]}"
    skipped="${RESULT_SKIPPED[$distro]}"
    exit_code="${RESULT_EXIT[$distro]}"

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

    printf "  ${colour}%-12s %6s %6s %6s %7s %8s${NC}\n" "$distro" "$total" "$passed" "$failed" "$skipped" "$status"
done

echo ""
echo -e "  Summary:  ${CYAN}$SUMMARY_FILE${NC}"
echo -e "  Logs:     ${CYAN}$RESULTS_DIR/<distro>.log${NC}"
echo ""

if [[ $overall_exit -eq 0 ]]; then
    echo -e "${GREEN}All distros passed.${NC}"
else
    echo -e "${RED}Some distros had failures — check logs.${NC}"
fi

exit $overall_exit
