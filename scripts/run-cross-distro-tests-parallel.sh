#!/bin/bash
# =============================================================================
# PARALLEL CROSS-DISTRO TEST RUNNER — Linux System Hardener
# =============================================================================
# Runs full-test-suite.sh in PARALLEL across all systemd-nspawn containers.
# Uses background processes to test multiple distros simultaneously.
#
# Usage: sudo ./scripts/run-cross-distro-tests-parallel.sh [OPTIONS]
#
# Options:
#   --apply           Enable destructive tests (apply + rollback)
#   --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
#   --jobs N          Max parallel jobs (default: auto-detect from CPU cores)
#   --rebuild         Build musl binary before testing
#   --help            Show usage
#
# Speed improvement: ~5x faster when testing all 5 distros
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results"

# Cargo may redirect build output away from ./target (CARGO_TARGET_DIR or a
# [build] target-dir in ~/.cargo/config.toml); probe candidates for "$@".
resolve_target_dir() {
    local dir probe home
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        echo "$CARGO_TARGET_DIR"
        return
    fi
    dir=""
    if command -v cargo &>/dev/null; then
        dir=$(cargo metadata --format-version 1 --no-deps \
            --manifest-path "$PROJECT_DIR/Cargo.toml" 2>/dev/null |
            sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
    fi
    [[ -n "$dir" ]] || dir="$PROJECT_DIR/target"
    for probe in "$@"; do
        [[ -e "$dir/$probe" ]] && { echo "$dir"; return; }
    done
    for home in "${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}" "$HOME"; do
        for probe in "$@"; do
            if [[ -n "$home" && -e "$home/.cache/cargo-target/$probe" ]]; then
                echo "$home/.cache/cargo-target"
                return
            fi
        done
    done
    echo "$dir"
}

TARGET_DIR="$(resolve_target_dir "x86_64-unknown-linux-musl/release/hardener" "release/hardener")"
MUSL_BINARY="$TARGET_DIR/x86_64-unknown-linux-musl/release/hardener"

declare -A CONTAINERS=(
    [arch]="hardener-test"
    [debian]="hardener-test-debian"
    [fedora]="hardener-test-fedora"
    [rhel]="hardener-test-rhel"
    [opensuse]="hardener-test-opensuse"
)

DISTRO_ORDER=(arch debian fedora rhel opensuse)

DO_APPLY=false
SINGLE_DISTRO=""
DO_REBUILD=false
MAX_JOBS=3

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

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
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --rebuild)
            DO_REBUILD=true
            shift
            ;;
        --help|-h)
            cat << 'EOF'
Parallel Cross-Distro Test Runner

Usage: sudo ./scripts/run-cross-distro-tests-parallel.sh [OPTIONS]

Options:
  --apply           Enable destructive tests (apply + rollback)
  --distro NAME     Run only one distro (arch|debian|fedora|rhel|opensuse)
  --jobs N          Max parallel jobs (default: auto-detect CPU cores)
  --rebuild         Build musl binary before testing
  --help            Show usage

Runs all distro tests in parallel for ~5x speedup.

Output:
  test-results/<distro>.log   Per-distro full output
  test-results/summary.txt    Aggregated results table
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

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

if [[ -n "$SINGLE_DISTRO" ]]; then
    DISTROS=("$SINGLE_DISTRO")
else
    DISTROS=("${DISTRO_ORDER[@]}")
fi

declare -A RESULT_PASSED RESULT_FAILED RESULT_SKIPPED RESULT_TOTAL RESULT_EXIT
declare -a PIDS
declare -a PID_DISTROS

APPLY_FLAG=""
[[ "$DO_APPLY" == "true" ]] && APPLY_FLAG="--apply"

BOX_W=74
print_boxline() {
    local content="$1"
    local visible_len=${#content}
    local pad=$((BOX_W - visible_len))
    local spaces=""
    for ((i=0; i<pad; i++)); do spaces+=" "; done
    echo -e "${MAGENTA}║${NC}${content}${spaces}${MAGENTA}║${NC}"
}

echo ""
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
print_boxline "   PARALLEL CROSS-DISTRO TEST RUNNER"
print_boxline "   Distros: ${#DISTROS[@]}  |  Apply: $DO_APPLY  |  Max jobs: $MAX_JOBS"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

run_single_distro() {
    local distro="$1"
    local container="${CONTAINERS[$distro]}"
    local container_path="/var/lib/machines/$container"
    local logfile="$RESULTS_DIR/${distro}.log"
    
    if [[ ! -d "$container_path" ]]; then
        echo "[$distro] ${YELLOW}SKIP${NC} — container not found"
        echo "CONTAINER NOT FOUND: $container_path" > "$logfile"
        return 99
    fi
    
    echo "[$distro] ${CYAN}Starting...${NC}"
    
    systemd-nspawn -D "$container_path" \
        --bind="$PROJECT_DIR:/project" \
        "${TARGET_BIND[@]}" \
        --pipe \
        /bin/bash /project/scripts/full-test-suite.sh $APPLY_FLAG \
        > "$logfile" 2>&1
    local exit_code=$?
    
    local stripped
    stripped=$(sed 's/\x1b\[[0-9;]*m//g' "$logfile")
    local passed failed skipped total
    passed=$(echo "$stripped" | grep -oP 'Passed:\s+\K\d+' 2>/dev/null || echo "0")
    failed=$(echo "$stripped" | grep -oP 'Failed:\s+\K\d+' 2>/dev/null || echo "0")
    skipped=$(echo "$stripped" | grep -oP 'Skipped:\s+\K\d+' 2>/dev/null || echo "0")
    total=$(echo "$stripped" | grep -oP 'Total Tests:\s+\K\d+' 2>/dev/null || echo "0")
    
    if [[ $exit_code -eq 0 ]] && [[ "$total" -gt 0 ]]; then
        echo "[$distro] ${GREEN}PASS${NC} — $passed/$total passed, $skipped skipped"
    elif [[ "$total" -eq 0 ]]; then
        echo "[$distro] ${RED}ERR${NC} — no results (exit: $exit_code)"
    else
        echo "[$distro] ${RED}FAIL${NC} — $failed failed (exit: $exit_code)"
    fi
    
    echo "$passed" > "$RESULTS_DIR/.${distro}.passed"
    echo "$failed" > "$RESULTS_DIR/.${distro}.failed"
    echo "$skipped" > "$RESULTS_DIR/.${distro}.skipped"
    echo "$total" > "$RESULTS_DIR/.${distro}.total"
    
    return $exit_code
}

echo -e "${CYAN}Launching parallel test jobs...${NC}"
echo ""

running=0
for distro in "${DISTROS[@]}"; do
    while [[ $running -ge $MAX_JOBS ]]; do
        wait -n 2>/dev/null || true
        ((running--)) || true
    done
    
    run_single_distro "$distro" &
    PIDS+=($!)
    PID_DISTROS+=("$distro")
    ((running++))
    echo -e "${DIM}  Started job for $distro (PID: ${PIDS[-1]})${NC}"
done

echo ""
echo -e "${CYAN}Waiting for all jobs to complete...${NC}"
echo ""

for i in "${!PIDS[@]}"; do
    pid="${PIDS[$i]}"
    distro="${PID_DISTROS[$i]}"
    wait "$pid" 2>/dev/null
    RESULT_EXIT[$distro]=$?
    RESULT_PASSED[$distro]=$(cat "$RESULTS_DIR/.${distro}.passed" 2>/dev/null || echo "0")
    RESULT_FAILED[$distro]=$(cat "$RESULTS_DIR/.${distro}.failed" 2>/dev/null || echo "0")
    RESULT_SKIPPED[$distro]=$(cat "$RESULTS_DIR/.${distro}.skipped" 2>/dev/null || echo "0")
    RESULT_TOTAL[$distro]=$(cat "$RESULTS_DIR/.${distro}.total" 2>/dev/null || echo "0")
    rm -f "$RESULTS_DIR/.${distro}."*
done

SUMMARY_FILE="$RESULTS_DIR/summary.txt"

{
    echo "Parallel Cross-Distro Test Results"
    echo "==================================="
    echo "Date: $(date)"
    echo "Apply mode: $DO_APPLY"
    echo "Max parallel jobs: $MAX_JOBS"
    echo ""
    printf "%-12s %6s %6s %6s %7s %5s %8s\n" "Distro" "Total" "Pass" "Fail" "Skip" "Exit" "Status"
    printf "%-12s %6s %6s %6s %7s %5s %8s\n" "--------" "-----" "----" "----" "----" "----" "------"
    
    for distro in "${DISTROS[@]}"; do
        total="${RESULT_TOTAL[$distro]:-0}"
        passed="${RESULT_PASSED[$distro]:-0}"
        failed="${RESULT_FAILED[$distro]:-0}"
        skipped="${RESULT_SKIPPED[$distro]:-0}"
        exit_code="${RESULT_EXIT[$distro]:-1}"
        
        if [[ "$exit_code" -eq 99 ]]; then
            status="MISSING"
        elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
            status="PASS"
        else
            status="FAIL"
        fi
        
        printf "%-12s %6s %6s %6s %7s %5s %8s\n" "$distro" "$total" "$passed" "$failed" "$skipped" "$exit_code" "$status"
    done
    
    echo ""
    echo "Logs: $RESULTS_DIR/<distro>.log"
} > "$SUMMARY_FILE"

echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline "   PARALLEL CROSS-DISTRO SUMMARY"
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-12s %6s %6s %6s %7s %8s${NC}\n" "Distro" "Total" "Pass" "Fail" "Skip" "Status"
printf "  %-12s %6s %6s %6s %7s %8s\n" "--------" "-----" "----" "----" "----" "------"

overall_exit=0
for distro in "${DISTROS[@]}"; do
    total="${RESULT_TOTAL[$distro]:-0}"
    passed="${RESULT_PASSED[$distro]:-0}"
    failed="${RESULT_FAILED[$distro]:-0}"
    skipped="${RESULT_SKIPPED[$distro]:-0}"
    exit_code="${RESULT_EXIT[$distro]:-1}"
    
    if [[ "$exit_code" -eq 99 ]]; then
        colour="$YELLOW"; status="MISSING"; overall_exit=1
    elif [[ "$failed" -eq 0 ]] && [[ "$total" -gt 0 ]]; then
        colour="$GREEN"; status="PASS"
    else
        colour="$RED"; status="FAIL"; overall_exit=1
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
