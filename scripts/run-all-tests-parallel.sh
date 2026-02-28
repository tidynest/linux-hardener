#!/bin/bash
# =============================================================================
# MASTER PARALLEL TEST RUNNER — Linux System Hardener
# =============================================================================
# Runs ALL tests in parallel: unit tests, CLI cross-distro, GUI web UI.
# Optionally runs desktop tests sequentially after container tests.
#
# Usage: sudo ./scripts/run-all-tests-parallel.sh [OPTIONS]
#
# Options:
#   --apply           Enable destructive tests (apply + rollback)
#   --desktop         Include desktop GUI tests (runs after containers, as user)
#   --no-cli          Skip CLI cross-distro tests
#   --no-gui          Skip GUI web UI tests
#   --no-unit         Skip unit tests (cargo test)
#   --jobs N          Max parallel jobs per suite (default: auto-detect)
#   --kitty           Open each test suite in a separate kitty window
#   --rebuild         Build musl binary before testing
#   --help            Show usage
#
# Speed improvement: ~5x faster by running all suites in parallel
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_DIR/test-results"

DO_APPLY=false
DO_DESKTOP=false
DO_CLI=true
DO_GUI=true
DO_UNIT=true
USE_KITTY=false
DO_REBUILD=false
MAX_JOBS=5

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
        --desktop)
            DO_DESKTOP=true
            shift
            ;;
        --no-cli)
            DO_CLI=false
            shift
            ;;
        --no-gui)
            DO_GUI=false
            shift
            ;;
        --no-unit)
            DO_UNIT=false
            shift
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --kitty)
            USE_KITTY=true
            shift
            ;;
        --rebuild)
            DO_REBUILD=true
            shift
            ;;
        --help|-h)
            cat << 'EOF'
Master Parallel Test Runner

Usage: sudo ./scripts/run-all-tests-parallel.sh [OPTIONS]

Options:
  --apply           Enable destructive tests (apply + rollback)
  --desktop         Include desktop GUI tests (runs after containers, as user)
  --no-cli          Skip CLI cross-distro tests
  --no-gui          Skip GUI web UI tests
  --no-unit         Skip unit tests (cargo test)
  --jobs N          Max parallel jobs per suite (default: auto-detect)
  --kitty           Open each test suite in a separate kitty window
  --rebuild         Build musl binary before testing
  --help            Show usage

Examples:
  # Run everything including desktop tests
  sudo ./scripts/run-all-tests-parallel.sh --apply --desktop

  # Run in separate kitty windows (visual separation)
  sudo ./scripts/run-all-tests-parallel.sh --apply --kitty

  # Quick test: unit tests only, skip containers
  ./scripts/run-all-tests-parallel.sh --no-cli --no-gui

  # Just desktop tests (no sudo needed)
  ./scripts/run-desktop-tests.sh

Output:
  test-results/                  All test outputs
    unit-tests.log               Cargo test output
    cli-tests.log                CLI cross-distro output
    gui-tests.log                Web UI test output
    desktop-tests.log            Desktop test output
    summary.txt                  CLI cross-distro summary
    gui/gui-summary.txt          GUI test summary
    desktop/                     Desktop test screenshots
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

NEEDS_ROOT=false
[[ "$DO_CLI" == "true" ]] && NEEDS_ROOT=true
[[ "$DO_GUI" == "true" ]] && NEEDS_ROOT=true

if [[ $EUID -ne 0 ]] && [[ "$NEEDS_ROOT" == "true" ]]; then
    echo -e "${RED}ERROR: Must run as root for container tests${NC}"
    echo -e "  Use --no-cli --no-gui for unit tests only"
    echo -e "  Or run ./scripts/run-desktop-tests.sh for desktop tests only"
    exit 1
fi

mkdir -p "$RESULTS_DIR"

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

run_unit_tests() {
    local logfile="$RESULTS_DIR/unit-tests.log"
    echo -e "${CYAN}[UNIT] Running cargo test --workspace...${NC}"
    
    cargo test --workspace --manifest-path "$PROJECT_DIR/Cargo.toml" \
        > "$logfile" 2>&1
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "[UNIT] ${GREEN}PASS${NC}"
    else
        echo -e "[UNIT] ${RED}FAIL${NC} (exit: $exit_code)"
    fi
    
    return $exit_code
}

run_cli_tests() {
    local logfile="$RESULTS_DIR/cli-tests.log"
    echo -e "${CYAN}[CLI] Running parallel cross-distro tests...${NC}"
    
    "$SCRIPT_DIR/run-cross-distro-tests-parallel.sh" \
        --jobs "$MAX_JOBS" $APPLY_FLAG \
        > "$logfile" 2>&1
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "[CLI] ${GREEN}PASS${NC}"
    else
        echo -e "[CLI] ${RED}FAIL${NC} (exit: $exit_code)"
    fi
    
    return $exit_code
}

run_gui_tests() {
    local logfile="$RESULTS_DIR/gui-tests.log"
    echo -e "${CYAN}[GUI] Running parallel web UI tests...${NC}"
    
    "$SCRIPT_DIR/run-gui-tests-parallel.sh" \
        --jobs "$MAX_JOBS" \
        > "$logfile" 2>&1
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "[GUI] ${GREEN}PASS${NC}"
    else
        echo -e "[GUI] ${RED}FAIL${NC} (exit: $exit_code)"
    fi
    
    return $exit_code
}

run_desktop_tests() {
    local logfile="$RESULTS_DIR/desktop-tests.log"
    echo -e "${CYAN}[DESKTOP] Running desktop GUI tests...${NC}"
    
    local user="${SUDO_USER:-$USER}"
    if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]]; then
        su - "$user" -c "cd '$PROJECT_DIR' && ./scripts/run-desktop-tests.sh" \
            > "$logfile" 2>&1
    else
        "$SCRIPT_DIR/run-desktop-tests.sh" > "$logfile" 2>&1
    fi
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "[DESKTOP] ${GREEN}PASS${NC}"
    else
        echo -e "[DESKTOP] ${RED}FAIL${NC} (exit: $exit_code)"
    fi
    
    return $exit_code
}

run_in_kitty() {
    local name="$1"
    local cmd="$2"
    local logfile="$3"
    local as_user="${4:-}"
    
    local full_cmd="$cmd"
    if [[ -n "$as_user" ]] && [[ $EUID -eq 0 ]]; then
        full_cmd="su - '$as_user' -c \"cd '$PROJECT_DIR' && $cmd\""
    fi
    
    kitty --detach --title "Test: $name" bash -c "
        echo '========================================'
        echo 'Test Suite: $name'
        echo '========================================'
        echo ''
        $full_cmd 2>&1 | tee $logfile
        echo ''
        echo '========================================'
        echo 'Press Enter to close this window...'
        read
    " 2>/dev/null
    
    echo -e "${DIM}  Launched $name in kitty window${NC}"
}

if [[ "$DO_REBUILD" == "true" ]]; then
    echo -e "${CYAN}Building musl binary...${NC}"
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    cargo build --release --target x86_64-unknown-linux-musl \
        --manifest-path "$PROJECT_DIR/Cargo.toml" || {
        echo -e "${RED}Build failed${NC}"
        exit 1
    }
    echo -e "${GREEN}Build complete${NC}"
fi

echo ""
echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline ""
print_boxline "   MASTER PARALLEL TEST RUNNER"
print_boxline "   Unit: $DO_UNIT  |  CLI: $DO_CLI  |  GUI: $DO_GUI  |  Desktop: $DO_DESKTOP"
print_boxline "   Apply: $DO_APPLY  |  Jobs: $MAX_JOBS  |  Kitty: $USE_KITTY"
print_boxline ""
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""

UNIT_EXIT=0
CLI_EXIT=0
GUI_EXIT=0
DESKTOP_EXIT=0

if [[ "$USE_KITTY" == "true" ]]; then
    echo -e "${CYAN}Launching test suites in kitty windows...${NC}"
    echo ""
    
    local_user="${SUDO_USER:-$USER}"
    
    if [[ "$DO_UNIT" == "true" ]]; then
        run_in_kitty "Unit Tests" \
            "cargo test --workspace --manifest-path '$PROJECT_DIR/Cargo.toml'" \
            "$RESULTS_DIR/unit-tests.log"
    fi
    
    if [[ "$DO_CLI" == "true" ]]; then
        run_in_kitty "CLI Tests" \
            "$SCRIPT_DIR/run-cross-distro-tests-parallel.sh --jobs $MAX_JOBS $APPLY_FLAG" \
            "$RESULTS_DIR/cli-tests.log"
    fi
    
    if [[ "$DO_GUI" == "true" ]]; then
        run_in_kitty "GUI Tests" \
            "$SCRIPT_DIR/run-gui-tests-parallel.sh --jobs $MAX_JOBS" \
            "$RESULTS_DIR/gui-tests.log"
    fi
    
    if [[ "$DO_DESKTOP" == "true" ]]; then
        run_in_kitty "Desktop Tests" \
            "./scripts/run-desktop-tests.sh" \
            "$RESULTS_DIR/desktop-tests.log" \
            "$local_user"
    fi
    
    echo ""
    echo -e "${GREEN}All test suites launched in separate windows.${NC}"
    echo -e "Check the kitty windows for results, or see logs in ${CYAN}$RESULTS_DIR/${NC}"
    exit 0
fi

echo -e "${CYAN}Running tests...${NC}"
echo ""

PIDS=()
declare -A PID_NAMES

if [[ "$DO_UNIT" == "true" ]]; then
    run_unit_tests &
    PIDS+=($!)
    PID_NAMES[$!]="UNIT"
    echo -e "${DIM}  Started unit tests (PID: ${PIDS[-1]})${NC}"
fi

if [[ "$DO_CLI" == "true" ]]; then
    echo -e "${DIM}  Started CLI tests (sequential - uses containers)${NC}"
fi

if [[ "$DO_GUI" == "true" ]]; then
    echo -e "${DIM}  GUI tests will run after CLI (shares containers)${NC}"
fi

if [[ ${#PIDS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${CYAN}Waiting for unit tests...${NC}"
    echo ""
    
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null
        exit_code=$?
        name="${PID_NAMES[$pid]}"
        case "$name" in
            *UNIT*) UNIT_EXIT=$exit_code ;;
        esac
    done
fi

if [[ "$DO_CLI" == "true" ]]; then
    echo ""
    echo -e "${CYAN}Running CLI cross-distro tests...${NC}"
    echo ""
    run_cli_tests || CLI_EXIT=$?
fi

if [[ "$DO_GUI" == "true" ]]; then
    echo ""
    echo -e "${CYAN}Running GUI web UI tests...${NC}"
    echo ""
    run_gui_tests || GUI_EXIT=$?
fi

if [[ "$DO_DESKTOP" == "true" ]]; then
    echo ""
    echo -e "${CYAN}Running desktop tests (requires user session)...${NC}"
    echo ""
    run_desktop_tests || DESKTOP_EXIT=$?
fi

echo -e "${MAGENTA}╔$(printf '═%.0s' $(seq 1 $BOX_W))╗${NC}"
print_boxline "   MASTER TEST SUMMARY"
echo -e "${MAGENTA}╚$(printf '═%.0s' $(seq 1 $BOX_W))╝${NC}"
echo ""
printf "  ${BOLD}%-20s %10s${NC}\n" "Test Suite" "Status"
printf "  %-20s %10s\n" "----------" "------"

overall_exit=0

if [[ "$DO_UNIT" == "true" ]]; then
    if [[ $UNIT_EXIT -eq 0 ]]; then
        printf "  ${GREEN}%-20s %10s${NC}\n" "Unit Tests" "PASS"
    else
        printf "  ${RED}%-20s %10s${NC}\n" "Unit Tests" "FAIL"
        overall_exit=1
    fi
fi

if [[ "$DO_CLI" == "true" ]]; then
    if [[ $CLI_EXIT -eq 0 ]]; then
        printf "  ${GREEN}%-20s %10s${NC}\n" "CLI Cross-Distro" "PASS"
    else
        printf "  ${RED}%-20s %10s${NC}\n" "CLI Cross-Distro" "FAIL"
        overall_exit=1
    fi
fi

if [[ "$DO_GUI" == "true" ]]; then
    if [[ $GUI_EXIT -eq 0 ]]; then
        printf "  ${GREEN}%-20s %10s${NC}\n" "GUI Web UI" "PASS"
    else
        printf "  ${RED}%-20s %10s${NC}\n" "GUI Web UI" "FAIL"
        overall_exit=1
    fi
fi

if [[ "$DO_DESKTOP" == "true" ]]; then
    if [[ $DESKTOP_EXIT -eq 0 ]]; then
        printf "  ${GREEN}%-20s %10s${NC}\n" "Desktop GUI" "PASS"
    else
        printf "  ${RED}%-20s %10s${NC}\n" "Desktop GUI" "FAIL"
        overall_exit=1
    fi
fi

echo ""
echo -e "  Logs:  ${CYAN}$RESULTS_DIR/${NC}"
echo ""

if [[ $overall_exit -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed — check logs.${NC}"
fi

exit $overall_exit
