#!/bin/bash
# =============================================================================
# GUI TEST INNER SCRIPT — Runs INSIDE systemd-nspawn container
# =============================================================================
# Installs deps, sets up Xvfb + HTTP server, runs Playwright tests.
# Expects /project bind-mount with dist/ and gui-tests/ directories.
#
# Usage (called by run-gui-tests.sh):
#   /bin/bash /project/scripts/gui-test-inner.sh
# =============================================================================

set -uo pipefail

PROJECT="/project"
SERVE_DIR="/tmp/gui-serve"
DISPLAY_NUM=":99"
HTTP_PORT=8787
GUI_TESTS="$PROJECT/gui-tests"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Detect distro and install packages
# =============================================================================

install_deps() {
    if command -v pacman &>/dev/null; then
        echo -e "${CYAN}[deps] Arch — installing packages...${NC}"
        pacman -Sy --noconfirm --needed \
            python xorg-server-xvfb chromium nodejs npm 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then
        echo -e "${CYAN}[deps] Debian — installing packages...${NC}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            python3 xvfb chromium nodejs npm 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        # Rocky/RHEL needs EPEL + CRB for Chromium, Xvfb, nodejs
        if grep -qi 'rocky\|rhel\|centos\|alma' /etc/os-release 2>/dev/null; then
            echo -e "${CYAN}[deps] RHEL/Rocky — enabling EPEL + CRB + Node 20...${NC}"
            dnf install -y -q epel-release 2>/dev/null || true
            dnf config-manager --set-enabled crb 2>/dev/null || true
            dnf module reset -y -q nodejs 2>/dev/null || true
            dnf module enable -y -q nodejs:20 2>/dev/null || true
        else
            echo -e "${CYAN}[deps] Fedora — installing packages...${NC}"
        fi
        dnf install -y -q \
            python3 xorg-x11-server-Xvfb chromium-headless nodejs npm 2>/dev/null || true
    elif command -v zypper &>/dev/null; then
        echo -e "${CYAN}[deps] openSUSE — installing packages...${NC}"
        zypper --gpg-auto-import-keys refresh 2>/dev/null || true
        zypper --non-interactive install -y \
            python3 xorg-x11-server-Xvfb chromium \
            nodejs20 npm20 nodejs-common \
            libpango-1_0-0 libicu73_2 Mesa-libGL1 2>/dev/null || true
    else
        echo -e "${RED}[deps] Unknown distro — skipping package install${NC}"
    fi
}

# =============================================================================
# Prepare serving directory
# =============================================================================

prepare_serve_dir() {
    echo -e "${CYAN}[setup] Preparing HTTP serve directory...${NC}"
    rm -rf "$SERVE_DIR"
    mkdir -p "$SERVE_DIR"

    # Copy all dist files
    cp -r "$PROJECT/crates/hardener-ui/dist/"* "$SERVE_DIR/"

    # Copy mock files
    cp "$GUI_TESTS/tauri-mock.js" "$SERVE_DIR/"

    # Replace index.html with mock version (injects tauri-mock.js)
    cp "$GUI_TESTS/mock-index.html" "$SERVE_DIR/index.html"

    echo -e "${GREEN}[setup] Serve directory ready: $SERVE_DIR${NC}"
    ls -la "$SERVE_DIR/"
}

# =============================================================================
# Start virtual display
# =============================================================================

start_xvfb() {
    echo -e "${CYAN}[xvfb] Starting Xvfb on $DISPLAY_NUM...${NC}"
    Xvfb "$DISPLAY_NUM" -screen 0 1280x720x24 -ac &
    XVFB_PID=$!
    export DISPLAY="$DISPLAY_NUM"
    sleep 1

    if ! kill -0 "$XVFB_PID" 2>/dev/null; then
        echo -e "${RED}[xvfb] Failed to start Xvfb${NC}"
        return 1
    fi
    echo -e "${GREEN}[xvfb] Xvfb running (PID $XVFB_PID)${NC}"
}

# =============================================================================
# Start HTTP server
# =============================================================================

start_http_server() {
    echo -e "${CYAN}[http] Starting Python HTTP server on port $HTTP_PORT...${NC}"

    # Kill any prior listener on the port
    if command -v fuser &>/dev/null; then
        fuser -k "$HTTP_PORT/tcp" 2>/dev/null || true
        sleep 0.5
    fi

    # SPA-aware server: serves index.html for non-file routes (client-side routing)
    cd "$SERVE_DIR"
    python3 "$GUI_TESTS/spa-server.py" "$HTTP_PORT" &
    HTTP_PID=$!
    cd /
    sleep 2

    if ! kill -0 "$HTTP_PID" 2>/dev/null; then
        echo -e "${RED}[http] Failed to start HTTP server${NC}"
        return 1
    fi
    echo -e "${GREEN}[http] HTTP server running on localhost:$HTTP_PORT (PID $HTTP_PID)${NC}"
}

# =============================================================================
# Install Playwright and run tests
# =============================================================================

run_playwright() {
    echo -e "${CYAN}[playwright] Installing npm dependencies...${NC}"
    cd "$GUI_TESTS"

    # Install Playwright (npm deps only — use system Chromium, not bundled)
    npm install --no-audit --no-fund 2>/dev/null
    export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

    # Locate system Chromium binary
    local chromium_bin=""
    for candidate in \
        /usr/bin/chromium \
        /usr/bin/chromium-browser \
        /usr/bin/google-chrome-stable \
        /usr/lib64/chromium-browser/headless_shell \
        /usr/lib/chromium-browser/chromium-browser \
        /usr/lib64/chromium/chromium \
        /usr/lib/chromium/chromium; do
        if [[ -x "$candidate" ]]; then
            chromium_bin="$candidate"
            break
        fi
    done
    if [[ -z "$chromium_bin" ]]; then
        echo -e "${RED}[playwright] No system Chromium found${NC}"
        return 1
    fi
    export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium_bin"
    echo -e "${GREEN}[playwright] Using system Chromium: $chromium_bin${NC}"

    echo -e "${CYAN}[playwright] Running tests...${NC}"
    mkdir -p test-results/screenshots

    local exit_code=0
    npx playwright test \
        --reporter=list \
        2>&1 || exit_code=$?

    # Copy results to project output
    if [[ -d test-results ]]; then
        mkdir -p "$PROJECT/test-results/gui/screenshots/webui"
        cp -r test-results/* "$PROJECT/test-results/gui/" 2>/dev/null || true
        cp -r test-results/screenshots/* "$PROJECT/test-results/gui/screenshots/webui/" 2>/dev/null || true
    fi

    return $exit_code
}

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    echo -e "${CYAN}[cleanup] Stopping services...${NC}"
    [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null || true
    [[ -n "${XVFB_PID:-}" ]] && kill "$XVFB_PID" 2>/dev/null || true
    rm -rf "$SERVE_DIR"
}
trap cleanup EXIT

# =============================================================================
# Main
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GUI TEST RUNNER (Web UI — Playwright)                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

install_deps
prepare_serve_dir
start_xvfb
start_http_server

pw_exit=0
run_playwright || pw_exit=$?

if [[ $pw_exit -eq 0 ]]; then
    echo -e "${GREEN}All Web UI tests passed.${NC}"
else
    echo -e "${RED}Some Web UI tests failed (exit code: $pw_exit).${NC}"
fi

exit $pw_exit
