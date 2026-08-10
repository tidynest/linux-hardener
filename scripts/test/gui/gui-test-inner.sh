#!/bin/bash
# =============================================================================
# GUI TEST INNER SCRIPT: Runs INSIDE systemd-nspawn container
# =============================================================================
# Installs deps, serves the built frontend over HTTP, runs Playwright tests.
#
# No X server is started. playwright.config.js sets `headless: true`, and a
# headless Chromium opens no display; Fedora's binary is `headless_shell`,
# which cannot talk to X at all and ran the suite regardless. Installing Xvfb
# was therefore one more package to get right on six distributions in exchange
# for nothing, and it was one of the two missing on the three that failed.
# Expects /project bind-mount with dist/ and gui-tests/ directories.
#
# Usage (called by run-gui-tests.sh):
#   /bin/bash /project/scripts/test/gui/gui-test-inner.sh
# =============================================================================

set -uo pipefail

PROJECT="/project"
SERVE_DIR="/tmp/gui-serve"
HTTP_PORT=8787
GUI_TESTS="$PROJECT/gui-tests"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Detect distro and install packages
# =============================================================================

# Runs a package install, keeping its output and naming it when it fails.
#
# Every install here used to end `2>/dev/null || true`, which is how a run that
# installed nothing reported nothing: on Rocky the EPEL step succeeded over the
# network and the install after it failed in silence, so the first sign of
# trouble was Chromium turning up missing three functions later, and the cause
# was read as a network fault it demonstrably was not. `-q` hides a successful
# install's output; only an unsuccessful one is worth printing.
#
# Returns non-zero rather than aborting: a distribution missing one package can
# still be worth attempting, and the Chromium probe below fails closed anyway.
run_install() {
    local output status=0
    output=$("$@" 2>&1) || status=$?
    [[ $status -eq 0 ]] && return 0
    echo -e "${RED}[deps] install failed (exit $status): $*${NC}"
    echo "$output" | tail -20
    return "$status"
}

install_deps() {
    if command -v pacman &>/dev/null; then
        echo -e "${CYAN}[deps] Arch: installing packages...${NC}"
        run_install pacman -Sy --noconfirm --needed \
            python chromium nodejs npm
    elif command -v apt-get &>/dev/null; then
        echo -e "${CYAN}[deps] Debian: installing packages...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        run_install apt-get update -qq
        run_install apt-get install -y -qq \
            python3 chromium nodejs npm
    elif command -v dnf &>/dev/null; then
        # Rocky/RHEL needs EPEL for Chromium, and CRB for what EPEL builds on.
        if grep -qi 'rocky\|rhel\|centos\|alma' /etc/os-release 2>/dev/null; then
            echo -e "${CYAN}[deps] RHEL/Rocky: enabling EPEL + CRB...${NC}"
            run_install dnf install -y -q epel-release
            dnf config-manager --set-enabled crb 2>/dev/null || true
            # `dnf module` was dropped with modularity in EL10, so the reset and
            # enable that used to pin nodejs:20 here failed on every run and
            # said nothing. EL10 carries nodejs and npm in AppStream directly.
        else
            echo -e "${CYAN}[deps] Fedora: installing packages...${NC}"
        fi
        run_install dnf install -y -q \
            python3 chromium-headless nodejs npm
    elif command -v zypper &>/dev/null; then
        echo -e "${CYAN}[deps] openSUSE: installing packages...${NC}"
        zypper --gpg-auto-import-keys refresh 2>/dev/null || true
        # Version-suffixed names, not the distribution's own. Leap 16 answered
        # `nodejs20`, `npm20` and `libicu73_2` with "not found in package
        # names", and zypper abandons the whole transaction when one name does
        # not resolve, so python3 and Chromium were never installed either and
        # the run read as a network fault. The -default metapackages track
        # whatever the distribution's current Node is; the hand-listed
        # libraries were Chromium's own dependencies, which zypper resolves.
        run_install zypper --non-interactive install -y \
            python3 chromium nodejs-default npm-default
        # Fonts, in a transaction of their own. Leap 16's chromium package
        # pulls none, and a browser with no font lays every glyph out at zero
        # width: the DOM is complete, the accessibility tree carries the text,
        # the icons draw, and every assertion on visible text fails as
        # "hidden". Measured at 72 of 110 failing that way, against markup that
        # was entirely correct. Separate because zypper abandons the whole
        # transaction on one unresolvable name, and the packages above must not
        # be hostage to a font name; the candidates are tried in turn for the
        # same reason.
        for font_package in dejavu-fonts google-noto-fonts noto-sans-fonts liberation-fonts; do
            run_install zypper --non-interactive install -y "$font_package" && break
        done
    else
        echo -e "${RED}[deps] Unknown distro: skipping package install${NC}"
    fi
}

# Refuse to run a suite that cannot draw a letter.
#
# This is a total check rather than a per-distribution one, and deliberately:
# no distribution's package list names a font, they pass because Chromium's
# dependencies happen to drag one in, and openSUSE was the first where that
# stopped being true. A per-distribution check would only ever have covered the
# distributions someone had already seen fail.
#
# Asked of the filesystem rather than through fc-list, which is fontconfig and
# is itself a package that may be absent. Any font at all is enough: the suite
# asserts that text is visible, not which typeface drew it.
require_a_font() {
    if [[ -n $(find /usr/share/fonts /usr/local/share/fonts -type f \
        \( -name '*.ttf' -o -name '*.otf' -o -name '*.ttc' -o -name '*.pcf.gz' \) \
        -print -quit 2>/dev/null) ]]; then
        return 0
    fi
    echo -e "${RED}[deps] No font found under /usr/share/fonts.${NC}"
    echo -e "${RED}       Chromium would lay every glyph out at zero width: the markup${NC}"
    echo -e "${RED}       renders, the icons draw, and every assertion on visible text${NC}"
    echo -e "${RED}       fails as 'hidden'. Install a font package for this distribution.${NC}"
    exit 1
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

    # Generate index.html: strip SRI integrity attrs + inject tauri-mock.js
    python3 -c "
import re, sys
html = open(sys.argv[1]).read()
html = re.sub(r' integrity=\"[^\"]*\"', '', html)
html = html.replace('<script type=\"module\">', '<script src=\"/tauri-mock.js\"></script>\n<script type=\"module\">', 1)
open(sys.argv[2], 'w').write(html)
" "$PROJECT/crates/hardener-ui/dist/index.html" "$SERVE_DIR/index.html"

    echo -e "${GREEN}[setup] Serve directory ready: $SERVE_DIR${NC}"
    ls -la "$SERVE_DIR/"
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

# True when a candidate path is a browser rather than a message about one.
#
# The exit code is not enough by itself, because a stub is free to apologise
# and exit 0; what settles it is whether the thing names itself when asked for
# a version. Captured rather than piped: `cmd | grep -q` under `set -o
# pipefail` reports failure when grep exits at its first match and the writer
# dies of SIGPIPE, which is how six assertions in the package suite came to
# fail because the string they looked for was present.
usable_chromium() {
    local output
    [[ -x "$1" ]] || return 1
    output=$("$1" --version 2>/dev/null) || true
    grep -qiE 'chrom' <<<"$output"
}

run_playwright() {
    echo -e "${CYAN}[playwright] Installing npm dependencies...${NC}"
    cd "$GUI_TESTS"

    # Install Playwright (npm deps only: use system Chromium, not bundled)
    npm install --no-audit --no-fund 2>/dev/null
    export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

    # Locate a system Chromium that actually runs.
    #
    # Executable is not the same as usable. Ubuntu's `chromium` package is a
    # transitional stub for the snap, and its /usr/bin/chromium-browser exits
    # saying "requires the chromium snap to be installed" on a container that
    # has no snapd. The probe tested `-x` alone, accepted the signpost, and all
    # 113 tests failed in about three milliseconds each with no browser ever
    # started. `usable_chromium` above is the cheapest question that tells a
    # browser from a message about one.
    local chromium_bin=""
    for candidate in \
        /usr/bin/chromium \
        /usr/bin/chromium-browser \
        /usr/bin/google-chrome-stable \
        /usr/lib64/chromium-browser/headless_shell \
        /usr/lib/chromium-browser/chromium-browser \
        /usr/lib64/chromium/chromium \
        /usr/lib/chromium/chromium; do
        if usable_chromium "$candidate"; then
            chromium_bin="$candidate"
            break
        fi
    done

    if [[ -n "$chromium_bin" ]]; then
        export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium_bin"
        echo -e "${GREEN}[playwright] Using system Chromium: $chromium_bin${NC}"
    else
        # Playwright's own browser, fetched here rather than baked into the
        # image. It is the fallback and not the default because it costs a
        # download on every run, but a distribution that ships no usable
        # Chromium outside a snap leaves nothing else, and a suite that cannot
        # start a browser reports on the browser rather than on the interface.
        # --with-deps because a debootstrap container carries none of the
        # libraries the downloaded build links against.
        echo -e "${CYAN}[playwright] No usable system Chromium; fetching Playwright's own...${NC}"
        unset PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD
        run_install npx playwright install --with-deps chromium || return 1
    fi

    echo -e "${CYAN}[playwright] Running tests...${NC}"
    mkdir -p test-results/screenshots

    # PLAYWRIGHT_GREP narrows the run to one spec or one test, so a session
    # diagnosing the suite can get an answer inside the 600 s ceiling instead of
    # waiting out 113 tests to reach the one it cares about.
    local -a filter=()
    [[ -n "${PLAYWRIGHT_GREP:-}" ]] && filter=(--grep "$PLAYWRIGHT_GREP")

    local exit_code=0
    npx playwright test \
        --reporter=list \
        "${filter[@]}" \
        2>&1 || exit_code=$?

    # The artefacts are written into the bind mount and are already on the host.
    # run-gui-tests.sh files them under test-results/gui once nspawn returns,
    # which is the only place that still runs when the ceiling kills this
    # container.
    return $exit_code
}

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    echo -e "${CYAN}[cleanup] Stopping services...${NC}"
    [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null || true
    rm -rf "$SERVE_DIR"
}
trap cleanup EXIT

# =============================================================================
# Main
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GUI TEST RUNNER (Web UI: Playwright)                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

install_deps
require_a_font
prepare_serve_dir
start_http_server

pw_exit=0
run_playwright || pw_exit=$?

if [[ $pw_exit -eq 0 ]]; then
    echo -e "${GREEN}All Web UI tests passed.${NC}"
else
    echo -e "${RED}Some Web UI tests failed (exit code: $pw_exit).${NC}"
fi

exit $pw_exit
