#!/bin/bash
# =============================================================================
# SHARED SCRIPT HELPERS: Linux Hardener
# =============================================================================
# Sourced by the test runners (scripts/test/*.sh, scripts/test/gui/*.sh,
# scripts/test/polkit/*.sh) and the container tooling (scripts/containers/*.sh).
# Provides the ANSI colour codes, the box-drawing banner helper, cargo
# target-dir resolution, and the distro/container name tables shared by the
# cross-distro, package and GUI test runners plus create-container.sh.
#
# Callers must set PROJECT_DIR before calling resolve_target_dir (it reads
# that variable); sourcing this file alone does not require it. Not safe to
# execute directly -- source only.
# =============================================================================

# shellcheck disable=SC2034  # colours and tables are consumed by sourcing scripts, not this file

# --- ANSI colour codes -------------------------------------------------------
# Same codes used project-wide; kept in one place so scripts stop re-declaring
# identical escape sequences under different variable-set combinations.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Box-drawing summary banner ----------------------------------------------
# print_boxline CONTENT
# Pads CONTENT to the caller's $BOX_W (default 74 if unset) and wraps it in
# the magenta box-drawing border used by the test runner banners. Callers set
# BOX_W before their first call, same as before this was shared.
print_boxline() {
    local content="$1"
    local pad=$(( ${BOX_W:-74} - ${#content} ))
    local spaces=""
    for ((i = 0; i < pad; i++)); do spaces+=" "; done
    echo -e "${MAGENTA}║${NC}${content}${spaces}${MAGENTA}║${NC}"
}

# --- Cargo target-dir resolution ---------------------------------------------
# resolve_target_dir PROBE...
# Cargo may redirect build output away from ./target (CARGO_TARGET_DIR or a
# [build] target-dir in ~/.cargo/config.toml); probe candidate directories for
# each PROBE relative path before falling back to "$PROJECT_DIR/target".
# Requires PROJECT_DIR to already be set by the caller.
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

# --- Distro / container name tables ------------------------------------------
# Shared by the cross-distro, package and GUI test runners, and by
# create-container.sh's per-distro dispatch. Container names are stable and
# relied upon across the test suite and docs -- do not rename lightly.
declare -A CONTAINERS=(
    [arch]="hardener-test"
    [debian]="hardener-test-debian"
    [fedora]="hardener-test-fedora"
    [rhel]="hardener-test-rhel"
    [opensuse]="hardener-test-opensuse"
)
DISTRO_ORDER=(arch debian fedora rhel opensuse)
