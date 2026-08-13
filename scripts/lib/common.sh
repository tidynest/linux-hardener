#!/bin/bash
# =============================================================================
# SHARED SCRIPT HELPERS: Linux Hardener
# =============================================================================
# Sourced by the test runners (scripts/test/*.sh, scripts/test/gui/*.sh,
# scripts/test/polkit/*.sh) and the container tooling (scripts/containers/*.sh).
# Provides the ANSI colour codes, the box-drawing banner helper, cargo
# target-dir resolution, the distro/container name tables shared by the
# cross-distro, package and GUI test runners plus create-container.sh, and the
# three binary-identity questions the release-readiness and CLI walk runners
# both ask before trusting a container's output.
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
    [ubuntu]="hardener-test-ubuntu"
    [fedora]="hardener-test-fedora"
    [rhel]="hardener-test-rhel"
    [opensuse]="hardener-test-opensuse"
    # An Arch bootstrap with ufw left out, so nftables is the only firewall
    # backend installed and the plugin has to select it (#47). Every one of the
    # six above reaches ufw or firewalld instead, so the plugin's nftables path
    # and the differential suite's nftables oracle had no fixture that could
    # exercise them.
    #
    # Deliberately NOT in DISTRO_ORDER. It is a second Arch rather than a
    # seventh distribution, and adding it there would change the container
    # count, the timings and the expected totals of every cross-distro runner
    # for a fixture that answers one question.
    [arch-nftables]="hardener-test-nftables"
)
# Ubuntu sits beside Debian because it takes the Debian family's code path and
# the same bootstrap. It is the newest entry and no run of any suite against it
# is dated anywhere: a container existing is not a container that has been run.
DISTRO_ORDER=(arch debian ubuntu fedora rhel opensuse)

# =============================================================================
# Binary identity
# =============================================================================
#
# Moved here from release-readiness-root.sh, which had the only copy, when the
# CLI walk needed the same three questions (#47 follow-up). A container run once
# attributed a failure to code the binary did not contain, and the CLI walk's
# first real run did it again: it reproduced `report --format json` printing
# prose, which had been fixed the previous day, because the container held a
# binary from the commit before the fix. Every runner checks a binary EXISTS;
# these are what check it is the one the tree describes.
#
# Callers must set PROJECT_DIR before calling workspace_version or
# first_source_newer_than.

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
# A commit check cannot see an uncommitted edit: the binary carries the commit
# it was built at, and an edit on top of that commit leaves the identity string
# untouched while making the binary stale. This is what notices.
first_source_newer_than() {
    local binary="$1"
    find "$PROJECT_DIR/crates" "$PROJECT_DIR/src-tauri" \
        "$PROJECT_DIR/Cargo.toml" "$PROJECT_DIR/Cargo.lock" \
        -newer "$binary" \
        \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
        -print -quit 2>/dev/null
}
