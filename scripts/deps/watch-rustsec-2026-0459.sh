#!/usr/bin/env bash
# =============================================================================
# Watch: can RUSTSEC-2026-0459 be fixed yet? (#188)
# =============================================================================
# libsqlite3-sys 0.39.0 is the first release that bundles a fixed SQLite
# (3.54.0), and no released sqlx accepts it: 0.8.6 needs ^0.30.1 and 0.9.0
# needs >=0.30.1, <0.38.0. Until one does, .cargo/audit.toml and deny.toml
# carry the advisory as an accepted risk. This asks cargo's own resolver
# whether a sqlx on crates.io now builds against a fixed libsqlite3-sys, so
# there is no version arithmetic here to get wrong.
#
# Exit status:
#   0  still blocked, and the review date has not passed
#   1  time to act: a released sqlx takes the fix, or the review date passed
#   2  the check could not run (no cargo, or no answer from the registry)
#
# The weekly Advisories workflow runs this, so a 1 reaches the maintainer as
# a failed run. Delete this script, its test, that job and both ignore entries
# in the same change that moves to the fixed release.
#
# Environment, for the test and for trying another floor:
#   FIXED_FLOOR  first fixed libsqlite3-sys release (default 0.39.0)
#   REVIEW_BY    the revisit date .cargo/audit.toml gives (default 2027-01-31)

set -euo pipefail

FIXED_FLOOR="${FIXED_FLOOR:-0.39.0}"
REVIEW_BY="${REVIEW_BY:-2027-01-31}"

# One line that GitHub shows as an annotation on the run, plain text elsewhere.
report() {
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        echo "::$1::$2"
    else
        echo "$2"
    fi
}

if ! command -v cargo >/dev/null 2>&1; then
    report error "cargo is not on PATH, so the check could not run"
    exit 2
fi

# ISO dates compare correctly as strings.
today="$(date -u +%F)"
if [[ "$today" > "$REVIEW_BY" ]]; then
    report error "RUSTSEC-2026-0459: the review date $REVIEW_BY has passed. Reassess the accepted risk in .cargo/audit.toml (#188), then either take the fix or set a new date there and in this script."
    exit 1
fi

probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT
mkdir "$probe/src"
: >"$probe/src/lib.rs"

# "sqlite" names the bundled backend in both the 0.8 and the 0.9 line. The
# empty [workspace] keeps the probe its own root wherever the directory sits.
# No version line: cargo has not needed one since 1.75, and a line starting
# `version = ` is what validate_version_locations.py reads as a release version.
cat >"$probe/Cargo.toml" <<EOF
[package]
name = "rustsec-2026-0459-probe"
edition = "2021"
publish = false

[dependencies]
sqlx = { version = ">=0.8.6", default-features = false, features = ["sqlite"] }
libsqlite3-sys = ">=$FIXED_FLOOR"

[workspace]
EOF

# The version a package resolved to, read from the probe's lockfile.
locked_version() {
    awk -v name="$1" '
        $0 == "name = \"" name "\"" { getline; gsub(/version = |"/, ""); print; exit }
    ' "$probe/Cargo.lock"
}

if output="$(cd "$probe" && cargo generate-lockfile 2>&1)"; then
    sqlx_version="$(locked_version sqlx)"
    sqlite_sys_version="$(locked_version libsqlite3-sys)"
    # Best effort: the minimum Rust that sqlx release declares, since moving
    # to it may raise the workspace's own rust-version.
    sqlx_rust="$(cd "$probe" && cargo info --quiet "sqlx@$sqlx_version" 2>/dev/null |
        sed -n 's/^rust-version: //p' | head -n 1 || true)"
    report error "RUSTSEC-2026-0459 can be fixed now: sqlx $sqlx_version accepts libsqlite3-sys $sqlite_sys_version${sqlx_rust:+ and declares Rust $sqlx_rust}. Follow the finishing steps in #188 and remove the accepted-risk entries."
    exit 1
fi

if grep -q 'failed to select a version' <<<"$output"; then
    echo "RUSTSEC-2026-0459 is still blocked: no released sqlx accepts libsqlite3-sys >= $FIXED_FLOOR. Review by $REVIEW_BY."
    exit 0
fi

report error "the check could not run: cargo did not resolve the probe"
echo "$output" >&2
exit 2
