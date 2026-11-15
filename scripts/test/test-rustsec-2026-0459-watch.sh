#!/usr/bin/env bash
# =============================================================================
# Unit test: the RUSTSEC-2026-0459 watch (#188)
# =============================================================================
# Runs unprivileged and offline in about a second. No network, no framework.
#
# What it protects. `scripts/deps/watch-rustsec-2026-0459.sh` decides whether
# the weekly Advisories run fails, and its three answers mean different things
# to the maintainer: 0 is "still waiting on sqlx", 1 is "act now", 2 is "the
# check itself is broken". A watch that read a registry outage as "still
# blocked" would stay green for good, which is the failure this guards.
#
# A stand-in `cargo` on PATH plays each answer the real resolver gives, so the
# watch runs unchanged against every case. The live answer is measured by
# running the watch itself, not here.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCH="$SCRIPT_DIR/../deps/watch-rustsec-2026-0459.sh"
FAILURES=0

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILURES=$((FAILURES + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAKE_BIN="$WORK/bin"
mkdir "$FAKE_BIN"

# The stand-in. FAKE_CARGO_MODE picks the resolver's answer; every call is
# logged so a case can assert that cargo was never asked.
cat >"$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_CARGO_LOG"
case "$1" in
    generate-lockfile)
        case "$FAKE_CARGO_MODE" in
            blocked)
                echo "error: failed to select a version for \`libsqlite3-sys\`." >&2
                exit 101
                ;;
            resolves)
                printf '[[package]]\nname = "libsqlite3-sys"\nversion = "0.39.1"\n\n' >Cargo.lock
                printf '[[package]]\nname = "sqlx"\nversion = "0.9.1"\n' >>Cargo.lock
                exit 0
                ;;
            unreachable)
                echo "error: failed to get \`sqlx\` as a dependency of package" >&2
                exit 101
                ;;
        esac
        ;;
    info)
        echo "sqlx #database #async"
        echo "rust-version: 1.94.0"
        exit 0
        ;;
esac
exit 99
EOF
chmod +x "$FAKE_BIN/cargo"

# Runs the watch with the stand-in first on PATH; sets STATUS and OUTPUT.
# GITHUB_ACTIONS is cleared first so a case runs the same inside CI, and the
# caller's assignments come after it so one case can set it back.
run_watch() {
    local mode="$1"
    shift
    : >"$WORK/cargo.log"
    OUTPUT="$(env GITHUB_ACTIONS= "$@" FAKE_CARGO_MODE="$mode" \
        FAKE_CARGO_LOG="$WORK/cargo.log" PATH="$FAKE_BIN:$PATH" \
        "$BASH" "$WATCH" 2>&1)"
    STATUS=$?
}

echo "watch-rustsec-2026-0459.sh"

run_watch blocked REVIEW_BY=2999-12-31
if [[ $STATUS -eq 0 && "$OUTPUT" == *"still blocked"* ]]; then
    pass "no release takes the fix: exit 0, still blocked"
else
    fail "blocked resolver: expected exit 0 and 'still blocked', got $STATUS: $OUTPUT"
fi

run_watch resolves REVIEW_BY=2999-12-31
if [[ $STATUS -eq 1 && "$OUTPUT" == *"sqlx 0.9.1 accepts libsqlite3-sys 0.39.1"* &&
    "$OUTPUT" == *"Rust 1.94.0"* ]]; then
    pass "a release takes the fix: exit 1, naming both versions and the Rust floor"
else
    fail "resolving resolver: expected exit 1 naming 0.9.1, 0.39.1 and 1.94.0, got $STATUS: $OUTPUT"
fi

run_watch unreachable REVIEW_BY=2999-12-31
if [[ $STATUS -eq 2 && "$OUTPUT" != *"still blocked"* ]]; then
    pass "a registry failure is exit 2, never read as still blocked"
else
    fail "unreachable registry: expected exit 2 without 'still blocked', got $STATUS: $OUTPUT"
fi

run_watch blocked REVIEW_BY=2000-01-01
if [[ $STATUS -eq 1 && "$OUTPUT" == *"review date 2000-01-01 has passed"* && ! -s "$WORK/cargo.log" ]]; then
    pass "a passed review date is exit 1 before cargo is asked"
else
    fail "past review date: expected exit 1 and no cargo call, got $STATUS: $OUTPUT"
fi

: >"$WORK/cargo.log"
OUTPUT="$(PATH="$WORK/empty" "$BASH" "$WATCH" 2>&1)"
STATUS=$?
if [[ $STATUS -eq 2 && "$OUTPUT" == *"cargo is not on PATH"* ]]; then
    pass "no cargo on PATH is exit 2"
else
    fail "missing cargo: expected exit 2, got $STATUS: $OUTPUT"
fi

run_watch resolves REVIEW_BY=2999-12-31 GITHUB_ACTIONS=true
if [[ "$OUTPUT" == "::error::"* ]]; then
    pass "under GitHub Actions the finding is an error annotation"
else
    fail "annotation: expected a ::error:: line, got: $OUTPUT"
fi

echo
if [[ $FAILURES -eq 0 ]]; then
    echo "All checks passed"
    exit 0
fi
echo "$FAILURES check(s) failed"
exit 1
