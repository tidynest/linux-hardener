#!/bin/bash
# =============================================================================
# RECIPES: cli-walk
# =============================================================================
# Data only. Sourced by the runners and by coverage.sh. Not executable.
#
# A tier states the MINIMUM a recipe requires, not the identity it runs as.
# Inside the container everything runs as root, so an "unprivileged" recipe
# runs privileged there and unprivileged on the host. That difference is one
# of the walk's better signals: #156 was exactly it, an unprivileged desktop
# unable to read the root-owned checkpoint database and saying nothing.
#
# phase kind "ro" means the recipe does not modify SYSTEM state, so it is safe
# to repeat in the pristine, applied and restored snapshots. Some ro recipes do
# write files (report, history export, scan); report and history export are
# directed into the capture directory rather than a system path. Scan persists a
# session to the history database, but this is application bookkeeping, not
# system state, so it remains ro and safe to repeat across phases.
# =============================================================================

RECIPE_SLUGS=()
RECIPE_TIERS=()
RECIPE_TIMEOUTS=()
RECIPE_ARGV=()
RECIPE_PHASEKIND=()
SKIP_SLUGS=()
SKIP_REASONS=()

# recipe_timeout SLUG TIER KIND SECONDS -- ARGV...
# The single registration point. Every field is written here and nowhere else,
# so a sixth parallel array cannot be added to one registrar and missed by the
# other.
recipe_timeout() {
    local slug="$1" tier="$2" kind="$3" secs="$4"
    shift 4
    [[ "${1:-}" == "--" ]] && shift
    RECIPE_SLUGS+=("$slug")
    RECIPE_TIERS+=("$tier")
    RECIPE_TIMEOUTS+=("$secs")
    RECIPE_PHASEKIND+=("$kind")
    RECIPE_ARGV+=("$(printf '%s\n' "$@")")
}

# recipe SLUG TIER KIND -- ARGV...
# A recipe with no timeout, which is the common case.
recipe() {
    local slug="$1" tier="$2" kind="$3"
    shift 3
    [[ "${1:-}" == "--" ]] && shift
    recipe_timeout "$slug" "$tier" "$kind" 0 -- "$@"
}

# skip COMMAND_PATH REASON
# Retained with no current users. coverage.sh fails closed, and a check that
# fails closed with no escape hatch gets disabled the first time somebody
# legitimately cannot cover something.
skip() {
    SKIP_SLUGS+=("$1")
    SKIP_REASONS+=("$2")
}

# --- Read-only core ----------------------------------------------------------
recipe scan-text            unprivileged ro -- scan
recipe scan-json            unprivileged ro -- scan --format json
recipe plugins-text         unprivileged ro -- plugins
recipe plugins-json         unprivileged ro -- plugins --format json
recipe report-text          unprivileged ro -- report --framework cis
recipe report-json          unprivileged ro -- report --framework cis --format json
recipe checkpoint-list      unprivileged ro -- checkpoint list
recipe checkpoint-list-json unprivileged ro -- checkpoint list --format json
recipe history-list         unprivileged ro -- history list
recipe history-list-json    unprivileged ro -- history list --format json
recipe history-trends       unprivileged ro -- history trends
recipe history-regressions  unprivileged ro -- history regressions

# --- Mutating local ----------------------------------------------------------
recipe apply-dry            root mut -- apply --dry-run
recipe apply-execute        root mut -- apply --execute
recipe checkpoint-create    root mut -- checkpoint create --name 'walk probe'
recipe checkpoint-repair    root mut -- checkpoint repair
recipe exception-add        root mut -- exception add --plugin service-minimisation --key bluetooth-service --reason 'cli walk probe'
recipe exception-remove     root mut -- exception remove --plugin service-minimisation --key bluetooth-service

# --- Scheduling --------------------------------------------------------------
recipe systemd-generate     root   ro  -- systemd generate
recipe daemon-status        root   ro  -- daemon status
recipe daemon-run-once      root   mut -- daemon run-once
recipe_timeout daemon-start booted mut 5 -- daemon start
recipe systemd-install      booted mut -- systemd install
recipe systemd-status       booted ro  -- systemd status
recipe systemd-uninstall    booted mut -- systemd uninstall

# --- Remote ------------------------------------------------------------------
recipe batch-scan           ssh ro  -- batch scan --format json
recipe batch-report         ssh ro  -- batch report --format json
recipe batch-apply          ssh mut -- batch apply --execute
recipe batch-rollback       ssh mut -- batch rollback
recipe ssh-refusal-daemon   unprivileged ro -- --ssh nonexistent.invalid daemon status

# --- Runtime-id placeholders ---------------------------------------------------
# checkpoint delete/show, rollback and history show/export each need an id
# that only exists at runtime. Task 5 resolves ids from earlier captures and
# registers the real recipes dynamically; these placeholders exist only so
# coverage.sh sees the command families as covered before that task lands.
recipe checkpoint-show      root ro  -- checkpoint show RUNTIME_ID
recipe checkpoint-delete    root mut -- checkpoint delete RUNTIME_ID
recipe rollback-run         root mut -- rollback RUNTIME_ID
recipe history-show         root ro  -- history show RUNTIME_SESSION
recipe history-export       root ro  -- history export RUNTIME_SESSION --output RUNTIME_OUT
