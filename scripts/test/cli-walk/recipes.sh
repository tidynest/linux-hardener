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
# Every verb rendering both formats is captured twice, under adjacent slugs.
# The pairing is a detector and not a convenience: `report --format json`
# emitted prose rather than JSON for a whole release, and it was caught only
# because its text and JSON captures sat next to each other in the index and
# compared byte-identical. One capture cannot show that. A pair that is
# identical means the verb ignored the flag or has no JSON renderer behind it,
# and which of those it is comes second to noticing at all.
#
# Each pair below was measured before being registered, never assumed: the two
# captures differ and the JSON one parses. `--format` is a global flag, so it
# is accepted everywhere and honoured only where a renderer exists, which is
# exactly why "the flag was accepted" says nothing.
recipe scan-text            unprivileged ro -- scan
recipe scan-json            unprivileged ro -- scan --format json
recipe plugins-text         unprivileged ro -- plugins
recipe plugins-json         unprivileged ro -- plugins --format json
recipe report-text          unprivileged ro -- report --framework cis
# Both format paths, because they are different code. `--report-format` is the
# command's own flag; the global `--format json` reaches it only through
# `resolve_output_format`, and until #160 it silenced progress and emitted prose,
# so the invocation that looked most like machine mode produced the least
# machine-readable output. One recipe cannot cover both.
recipe report-json          unprivileged ro -- report --framework cis --format json
recipe report-report-format unprivileged ro -- report --framework cis --report-format json
# A second framework, because a walk over one says nothing about the catalogue.
recipe report-nist          unprivileged ro -- report --framework nist
recipe checkpoint-list      unprivileged ro -- checkpoint list
recipe checkpoint-list-json unprivileged ro -- checkpoint list --format json
recipe history-list         unprivileged ro -- history list
recipe history-list-json    unprivileged ro -- history list --format json
# `--host` is required, and `local` is the identifier `host_key_for` gives this
# host: read out of a real capture's `history list --format json`, not assumed.
recipe history-trends       unprivileged ro -- history trends --host local
recipe history-trends-json  unprivileged ro -- history trends --host local --format json
recipe history-regressions  unprivileged ro -- history regressions
recipe history-regressions-json unprivileged ro -- history regressions --format json

# --- Mutating local ----------------------------------------------------------
# Every argument here was read off `<command> --help`, not guessed. The first
# real walk lost its whole mutate phase to six recipes that invented flags the
# CLI does not have: `--execute` (there is none; a bare `apply --all` IS the
# execute path), `--name` and `--plugin`/`--key` (positionals), and an `apply`
# with neither `--all` nor `--plugin`, which the tool correctly refuses.
# ORDER IS LOAD-BEARING in this block. A phase runs its recipes in declaration
# order, so a recipe that consumes what an earlier one produced has to come
# after it, and one that needs a state an earlier one destroys has to come
# before. Two orderings were wrong on the first real walk and both read as
# product failures rather than as recipe bugs.
#
# `exception add` pins the value of a finding that is live NOW, so it must run
# BEFORE the apply that fixes that finding. Placed after, it correctly refused
# with "No live finding is keyed 'PASS_MAX_DAYS'" on every phase, and the
# success path was never walked at all.
#
# pam-hardening/PASS_MAX_DAYS rather than a service key: this pairing is raised
# on every distribution a pristine container can be, so the recipe exercises
# `exception add` instead of exercising its "no such key" refusal everywhere.
recipe exception-add        root mut -- exception add pam-hardening PASS_MAX_DAYS --reason 'cli walk probe'
recipe exception-remove     root mut -- exception remove pam-hardening PASS_MAX_DAYS
# `checkpoint create` BEFORE the apply, and this is the third ordering the
# first walks had wrong. `checkpoint list` is `ORDER BY timestamp DESC`, so
# RUNTIME_ID always resolves to the NEWEST checkpoint. Created after the apply,
# the probe was the newest and held the already-hardened state, so the rollback
# in the restore phase faithfully restored the host to exactly where it already
# was: it reported twenty files restored, exited as designed, and left the
# restored snapshot byte-identical to the applied one. A no-op by construction
# is the worst kind of green.
#
# Created before, every checkpoint at that boundary is pre-apply: this probe and
# the per-plugin `<plugin>-pre-apply` ones the apply takes itself. Whichever is
# newest, rolling back to it undoes real changes and the two snapshots differ.
recipe checkpoint-create    root mut -- checkpoint create 'walk probe'
recipe checkpoint-repair    root mut -- checkpoint repair
recipe apply-dry            root mut -- apply --all --dry-run
recipe apply-all            root mut -- apply --all

# --- Scheduling --------------------------------------------------------------
recipe systemd-generate     root   ro  -- systemd generate
recipe systemd-generate-json root  ro  -- systemd generate --format json
recipe daemon-status        root   ro  -- daemon status
recipe daemon-status-json   root   ro  -- daemon status --format json
recipe daemon-run-once      root   mut -- daemon run-once
recipe_timeout daemon-start booted mut 5 -- daemon start
recipe systemd-install      booted mut -- systemd install
recipe systemd-status       booted ro  -- systemd status
recipe systemd-status-json  booted ro  -- systemd status --format json
recipe systemd-uninstall    booted mut -- systemd uninstall

# --- Remote ------------------------------------------------------------------
# The ssh tier runs OUTSIDE a container, pointing at the booted SSH fixture.
# These are `batch` verbs: they target a remote, so running them inside the
# container under test would target the container from itself. RUNTIME_SSH is
# resolved to the fixture's `user@host` by whoever runs the tier; without a
# target `batch` has no hosts and the capture would say nothing.
#
# Both renderers here too. These were registered JSON-only, which is the shape
# the GUI and the suites drive them in, so the text path they also carry had
# never been captured at all.
recipe batch-scan-text      ssh ro  -- batch scan --ssh RUNTIME_SSH
recipe batch-scan-json      ssh ro  -- batch scan --ssh RUNTIME_SSH --format json
recipe batch-report-text    ssh ro  -- batch report --ssh RUNTIME_SSH
recipe batch-report-json    ssh ro  -- batch report --ssh RUNTIME_SSH --format json
recipe batch-apply          ssh mut -- batch apply --ssh RUNTIME_SSH --execute
recipe batch-rollback       ssh mut -- batch rollback --ssh RUNTIME_SSH
recipe ssh-refusal-daemon   unprivileged ro -- --ssh nonexistent.invalid daemon status

# --- Runtime-id placeholders ---------------------------------------------------
# checkpoint delete/show, rollback and history show/export each need an id
# that only exists at runtime. The runners substitute RUNTIME_ID and
# RUNTIME_SESSION from earlier captures in the same phase sequence, and skip
# with a reason where no id exists yet. RUNTIME_OUT is the capture directory.
recipe checkpoint-show      root ro  -- checkpoint show RUNTIME_ID
# `rollback` BEFORE `checkpoint delete`, and this is the second ordering the
# first walk had wrong. Both resolve the same RUNTIME_ID, which is fixed for
# the whole phase, so delete-then-rollback hands `rollback` an id it has just
# destroyed. The restore phase did nothing, the restored snapshot came out
# byte-identical to the applied one, and the walk could not show that a
# rollback undoes anything.
#
# The restored snapshot does NOT come back to the pristine one, and that is the
# design rather than a defect. `rollback` takes exactly one checkpoint id, and
# `apply --all` records one checkpoint per plugin, so this single invocation
# undoes whichever plugin's checkpoint is newest and leaves the other seven
# hardened. On arch that reads as 50 findings pristine against 45 restored: SSH
# returns in full, three PAM settings and two permissions findings stay fixed.
# Do not "fix" the gap by reverting every checkpoint here. Rolling all eight
# back in reverse order would hide the very thing the walk is showing, which is
# that a whole-system apply has no whole-system undo.
recipe rollback-run         root mut -- rollback RUNTIME_ID
recipe checkpoint-delete    root mut -- checkpoint delete RUNTIME_ID
recipe history-show         root ro  -- history show RUNTIME_SESSION
recipe history-export       root ro  -- history export RUNTIME_SESSION --output RUNTIME_OUT
