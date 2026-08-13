#!/bin/bash
# =============================================================================
# CAPTURE LIBRARY: cli-walk
# =============================================================================
# Owns the capture layout and the index. Sourced by the host runner, the
# container inner script, and the self-test. Not safe to execute directly.
#
# The governing rule: a failing command is DATA. Every recipe runs, its exit
# code is recorded, and the walk carries on. Usage errors, permission denials
# and panics are the material a walk exists to surface.
# =============================================================================

WALK_ROOT=""
WALK_SEQ=0
WALK_ROWS=()

# walk_init CAPTURE_ROOT
# Creates the capture root and resets sequence state.
walk_init() {
    WALK_ROOT="$1"
    WALK_SEQ=0
    WALK_ROWS=()
    mkdir -p "$WALK_ROOT"
}

# run_recipe SLUG PHASE TIMEOUT_SECONDS -- ARGV...
# TIMEOUT_SECONDS of 0 means no timeout. Captures argv, stdout, stderr and the
# exit code into $WALK_ROOT/$PHASE/<NNN>-<slug>/.
run_recipe() {
    local slug="$1" phase="$2" timeout_s="$3"
    shift 3
    [[ "${1:-}" == "--" ]] && shift

    WALK_SEQ=$((WALK_SEQ + 1))
    local seq
    seq="$(printf '%03d' "$WALK_SEQ")"
    local dir="$WALK_ROOT/$phase/$seq-$slug"
    mkdir -p "$dir"

    printf '%q ' "$@" > "$dir/cmd"
    printf '\n' >> "$dir/cmd"

    local code note=""
    if [[ "$timeout_s" != "0" ]]; then
        # SIGTERM by default, which is what a service manager sends, so the
        # process takes its real shutdown path and whatever it prints on the
        # way out lands in the capture. --kill-after is a backstop only.
        timeout --kill-after=5 "$timeout_s" "$@" > "$dir/stdout" 2> "$dir/stderr"
        code=$?
        if [[ $code -eq 124 ]]; then
            note="timed out at ${timeout_s}s, which is the intended outcome for a blocking command"
        elif [[ $code -eq 137 ]]; then
            note="ignored SIGTERM and needed the SIGKILL backstop, which is itself a finding"
        fi
    else
        "$@" > "$dir/stdout" 2> "$dir/stderr"
        code=$?
    fi
    # Written from a plain run above, never through a pipe.
    echo "$code" > "$dir/exit"

    local bytes
    bytes=$(wc -c < "$dir/stdout")

    # The single total check. Unparseable JSON from a --format json command is
    # unambiguously wrong, requires nobody to have anticipated a case, and
    # catches a whole class at once: a tracing line leaking to stdout, a
    # partial write, a panic mid-serialisation. It FLAGS only. The walk's exit
    # code has to keep meaning "trustworthy or not" and nothing else.
    if [[ " $* " == *" --format json "* ]] && [[ -s "$dir/stdout" ]]; then
        if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$dir/stdout" 2>/dev/null; then
            note="${note:+$note; }stdout is not valid JSON"
        fi
    fi

    WALK_ROWS+=("$phase|$seq-$slug|$code|$bytes|$note")
}

# walk_skip SLUG PHASE REASON
# Records a recipe that could not be attempted. An omitted row reads as a
# clean sheet, and "never ran" must never render as "ran and passed".
walk_skip() {
    WALK_ROWS+=("$2|$1|skipped|0|$3")
}

# walk_write_index HEADER_LINE
# Writes $WALK_ROOT/index.md. HEADER_LINE names the binary that spoke.
walk_write_index() {
    local header="$1"
    local out="$WALK_ROOT/index.md"
    {
        echo "# CLI walk capture"
        echo ""
        echo "$header"
        echo ""
        echo "| Phase | Invocation | Exit | Bytes | Note |"
        echo "|-------|------------|------|-------|------|"
        local row
        for row in "${WALK_ROWS[@]}"; do
            IFS='|' read -r phase slug code bytes note <<< "$row"
            echo "| $phase | $slug | $code | $bytes | $note |"
        done
    } > "$out"
}
