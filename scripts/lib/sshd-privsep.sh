#!/bin/bash
# =============================================================================
# sshd privilege separation directory guard, shared
# =============================================================================
# Sourced by every suite that reaches sshd inside an unbooted container:
# differential-suite.sh, full-test-suite.sh and the CLI walk's inner runner.
# It lived in differential-suite.sh alone, which is why the walk and the full
# suite both went without it and reported SSH coverage they never had.
#
# The self-test that guards this function lives in differential-suite.sh and
# drives it through a stubbed sshd: healthy host, creatable directory,
# unrelated complaint, uncreatable path, still-refused-after-creating, and a
# carriage return in sshd's message. Moving the function here does not move
# those cases, so run `differential-suite.sh --self-test` after touching it.
# =============================================================================

# sshd refuses to parse a configuration without its compiled-in privilege
# separation directory, and on a booted host systemd creates that directory
# through `RuntimeDirectory=sshd`. This suite runs under `nspawn --pipe`, where
# nothing boots, so on Debian the directory is simply absent and every ssh
# oracle dies on "Missing privilege separation directory" before it can read a
# single value. The container is not wrong; it has just never been booted.
#
# Create exactly the directory sshd names, and only when sshd names one: a
# container that already has it is left untouched, and any other sshd complaint
# is left for the oracle to report rather than being second-guessed here.
require_sshd_privsep_dir() {
    local complaint dir
    # `if` rather than `sshd -t && return 0`: under `set -e` the exemption for a
    # failing left operand does not extend to the status of the list itself.
    if complaint=$(sshd -t 2>&1); then
        return 0
    fi
    # sshd's message arrives carriage-return terminated under nspawn's console
    # handling, and `mkdir "/run/sshd\r"` creates a directory sshd will never
    # look for while the line reporting it reads exactly right. Strip the
    # carriage returns, and any other surrounding blank, before the path is used
    # for anything at all.
    dir=$(printf '%s\n' "$complaint" | tr -d '\r' |
        sed -n 's/^Missing privilege separation directory:[[:space:]]*//p' |
        sed 's/[[:space:]]*$//' | head -1)
    [[ -n "$dir" ]] || return 0
    if ! mkdir -p "$dir" || ! chmod 0755 "$dir"; then
        echo "FATAL: sshd needs the privilege separation directory $dir, and it" >&2
        echo "  could not be created. Every ssh oracle reads through sshd, so a" >&2
        echo "  run without it would compare nothing and print a clean summary." >&2
        return 1
    fi
    # Creating it is not the same as fixing it. Ask sshd again rather than
    # assume, and carry what it still says: a guard that reports a success it
    # never observed is the exact failure this suite exists to catch, and the
    # first version of this function shipped with that defect.
    if complaint=$(sshd -t 2>&1); then
        echo "Created sshd privilege separation directory $dir (nothing booted to create it)"
        return 0
    fi
    echo "FATAL: created $dir, and sshd still refuses to parse a configuration:" >&2
    printf '  %s\n' "$complaint" >&2
    ls -ld "$dir" >&2 || echo "  and $dir does not stat" >&2
    return 1
}
