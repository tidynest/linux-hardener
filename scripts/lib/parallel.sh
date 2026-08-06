#!/bin/bash
# =============================================================================
# PARALLEL JOB-POOL HELPER: Linux Hardener
# =============================================================================
# Shared bounded-concurrency job pool used by the cross-distro and Web UI GUI
# test runners' --parallel mode. Depends on lib/common.sh's DIM/CYAN/NC colour
# vars being set (source common.sh first). Not safe to execute directly --
# source only.
# =============================================================================

# launch_job_pool MAX_JOBS DISTRO_ARRAY_NAME [STAGGER_SECONDS]
# Runs the caller-defined run_single_distro() once per entry in the named
# array, at most MAX_JOBS concurrently (throttled via `wait -n`). Populates
# the global PIDS and PID_DISTROS arrays in launch order so the caller can
# `wait` on each PID and harvest its result afterwards.
launch_job_pool() {
    local max_jobs="$1"
    local -n _job_pool_distros="$2"
    local stagger="${3:-0}"

    PIDS=()
    PID_DISTROS=()

    local running=0 distro
    for distro in "${_job_pool_distros[@]}"; do
        while [[ $running -ge $max_jobs ]]; do
            wait -n 2>/dev/null || true
            ((running--)) || true
        done

        run_single_distro "$distro" &
        PIDS+=($!)
        PID_DISTROS+=("$distro")
        ((running++))
        echo -e "${DIM}  Started job for $distro (PID: ${PIDS[-1]})${NC}"
        [[ "$stagger" -gt 0 ]] && sleep "$stagger"
    done

    echo ""
    echo -e "${CYAN}Waiting for all jobs to complete...${NC}"
    echo ""
}
