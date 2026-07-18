#!/bin/bash
# Bulletproof Tauri dev launcher for Arch Linux + Hyprland + NVIDIA
# Automatically detects session type and applies WebKitGTK workarounds
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# ─────────────────────────────────────────────────────────────
# Session Detection
# ─────────────────────────────────────────────────────────────
detect_session() {
    if [ -n "${XDG_SESSION_TYPE:-}" ]; then
        echo "$XDG_SESSION_TYPE"
    elif [ -n "${WAYLAND_DISPLAY:-}" ]; then
        echo "wayland"
    elif [ -n "${DISPLAY:-}" ]; then
        echo "x11"
    else
        echo "unknown"
    fi
}

has_nvidia() {
    lspci 2>/dev/null | grep -qi nvidia || command -v nvidia-smi &>/dev/null
}

# ─────────────────────────────────────────────────────────────
# Environment Configuration
# ─────────────────────────────────────────────────────────────
SESSION_TYPE=$(detect_session)
echo "» Session type: $SESSION_TYPE"
echo "» Project: $PROJECT_ROOT"

# CRITICAL: Fix for NVIDIA + Wayland (affects 95% of blank window issues)
if has_nvidia; then
    export WEBKIT_DISABLE_DMABUF_RENDERER=1
    echo "» NVIDIA detected: WEBKIT_DISABLE_DMABUF_RENDERER=1"
fi

# Hyprland-specific: disable compositing mode if resize crashes occur
if [ -n "${HYPRLAND_INSTANCE_SIGNATURE:-}" ]; then
    export WEBKIT_DISABLE_COMPOSITING_MODE=1
    echo "» Hyprland detected: WEBKIT_DISABLE_COMPOSITING_MODE=1"
fi

# Fallback for persistent issues (uncomment if needed)
# export GDK_BACKEND=x11
# export __NV_DISABLE_EXPLICIT_SYNC=1

# Rust debugging
export RUST_BACKTRACE=1
export RUST_LOG="${RUST_LOG:-info}"

# ─────────────────────────────────────────────────────────────
# Pre-flight Checks
# ─────────────────────────────────────────────────────────────
echo "» Running pre-flight checks..."

# Check required packages
check_package() {
    if ! pacman -Qi "$1" &>/dev/null; then
        echo "ERROR: Missing package: $1"
        echo "  Install with: sudo pacman -S $1"
        exit 1
    fi
}

check_package webkit2gtk-4.1
check_package librsvg

# Verify Rust WASM target
if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
    echo "» Installing wasm32 target..."
    rustup target add wasm32-unknown-unknown
fi

# Check for port conflicts
if lsof -i :1420 &>/dev/null; then
    echo "» Port 1420 in use, killing existing process..."
    lsof -ti:1420 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# Check for existing Tauri processes
if pgrep -f "linux-system-hardener" &>/dev/null; then
    echo "» Existing app process found, killing..."
    pkill -f "linux-system-hardener" 2>/dev/null || true
    sleep 1
fi

# ─────────────────────────────────────────────────────────────
# Launch Tauri Dev Mode
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Starting Tauri Dev Mode"
echo "  Press Ctrl+Shift+I in app window to open DevTools"
echo "═══════════════════════════════════════════════════════════"
echo ""

exec cargo tauri dev "$@"
