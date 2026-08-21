#!/usr/bin/env python3
"""Capture each GUI route via headless Chromium, then trim bottom whitespace.
Tall viewport so below-the-fold content is fully captured; width stays 1920."""
import subprocess
import sys
import shutil
from pathlib import Path
from PIL import Image

SP = Path(__file__).resolve().parent
SHOTS = SP / "shots"
SHOTS.mkdir(exist_ok=True)
BASE = "http://127.0.0.1:8137"
# Resolved from PATH rather than hardcoded to one machine's home directory,
# which is what it was until this moved into the tracked tree. Falls back to
# bare chromium where the machine has no thermal shim.
HOTRUN = shutil.which("hotrun")
PROFILE = SP / "chrome-profile"

WIDTH, TALL = 1920, 3000

# route -> output filename
PAGES = [
    ("/", "dashboard.png"),
    ("/analysis", "analysis-findings.png"),
    ("/hardening", "hardening.png"),
    ("/remote", "remote.png"),
    ("/fleet", "fleet.png"),
    ("/fleet-apply", "fleet-apply.png"),
    ("/scheduler", "scheduler.png"),
]


def capture(route: str, out: Path, idx: int) -> None:
    # Fresh profile per page: avoids the singleton lock stalling back-to-back
    # headless launches. `timeout` is a hard backstop against any residual hang.
    subprocess.run(
        [
            "timeout", "35",
            *( [HOTRUN] if HOTRUN else [] ), "chromium", "--headless=old", "--no-sandbox", "--disable-gpu",
            "--hide-scrollbars", "--force-device-scale-factor=1",
            f"--user-data-dir={PROFILE}-{idx}", "--no-first-run",
            "--no-default-browser-check",
            f"--window-size={WIDTH},{TALL}",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=6000",
            f"--screenshot={out}", f"{BASE}{route}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def trim_bottom(path: Path, pad: int = 40, tol: int = 12) -> tuple:
    """Crop trailing rows that match the page background colour."""
    im = Image.open(path).convert("RGB")
    w, h = im.size
    px = im.load()
    bg = px[5, h - 5]  # bottom strip is empty background

    def row_empty(y: int) -> bool:
        return all(
            all(abs(px[x, y][c] - bg[c]) <= tol for c in range(3))
            for x in range(0, w, 17)  # sample every 17px for speed
        )

    bottom = h
    while bottom > 1 and row_empty(bottom - 1):
        bottom -= 1
    bottom = min(h, bottom + pad)
    if bottom < h:
        im = im.crop((0, 0, w, bottom))
        im.save(path)
    return im.size


def main() -> None:
    for idx, (route, name) in enumerate(PAGES):
        out = SHOTS / name
        capture(route, out, idx)
        size = trim_bottom(out)
        print(f"{route:14s} -> {name:22s} {size[0]}x{size[1]}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
