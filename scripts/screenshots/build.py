#!/usr/bin/env python3
"""Assemble the screenshot serve dir: real prebuilt dist + Tauri IPC shim +
mock payloads, with index.html patched to boot the shim and drop Trunk's
autoreload websocket."""
import re
import shutil
from pathlib import Path

SP = Path(__file__).resolve().parent
# Repository-relative, not absolute. This file carried the author's own
# checkout path until it moved into the tracked tree on 2026-08-21, which is
# the kind of thing a gitignored tool never has to answer for.
REPO = SP.parents[1]
DIST = REPO / "crates" / "hardener-ui" / "dist"
REPORTS = SP / "mock-reports.json"
SERVE = SP / "serve"

# Fresh copy of the real prebuilt UI (byte-identical js/css/wasm -> SRI holds).
if not DIST.exists():
    raise SystemExit(
        f"no built frontend at {DIST}. Run `trunk build` in crates/hardener-ui "
        "first: this harness serves whatever is there and cannot build it."
    )
if SERVE.exists():
    shutil.rmtree(SERVE)
shutil.copytree(DIST, SERVE)

# The IPC fixture is `gui-tests/tauri-mock.js`, the SAME file the container
# suite injects, and not a shim of this harness's own.
#
# There was one here, `tauri-shim.js`, and it had gone stale in exactly the way
# a second copy of a fixture does. It answered nine commands and returned `[]`
# for `list_remote_hosts`, `get_checkpoints` and `get_scan_history`, so Hosts,
# Hardening History and Fleet Apply rendered empty and none of the states the
# committed screenshots show could be reached at all; it also stamped the
# header "v1.4.0" by hand, two releases back. Nothing checked either, because
# nothing validates a fixture only this harness uses.
#
# `tauri-mock.js` is held to the Rust types by
# `scripts/validate/validate_gui_mock_fixtures.py` on every run of
# `validate_all.py`, answers 34 commands, and is driven daily by 165 Playwright
# cases, so every state the suite reaches is a state this harness can now
# capture. Its data is the test fixture's rather than a curated demo, which is
# the trade: reproducible and type-checked, in exchange for web-01 and db-01
# instead of prettier names.
shutil.copy(
    REPO / "gui-tests" / "tauri-mock.js", SERVE / "tauri-mock.js"
)
shutil.copy(SP / "mock-scan.json", SERVE / "mock-scan.json")
shutil.copy(REPORTS, SERVE / "mock-reports.json")

# Patch index.html.
html = (SERVE / "index.html").read_text()

# 1. Boot the shim before anything else in <head> (classic script = runs
#    during parse, ahead of the deferred WASM module).
assert "<head>" in html
html = html.replace(
    "<head>",
    "<head>\n"
    '    <script src="/tauri-mock.js"></script>\n'
    # Freeze animations/transitions so headless virtual-time settles and every
    # capture is deterministic (no mid-transition frames).
    "    <style>*,*::before,*::after{animation:none!important;"
    "transition:none!important;caret-color:transparent!important}"
    # Unpin the dashboard footer (margin-top:auto in a 100vh flex column) so
    # tall-viewport captures collapse to real content height for the trim.
    ".main-content,.dashboard-page{min-height:0!important}"
    ".dashboard-footer{margin-top:16px!important}</style>",
    1,
)

# 2. Remove Trunk's dev autoreload script (the IIFE that opens a websocket to
#    the unsubstituted {{__TRUNK_ADDRESS__}} template and can paint a "Build
#    failure" overlay). Match the <script> block that mentions the template.
html = re.sub(
    r"<script>\s*\"use strict\";.*?__TRUNK_ADDRESS__.*?</script>",
    "",
    html,
    flags=re.DOTALL,
)
# Not every trunk build emits the dev autoreload script (this build did not),
# so its absence is fine; only guard against a partial/failed strip.
assert "__TRUNK_ADDRESS__" not in html

(SERVE / "index.html").write_text(html)
print("serve dir ready:", SERVE)
print("files:", sorted(p.name for p in SERVE.iterdir()))
