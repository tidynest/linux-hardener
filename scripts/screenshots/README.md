# Headless GUI screenshot / mockup harness

Renders the **real Leptos/WASM UI headlessly with mock data** (no Tauri backend,
no sudo, no window focus stolen), then writes 1920-wide PNGs auto-trimmed to
content. Built for refreshing the README screenshots; reuse it for before/after
visual regression during the GUI/UX redesign, and to preview static mockups.

## Why it exists

In a plain browser the app has no Tauri IPC, so every `invoke()` errors and pages
render empty. `tauri-shim.js` injects a fake `window.__TAURI__` that returns
representative JSON per command, so the real UI renders fully populated.

## Files

- `build.py`   - assembles a `serve/` dir: copies the prebuilt
  `crates/hardener-ui/dist/`, drops in the shim + mock payloads, injects the shim
  before the WASM module, injects an animation/transition killer (deterministic
  frames + lets headless virtual-time settle), and strips Trunk's autoreload
  script. Edit the injected `<style>` to unpin the dashboard footer etc.
- `serve.py`   - localhost SPA server (unknown paths fall back to `index.html`
  so client-side routes like `/analysis` resolve). Port 8137.
- `shoot.py`   - drives `chromium --headless` per route, writes to `shots/`,
  trims bottom whitespace. Edit the `PAGES` list to choose routes/filenames.
  **Routes only**: `--screenshot` loads a URL and shoots it, so nothing behind a
  click is reachable.
- `capture-docs.js` - the 23 states `docs/assets/screenshots/` documents, at a
  fixed 1920x1080, driven with Playwright from `gui-tests/node_modules`. Every
  shot names a `ready` selector that exists ONLY in the state it claims and
  fails if it never appears, because a step that clicked and hoped would write
  a plausible PNG of the wrong screen and a screenshot is the one artefact
  nobody diffs.
- The IPC fixture is **`gui-tests/tauri-mock.js`**, copied in by `build.py`.
  There was a `tauri-shim.js` here and it was deleted on 2026-08-21: it
  answered nine commands, returned `[]` for `list_remote_hosts`,
  `get_checkpoints` and `get_scan_history`, and stamped the header `v1.4.0` by
  hand two releases after that was true. Hosts, Hardening History and Fleet
  Apply all rendered empty, so 12 of the 23 states could not be reached at all.
  Nothing checked any of it, because nothing validates a fixture only this
  harness uses. `tauri-mock.js` is held to the Rust types by
  `scripts/validate/validate_gui_mock_fixtures.py` on every `validate_all.py`
  run and answers 34 commands.
- `mock-scan.json`    - `get_latest_scan` payload (the project's curated demo
  findings, wire-shaped like `hardener_types::ScanResult`).
- `mock-reports.json` - `generate_compliance_report` payload (real
  `ComplianceReport` JSON; drives the security score). Regenerate anytime with
  `hardener report --scenario all --report-format json --quiet`.

## Where this lives

It sat in `docs/superpowers/tools/screenshot-harness/` until 2026-08-21, which
is a **gitignored** tree (`.gitignore:81`). The README's caption calls these
screenshots reproducible, and the fixture they rest on is committed, but the
driver that uses it was not in a clone - so the claim was only true for one
machine. Two things it had quietly grown while nobody could review it: an
absolute `/home/<user>/...` path to `dist/`, and another to `hotrun`. Both are
resolved from the repository root and from `PATH` now.

Its working output stays ignored: `serve/` is a copy of the built frontend,
`shots/` is regenerated every run, and `chrome-profile-*` exist only because
back-to-back headless launches stall on a shared singleton lock.

## Run

```sh
cd scripts/screenshots
python3 build.py                 # assemble serve/
python3 serve.py &               # localhost:8137 (SPA fallback)
python3 shoot.py                 # 7 routes, trimmed -> shots/*.png
node capture-docs.js             # all 23 documented states at 1920x1080
cp shots/*.png ../../../assets/screenshots/   # refresh the committed corpus
# when done:
kill %1                          # stop the server
```

Requirements: system `chromium`, Python with Pillow (`PIL`), and a built
`crates/hardener-ui/dist/` (run `trunk build` in that crate after CSS/markup
changes so the harness renders the new UI). Heavy binaries go through `hotrun`
per the machine's thermal policy; `shoot.py` already wraps chromium in it.

## Notes

- Serve dir and `shots/` are throwaway; regenerate freely.
- **19 of the 23 shots are byte-identical across runs; the four Scheduler ones
  are not.** That page renders a computed next-run time, so its shots differ by
  whatever the clock did between runs. Not a fault and not worth chasing: it
  means a Scheduler shot cannot be diffed for a visual regression, while the
  other nineteen can.
- To preview a **mockup** instead of the real app, point `serve.py`/`shoot.py` at
  a mockup HTML file, or drop it into `serve/` and add a route.
- **The header version is whatever the built `dist/` baked in**, which is the
  honest answer and no longer stamped over. Run `trunk build` in
  `crates/hardener-ui` first if the CSS or markup changed, or the shots will
  show the previous bundle.
