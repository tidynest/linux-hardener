# Coverage Baseline

**Last Updated**: 2026-08-07

This is a map, not a scorecard. Coverage says which lines no test *reaches*. It
says nothing about whether the tests that do reach a line *check* anything, and
a later phase answers that separately with mutation testing. A file at 95 per
cent whose assertions are all `is_ok()` is worse off than a file at 40 per cent
with sharp assertions on the part that matters.

So a low number here is not a defect. It is a place to look, and the two things
worth looking for are opposites:

- **Code nothing reaches because nothing needs it.** That is Phase 3 work, and
  the answer is deletion rather than tests.
- **Code nothing reaches that a user reaches every day.** That is Phase 4 work,
  and the answer is tests sharp enough that a mutant dies.

Read it beside [the evidence ledger](evidence-ledger.md), which records what
each capability's tests actually ask. The two documents disagree usefully. The
ledger calls `ssh-hardening` the best-evidenced plugin in the tree because
`sshd -T` answers for it, and calls `audit-hardening`'s scan mock-only because
`auditctl` is asked nowhere. Here `ssh/mod.rs` reads 90.05 per cent and
`audit/mod.rs` reads 96.09 per cent, the wrong way round, because a mock covers
lines exactly as thoroughly as a live oracle does. Coverage cannot see the
difference the ledger exists to record, and the ledger cannot see the code
neither of them reaches.

---

## Reproducing the numbers

Every figure below came from one of these two commands, run on commit `dfb9585`
of `chore/release-readiness-phase-0` with a clean working tree.

```bash
# Per-crate and per-file summary (the table below)
cargo llvm-cov --workspace --summary-only

# Machine-readable export (the work-list below)
cargo llvm-cov --workspace --json --output-path /tmp/cov.json
```

The 58-row work-list at the end of this document is a filter over that JSON
rather than a third measurement: the entries whose `summary.lines.count` is
non-zero, whose `summary.lines.percent` is below 60, sorted ascending. Stated
here so the table that matters most is as reproducible as the totals are.

```bash
python3 - <<'EOF'
import json

with open("/tmp/cov.json") as handle:
    data = json.load(handle)

rows = [
    (entry["summary"]["lines"]["percent"], entry["filename"])
    for entry in data["data"][0]["files"]
    if entry["summary"]["lines"]["count"]
    and entry["summary"]["lines"]["percent"] < 60
]

for percent, path in sorted(rows):
    print(f"{percent:6.2f}  {path}")
EOF
```

Both `cargo llvm-cov` runs exited 0. Each ran the same test set: **1706 passed,
0 failed, 40 ignored, across 51 test binaries**, which is the figure the
evidence ledger records for `cargo nextest run --workspace`. The two readings
agreeing is the check that this baseline measured the suite the rest of the
release is judged on, and not some subset of it.

Toolchain, because a coverage figure is not comparable across compilers:

| Component | Version |
|---|---|
| `rustc` | 1.97.1 (8bab26f4f 2026-07-14) |
| `cargo-llvm-cov` | 0.8.7 |
| Export format | `llvm.coverage.json.export` 3.1.0 |

**On `hotrun`.** The task brief prefixes both commands with `hotrun`. That does
not work here and the numbers were produced without it. `~/.local/bin/hotrun`
opens a transient systemd scope in `buildwork.slice`, and `~/.local/bin/cargo`
is a PATH shim that opens one too, so `hotrun cargo` nests two scopes and the
inner one fails with `Unit run-pNNNNN-iNNNNN.scope was already loaded`. Bare
`cargo` still lands inside the same thermal cap through the shim, so dropping
the prefix changes the CPU budget not at all. Use the commands exactly as
printed above.

---

## What this run does and does not measure

Six limitations, stated here rather than discovered by someone comparing a
future run against this one.

1. **No crate was excluded.** CI runs `cargo test --workspace $WORKSPACE_EXCLUDE`
   with `--exclude linux-hardener-desktop --exclude hardener-ui`
   (`.github/workflows/ci.yml`), and this baseline deliberately does not. Both
   crates build, test and instrument on the host target, and both carry real
   tests that a CI run never executes, so excluding them would have hidden the
   largest uncovered surface in the workspace behind the same door CI already
   hides it behind. Where their exclusion changes how a number should be read,
   the reading below says so.
2. **`hardener-ui` was measured on the host target, not on `wasm32-unknown-unknown`.**
   What ships is the WASM build. Nothing here is a statement about that artefact.
   On the host there is no DOM, so a Leptos `#[component]` body is compiled and
   never instantiated, and a `#[wasm_bindgen]` extern cannot execute at all.
   That is the whole of why 42 of this crate's 43 *instrumented* source files
   sit under 60 per cent, most of them at zero. The crate holds 46 non-test
   `.rs` files; `components/mod.rs`, `pages/mod.rs` and `types.rs` carry no
   instrumented lines and never enter the report at all, which is where 46 and
   43 differ. The one exception among the 43, `src/utils/mod.rs` at 93.71 per
   cent, is the crate's pure logic and shows what the rest would look like if a
   DOM were available.
3. **No doctests ran.** `cargo llvm-cov` needs the unstable `--doctests` flag on
   nightly, which this run did not pass. That accounts for the difference
   between the 51 test binaries counted above and the 60 the evidence ledger
   records for `cargo test --workspace`: the workspace holds exactly nine
   library crates, and a doctest binary each is what the gap of nine is. Any
   code whose only exercise is a doc example reads as uncovered here.
4. **No branch coverage.** `--branch` is unstable and was not passed, so the
   branch columns are empty. Region coverage is the nearest available proxy and
   is the second number in every table below.
5. **Test code is not counted.** No file under a `tests/` directory and no
   `tests.rs` appears anywhere in the report, which is the behaviour a baseline
   wants: a test asserting nothing would otherwise count as covered code and
   raise the total. It also means the denominators below are production lines
   only, so they are smaller than a `wc -l` of the same crate.
6. **Only what a default `cargo test` runs is counted.** The 40 `#[ignore]`d
   tests did not execute, and neither did `scripts/test/differential-suite.sh`
   nor `scripts/test/full-test-suite.sh`, which are where every grade-3 result
   in the evidence ledger comes from. A line covered only by a container suite
   reads as uncovered here.

One artefact worth knowing about: `scripts/build_identity.rs` is a build script
shared by `hardener-cli` and `hardener-ui`, so the JSON carries it twice under
two paths and the text summary prints it twice under one. 145 JSON entries are
144 distinct source files.

---

## Per-crate coverage

Sorted best first, so the shape of the workspace is visible in one read.

| Crate | Files | Lines | Line coverage | Regions | Region coverage |
|---|---:|---:|---:|---:|---:|
| `hardener-types` | 3 | 335 | 94.33% | 431 | 93.50% |
| `hardener-plugins` | 20 | 6180 | 91.44% | 7265 | 92.80% |
| `hardener-compliance` | 13 | 1454 | 89.68% | 2040 | 88.97% |
| `hardener-state` | 8 | 1866 | 88.10% | 2516 | 84.70% |
| `hardener-common` | 7 | 729 | 82.85% | 953 | 85.41% |
| `hardener-core` | 11 | 1083 | 77.56% | 1504 | 76.60% |
| `hardener-scheduler` | 10 | 1415 | 70.39% | 1910 | 66.07% |
| `hardener-cli` | 19 | 4131 | 61.12% | 5797 | 57.93% |
| `linux-hardener-desktop` | 3 | 1771 | 33.94% | 2762 | 29.00% |
| `hardener-distro` | 7 | 456 | 18.20% | 638 | 21.79% |
| `hardener-ui` | 44 | 5779 | 10.02% | 9296 | 8.37% |
| **Workspace total** | **145** | **25199** | **60.09%** | **35112** | **55.24%** |

The file counts include `scripts/build_identity.rs` twice, once against each of
the two crates that build it, which is why `hardener-ui` reads 44 files for 43
instrumented source files and `hardener-cli` reads 19 for 18.

### The two totals

The workspace total is 60.09 per cent, and quoting it alone would be
misleading in both directions.

| Reading | Files | Lines | Line coverage | Region coverage |
|---|---:|---:|---:|---:|
| Whole workspace | 145 | 25199 | 60.09% | 55.24% |
| Excluding `hardener-ui` and `linux-hardener-desktop` | 98 | 17649 | **79.11%** | 77.28% |

The second row is the set CI tests. The engine, the plugins, the state layer
and the compliance renderers sit at 79.11 per cent line coverage between them;
the workspace figure is 19 points lower because two front-end crates contribute
7506 source lines of which 6367 are never reached on the host target.

Those two crates' rows in the per-crate table sum to 7550, not 7506, and 7550
is what both the 25199 and the 17649 totals are computed with. The 44-line
difference is the shared build script `scripts/build_identity.rs`, counted once
against each of the two crates that build it. So `hardener-ui`'s 5779 includes
44 lines that are not front-end source; 5779 - 44 = 5735 is the crate's own,
and 5735 + 1771 = 7506.

Neither number is the honest headline on its own. **60.09 per cent is what the
release ships. 79.11 per cent is what the release tests.** The gap between them
is the desktop application, which is exactly what the evidence ledger already
says it has no row for.

---

## Where to start

The list below is sorted worst first because that is the literal work-list, and
sorting it that way puts 42 near-identical front-end files at the top. They are
the largest uncovered surface and they are also the most uniformly explained.
The entries a later phase should read first are these, and none of them is at
the top of the sort:

**Reaches nobody (Phase 3, delete rather than test):**

- `crates/hardener-distro/src/package/` in its entirety, 5 files and 400
  instrumented lines, 0 to 29 per cent. Nothing in the workspace calls it:
  `PackageManager`,
  `AptPackageManager`, `DnfPackageManager`, `PacmanPackageManager`,
  `ZypperPackageManager` and `hardener_distro::package` have no reference
  anywhere outside the module itself. Three crates depend on `hardener-distro`,
  and between them they import exactly two symbols, both defined in `lib.rs`:
  `Distribution` (`src-tauri/src/commands.rs:13`,
  `crates/hardener-cli/src/commands/batch.rs:19`,
  `crates/hardener-compliance/src/profiles.rs:13`) and `DistroFamily`
  (`crates/hardener-compliance/src/profiles.rs:13`). `Distribution::detect` and
  `Distribution::from_os_release` are live and must not be touched with the
  module.
- `DistributionAdapter` is the separate case, and the opposite one. It has three
  references in the whole tree, all inside `hardener-distro`: the definition at
  `crates/hardener-distro/src/adapter.rs:12`, the re-export at
  `crates/hardener-distro/src/lib.rs:8` and a mock implementation at
  `crates/hardener-distro/src/adapter/tests.rs:24`. No dependent uses it. It
  does not appear in the table below, and cannot; see "What the next phases
  inherit".
- `crates/hardener-ui/src/utils/mock_data.rs`, 103 lines at 0 per cent. Already
  declared dead in the tree: `crates/hardener-ui/src/utils/mod.rs` carries
  `#[allow(dead_code)]` above the module and a comment reading "Mock data is
  available for development/testing but not currently used".

**Reaches users, reaches no test (Phase 4, hunt here):**

- `crates/hardener-compliance/src/output/mod.rs` at 47.27 per cent. The default
  `ReportFormatter::format_all` is entered by no test, in no formatter, and it
  is the multi-report path that `hardener report`, the report wizard and the
  desktop all call (`commands/report.rs:107-123`,
  `commands/report_wizard.rs:536-552`). `compare_control_ids`, the comparator
  that decides control ordering in every rendered report, is also never
  entered. This sharpens rather than repeats the evidence ledger's renderer
  ceiling: the ledger records that no test parses a rendered report back with
  its real consumer; this adds that the entry point the real consumers use is
  not called at all.
- `crates/hardener-cli/src/commands/history.rs` at 26.94 per cent, 263 lines
  missed, against **one** test in `history/tests.rs`. `truncate_string`,
  `format_timestamp` and `print_session_detail` are pure or near-pure and have
  no test at all, and `trends` and `show` are whole subcommands. The cheapest
  entry on this list to improve.
- `src-tauri/src/commands.rs` at 26.60 per cent, 1115 missed lines, the single
  largest uncovered file in the workspace. Thirty `#[tauri::command]` bodies.
  Its neighbour `src-tauri/src/validation.rs` reaches 91.39 per cent, so the
  split is clean: the pure validation layer is tested, the command bodies that
  need a Tauri runtime and `pkexec` are not. The most expensive entry to close
  and the one CI's exclusion hides most completely.
- `crates/hardener-cli/src/output.rs` at 46.17 per cent, 253 missed. Eleven
  output functions are entered by nothing: `apply_results`, `checkpoint_list`,
  `checkpoint_created`, `checkpoint_deleted`, `checkpoint_details`,
  `checkpoint_repair`, `rollback_result`, `scan_timings`, `format_timestamp`,
  `error` and `warning`. Structurally fixable, since they print rather than
  return, which is why the 26 tests in `output/tests.rs` reach the helpers and
  stop there.
- `crates/hardener-cli/src/commands/systemd.rs` at 22.47 per cent, against 2
  tests for 359 lines. The unit-file generation half needs no root and is not
  covered.

**Reads like a gap and is not:** `ReportFormatter::format_bytes` sits in the
same file as `format_all` and is likewise entered by nothing, but it belongs on
neither list. Its default body in `output/mod.rs` is one line,
`self.format(report).into_bytes()`, and every call site in the tree is
`PdfFormatter::new().format_bytes(...)` (`commands/report.rs:138` and `:151`,
`commands/report_wizard.rs:591` and `:608`, `src-tauri/src/commands.rs:1316`),
all of which take the override at `output/pdf.rs:104`. The default is
unreachable rather than merely unreached, so a test for it would raise a
percentage and change nothing else. Named here so it is not mistaken for the
gap next to it.

---

## Every file under 60 per cent line coverage

58 files, worst first. **Missed** is missed lines over total lines, and it is
the column that ranks the work, since a 0 per cent file of five lines is not
where anyone should start.

Three readings repeat, and are stated once here rather than 40 times below:

- **[host-target view]** A Leptos `#[component]` body. Compiled on the host
  target, never instantiated because there is no DOM, and shipped as WASM which
  this run did not measure. Says nothing about whether the component works. The
  desktop GUI's evidence is a person looking at it, which is the ceiling the
  evidence ledger already records.
- **[wasm-only]** Cannot execute on the host target at all, rather than merely
  not being called: `#[wasm_bindgen]` externs and `web_sys` calls.
- **[needs privilege or a live service]** The command body needs root, a
  database, a booted daemon, a TTY or a network peer, so a default `cargo test`
  cannot enter it. Innocent as a coverage reading, and still the place a
  regression would hide.

| File | Line coverage | Missed | Reading |
|---|---:|---:|---|
| `crates/hardener-ui/src/tauri_bindings.rs` | 0.00% | 408 / 408 | [wasm-only] Every IPC call the frontend makes, as `#[wasm_bindgen]` externs into `window.__TAURI__`. Largest single zero in the workspace. |
| `crates/hardener-ui/src/pages/hosts_page.rs` | 0.00% | 396 / 396 | [host-target view] |
| `crates/hardener-ui/src/components/history_section.rs` | 0.00% | 247 / 247 | [host-target view] |
| `crates/hardener-ui/src/components/host_panel.rs` | 0.00% | 229 / 229 | [host-target view] |
| `crates/hardener-ui/src/components/findings_tab.rs` | 0.00% | 212 / 212 | [host-target view] |
| `crates/hardener-ui/src/components/rollback_modal.rs` | 0.00% | 189 / 189 | [host-target view] Confirmation gate on a destructive action, so worth an eyeball even though no test can reach it. |
| `crates/hardener-ui/src/components/security_score.rs` | 0.00% | 166 / 166 | [host-target view] |
| `crates/hardener-ui/src/components/compliance_tab.rs` | 0.00% | 158 / 158 | [host-target view] |
| `crates/hardener-ui/src/components/host_form.rs` | 0.00% | 147 / 147 | [host-target view] |
| `crates/hardener-ui/src/keyboard.rs` | 0.00% | 145 / 145 | [wasm-only] Global shortcut handling, including the Alt+T theme cycle. Registers `web_sys` listeners, so none of it runs on the host. |
| `crates/hardener-ui/src/components/config_file_card.rs` | 0.00% | 125 / 125 | [host-target view] |
| `crates/hardener-ui/src/pages/scheduler_page.rs` | 0.00% | 118 / 118 | [host-target view] |
| `crates/hardener-ui/src/lib.rs` | 0.00% | 113 / 113 | [host-target view] The `App` root, which holds the sole apply-and-persist theme `Effect`. |
| `crates/hardener-ui/src/components/scan_history_tab.rs` | 0.00% | 111 / 111 | [host-target view] |
| `crates/hardener-ui/src/components/host_row.rs` | 0.00% | 109 / 109 | [host-target view] |
| `crates/hardener-ui/src/components/sidebar.rs` | 0.00% | 108 / 108 | [host-target view] |
| `crates/hardener-ui/src/utils/mock_data.rs` | 0.00% | 103 / 103 | **Declared dead.** `#[allow(dead_code)]` in `utils/mod.rs` with a comment saying it is not currently used. Phase 3: delete. |
| `crates/hardener-distro/src/package/apt.rs` | 0.00% | 102 / 102 | **No caller anywhere.** Phase 3: delete with the rest of `package/`. |
| `crates/hardener-ui/src/components/schedule_section.rs` | 0.00% | 95 / 95 | [host-target view] |
| `crates/hardener-ui/src/components/tabs.rs` | 0.00% | 94 / 94 | [host-target view] |
| `crates/hardener-ui/src/pages/analysis_page.rs` | 0.00% | 88 / 88 | [host-target view] |
| `crates/hardener-distro/src/package/dnf.rs` | 0.00% | 76 / 76 | **No caller anywhere.** Phase 3: delete with the rest of `package/`. |
| `crates/hardener-ui/src/components/notification_section.rs` | 0.00% | 70 / 70 | [host-target view] |
| `crates/hardener-ui/src/components/segmented_control.rs` | 0.00% | 70 / 70 | [host-target view] |
| `crates/hardener-ui/src/components/theme_picker.rs` | 0.00% | 70 / 70 | [host-target view] |
| `crates/hardener-distro/src/package/zypper.rs` | 0.00% | 69 / 69 | **No caller anywhere.** Phase 3: delete with the rest of `package/`. |
| `crates/hardener-distro/src/package/pacman.rs` | 0.00% | 61 / 61 | **No caller anywhere.** Phase 3: delete with the rest of `package/`. |
| `crates/hardener-ui/src/components/modal.rs` | 0.00% | 58 / 58 | [host-target view] |
| `crates/hardener-ui/src/components/recent_activity.rs` | 0.00% | 57 / 57 | [host-target view] |
| `crates/hardener-ui/src/state/mod.rs` | 0.00% | 49 / 49 | [host-target view] `AppState` signal construction, which needs a Leptos runtime. |
| `crates/hardener-ui/src/components/clipboard.rs` | 0.00% | 47 / 47 | [wasm-only] |
| `crates/hardener-ui/src/components/confirm_delete.rs` | 0.00% | 45 / 45 | [host-target view] |
| `crates/hardener-ui/src/components/card.rs` | 0.00% | 37 / 37 | [host-target view] |
| `crates/hardener-ui/src/components/form_helpers.rs` | 0.00% | 27 / 27 | [host-target view] |
| `crates/hardener-ui/src/utils/theme.rs` | 0.00% | 27 / 27 | Sharper than its neighbours: it **has** 3 tests, and they assert on the `THEMES` constant, which is data and carries no executable lines. `apply_theme`, `get_stored_theme` and `store_theme` are the sole writers of `<html data-theme>` and the `theme` localStorage key, and are [wasm-only]. |
| `crates/hardener-ui/src/pages/hardening_page.rs` | 0.00% | 26 / 26 | [host-target view] |
| `crates/hardener-ui/src/components/fleet_outcome_row.rs` | 0.00% | 24 / 24 | [host-target view] |
| `crates/hardener-ui/src/pages/dashboard_page.rs` | 0.00% | 21 / 21 | [host-target view] |
| `crates/hardener-ui/src/navigation.rs` | 0.00% | 19 / 19 | [wasm-only] Scroll and focus management on route change. |
| `crates/hardener-ui/src/components/theme_toggle.rs` | 0.00% | 17 / 17 | [host-target view] |
| `crates/hardener-ui/src/pages/settings_page.rs` | 0.00% | 11 / 11 | [host-target view] |
| `crates/hardener-ui/src/components/icons.rs` | 0.00% | 5 / 5 | [host-target view] Static markup. Nothing to test. |
| `crates/hardener-ui/src/components/status_icons.rs` | 0.00% | 5 / 5 | [host-target view] Static markup. Nothing to test. |
| `crates/hardener-ui/src/pages/fleet_apply_page.rs` | 4.75% | 281 / 295 | [host-target view] The 2 tests cover a pure helper; the page body is the rest. |
| `crates/hardener-ui/src/components/configure_section.rs` | 7.74% | 751 / 814 | [host-target view] Second largest uncovered file in the workspace. The 11 tests cover pure helpers only. |
| `crates/hardener-ui/src/components/adhoc_host_input.rs` | 13.59% | 89 / 103 | [host-target view] The 1 test covers `target_error`, the frontend guard that mirrors the backend's refusal of a malformed `user@host[:port]` target. |
| `src-tauri/src/main.rs` | 13.95% | 37 / 43 | [needs privilege or a live service] Tauri builder and setup hook. The one piece of pure logic, `desktop_is_tiling`, is covered by `src-tauri/src/decoration_tests.rs`. |
| `crates/hardener-cli/src/commands/systemd.rs` | 22.47% | 176 / 227 | **Genuine gap.** 2 tests for 359 lines. Half the module shells out to `systemctl` and needs root; the other half generates unit files from a config and does not. |
| `crates/hardener-cli/src/commands/report_wizard.rs` | 24.23% | 294 / 388 | [needs privilege or a live service] `dialoguer` prompts cannot run without a TTY, which explains most of it. It also holds the uncovered `format_all` dispatch at lines 536-552. |
| `crates/hardener-cli/src/commands/checkpoint.rs` | 24.31% | 137 / 181 | [needs privilege or a live service] The 5 tests cover argument handling; the bodies need a checkpoint database and, for rollback, privilege. |
| `crates/hardener-scheduler/src/daemon.rs` | 24.50% | 114 / 151 | [needs privilege or a live service] `tokio-cron-scheduler` job loop and Unix signal shutdown. Awkward to cover, and a mutation in the shutdown path would currently be invisible, so worth Phase 4's attention despite the innocent reading. |
| `src-tauri/src/commands.rs` | 26.60% | 1115 / 1519 | **Genuine gap, largest by volume.** 30 `#[tauri::command]` bodies, needing a Tauri runtime and `pkexec`. Contrast `src-tauri/src/validation.rs` at 91.39%. Hidden from CI by `--exclude linux-hardener-desktop`. |
| `crates/hardener-cli/src/commands/history.rs` | 26.94% | 263 / 360 | **Genuine gap, cheapest to close.** One test, covering `find_regressions`. `truncate_string`, `format_timestamp` and `print_session_detail` are pure and untested; `trends` and `show` are whole subcommands. |
| `crates/hardener-distro/src/package/mod.rs` | 29.35% | 65 / 92 | **No caller anywhere.** Phase 3: delete. The 27 covered lines are almost all `validate_package_name`, the shell-injection guard, which `package/tests.rs` enters 16 times over 6 tests across the Debian, RPM and Arch rule sets, injection cases (`package;rm`, `package;evil`, `package\|whoami`) included. Unreferenced from outside the module *and* well tested from inside is the argument for deleting it, not against: there is no test to write first. |
| `crates/hardener-cli/src/commands/daemon.rs` | 37.42% | 102 / 163 | [needs privilege or a live service] Thin CLI wrapper over `hardener-scheduler`'s daemon; inherits that module's reading. |
| `crates/hardener-cli/src/output.rs` | 46.17% | 253 / 470 | **Genuine gap.** 26 tests reach the string helpers; 11 renderers are entered by nothing. See "Where to start" for the list. |
| `crates/hardener-compliance/src/output/mod.rs` | 47.27% | 29 / 55 | **Genuine gap, sharpest in the backend.** The default `ReportFormatter::format_all` and `compare_control_ids` are entered by no test, and `format_all` is what every real consumer calls. The uncovered `format_bytes` in this file is *not* part of that gap: it is an unreachable default, see "Where to start". |
| `crates/hardener-scheduler/src/notification/email.rs` | 54.29% | 48 / 105 | Mostly innocent. The 2 tests in `notification/email/tests.rs` cover the free `format_subject`, `format_body` and the `sanitise_for_header` injection guard. Uncovered are `EmailNotifier::build_transport`, its method wrappers and `Notifier::send`, which need an SMTP peer. `build_transport` chooses TLS mode and applies credentials, so it is the one piece here worth separating out and testing without a server. |

---

## What the next phases inherit

- **Phase 3** takes *at least* 6 files and 503 instrumented lines with no caller
  in the tree: the 5 files of `crates/hardener-distro/src/package/` and
  `crates/hardener-ui/src/utils/mock_data.rs`. Both are confirmed by reference
  search rather than by their coverage number, which is the only way a
  dead-code claim is safe to act on.

  The converse of that rule matters more, and is why "at least" is not hedging.
  **This list is a lower bound, not the set.** Coverage cannot see dead code
  that its own tests cover: anything whose sole exercise is a test reads as
  covered, so it can never surface in a list of files under 60 per cent, no
  matter how dead it is. The worked example sits in the crate this document
  already has open. `crates/hardener-distro/src/adapter.rs` is 23 lines
  defining `DistributionAdapter`, its only implementor is the mock in
  `adapter/tests.rs`, no crate outside `hardener-distro` refers to it, and it
  reads **100.00 per cent**. It is invisible to this method and dead all the
  same. Phase 3 therefore needs a reference search of its own, run over the
  whole tree and independently of these 58 rows, and should treat this section
  as a head start rather than an inventory.
- **Phase 4** takes the five genuine gaps named above. Two of them,
  `hardener-compliance/src/output/mod.rs` and `hardener-cli/src/output.rs`, are
  rendering paths a user sees on every run, and both are cheap to reach.
- **Nobody takes the 42 front-end files** on the strength of this document
  alone. Their number is an artefact of measuring a WASM crate on the host
  target. Deciding what to do about the desktop's evidence is a separate
  question from coverage, and the evidence ledger is where it belongs.

When this baseline is re-measured, re-run both commands above rather than
copying a figure forward, and record the commit the run was taken on. A number
whose command nobody wrote down cannot be compared against anything.
