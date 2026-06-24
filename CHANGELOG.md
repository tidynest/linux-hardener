# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-06-24

### Added
- **`hardener batch apply`** — apply hardening across many hosts concurrently.
  Dry-run by default (validates each host and reports what would change); pass
  `--execute` to perform real changes. Before executing on a host the command
  probes for privilege (uid 0 or passwordless `sudo`); a non-privileged host is
  isolated as failed while the others proceed. On `--execute` each host gets an
  automatic host-keyed checkpoint and a best-effort audit-log entry. Tiered exit
  codes: 0 all clean, 1 any apply or validation failure, 2 any connect, privilege
  or usage error. Flags mirror `batch scan`: `--all`, `--host`, `--ssh`,
  `--plugin`, `--concurrency`, `--format`, `--output`, `--quiet`.
- **`hardener batch rollback`** — roll back many hosts concurrently to their
  latest per-plugin checkpoint (`<plugin-id>-pre-apply`). Dry-run by
  default (previews per host which checkpoint(s) would be restored); pass
  `--execute` to restore. Before executing on a host it probes for privilege
  (uid 0 or passwordless `sudo`) and isolates a non-privileged host as failed
  while the others proceed. Restores reuse the host-keyed checkpoints created by
  `batch apply`, so a checkpoint is never restored onto a different host; each
  `--execute` host gets a best-effort audit-log entry. Tiered exit codes: 0 all
  clean, 1 any checkpoint restore failure, 2 any connect, privilege or usage
  error. Flags mirror `batch apply`: `--all`, `--host`, `--ssh`, `--plugin`,
  `--execute`, `--concurrency`, `--format`, `--output`, `--quiet`.
- **`hardener batch report`** — assess multiple hosts against a compliance
  framework or scenario in one concurrent run, printing a fleet posture table
  (host × framework → score and pass/fail/manual/N-A control counts) with a
  tiered exit code (0 compliant / 1 failing control / 2 host error) for CI
  gating. Reuses the `batch scan` engine; `--format json` and `--output`
  supported.
- **Per-host security trend.** `hardener history trends --host <key>` charts a
  host's completed scans oldest-first — per-severity counts, the change in total
  findings, and a per-scan direction (`better`/`worse`/`same`) computed by
  severity priority (a new critical outranks any number of lower-severity
  improvements). Derived on query from the persisted scan history; no score is
  stored. `--format json` emits the trend points for automation.
- **Regression detection / CI gate.** `hardener history regressions [--host <key>]`
  reports hosts whose latest completed scan is worse than the previous one (by the
  same severity priority as trends) and exits `1` when any regression is found, so
  it can gate CI; `0` when clean. `--format json` emits the regression records.
- **Scheduled-scan regression alerts.** The scheduler can now notify (email/webhook)
  when a scheduled scan is *worse than the host's previous scan*, not only when it
  has findings above a threshold. New `notify_mode` setting: `findings` (default,
  unchanged behaviour), `regression` (quiet until the posture worsens), or `both`.
  Regressions are measured at the existing `notify_min_severity` floor and the
  alert is annotated with the per-severity deltas. Self-deduping — fires only on
  the scan where the posture changes.
- **Batch scan persists per-host history.** `hardener batch scan` now records each
  host's results to the scan-history database keyed by host (the inventory name,
  or `user@host:port` for ad-hoc `--ssh` hosts); read them back with
  `hardener history list --host <key>`. Persistence is best-effort — a history
  write failure never changes a host's scan result. The history pool now uses
  SQLite WAL so concurrent per-host writes are safe.
- **Multi-host batch scanning.** `hardener batch scan` scans many hosts at once
  (`--all`, `--host a,b`, ad-hoc `--ssh user@host`) with bounded concurrency
  (`--concurrency`), a per-host + rollup report (text or `--format json`), and
  tiered CI exit codes (0 clean / 1 findings / 2 host or usage error). The host
  inventory (`~/.config/linux-hardener/hosts.toml`) is now shared between the CLI
  and the desktop GUI via `hardener_core::inventory`.
- **ISO/IEC 27001:2022 compliance framework.** The empty `ISO27001` stub is
  replaced with the full 93-control Annex A:2022 catalogue (Organizational,
  People, Physical, Technological themes), and plugin findings map to the
  Technological controls — so ISO 27001 reports now assess real system state.
- **Multi-framework compliance mappings.** All 8 plugins now tag findings with
  STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR and ISO 27001:2022 control IDs
  (sourced from ComplianceAsCode/SSG and the project catalogues) alongside CIS,
  so every framework genuinely fails on insecure systems instead of only
  reporting `ManualReview`. A wrong mapping can only cause a false *failure*,
  never a false pass.
- **Plugin-declared compliance coverage (single source of truth).** Each plugin
  now exposes `coverage()` — the complete set of `(framework, control)` it can
  assess — aggregated by `hardener_plugins::compliance_coverage()` and injected
  into the report generator. This replaces the framework-level
  `AUTOMATED_FRAMEWORKS` flag with per-control coverage, so partial framework
  support is reported honestly.
- **Accurate `Pass` for hardened systems.** A control the engine assesses and
  finds compliant now reports `Pass` for *every* framework, not just CIS — so a
  genuinely hardened host scores accurately instead of being buried under
  `ManualReview`.
- **SSH crypto-algorithm hardening.** The SSH plugin now hardens `KexAlgorithms`,
  `Ciphers` and `MACs`, including post-quantum key exchange
  (`mlkem768x25519-sha256`). It auto-detects what the host's OpenSSH supports
  (`ssh -Q …`) and only ever writes the intersection with a strong allow-list, so
  it cannot set an unknown algorithm (no lockout) or a weak one (no downgrade),
  and validates the candidate config with `sshd -t` before restarting.

### Fixed
- **Corrected HIPAA citations on kernel hardening controls.** The kernel plugin
  cited HIPAA `164.312(c)(1)` (Integrity) on six exploit-mitigation sysctls,
  which guard against memory disclosure rather than ePHI alteration. Cross-checked
  against the upstream SSG `references:` blocks: where SSG maps these rules to
  HIPAA it cites `164.312(a)` (Access Control), never `(c)(1)`, and for several it
  carries no HIPAA reference at all. ASLR, `dmesg_restrict` and `suid_dumpable`
  are re-cited to `164.312(a)(1)`; `kptr_restrict`, `yama.ptrace_scope` and
  `protected_hardlinks/symlinks` (no SSG HIPAA reference) drop the mapping. The
  permissions plugin (credential files) and MAC plugin, which already carried
  `164.312(a)(1)` alongside the `(c)(1)` citation, drop the redundant `(c)(1)` to
  match the same SSG preference. NIST, STIG, CIS, GDPR and ISO mappings are
  unchanged.
- **Removed an unsourced CIS mapping.** The kernel plugin tagged
  `fs.protected_hardlinks` / `fs.protected_symlinks` with CIS `1.6.1`, but the
  upstream SSG rules (`sysctl_fs_protected_hardlinks/symlinks`) carry no CIS
  reference, and `1.6.1` is the Mandatory Access Control subsection header (the
  curated catalogue already lists `1.6.1.1`–`1.6.1.4` there). The mapping is
  dropped; the sourced NIST `CM-6(a)`/`AC-6(1)` and STIG `OL08-00-010373/4`
  mappings are kept.
- **Desktop compliance commands build again.** The phase-3 coverage change gave
  `ReportGenerator::new` a second `coverage` parameter but the Tauri
  `generate_compliance_report` / `export_compliance_report` commands still called
  the one-argument form, so the desktop crate failed to compile. Both now inject
  `hardener_plugins::compliance_coverage()`, matching the CLI. (The frontend
  `dist/` already exists, so this was the desktop crate's only build blocker.)
- **Ad-hoc batch SSH targets honour a `:port` suffix.** `hardener batch scan
  --ssh user@host:2222` now connects on the given port instead of always
  defaulting to 22; an unbracketed IPv6 literal keeps the default port (it has no
  unambiguous `host:port` form).
- **Honest reporting for not-yet-assessed frameworks.** Control results are
  derived from scan findings, which initially carried CIS control IDs only. For
  frameworks without mappings yet (STIG, NIST, PCI-DSS, HIPAA, GDPR), a control
  with no matching finding previously defaulted to `Pass`, reporting coverage the
  engine had not actually evaluated. Such controls now report `ManualReview`
  until a mapping exists, and the generator surfaces any finding-referenced
  control missing from a framework's catalogue — so an incomplete mapping can
  only ever over-report a failure, never a pass.

### Changed
- **`tauri` 2.11.2 → 2.11.3.** Routine patch bump (no CVE); pulls the matching
  `tauri-runtime`/`tauri-utils`/`wry` updates in the lockfile.
- **Curated CIS SSH section completed.** The curated CIS catalogue now lists the
  strong-crypto SSH controls `5.2.14`–`5.2.16` (Key Exchange, Ciphers, MACs)
  alongside the existing `5.2.x` entries, so the SSH plugin's crypto assessment
  is reflected in the curated standard rather than surfacing only via the
  coverage merge.
- **Non-CIS catalogues are derived from plugin coverage.** The hand-written
  STIG / NIST 800-53 / PCI-DSS / HIPAA / GDPR catalogues — whose identifier
  schemes diverged from the upstream (SSG) IDs the plugins emit, producing
  duplicate and `ManualReview`-only noise — are removed. Each of those
  frameworks' reports now lists exactly the controls the engine assesses, on a
  single identifier scheme. CIS and ISO/IEC 27001:2022 keep their curated
  catalogues (the full standard, with unassessed controls flagged
  `ManualReview`).

### Fixed
- **Remote checkpoint capture and restore now operate on the remote host.**
  Previously, `apply --ssh` and `rollback --ssh` would snapshot and restore files
  on the controller rather than the target. Checkpoint operations now run through
  the active `SystemExecutor`, so remote sessions correctly read and write files on
  the remote. Checkpoints are keyed by host; rollback refuses to restore one host's
  checkpoint onto another.

### Changed
- **Executor abstraction relocated to `hardener-common`.** `SystemExecutor`,
  `FileMetadata`, `CommandOutput`, and `MockExecutor` now live in
  `hardener-common` (under `executor/`), re-exported from `hardener-core` for
  source compatibility. `SystemExecutor` gained a `read_dir` method;
  `FileMetadata` gained `uid` and `gid` fields.

### Removed
- **Obsolete SSH `Protocol 2` directive.** Modern OpenSSH ignores the `Protocol`
  keyword (SSHv1 was removed years ago), so enforcing it was vestigial.
- **Hand-written non-CIS framework catalogues** (`frameworks/{stig,nist,pci,
  hipaa,gdpr}.rs`) and the `AUTOMATED_FRAMEWORKS` / `is_automated` API, replaced
  by coverage-derived catalogues and per-control coverage (see above).

### Security
- **RUSTSEC-2026-0185** — Updated `quinn-proto` 0.11.14 → 0.11.15 (remote memory
  exhaustion, CVSS 7.5: unbounded out-of-order QUIC stream reassembly; pulled
  transitively).
- **RUSTSEC-2026-0173** — `proc-macro-error2` flagged unmaintained with no safe
  upgrade; accepted in `deny.toml`. Compile-time-only proc-macro, transitive via
  the Leptos macro stack (`leptos_macro`/`leptos_router`/`rstml`), no runtime
  attack surface.
- Pruned two stale `deny.toml` advisory ignores no longer present in the resolved
  dependency graph: `RUSTSEC-2024-0429` (`glib`) and `RUSTSEC-2026-0097` (`rand`).

## [1.0.5] - 2026-05-24

### Security
- **CVE-2026-42184 / GHSA-7gmj-67g7-phm9** — Updated `tauri` 2.9.5 → 2.11.2, fixing an origin-confusion flaw that could let remote pages invoke local-only IPC commands.
- **RUSTSEC-2026-0141** — Updated `lettre` 0.11.19 → 0.11.22 (TLS hostname verification bypass in the Boring TLS backend; not exposed — the project builds `lettre` with the rustls backend).
- **RUSTSEC-2026-0104** — Updated `rustls-webpki` 0.103.12 → 0.103.13 (reachable panic when parsing a certificate revocation list).

## [1.0.4] - 2026-04-15

### Changed
- Updated to Rust edition 2024.
- Bumped all dependencies to latest compatible versions.

## [1.0.3] - 2026-02-28

### Added (Testing Infrastructure)
- **Parallel test runners**: 4 new scripts for concurrent cross-distro testing
  - `run-gui-tests-parallel.sh` — Web UI tests across 5 distros simultaneously
  - `run-cross-distro-tests-parallel.sh` — CLI tests across 5 distros simultaneously
  - `run-desktop-tests.sh` — Tauri desktop GUI tests (auto-starts app)
  - `run-all-tests-parallel.sh` — Master runner with `--desktop` flag
- **Scripts documentation**: `scripts/README.md` expanded with +207 lines covering all parallel test workflows

### Fixed (GUI Tests)
- **TabBar selector migration**: GUI tests now use `getByRole('tab', { name: '...' })` instead of deprecated `.section-btn` class selectors
  - Aligns with Analysis and Hardening pages' migration to shared `TabBar` component (v1.0.2)
  - Affects `hardening.spec.js`, `themes.spec.js`, `errors.spec.js`, `helpers.js`

### Changed
- Removed unused theme screenshots from `pics-debug/`

## [1.0.2] - 2026-02-28

### Fixed (CLI)
- **Daemon status crash**: `daemon status` no longer panics when no scan history exists
- **Checkpoint list crash**: `checkpoint list` handles empty database gracefully
- **Report wizard crash**: Interactive wizard no longer panics on empty scan results
- **Stderr routing**: Progress messages now sent to stderr, keeping stdout clean for piping (`report` command)
- **Idempotent directory creation**: State initialisation no longer fails if directories already exist
- **User-mode systemd**: `systemd install --user` now generates correct user-scoped unit paths

### Added (Desktop UX)
- **Keyboard navigation**: Global shortcuts — Ctrl+1-5 (page nav), Alt+T (theme cycle), Escape (close panels/fullscreen), F11 (fullscreen)
- **ARIA accessibility**: Full WAI-ARIA tabs pattern (`role="tab"`, `role="tablist"`, `role="tabpanel"`), skip link, `aria-selected`, `aria-live` regions
- **Shared TabBar component**: Reusable `TabBar` with keyboard nav (ArrowLeft/Right, Home, End) and ARIA, migrated Analysis and Hardening pages
- **CopyButton component**: Async Clipboard API integration with visual feedback for compliance reports
- **ConfirmDelete component**: Inline delete confirmation to prevent accidental checkpoint deletion
- **Findings grid keyboard nav**: Arrow keys, Enter/Space to open detail, full focus management
- **95 automated desktop tests**: `tauri-ux-test.sh` (49 tests), `tauri-functional-test.sh` (46 tests), `run-tests.mjs` (21 Playwright tests)

### Changed
- **TabBar migration**: Analysis page (Findings/Compliance/History) and Hardening page (Configure/History) now use shared `TabBar` component instead of page-specific tab implementations
- **Focus management**: Tab focus race condition resolved; keyboard focus properly tracked across tab switches

## [1.0.1] - 2026-02-27

### Fixed
- Source checksum updated for AUR package

## [1.0.0] - 2026-02-27

### 1.0.0 — Production Release

First stable release. Feature-complete Linux system hardener with 8 security plugins, CLI and desktop GUI, compliance reporting across 6 frameworks, remote SSH scanning, scheduled scanning with notifications, and checkpoint/rollback. Validated across 5 Linux distributions (Arch, Debian, Fedora, Rocky 9, openSUSE).

### Added
- Installation guide covering all 5 distro families (`docs/INSTALL.md`)
- Package install validation scripts for cross-distro packaging QA
- Distribution packages: AUR PKGBUILD, RPM spec, Debian packaging tree

### Changed
- All 53 internal security audit findings resolved
- Extracted shared helpers to reduce code duplication across UI and package crates
- SECURITY.md updated with 8 security practices, corrected 3 stale Known Limitations
- 505+ tests pass, clippy clean, native + WASM builds clean

### Fixed
- Systemd `ReadWritePaths` covers all required runtime directories
- Man page URL corrected to project homepage
- Tauri plugin ID matches canonical `service-minimisation`
- AUR, RPM, and Debian packaging install all data files correctly

## [0.3.3] - 2026-02-25

### Added (v1.0.0 Infrastructure 2026-02-25)
- **Packaging Infrastructure**: Complete build specs for three distribution families
  - AUR `PKGBUILD` with musl CLI + Tauri desktop builds
  - RPM `.spec` for Fedora/RHEL/openSUSE with systemd integration
  - Debian packaging (`debian/control`, `rules`, `changelog`, `postinst`, `prerm`, `copyright`)
- **Systemd Units**: `linux-hardener.service` (oneshot) and `linux-hardener.timer` (daily at 02:00)
  - Security hardened: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTemp`
- **Desktop Entry**: XDG `.desktop` file for application launcher integration
- **Config Example**: Comprehensive `data/config.toml.example` with all 8 plugin sections documented
- **Polkit Policy**: `com.tidynest.linux-hardener.policy` for nicer pkexec authentication dialogs
  - Separate actions for apply and rollback with descriptive messages
  - `auth_admin_keep` for active sessions (avoids repeated password prompts)
- **Man Page**: `data/hardener.1` troff man page covering all commands, options, and examples
- **High Contrast Theme**: WCAG AAA accessibility theme with 7:1+ contrast ratios
  - Pure black background with bright white text for maximum readability
  - High-saturation semantic colours chosen for colour-blind distinguishability
  - Available in theme selector dropdown alongside existing 6 themes

### Changed (Test Quality 2026-02-25)
- **Assertion Messages**: Added descriptive messages to 178+ bare `assert!()` calls across 12 test files
  - Failure output now shows what was expected and the actual value
  - Consistent patterns: `.is_ok()` shows error, `.contains()` shows searched value, `.is_empty()` shows contents
- **Test Output Cleanup**: Removed 80+ `println!`/`eprintln!` calls from test code
  - Some replaced with proper assertions; others simply removed (test output noise)
  - Net reduction of 422 lines while improving test diagnostics

### Changed (UI Polish Pass 2026-02-24)
- **Dashboard**: `RecentActivity` card no longer stretches to fill remaining page height
  - Removed `flex: 1 1 auto` and `min-height: 150px` — card sizes to content
  - Empty-state hint directs users to Quick Actions above
- **Remote Page**: Empty right panel replaced with numbered quick-start guide
  - Dropped `min-height: 400px` on `.remote-layout`
  - "Getting Started" guide with CSS-counter numbered steps
- **Hardening Configure Tab**: Security Profile and Plugin Control now side-by-side
  - Shared `.two-col-row` CSS class for consistent two-column layouts
  - Preview Changes button is standalone (removed unnecessary Card wrapper)
- **Hardening History Tab**: Latest Apply and Latest Rollback now side-by-side
  - Directional empty-state guidance ("Configure and apply hardening in the Configure tab...")
  - System Checkpoints table remains full-width below
- **Scheduler Page**: Cards no longer height-stretch to match sibling
  - `align-self: start` prevents shorter Notifications card from expanding
  - Removed `margin-top: auto` that pinned buttons to bottom of stretched cards

### Added (Config File Picker 2026-02-24)
- **Config File Picker**: GUI equivalent of CLI `--config FILE` flag on Hardening page
  - Text input + native file dialog (Browse button) via `tauri-plugin-dialog`
  - Inline validation with one-line summary (plugin count, directives, exceptions)
  - Config path threaded through scan, apply, dry-run, and rollback commands
  - `ConfigSummary` type in `hardener-types` for WASM-safe validation results

### Added (Scheduler UI 2026-02-24)
- **Scheduler Configuration Page**: New top-level "Scheduler" page for configuring scan scheduling and notifications
  - Schedule section: enabled toggle, cron presets (Daily/6h/12h/Weekly) with custom cron input, plugin checkboxes, severity threshold
  - Notification section: email recipients and from address, webhook endpoint with Slack/Discord/Generic format
  - Test notification button with inline success/failure feedback
- **WASM-safe Scheduler Types**: `SchedulerUiConfig`, `NotificationUiConfig`, `EmailUiConfig`, `WebhookUiConfig`, `TestNotificationResult` in `hardener-types`
- **Tauri IPC Commands**: `get_scheduler_config`, `save_scheduler_config`, `test_notification` with `toml_edit` for surgical config updates
- **Mock Handlers**: 3 new scheduler IPC mock handlers for GUI testing

### Added (Rollback JSON Output 2026-02-23)
- **Structured Rollback Results**: `checkpoint rollback` now returns per-file restore status
  - `RollbackResult` with `rollback_success`, `rollback_checkpoint_id`, `rollback_files`
  - `FileRestoreResult` per file: path, action (Restored/Removed/PermissionsRestored/Skipped), success, error
  - `FileRestoreAction` enum for discriminating restore types
  - CLI outputs JSON (`--format json`) or human-readable summary with colour-coded status
  - Non-zero exit code on partial rollback failure
- **GUI Rollback Detail**: Tauri GUI now parses and displays per-file rollback results
  - Rollback types (`RollbackResult`, `FileRestoreResult`, `FileRestoreAction`) canonicalised in `hardener-types` for WASM compatibility; `hardener-state` re-exports to avoid duplication
  - `run_rollback` Tauri command returns `RollbackResult` instead of `bool`
  - WASM bindings deserialise structured result; `AppState.rollback_result` reactive signal stores it
  - "Latest Rollback" card in History section shows success/failure, file count, and per-file restore actions
- **Extended Tauri IPC Mock**: 8 new mock handlers for GUI testing
  - `run_scan_filtered`, `run_scan_with_options`, `create_checkpoint`, `delete_checkpoint`
  - `export_report`, `get_scan_history`, `get_scan_session`, plus mock scan history data
- **Severity Filter**: Full severity filtering for the analysis view
  - `severity_filter` reactive signal in `AppState` with `severity_rank()` and `parse_severity()` helpers
  - `FindingsGrid` refactored to accept a `findings` prop (filtered externally)
  - Dropdown in `FindingsTab` for selecting minimum severity threshold
  - "X of Y findings" count display updates reactively
  - `ViewMode` filter (All / Compliance) for toggling compliance-only findings
  - CSS styling for the severity dropdown and filter controls

### Fixed (2026-02-23)
- **Checkpoint Directory Permissions**: Checkpoints now capture and restore directory metadata (mode/uid/gid)
  - Added `capture_directory_entry()` to `CheckpointManager` for metadata-only directory snapshots
  - `capture_directory_recursive()` now includes the directory entry itself, not just child files
  - `restore_file_state()` distinguishes directories (restore permissions) from absent paths (delete)
- **Metadata-Only Checkpoints**: Permissions plugin uses `create_checkpoint_metadata_only()` instead of recursive file snapshots
  - Captures 5 `FileState` entries (~200 bytes) instead of recursively snapshotting entire directory trees (e.g., 156MB `/boot` ESP)
  - Apply operations complete instantly instead of minutes
- **FAT32/vfat chmod Detection**: Post-chmod verification detects filesystems where `chmod` is a no-op
  - Re-reads actual permissions after `chmod` and reports failure if unchanged
  - Clear error message explaining mount-option-governed permissions
- **Scan History Persistence**: `hardener scan` now persists results to the history database
  - `history list` and `history show` commands now display CLI scan results
  - Best-effort persistence (failures silently ignored to avoid disrupting scan output)
- **Audit Rules Reload**: Uses `augenrules --load` instead of `systemctl restart auditd`
  - On Arch/RHEL/Fedora, auditd ignores SIGTERM from systemd; direct restart fails
  - `augenrules --load` is the supported mechanism, with systemctl as fallback
  - Fixed in both apply and rollback code paths
- **CLI Apply Output**: Partial failures now show individual change status instead of blanket "Unknown error"

### PluginConfig Wiring (2026-02-23)
- **All 8 plugins now consume PluginConfig**: Directives override default values; exceptions exempt specific items from hardening
  - Two families: **value-override** (directives + exceptions) for SSH, Kernel, Firewall, PAM, Permissions; **binary** (exceptions only) for Services, Audit, MAC
  - SSH (`755bc35`), Kernel (`ca53286`), Firewall (`820f406`), PAM (`95bf62b`), Services (`f97e33b`), Permissions (`d01432a`), Audit (`2ec356a`), MAC (`ef0f8f6`)
  - `HardeningPlugin` trait receives `&PluginConfig` per-plugin; `HardenerConfig` decomposed by callers
  - 418 tests pass, clippy clean

### Added (GUI/CLI Feature Parity - Phase 1)
- **Preview & Apply Flow**: Users can now preview changes before applying hardening
  - "Preview Changes" button runs dry-run and displays estimated changes
  - Preview panel shows changes grouped by plugin with Cancel/Confirm actions
  - "Confirm & Apply" triggers actual apply with pkexec authentication
  - Safer workflow prevents accidental system modifications
- **`run_apply_dry_run` Tauri Command**: Backend support for dry-run preview
  - Calls CLI with `--dry-run --format json` without pkexec (read-only operation)
  - Returns `Vec<ValidationReport>` with estimated changes per plugin
- **Preview State Signals**: Leptos reactive state for preview workflow
  - `preview_results`, `is_previewing`, `show_preview` signals in AppState
- **Short Plugin Name Support for Apply**: `apply --plugin kernel` now works
  - Expands short names to full IDs (e.g., "kernel" → "kernel-hardening")
  - Consistent with scan command behaviour

### Fixed (GUI/CLI Feature Parity - Phase 1)
- **CLI Output Format Inverted**: Fixed 7 functions in `output.rs` where `--format json` outputted text
  - `scan_results`, `apply_results`, `plugin_list`, `checkpoint_list`, `checkpoint_created`, `checkpoint_details`, `validation_reports`
- **Dry-run JSON Not Array**: Changed from per-plugin JSON objects to single array output
  - Added `validation_reports()` function for proper array formatting

### Added (Cross-Distro Validation 2026-02-23)
- **Cross-Distro Test Runner**: `scripts/run-cross-distro-tests.sh` orchestrates testing across all distributions
  - Single command: `sudo ./scripts/run-cross-distro-tests.sh --apply`
  - Uses `systemd-nspawn --pipe` for non-interactive container execution
  - Per-distro logs saved to `test-results/<distro>.log`
  - Aggregated summary in `test-results/summary.txt`
  - Options: `--apply`, `--distro NAME`, `--rebuild`, `--help`
- **Expanded Test Suite**: `scripts/full-test-suite.sh` expanded from 102 to 123 tests (26 sections)
  - Section 20: Scan history persistence (scan -> history list verification)
  - Section 21: History filtering (--limit, --status)
  - Section 22: Plugin filter combinations (short names, mixed, multi-plugin)
  - Section 23: Per-plugin apply/rollback lifecycle (gated behind --apply)
  - Section 24: Config file loading (valid/invalid paths)
  - Section 25: Report framework + scenario combinations
  - Section 26: Flag combinations (--quiet + --format, --audit + --format)
- **Container-Aware Testing**: Auto-detects container environment and skips impossible tests
  - 6 tests correctly SKIPPED instead of falsely FAILED in containers
  - Partial apply treated as pass in container mode (expected behaviour)
  - `--apply` flag gates destructive tests (apply + rollback)
- **3-Layer Host Safety**: Prevents accidental execution on real systems
  - Layer 1: nspawn container isolation
  - Layer 2: Container detection with hard `exit 1` if not in container
  - Layer 3: `--apply` flag gates all destructive operations
- **Rocky Linux 9 Validation**: Added 5th distribution (RHEL family)
  - Container created via podman export at `/var/lib/machines/hardener-test-rhel`
  - 123/123 tests pass, 6 skipped (container limitations)
- **5-Distro Validation Results**: 123/123 tests pass on all distributions
  - Arch Linux (Rolling): 123/123 pass, 6 skip
  - Debian 12 (Bookworm): 123/123 pass, 6 skip
  - Fedora 41: 123/123 pass, 6 skip
  - Rocky Linux 9: 123/123 pass, 6 skip
  - openSUSE Leap 15.6: 123/123 pass, 6 skip

### Added (GUI Testing 2026-02-23)
- **Web UI Test Suite**: 84 Playwright tests covering all GUI functionality
  - Dashboard (9 tests): score display, scan trigger, navigation, activity feed
  - Findings (10 tests): scan, table, detail panel, finding count
  - Compliance (8 tests): framework selection, report generation, score colours
  - Configure (10 tests): profiles, plugin toggles, preview, cancel
  - History (6 tests): checkpoints, rollback, apply results
  - Themes (7 tests + 30 screenshots): all 6 themes verified
  - Error handling (4 tests): scan/apply/checkpoint errors, dismiss
- **Tauri IPC Mock**: JavaScript mock of `window.__TAURI__` with all IPC commands
- **Cross-Distro GUI Validation**: 84/84 tests pass on all 5 distros
- **GUI Test Runner**: `scripts/run-gui-tests.sh` orchestrates Playwright tests inside nspawn containers
- **`--gui` flag for cross-distro runner**: `run-cross-distro-tests.sh --gui` runs GUI tests after CLI tests

### Fixed (GUI Testing 2026-02-23)
- **GUI Test HTML Generation**: `mock-index.html` removed; `gui-test-inner.sh` now generates `index.html` at
  serve-time by reading `dist/index.html`, stripping SRI integrity attributes, and injecting `tauri-mock.js`
  — eliminates hash drift when the WASM bundle changes

### Added (Distribution Validation)
- **Container Test Scripts**: Distribution-specific container creation scripts
  - `scripts/create-debian-container.sh` - Debian/Ubuntu testing
  - `scripts/create-fedora-container.sh` - Fedora/RHEL testing
  - `scripts/create-opensuse-container.sh` - openSUSE/SUSE testing
- **Musl Static Build**: Cross-distribution binary using musl libc for maximum compatibility

### Fixed (2025-12-10)
- **Invalid Plugin Name Accepted Silently**: `--plugin nonexistent` now returns error with valid plugin list
  - Added `validate_plugin_filter()` in scan.rs to check plugin names before scanning
  - Supports both full IDs (`kernel-hardening`) and short names (`kernel`)
  - Exit code 1 for invalid plugins, enabling proper CI/CD error detection
- **Test Script 105% Pass Rate**: Fixed test counter bug in `full-test-suite.sh`
  - Preflight checks were incrementing PASSED without incrementing TOTAL
  - Added `log_check()` function for non-test verification steps

### Fixed (2025-12-09)
- **Security Score Calculation**: Redesigned from findings-based to compliance-based weighted scoring
  - Pass = 100pts, Critical fail = 0pts, High = 25pts, Medium = 50pts, Low = 75pts
  - Overall score = average of framework weighted scores
  - Added expandable "Framework Breakdown" showing per-framework scores
- **UFW False Positive**: Firewall plugin now uses `systemctl is-active ufw` first (no root needed)
  - Falls back to `ufw status` only when systemctl unavailable
- **Audit Rules False Positives**: Added `AuditRulesResult` enum to distinguish permission denied from missing rules
  - No longer reports 25 false positives when running without root
- **Empty validate() Stubs**: Implemented proper validate() for permissions, SSH, and firewall plugins
  - Now reports estimated changes like "PermitRootLogin: yes → no"
- **Kernel Rollback Gap**: apply() now creates `/etc/sysctl.d/99-hardener.conf`
  - Kernel hardening persists across reboot
  - Rollback properly removes config and reloads sysctl

### Fixed (GUI Issues 2025-12-09)
- **Theme Selector Unreadable**: Added `appearance: none` CSS reset for cross-browser styling
  - Custom SVG dropdown arrow for dark and light themes
  - WebKit now respects CSS colours instead of native controls
- **Generate Reports No Feedback**: Added status message display for report generation
  - Shows success message with report count after generation
  - Shows error message if generation fails
- **Checkpoints Not Visible After Apply**: Now reads from both user and system databases
  - GUI reads from `~/.local/share/linux-hardener/checkpoints.db` (user) AND `/var/lib/linux-hardener/checkpoints.db` (system)
  - Added refresh button to checkpoint list
  - Checkpoints from privileged apply operations (pkexec) now visible
- **Score Mismatch Dashboard vs Analysis**: Unified score calculation
  - `MiniSecurityScore` component now uses shared `calculate_all_scores()` function
  - Both pages display identical compliance-based weighted scores

### Added
- **GUI Dark Terminal Theme**: Complete CSS styling with professional dark aesthetic
- **Fluid Typography**: Score ring text uses `clamp()` for proportional scaling across viewport widths
- **Card Component**: Reusable `Card` component in `card.rs` with `CardVariant` (Default, Compact, Empty) and `HeadingLevel` (H2, H3, H4) props for consistent section styling
- **CSS Transitions**: Added transition variables (`--transition-fast`, `--transition-normal`, `--transition-slow`) for smooth hover animations
- **Empty State Icons**: Consistent empty states with contextual icons across all pages: activity, findings, compliance, apply operations, checkpoints
- **Button Hover Effects**: Subtle `translateY(-1px)` lift effect with box-shadow on hover for action buttons
- **E2E Test Cases**: Added TC-11 to TC-14 covering empty states, animations, themes, and responsive layout

### Changed
- **Responsive Dashboard Layout**: Improved single-column mode with compact sections and proper stacking order (Score → Actions → Activity)
- **Refactored Section Containers**: All page sections now use the `Card` component instead of raw `<section>` tags for consistent styling
- **Score Ring Sizing**: Changed from fixed 160px to proportional `min(160px, 45vw)` with `aspect-ratio: 1` for smooth scaling
- **No Minimum Width**: Removed 320px minimum width constraint; content now shrinks/wraps at any viewport width
- **Playwright MCP Documentation**: Added `MCP_INSTRUCTIONS.md` with detailed instructions for automated UI testing
- **Accessibility: Skip Link**: Added keyboard-accessible skip link for screen reader users (`lib.rs`)
- **Accessibility: Tab ARIA**: Full WAI-ARIA tabs pattern with `aria-controls`, `aria-labelledby`, `tabindex` management
- **CSS Utility Classes**: Added `.truncate`, `.line-clamp-2`, `.line-clamp-3`, `.sr-only`, `.min-w-0`, `.skip-link`
- **CSS Flex/Grid Utilities**: Added `.flex`, `.flex-col`, `.flex-wrap`, `.flex-1`, `.items-center`, `.items-start`, `.justify-center`, `.justify-between`, `.grid`, `.gap-xs`, `.gap-sm`, `.gap-md`, `.gap-lg`, `.gap-xl`
- **CSS Variables**: Extended spacing scale (`--space-xs` to `--space-2xl`), border radius scale, z-index scale
- **Responsive Testing**: Verified layouts at 320px, 640px, 1920px viewports

### Fixed
- **WCAG AA Text Contrast**: Brightened `--text-secondary` (#a1aebe → #a8b8c8) and `--text-muted` (#7a8a9e → #8a9aae) to meet 4.5:1 contrast ratio
- **Theme Select Dropdown**: Added `!important` rules for option styling to override browser defaults in all themes
- **Section Header Readability**: Increased section headers (Security-Score, Quick Actions, Recent Activity) from 0.875rem to 0.9375rem
- **CSS Cleanup**: Removed redundant container styles (`.dashboard-section`, `.profile-selector`, `.plugin-toggles`, `.apply-controls`, `.framework-selection`) - Card component now provides these styles
- **GUI Responsive Layout (Ultra-Wide)**: Content now constrained to 1600px max-width and centred on ultra-wide screens (4K)
- **GUI Value Cell Overflow**: Long file paths in tables now truncate with ellipsis instead of breaking layout
- **Flex Container Overflow**: Added `min-width: 0` to flex children (`.navigation`, `.nav-links`, `.header-content`, `.activity-content`)
- **Grid Container Overflow**: Updated grid templates to use `minmax(0, 1fr)` pattern (`.dashboard-grid`, `.scanner-layout`, `.report-summary`)
- **Auto-fill Grid Overflow**: Used `minmax(min(Xpx, 100%), 1fr)` for `.plugin-grid` and `.framework-grid` to prevent narrow viewport overflow

### Added (continued)
- CSS Variables for consistent theming (colours, typography, spacing)
- JetBrains Mono for data/code, Inter for UI text
- Colour-coded security states (green/amber/red for good/warning/critical)
- Horizontal navigation bar with hover effects
- Security score circular gauge with glow effects
- Styled buttons, tables, forms, badges, and empty states
- Foundation styles for 3-page architecture: Dashboard, Analysis (tabbed), Hardening (sectioned)
- **WASM-Compatible Types Crate**: New `hardener-types` crate for shared type definitions
  - Extracted all shared types (PluginId, Severity, Finding, ScanResult, etc.) to dedicated crate
  - WASM-safe dependencies only (serde, chrono)
  - Enables GUI frontend to compile to `wasm32-unknown-unknown` target
- **PDF Feature Gate**: krilla PDF library now behind optional `pdf` feature in hardener-compliance
- **WASM Entry Point**: Added `#[wasm_bindgen(start)]` entry point for Leptos app mounting
- `.cargo/config.toml` for WASM rustflags (getrandom backend configuration)
- `crates/hardener-ui/styles.css` - Complete dark terminal theme CSS (~2700 lines)

### Fixed
- **GUI "Loading..." text persistence**: Fixed by mounting app to `#app` element instead of body and clearing inner HTML
- **Security score showing 100/100 before scan**: Added `has_scan_results()` check, now shows "--/100" and "Run a scan to see your score" initially
- **"View Findings" appearing as hyperlink**: Changed from `<A>` link to styled `<button>` with programmatic navigation

- Configuration file support with layered loading (system → user → CLI → env vars)
- `HardenerConfig`, `GlobalConfig`, `PluginConfig` structs for configuration management
- `ConfigLoader` with multi-source config merging
- `PolicyException` support for documenting security deviations with audit trail
- `FindingPolicyException` field on `Finding` struct for policy annotation
- CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code` for scan command
- Three scan modes: Default (annotated), Audit (pure), Compliance (violations only)
- Config paths: `/etc/linux-hardener/config.toml` (system), `~/.config/linux-hardener/config.toml` (user)
- Interactive report wizard with `--interactive` flag for guided report generation
- CSV and HTML output format support in CLI report command
- `dialoguer` dependency for interactive terminal prompts
- PDF report formatter with professional multi-page layout and embedded fonts (NotoSans)
- Automatic timestamped PDF filenames (`compliance-report-YYYYMMDD-HHMMSS.pdf`)
- Colour-coded status badges in PDF reports (PASS=green, FAIL=red, PARTIAL=amber)
- `krilla` dependency for PDF generation
- Full compliance framework names in report titles (e.g., "CIS Benchmark" instead of "CIS")
- `full_name()` and `description()` methods on `ComplianceFramework` enum
- Improved PDF findings formatting: bold 10pt text, proper indentation, spacing after FAIL rows
- GUI compliance report page with framework selection and report generation
- Tauri command `generate_compliance_report` for GUI integration
- Compliance page route `/compliance` with navigation link

### Changed
- Test suite expanded from 220 to 428+ tests (95% increase)
- PDF findings now display with better visual hierarchy and spacing
- All 8 plugins converted to async with `#[async_trait]`
- HardeningPlugin trait methods now async: `scan()`, `apply()`, `rollback()`, `validate()`
- **hardener-ui** now depends only on `hardener-types` (removed hardener-core, hardener-common, hardener-compliance dependencies)
- Types re-exported from source crates for backwards compatibility

### Added (v0.3.0 Features)
- **SSH Remote Scanning**: Scan, apply, and rollback on remote hosts via SSH
- `SystemExecutor` trait for abstracting local/remote operations
- `LocalExecutor` implementation (wraps std::fs and std::process)
- `SshExecutor` implementation (uses openssh crate for remote operations)
- `MockExecutor` implementation for unit testing without filesystem access
- CLI SSH flags: `--ssh`, `--ssh-key`, `--port`, `--ssh-timeout`, `--ssh-no-verify`
- `SshConnectionConfig` helper for CLI argument parsing
- SSH remote scanning user guide (`docs/SSH_REMOTE_SCANNING.md`)
- Context now holds executor via `ctx.executor()` accessor
- 94 new mock-based unit tests for plugin testing
- SSH integration tests (Docker-compatible)
- `testing.rs` module with `MockPlugin` builder for test infrastructure
- **Scheduled Scanning (Phase 1 + 1.5)**: Foundation for scheduled security scans
- `hardener-scheduler` crate with configuration, SQLite storage, JSON output, and scan orchestration
- `SchedulerConfig` structs for TOML configuration
- `ScanHistoryManager` for SQLite scan history storage
- `JsonStore` for timestamped JSON file output with SHA-256 integrity hashing
- `ScanRunner` for orchestrating plugin scans with database and JSON persistence
- `TriggerType` enum (Scheduled, Manual, Systemd) for session tracking
- `ScanSummary` struct for notification payloads with severity counts
- `SeverityCounts` shared helper for consistent severity counting across crate
- Severity filtering with configurable minimum threshold
- Compliance mapping conversion for scheduled scan findings
- **Scheduled Scanning Daemon**: Cron-based scheduling with graceful shutdown
- `Daemon` struct with tokio-cron-scheduler for automated scans
- Signal handling (SIGTERM, SIGINT) for graceful daemon shutdown
- Atomic scan guard to prevent overlapping scans
- CLI daemon commands: `hardener daemon start`, `run-once`, `status`
- Scan history display with session ID, status, trigger type, and severity counts
- **Notification System**: Email and webhook notifications for scan results
- `Notifier` trait with `NotificationResult` for consistent notification handling
- `EmailNotifier` implementation using lettre for SMTP delivery
- `WebhookNotifier` for Slack, Discord, and generic HTTP endpoints
- `NotificationDispatcher` for coordinating multiple notification channels
- Configurable severity thresholds for notification triggers
- **Systemd Integration**: Generate and manage systemd unit files
- `SystemdGenerator` for creating `.service` and `.timer` unit files
- `cron_to_calendar()` function for cron-to-systemd calendar conversion
- CLI commands: `hardener systemd generate`, `install`, `uninstall`, `status`
- Security hardening directives in generated service unit (NoNewPrivileges, ProtectSystem, etc.)
- Support for both system and user service installation
- **History CLI Commands**: View and export scan history
- CLI commands: `hardener history list`, `show`, `export`
- Session filtering by host, status, and limit
- JSON export for session data and findings

### Documentation
- Added `docs/SSH_REMOTE_SCANNING.md` - comprehensive user guide for SSH remote scanning

### CI/CD Status
- GitHub Actions CI/CD workflows connected and functional
- Runs on push/PR to `main`: check, test, clippy, fmt, security audit, multi-platform builds
- GitLab CI also functional for builds and releases

## [0.3.2] - 2025-12-09

GUI major redesign with dark terminal theme, responsive layouts, accessibility improvements (WCAG AA contrast, WAI-ARIA tabs, skip link), and multiple bug fixes including security score calculation, UFW false positives, audit rules false positives, and checkpoint visibility.

## [0.3.1] - 2025-12-05

GUI polish pass: CSS transitions, empty state icons, button hover effects, fluid typography, reusable Card component, and E2E test cases TC-11 through TC-14.

## [0.3.0] - 2025-12-01

Remote SSH scanning (`--ssh` flag), scheduled scanning daemon with cron-based scheduling, notification system (email via SMTP, webhooks for Slack/Discord), systemd integration for service/timer generation, and scan history CLI commands.

## [0.2.0] - 2025-11-28

Configuration file support with layered loading, compliance framework reporting (CIS, STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR), PDF report generation, interactive report wizard, and CSV/HTML output formats.

## [0.1.0] - 2025-11-25

### Added

#### Core Infrastructure
- Plugin trait system for modular security checks
- Plugin manager with dependency resolution and topological sorting
- Distribution detection (Debian, Red Hat, Arch, SUSE families)
- Package manager abstraction (apt, dnf, pacman, zypper)
- Checkpoint system with SQLite storage
- Ed25519 cryptographic signatures for checkpoints
- Hash chain audit logging with tamper detection
- Full plugin rollback integration with checkpoint system

#### Security Plugins (8 Total)
- **Kernel Hardening**: 12 sysctl security parameters (ASLR, ptrace, dmesg, etc.)
- **SSH Hardening**: 8 SSH configuration directives with secure defaults
- **Firewall Hardening**: firewalld/nftables/ufw backend support
- **PAM Hardening**: Password policies and authentication configuration
- **Services Minimisation**: Disable unnecessary services
- **Audit Hardening**: auditd configuration and rules
- **Permissions Hardening**: File permission security checks
- **MAC Hardening**: SELinux/AppArmor detection and status

#### Command Line Interface
- `hardener scan` - Scan system for security issues
- `hardener apply` - Apply hardening recommendations
- `hardener report` - Generate compliance reports
- `hardener checkpoint` - Manage system checkpoints
- `hardener plugins` - List available plugins
- Severity filtering and JSON output support

#### Compliance Report Generation
- **CIS Benchmark** framework (35+ controls)
- **STIG** framework - DISA Security Technical Implementation Guides (20+ controls)
- **NIST 800-53** framework - US Federal security controls (20+ controls)
- **PCI-DSS v4.0** framework - Payment Card Industry standards (20+ controls)
- **HIPAA** Security Rule framework (15+ controls)
- **GDPR** Article 32 framework (12+ controls)
- Output formats: Text, JSON, CSV, HTML

#### User Interface
- Tauri-based desktop application
- Leptos (Rust) frontend with reactive state
- Dashboard with security score
- Scanner page with real-time progress
- Configuration page for plugin selection
- Results page with severity filtering
- Checkpoints page for rollback management

#### Developer Tools
- Naming convention validator script
- Pre-commit hook for validation
- Comprehensive test suite (220 tests)

### Security
- Disabled unused sqlx database backends (mysql, postgres) to reduce attack surface

### Test Coverage
- 48 plugin tests
- 59 core infrastructure tests
- 113 new unit/integration tests added
- >90% code coverage

### Known Limitations
- Some hardening requires system reboot
- SELinux/AppArmor policies detected but not fully managed
- Certain checks require root privileges
- Wayland/GBM issues on some Linux configurations

### Dependencies
- Rust 1.85+
- Tauri 2.0
- Leptos 0.8
- SQLite (via sqlx)
- tokio async runtime

---

## Version History

- **1.0.3** (2026-02-28): Parallel test runners, GUI test selector fixes for TabBar component
- **1.0.2** (2026-02-28): CLI crash fixes, desktop UX enhancements (keyboard nav, ARIA, clipboard, 95 tests)
- **1.0.1** (2026-02-27): AUR source checksum fix
- **1.0.0** (2026-02-27): First stable production release
- **0.3.3** (2026-02-25): Distribution validation complete (5 distributions across 4 families)
- **0.3.2** (2025-12-09): GUI major redesign, bug fixes, accessibility
- **0.3.1** (2025-12-05): GUI polish and testing
- **0.3.0** (2025-12-01): Remote SSH scanning, scheduled scanning, notifications
- **0.2.0** (2025-11-28): Compliance frameworks, PDF reports, configuration system
- **0.1.0** (2025-11-25): Initial development release

[Unreleased]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.5...HEAD
[1.0.5]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.3...v1.0.0
[0.3.3]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tidynest/linux-system-hardener/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tidynest/linux-system-hardener/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tidynest/linux-system-hardener/releases/tag/v0.1.0

**Last Updated**: 2026-06-23
