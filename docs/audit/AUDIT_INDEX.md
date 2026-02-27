# Codebase Audit Index

Tracks the incremental crate-by-crate audit of all production files.

**Scope:** Production code only (test files excluded).
**Per-file:** Module doc, inline comments, if-flatten, unwrap fixes, per-file documentation.
**Verification:** `cargo check`, `cargo clippy -- -D clippy::unwrap_used`, `cargo test --workspace` after each crate.

---

## Session 2: hardener-common (5 files, 680 lines)

Foundation crate — shared error types, file utilities, logging, and common types.

- [x] `error.rs` (168 lines)
- [x] `file_utils.rs` (451 lines)
- [x] `types.rs` (10 lines)
- [x] `logging.rs` (47 lines)
- [x] `lib.rs` (4 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (401 tests, 0 failures, clippy clean)

## Session 3: hardener-types (1 file, 467 lines)

Shared DTOs and data shapes used across crates.

- [x] `lib.rs` (467 lines) — no changes needed
- [x] `CRATE.md` assembled
- [x] Verification passed (clippy clean, 0 unwraps)

## Session 4: hardener-core (11 files, 2,288 lines)

Trait contracts, executors, config loading, plugin management.

- [x] `context.rs` (358 lines)
- [x] `plugin_manager.rs` (334 lines)
- [x] `executor/mock.rs` (315 lines)
- [x] `config_loader.rs` (292 lines)
- [x] `config.rs` (286 lines)
- [x] `registry.rs` (199 lines)
- [x] `executor/ssh.rs` (199 lines)
- [x] `plugin.rs` (93 lines)
- [x] `executor/local.rs` (87 lines)
- [x] `executor/mod.rs` (72 lines)
- [x] `lib.rs` (53 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (401 tests, 0 failures, clippy clean)

## Session 5: hardener-state (9 files, 2,987 lines)

Crypto, persistence, rollback — highest security surface.

- [x] `audit.rs` (1,022 lines)
- [x] `manager.rs` (619 lines)
- [x] `scan_manager.rs` (497 lines)
- [x] `signing.rs` (277 lines)
- [x] `db.rs` (201 lines)
- [x] `hash_chain.rs` (129 lines)
- [x] `checkpoint.rs` (108 lines)
- [x] `scan_history.rs` (98 lines)
- [x] `lib.rs` (36 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Session 6: hardener-plugins (13 files, 5,492 lines)

Largest crate — directly mutates system configuration.

- [x] `audit/mod.rs` (808 lines)
- [x] `pam/mod.rs` (661 lines)
- [x] `ssh/mod.rs` (620 lines)
- [x] `mac/mod.rs` (523 lines)
- [x] `kernel/mod.rs` (480 lines)
- [x] `services/mod.rs` (453 lines)
- [x] `permissions/mod.rs` (423 lines)
- [x] `firewall/mod.rs` (419 lines)
- [x] `firewall/nftables.rs` (314 lines)
- [x] `firewall/firewalld.rs` (281 lines)
- [x] `firewall/ufw.rs` (259 lines)
- [x] `lib.rs` (170 lines)
- [x] `macros.rs` (81 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Session 7: hardener-scheduler (11 files, 3,305 lines)

Daemon stability — 4 parse-twice unwraps.

- [x] `runner.rs` (616 lines)
- [x] `db.rs` (603 lines)
- [x] `daemon.rs` (382 lines)
- [x] `notification/webhook.rs` (360 lines)
- [x] `systemd.rs` (276 lines)
- [x] `config.rs` (258 lines)
- [x] `notification/mod.rs` (242 lines)
- [x] `json_store.rs` (205 lines)
- [x] `notification/email.rs` (197 lines)
- [x] `notification/dispatcher.rs` (142 lines)
- [x] `lib.rs` (24 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Session 8: hardener-cli (14 files, 3,191 lines)

User-facing CLI — 5 serde unwraps.

- [x] `commands/report_wizard.rs` (589 lines)
- [x] `cli.rs` (544 lines)
- [x] `output.rs` (344 lines)
- [x] `commands/history.rs` (254 lines)
- [x] `commands/systemd.rs` (243 lines)
- [x] `commands/scan.rs` (229 lines)
- [x] `commands/daemon.rs` (221 lines)
- [x] `commands/report.rs` (205 lines)
- [x] `commands/apply.rs` (163 lines)
- [x] `main.rs` (160 lines)
- [x] `commands/checkpoint.rs` (111 lines)
- [x] `ssh_config.rs` (106 lines)
- [x] `commands/plugins.rs` (13 lines)
- [x] `commands/mod.rs` (9 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Session 9: hardener-distro (7 files, 1,071 lines)

Package manager abstraction for multiple distros.

- [x] `package/mod.rs` (207 lines)
- [x] `lib.rs` (185 lines)
- [x] `package/apt.rs` (184 lines)
- [x] `package/dnf.rs` (144 lines)
- [x] `package/zypper.rs` (132 lines)
- [x] `package/pacman.rs` (112 lines)
- [x] `adapter.rs` (107 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Session 10: hardener-compliance (17 files, 3,120 lines)

Report generation — 1 NormalizedF32 unwrap.

- [x] `output/pdf.rs` (707 lines)
- [x] `output/html.rs` (283 lines)
- [x] `frameworks/cis.rs` (279 lines)
- [x] `config.rs` (221 lines)
- [x] `frameworks/pci.rs` (177 lines)
- [x] `output/csv.rs` (172 lines)
- [x] `output/text.rs` (171 lines)
- [x] `report.rs` (167 lines)
- [x] `generator.rs` (163 lines)
- [x] `frameworks/stig.rs` (156 lines)
- [x] `output/json.rs` (153 lines)
- [x] `frameworks/nist.rs` (151 lines)
- [x] `frameworks/hipaa.rs` (118 lines)
- [x] `frameworks/gdpr.rs` (105 lines)
- [x] `lib.rs` (37 lines)
- [x] `output/mod.rs` (34 lines)
- [x] `frameworks/mod.rs` (26 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Session 11: hardener-ui (25 files, 2,374 lines)

WASM/Leptos GUI — lowest risk, 3 fixes.

- [x] `components/configure_section.rs` (315 lines)
- [x] `components/security_score.rs` (218 lines)
- [x] `components/history_section.rs` (193 lines)
- [x] `components/compliance_tab.rs` (183 lines)
- [x] `tauri_bindings.rs` (141 lines)
- [x] `lib.rs` (119 lines)
- [x] `pages/analysis_page.rs` (108 lines)
- [x] `utils/mock_data.rs` (106 lines)
- [x] `components/tabs.rs` (102 lines)
- [x] `components/quick_actions.rs` (99 lines)
- [x] `components/recent_activity.rs` (97 lines)
- [x] `components/theme_toggle.rs` (89 lines)
- [x] `components/finding_detail.rs` (85 lines)
- [x] `components/card.rs` (79 lines)
- [x] `components/findings_grid.rs` (76 lines)
- [x] `pages/hardening_page.rs` (71 lines)
- [x] `state/mod.rs` (57 lines)
- [x] `components/findings_tab.rs` (55 lines)
- [x] `components/mini_security_score.rs` (52 lines)
- [x] `components/severity_badge.rs` (39 lines)
- [x] `pages/dashboard_page.rs` (35 lines)
- [x] `components/mod.rs` (31 lines)
- [x] `types.rs` (20 lines)
- [x] `pages/mod.rs` (7 lines)
- [x] `utils/mod.rs` (3 lines)
- [x] `CRATE.md` assembled
- [x] Verification passed (400 tests, 0 failures, clippy clean)

## Audit Summary

All 11 production crates audited across sessions 2–11.

| Session | Crate | Files | Lines | Fixes | Flags |
|---------|-------|-------|-------|-------|-------|
| 2 | hardener-common | 6 | 640 | 2 | 1 |
| 3 | hardener-types | 4 | 645 | 0 | 0 |
| 4 | hardener-core | 13 | 2,719 | 5 | 7 |
| 5 | hardener-state | 9 | 2,550 | 13 | 2 |
| 6 | hardener-plugins | 13 | 5,947 | 28 | 9 |
| 7 | hardener-scheduler | 11 | 3,580 | 12 | 2 |
| 8 | hardener-cli | 15 | 3,393 | 19 | 6 |
| 9 | hardener-distro | 7 | 1,019 | 6 | 3 |
| 10 | hardener-compliance | 17 | 2,856 | 5 | 3 |
| 11 | hardener-ui | 33 | 4,574 | 3 | 2 |
| **Total** | **11 crates** | **128** | **27,923** | **93** | **35** |

> **Note (2026-02-27):** Line counts updated to reflect post-refactor state. New files: `binary_utils.rs` (common), `config_validation.rs` (core), `state.rs` (cli), 3 type submodules, 8 UI components + 2 pages + `form_helpers.rs`.

## Known Issues (pre-flagged)

| Flag | File | Issue | Status |
|------|------|-------|--------|
| DEAD CODE | `hardener-state/src/lib.rs:23-36` | Cargo template `add()` fn + `it_works` test | Deferred |
| DUPLICATION | `hardener-core/src/registry.rs` | 4x identical `RwLock` read error blocks | Deferred |
| ANTIPATTERN | `hardener-scheduler/src/systemd.rs:153-174` | `is_ok()` + `unwrap()` parses twice | Fixed (Session 7) |
| INCONSISTENCY | `hardener-cli/src/output.rs` | 5x `serde_json::to_string_pretty().unwrap()` | Fixed (Session 8) |
| DEAD CODE | `hardener-core/src/context.rs:27` | `#[allow(dead_code)]` on `shared_data` field | Deferred |
| ANTIPATTERN | `hardener-plugins/src/macros.rs` | `todo!()` stubs in macro — runtime panic | Deferred |
| SILENT FAILURE | `hardener-state/src/scan_manager.rs:232,235` | `unwrap_or_default()` hides corrupted JSON | Deferred |
| CONSTANT | `hardener-compliance/src/output/pdf.rs:580` | `NormalizedF32::new(0.8).unwrap()` | Fixed (Session 8) |
