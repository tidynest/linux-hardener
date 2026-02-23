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

- [ ] `runner.rs` (616 lines)
- [ ] `db.rs` (603 lines)
- [ ] `daemon.rs` (382 lines)
- [ ] `notification/webhook.rs` (360 lines)
- [ ] `systemd.rs` (276 lines)
- [ ] `config.rs` (258 lines)
- [ ] `notification/mod.rs` (242 lines)
- [ ] `json_store.rs` (205 lines)
- [ ] `notification/email.rs` (197 lines)
- [ ] `notification/dispatcher.rs` (142 lines)
- [ ] `lib.rs` (24 lines)
- [ ] `CRATE.md` assembled
- [ ] Verification passed

## Session 8: hardener-cli (14 files, 3,191 lines)

User-facing CLI — 5 serde unwraps.

- [ ] `commands/report_wizard.rs` (589 lines)
- [ ] `cli.rs` (544 lines)
- [ ] `output.rs` (344 lines)
- [ ] `commands/history.rs` (254 lines)
- [ ] `commands/systemd.rs` (243 lines)
- [ ] `commands/scan.rs` (229 lines)
- [ ] `commands/daemon.rs` (221 lines)
- [ ] `commands/report.rs` (205 lines)
- [ ] `commands/apply.rs` (163 lines)
- [ ] `main.rs` (160 lines)
- [ ] `commands/checkpoint.rs` (111 lines)
- [ ] `ssh_config.rs` (106 lines)
- [ ] `commands/plugins.rs` (13 lines)
- [ ] `commands/mod.rs` (9 lines)
- [ ] `CRATE.md` assembled
- [ ] Verification passed

## Session 9: hardener-distro (7 files, 1,071 lines)

Package manager abstraction for multiple distros.

- [ ] `package/mod.rs` (207 lines)
- [ ] `lib.rs` (185 lines)
- [ ] `package/apt.rs` (184 lines)
- [ ] `package/dnf.rs` (144 lines)
- [ ] `package/zypper.rs` (132 lines)
- [ ] `package/pacman.rs` (112 lines)
- [ ] `adapter.rs` (107 lines)
- [ ] `CRATE.md` assembled
- [ ] Verification passed

## Session 10: hardener-compliance (17 files, 3,120 lines)

Report generation — 1 NormalizedF32 unwrap.

- [ ] `output/pdf.rs` (707 lines)
- [ ] `output/html.rs` (283 lines)
- [ ] `frameworks/cis.rs` (279 lines)
- [ ] `config.rs` (221 lines)
- [ ] `frameworks/pci.rs` (177 lines)
- [ ] `output/csv.rs` (172 lines)
- [ ] `output/text.rs` (171 lines)
- [ ] `report.rs` (167 lines)
- [ ] `generator.rs` (163 lines)
- [ ] `frameworks/stig.rs` (156 lines)
- [ ] `output/json.rs` (153 lines)
- [ ] `frameworks/nist.rs` (151 lines)
- [ ] `frameworks/hipaa.rs` (118 lines)
- [ ] `frameworks/gdpr.rs` (105 lines)
- [ ] `lib.rs` (37 lines)
- [ ] `output/mod.rs` (34 lines)
- [ ] `frameworks/mod.rs` (26 lines)
- [ ] `CRATE.md` assembled
- [ ] Verification passed

## Session 11: hardener-ui (25 files, 2,254 lines)

WASM/Leptos GUI — lowest risk.

- [ ] `components/configure_section.rs` (315 lines)
- [ ] `components/security_score.rs` (212 lines)
- [ ] `components/history_section.rs` (193 lines)
- [ ] `components/compliance_tab.rs` (183 lines)
- [ ] `tauri_bindings.rs` (141 lines)
- [ ] `lib.rs` (119 lines)
- [ ] `pages/analysis_page.rs` (108 lines)
- [ ] `utils/mock_data.rs` (106 lines)
- [ ] `components/tabs.rs` (102 lines)
- [ ] `components/quick_actions.rs` (99 lines)
- [ ] `components/recent_activity.rs` (97 lines)
- [ ] `components/theme_toggle.rs` (89 lines)
- [ ] `components/finding_detail.rs` (85 lines)
- [ ] `components/card.rs` (79 lines)
- [ ] `components/findings_grid.rs` (76 lines)
- [ ] `pages/hardening_page.rs` (71 lines)
- [ ] `state/mod.rs` (57 lines)
- [ ] `components/findings_tab.rs` (55 lines)
- [ ] `components/mini_security_score.rs` (52 lines)
- [ ] `components/severity_badge.rs` (39 lines)
- [ ] `pages/dashboard_page.rs` (35 lines)
- [ ] `components/mod.rs` (31 lines)
- [ ] `types.rs` (20 lines)
- [ ] `pages/mod.rs` (7 lines)
- [ ] `utils/mod.rs` (3 lines)
- [ ] `CRATE.md` assembled
- [ ] Verification passed

## Known Issues (pre-flagged)

| Flag | File | Issue |
|------|------|-------|
| DEAD CODE | `hardener-state/src/lib.rs:23-36` | Cargo template `add()` fn + `it_works` test |
| DUPLICATION | `hardener-core/src/registry.rs` | 4x identical `RwLock` read error blocks |
| ANTIPATTERN | `hardener-scheduler/src/systemd.rs:153-174` | `is_ok()` + `unwrap()` parses twice |
| INCONSISTENCY | `hardener-cli/src/output.rs` | 5x `serde_json::to_string_pretty().unwrap()` |
| DEAD CODE | `hardener-core/src/context.rs:27` | `#[allow(dead_code)]` on `shared_data` field |
| ANTIPATTERN | `hardener-plugins/src/macros.rs` | `todo!()` stubs in macro — runtime panic |
| SILENT FAILURE | `hardener-state/src/scan_manager.rs:232,235` | `unwrap_or_default()` hides corrupted JSON |
| CONSTANT | `hardener-compliance/src/output/pdf.rs:580` | `NormalizedF32::new(0.8).unwrap()` |
