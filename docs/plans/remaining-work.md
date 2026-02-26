# Remaining Work — Linux System Hardener

> **Last Updated:** 2026-02-26 | **Version:** 0.3.3 | **Target:** v1.0.0

---

## Current State

Feature-complete at v0.3.3. All 8 plugins, CLI, GUI, compliance reporting, remote scanning, scheduler, checkpoint/rollback, and the full security audit (53/53 SAM findings fixed) are done. 505+ tests pass, clippy clean. The gap to v1.0.0 is operational maturity, not features.

---

## Resolved — Code Quality & Correctness

All 6 items fixed. SSH path quoting (item 4) was already correct on inspection.

| # | Item | Fix |
|---|------|-----|
| 1 | SELinux rollback ignored saved mode | Reads `SELINUX=` from restored config before `setenforce` |
| 2 | Service commands ignored exit codes | `stop/disable/mask` now check `output.success()` |
| 3 | Plugin registration errors discarded | `let _ =` replaced with `expect()` — panics on programming bugs |
| 4 | SSH path quoting | Already handled by `shell_escape()` using `'\''` pattern |
| 5 | PDF bytes corrupted through String | Call sites now use `format_bytes()` directly, bypassing String |
| 6 | Test in production binary | Moved `test_family_mapping` inside `#[cfg(test)] mod tests` |

---

## Open Work — Defence-in-Depth (Deferred SAM Items)

These remain after the 53/53 remediation pass. Lower priority — hardening beyond the current threat model.

| SAM-ID | Category | Description |
|--------|----------|-------------|
| SAM-039 | Capability | Define explicit Tauri capability ACLs for custom commands |
| SAM-061 | Environment | Use passwd lookup instead of `$HOME` env var |
| SAM-062 | DoS | Bound directive/exception map sizes after parsing |
| SAM-063 | Config | Validate env var override plugin IDs against registry |
| SAM-070 | CSP | Remove `unsafe-inline` from style-src |
| SAM-074 | Frontend | Validate theme from localStorage against allowlist |
| SAM-076 | Code Quality | Standardise IPC parameter key casing |

---

## Crate-Level Design Flags

Minor design issues found during the codebase audit. None are blocking.

### hardener-cli (4 remaining)

| ID | Issue |
|----|-------|
| D2 | `get_checkpoint_manager()` duplicated in `checkpoint.rs` and `apply.rs`. |
| D3 | `ReportFormat` enum defined but unused in production paths. |
| D4 | Framework/format display-name match arms repeated 3 times in `report_wizard.rs`. |
| D6 | Config parse errors silently swallowed in `apply.rs`. |

### hardener-common (3 remaining)

| ID | Issue |
|----|-------|
| D1 | `set_config_directive` KeyValue mode may not match all key=value formats. |
| D2 | `safe_modify_file` silently continues when backup cleanup fails. |
| D3 | `From<anyhow::Error>` maps all errors to `Executor` variant, losing context. |

### hardener-compliance (2 remaining)

| ID | Issue |
|----|-------|
| D2 | `format()` and `format_all()` duplicate ~30 lines in `csv.rs`. |
| D3 | HTML sorts sections alphabetically, PDF sorts numerically. |

### hardener-core (3 remaining)

| ID | Issue |
|----|-------|
| F-01 | `shared_data` field has `#[allow(dead_code)]` — never read. |
| F-02 | 4 methods repeat same read-lock acquisition in `registry.rs`. |
| F-03 | `Arc<Box<dyn HardeningPlugin>>` double indirection. |

### hardener-distro (2 remaining)

| ID | Issue |
|----|-------|
| D1 | `PackageManager::remove()` takes `&str` but should take `&[&str]`. |
| D3 | `execute_dpkg_query` duplicates command-execution pattern. |

### hardener-plugins (4 remaining)

| ID | Issue |
|----|-------|
| D1 | Audit scan matches by category name, not exact content — masking risk. |
| D3 | Kernel `finding_impact` describes effort, not security impact. |
| D4 | All 6 kernel params uniformly `Medium`; ASLR should be `High`. |
| D6 | `_permission_owner`/`_permission_group` fields defined but never read. |
| D7 | All 4 permission checks share uniform "Low" impact text. |

### hardener-scheduler (2 remaining)

| ID | Issue |
|----|-------|
| D1 | `started_at_utc()` returns epoch for invalid timestamps. |
| D2 | `plugins()` returns empty vec for corrupted JSON. |

### hardener-state (1 remaining)

| ID | Issue |
|----|-------|
| D1 | Silent enum fallbacks for unknown status/severity strings. |

---

## v1.0.0 Release Checklist

### Release Criteria

| Category | Item | Rationale |
|----------|------|-----------|
| Must-Have | Distribution packages (AUR, deb, rpm) | Users can't install without packages |
| Must-Have | Systemd unit files in repo | Required for packaging + scheduled scanning |
| Must-Have | Man page (`hardener.1`) | Standard for CLI tools in packages |
| Must-Have | Default config file with comments | Users need a starting point |
| Must-Have | Install/upgrade documentation | End-user guide for each distro |
| Must-Have | Security policy review | Verify SECURITY.md is complete and accurate |
| Should-Have | Integration test suite for packages | Verify install -> scan -> apply -> rollback on fresh systems |
| Should-Have | Polkit policy file | Nicer auth dialogs instead of raw pkexec |
| Should-Have | WCAG AA contrast audit | Accessibility compliance for the GUI |

### Phase 1 — Infrastructure

- [ ] `systemd/hardener-scheduler.service` + `.timer`
- [ ] `data/linux-hardener.desktop`
- [ ] `data/config.toml.example` with commented defaults
- [ ] `man/hardener.1` man page
- [ ] `packaging/` — PKGBUILD (AUR), `.spec` (RPM), `debian/` tree

### Phase 2 — Quality

- [ ] Review `SECURITY.md` completeness
- [ ] Write install/upgrade guide per distro family
- [ ] Final cross-distro validation run
- [ ] Verify musl binary on all 5 distros

### Phase 3 — Packaging

- [ ] Build and test AUR package locally with `makepkg`
- [ ] Build and test `.deb` with `dpkg-buildpackage` or `cargo-deb`
- [ ] Build and test `.rpm` with `rpmbuild`
- [ ] Test full install -> scan -> apply -> rollback cycle per package

### Phase 4 — Release

- [ ] Version bump all `Cargo.toml` + `tauri.conf.json` to 1.0.0
- [ ] CHANGELOG + ROADMAP updates
- [ ] Git tag, GitHub release, AUR submit, PPA/COPR upload

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Packaging breaks on specific distro | Medium | High | Test on all 5 before release |
| Systemd unit doesn't start correctly | Low | Medium | Test in nspawn containers |
| Config file path mismatch | Low | High | Verify all path constants match packaging |
| Missing runtime dependency | Medium | Medium | Test fresh installs (not dev machines) |
| GUI needs webkit version not in stable repos | Low | High | Document minimum distro versions |

---

## Post-v1.0.0

- Multi-host management UI, historical trends, alert notifications
- SSH password auth, parallel scanning, jump host support
- Ansible/Puppet/Salt/Chef integration modules
- ISO 27001, SOC 2, FedRAMP compliance frameworks
- SELinux policy editor, AppArmor profile editor
- Shell completions, i18n, AppImage build

---

## Source Code Markers

No `todo!()`, `FIXME`, `HACK`, `XXX`, `unimplemented!()`, or `unreachable!()` markers in the codebase.
