# Remaining Work — Linux System Hardener

> **Last Updated:** 2026-02-27 | **Version:** 1.0.2

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

## Resolved — Defence-in-Depth (Deferred SAM Items)

6 of 7 items fixed. SAM-039 deferred to post-v1.0 (requires refactoring all commands into a Tauri plugin; existing PrivilegedOpGuard + pkexec + input validation is sufficient).

| SAM-ID | Category | Fix |
|--------|----------|-----|
| SAM-061 | Environment | Replaced `env::var("HOME")` with `dirs::home_dir()` (passwd lookup) |
| SAM-062 | DoS | Bounded directive/exception map sizes in `merge_plugin()` |
| SAM-063 | Config | Env var plugin IDs validated against `KNOWN_PLUGIN_IDS` |
| SAM-070 | CSP | Removed `'unsafe-inline'` from `style-src` |
| SAM-074 | Frontend | Theme from localStorage validated against `THEMES` allowlist |
| SAM-076 | Code Quality | Standardised all IPC parameter keys to camelCase |

---

## Resolved — Crate-Level Design Flags

All 21 items fixed across 8 crates.

| Crate | IDs | Summary |
|-------|-----|---------|
| hardener-cli | D2-D6 | Shared state helper; test-only enum; `full_name()` dedup; config warning |
| hardener-common | D1-D3 | KeyValue separator; non-fatal backup cleanup; anyhow downcast |
| hardener-compliance | D2-D3 | CSV row helper; shared section grouping + numerical sort |
| hardener-core | F-01-F-03 | Dead field removed; `read_plugins()` helper; Arc single indirection |
| hardener-distro | D1, D3 | Already fixed; removed duplicate command helper |
| hardener-plugins | D1, D3-D7 | Audit match by content; kernel severity + impact text; dead fields; permission impact |
| hardener-scheduler | D1-D2 | `Option` return for timestamps; `Result` return for plugins JSON |
| hardener-state | D1 | `tracing::warn` on unknown enum values |

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

### Phase 1 — Infrastructure (Complete)

- [x] `systemd/linux-hardener.service` + `.timer` — oneshot + daily 02:00 timer, sandboxed with `ProtectSystem=strict`
- [x] `data/linux-hardener.desktop` — XDG 1.0 compliant desktop entry
- [x] `data/config.toml.example` — commented defaults for all 8 plugins
- [x] `data/hardener.1` — full man page covering all commands and options
- [x] `data/com.tidynest.linux-hardener.policy` — polkit actions for apply + rollback
- [x] `packaging/` — PKGBUILD (AUR), `.spec` (RPM), `debian/` tree — all install man page, polkit policy, config, log dir

### Phase 2 — Quality

- [x] Review `SECURITY.md` completeness — corrected 3 stale Known Limitations, added 8 security practices, updated version table
- [x] Write install/upgrade guide per distro family — `docs/INSTALL.md` covers all 5 families + source + binary + troubleshooting
- [x] Final cross-distro validation run — `run-package-tests.sh` all 5 distros green (25/28, 3 expected skips)
- [x] Verify musl binary on all 5 distros — musl binary installed + functional tests passed in all containers

### Phase 3 — Packaging (Complete)

- [x] Simulated package install test scripts (`scripts/test-package-install.sh` + `scripts/run-package-tests.sh`)
- [x] Man page version fixed to match current version, wired into `release.sh` auto-bump + verify
- [x] `tauri.conf.json` added to `release.sh` auto-bump + verify
- [x] Test full install -> scan -> apply -> rollback cycle per package (via `run-package-tests.sh --apply`)
- [x] Build and test AUR package locally with `makepkg` (post-tag) — PKGBUILD validated, container tests pass
- [x] Build and test `.deb` with `dpkg-buildpackage` or `cargo-deb` (post-tag) — container tests pass
- [x] Build and test `.rpm` with `rpmbuild` (post-tag) — container tests pass (fedora, rhel, opensuse)

### Phase 4 — Release

- [x] CHANGELOG consolidated for v1.0.0
- [x] ROADMAP updated for v1.0.0
- [x] Project cleanup (dead files, stale worktree, .idea untracked, scripts README)
- [x] Run `./scripts/release.sh major` (bumps versions, commits, tags, pushes)
- [x] Build actual AUR/deb/rpm packages from tagged release — package specs bumped to 1.0.0, all containers tested
- [x] GitHub release with binary assets

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

- SAM-039: Explicit Tauri capability ACLs (requires plugin refactor)
- Multi-host management UI, historical trends, alert notifications
- SSH password auth, parallel scanning, jump host support
- Ansible/Puppet/Salt/Chef integration modules
- ISO 27001, SOC 2, FedRAMP compliance frameworks
- SELinux policy editor, AppArmor profile editor
- Shell completions, i18n, AppImage build

---

## Source Code Markers

No `todo!()`, `FIXME`, `HACK`, `XXX`, `unimplemented!()`, or `unreachable!()` markers in the codebase.
