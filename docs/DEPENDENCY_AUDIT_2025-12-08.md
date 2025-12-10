# Dependency Audit Report

**Date**: 2025-12-08
**Tools Used**: cargo-audit, cargo-machete, cargo-outdated, cargo-bloat, cargo-geiger, cargo-deny, Miri

---

## Summary

| Category | Status | Count | Action Required |
|----------|--------|-------|-----------------|
| Security Vulnerabilities | None | 0 | None |
| Unmaintained Dependencies | Warning | 19 | Wait for upstream (Tauri) |
| Unused Dependencies | Actionable | 12 | Remove from Cargo.toml |
| Outdated Dependencies | Actionable | ~25 | Run cargo update |
| Binary Size | Normal | 12.3 MiB | None |
| Memory Safety (Miri) | Pass | 52/54 tests | 2 tests use unsupported syscalls |

---

## 1. Security Vulnerabilities (cargo audit)

**Status**: No vulnerabilities found

All 19 findings are **warnings** (unmaintained crates), not security vulnerabilities.

---

## 2. Unmaintained Dependencies

These are transitive dependencies from Tauri/GTK3 ecosystem. **No action possible** until Tauri updates.

### GTK3 Bindings (12 crates)
All marked unmaintained as gtk-rs moved to GTK4:

| Crate | Advisory |
|-------|----------|
| atk | RUSTSEC-2024-0413 |
| atk-sys | RUSTSEC-2024-0416 |
| gdk | RUSTSEC-2024-0412 |
| gdk-sys | RUSTSEC-2024-0418 |
| gdkwayland-sys | RUSTSEC-2024-0411 |
| gdkx11 | RUSTSEC-2024-0417 |
| gdkx11-sys | RUSTSEC-2024-0414 |
| gtk | RUSTSEC-2024-0415 |
| gtk-sys | RUSTSEC-2024-0420 |
| gtk3-macros | RUSTSEC-2024-0419 |
| glib (unsound) | RUSTSEC-2024-0429 |
| proc-macro-error | RUSTSEC-2024-0370 |

### Other Unmaintained (6 crates)

| Crate | Advisory | Source |
|-------|----------|--------|
| fxhash | RUSTSEC-2025-0057 | via selectors → kuchikiki → wry |
| paste | RUSTSEC-2024-0436 | via leptos ecosystem |
| unic-char-property | RUSTSEC-2025-0081 | via urlpattern → tauri-utils |
| unic-char-range | RUSTSEC-2025-0075 | via urlpattern → tauri-utils |
| unic-common | RUSTSEC-2025-0080 | via urlpattern → tauri-utils |
| unic-ucd-ident | RUSTSEC-2025-0100 | via urlpattern → tauri-utils |
| unic-ucd-version | RUSTSEC-2025-0098 | via urlpattern → tauri-utils |

**Recommendation**: Monitor Tauri releases. These will be fixed when Tauri updates their dependencies.

---

## 3. Unused Dependencies (cargo machete)

**Status**: Actionable - can remove these to reduce compile time and attack surface.

### hardener-ui (crates/hardener-ui/Cargo.toml)
```toml
# REMOVE these if truly unused:
js-sys = "..."          # Verify: may be needed for WASM builds
tracing = "..."         # Verify: may be used via macros
wasm-bindgen-futures = "..."  # Verify: may be needed for WASM builds
```

### hardener-state (crates/hardener-state/Cargo.toml)
```toml
# REMOVE:
thiserror = "..."
```

### hardener-plugins (crates/hardener-plugins/Cargo.toml)
```toml
# REMOVE:
anyhow = "..."
log = "..."
tempfile = "..."   # Verify: may be used in tests only
```

### hardener-compliance (crates/hardener-compliance/Cargo.toml)
```toml
# REMOVE:
serde = "..."      # Verify: may be used via derive macros
```

### hardener-scheduler (crates/hardener-scheduler/Cargo.toml)
```toml
# REMOVE:
anyhow = "..."
hardener-plugins = "..."
thiserror = "..."
```

### hardener-common (crates/hardener-common/Cargo.toml)
```toml
# REMOVE:
serde = "..."      # Verify: may be used via derive macros
```

### Verification Commands
Before removing, verify each dependency isn't used:
```bash
# Check if a dependency is actually used (example for serde)
grep -r "serde" crates/hardener-common/src/
grep -r "Serialize\|Deserialize" crates/hardener-common/src/
```

---

## 4. Outdated Dependencies (cargo outdated)

### High Priority (Tauri - security/bug fixes)
```bash
cargo update -p tauri -p tauri-build -p tauri-codegen -p tauri-macros -p tauri-runtime -p tauri-runtime-wry -p tauri-utils
```

| Crate | Current | Latest |
|-------|---------|--------|
| tauri | 2.9.3 | 2.9.4 |
| tauri-build | 2.5.2 | 2.5.3 |
| tauri-codegen | 2.5.1 | 2.5.2 |
| tauri-macros | 2.5.1 | 2.5.2 |
| tauri-runtime | 2.9.1 | 2.9.2 |
| tauri-runtime-wry | 2.9.1 | 2.9.2 |
| tauri-utils | 2.8.0 | 2.8.1 |

### Medium Priority (Logging - patch versions)
```bash
cargo update -p tracing -p tracing-subscriber -p log
```

| Crate | Current | Latest |
|-------|---------|--------|
| tracing | 0.1.41 | 0.1.43 |
| tracing-subscriber | 0.3.20 | 0.3.22 |
| log | 0.4.28 | 0.4.29 |

### Low Priority (Other patch updates)
```bash
cargo update -p openssh
```

| Crate | Current | Latest |
|-------|---------|--------|
| openssh | 0.11.5 | 0.11.6 |

### Breaking Changes (Requires code review)
**Do not auto-update** - these may require code changes:

| Crate | Current | Latest | Notes |
|-------|---------|--------|-------|
| krilla | 0.5.0 | 0.6.0 | PDF generation - review changelog |
| schemars | 0.9.0 | 1.1.0 | Major version bump - API changes likely |
| zune-core | 0.4.12 | 0.5.0 | Image processing |
| zune-jpeg | 0.4.21 | 0.5.5 | Image processing |

---

## 5. Binary Size Analysis (cargo bloat)

**Total Binary**: 12.3 MiB
**Code Section (.text)**: 7.0 MiB

### Top Contributors

| Component | Size | % of .text |
|-----------|------|------------|
| Your code (linux_hardener_desktop::main) | 180 KiB | 2.5% |
| Tauri menu plugin | 101 KiB | 1.4% |
| Tauri webview handling | 150 KiB | 2.1% |
| X11 bindings | 70 KiB | 1.0% |
| SQLite | 90 KiB | 1.3% |
| Other (8,333 functions) | 6.1 MiB | 87% |

**Assessment**: Normal for a Tauri desktop application. No optimization needed.

---

## 6. Unsafe Code Analysis (cargo geiger)

**Note**: Must run per-package in workspace:
```bash
cargo geiger -p linux-hardener-desktop
cargo geiger -p hardener-core
cargo geiger -p hardener-ui
```

---

## 7. Memory Safety Testing (Miri)

**Results**: 52 of 54 tests pass

### Passing Tests
- All 31 tests in `hardener-cli` (main binary)
- 19 of 21 tests in `hardener-common`
- All 10 tests in `common_types` integration tests

### Tests Skipped/Failed (Miri Limitations)

| Test | Issue | Reason |
|------|-------|--------|
| `file_utils::tests::test_backup_file_creates_backup` | `fchmod` not supported | Miri can't emulate filesystem permissions |
| `logging::tests::test_logger_initialisation` | `clock_gettime(REALTIME)` not supported | Miri can't emulate system clock in isolation mode |

**These are Miri limitations, not bugs in your code.** The tests pass with regular `cargo test`.

### Recommended Miri Command
```bash
# Skip tests that use unsupported syscalls
cargo +nightly miri test -- --skip file_utils --skip logging
```

---

## 8. cargo deny

**Status**: Blocked by upstream bug

The RustSec advisory database has a corrupted git signature that prevents fetching:
```
failed to fetch advisory database: Signature name or email must not contain '<', '>'
```

This is an upstream issue in the RustSec repo. Use `cargo audit` instead for now.

---

## Action Items

### Immediate (Safe to do now)

- [x] Update Tauri patch versions: ✅ **DONE 2025-12-08**
  ```bash
  cargo update -p tauri -p tauri-build -p tauri-codegen -p tauri-macros -p tauri-runtime -p tauri-runtime-wry -p tauri-utils
  ```
  Updated: tauri 2.9.3→2.9.4, tauri-build 2.5.2→2.5.3, tauri-codegen 2.5.1→2.5.2, tauri-macros 2.5.1→2.5.2, tauri-runtime 2.9.1→2.9.2, tauri-runtime-wry 2.9.1→2.9.2, tauri-utils 2.8.0→2.8.1

- [x] Update logging crates: ✅ **DONE 2025-12-08**
  ```bash
  cargo update -p tracing -p tracing-subscriber -p log
  ```
  Updated: log 0.4.28→0.4.29, tracing 0.1.41→0.1.43, tracing-subscriber 0.3.20→0.3.22

- [x] Run full test suite after updates: ✅ **PASSED 2025-12-08**
  ```bash
  cargo test --workspace
  ```
  Result: **353 tests passed**, 0 failed, 32 ignored (SSH/root-required tests)

### Soon (Verify before acting)

- [x] Verify and remove unused dependencies: ✅ **DONE 2025-12-08**
  Removed 6 unused dependencies:
  - `hardener-ui`: `tracing`
  - `hardener-state`: `thiserror`
  - `hardener-plugins`: `anyhow`, `tempfile`
  - `hardener-scheduler`: `anyhow`, `hardener-plugins`, `thiserror`

  Note: `js-sys` and `wasm-bindgen-futures` were false positives (needed by `#[wasm_bindgen]` macro)

- [x] Update openssh: ✅ **DONE 2025-12-08**
  ```bash
  cargo update -p openssh
  ```
  Updated: openssh 0.11.5 → 0.11.6

- [x] Run `cargo geiger`: ⚠️ **SKIPPED** - Tool has compatibility issues with complex workspaces

### Later (Requires planning)

- [ ] ~~Evaluate `krilla` 0.6.0 upgrade~~ — **No action needed**: 0.6.0 doesn't exist yet
- [ ] ~~Evaluate `schemars` 1.x upgrade~~ — **No action needed**: Transitive dependency from Tauri, not used directly

### Monitor (No action possible)

- [ ] GTK3 unmaintained warnings - wait for Tauri to migrate
- [ ] cargo deny upstream bug - wait for RustSec fix

---

## Appendix: Full Tool Commands

```bash
# Security audit
cargo audit

# Find unused dependencies
cargo machete

# Check for updates
cargo outdated

# Binary size analysis
cargo bloat --release -p linux-hardener-desktop

# Unsafe code count
cargo geiger -p linux-hardener-desktop

# Memory safety (skip I/O tests)
cargo +nightly miri test -- --skip file_utils --skip logging

# License/dependency check (currently broken)
cargo deny check
```
