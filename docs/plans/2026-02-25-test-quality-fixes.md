# Test Quality Improvement Plan

**Date**: 2026-02-25
**Scope**: All test code across 11 crates (21 test files, ~7,928 lines)
**Status**: Documented — code changes pending manual implementation

---

## Summary

| Category | Count | Priority | Effort |
|----------|-------|----------|--------|
| `assert!()` without messages | 60+ | HIGH | 2-3 hours |
| `println!()`/`eprintln!()` in tests | 80+ across 11 files | MEDIUM | 1.5 hours |
| Repeated setup boilerplate | 5 patterns | MEDIUM | 1-2 hours |
| Bare `panic!()` | 1 | LOW | 5 minutes |
| Test naming inconsistencies | 0-2 | LOW | 15 minutes |

---

## 1. Bare Assertions (Priority 1 — HIGH)

60+ `assert!()` calls lack descriptive messages, making failures hard to diagnose.

### Files and Fixes

#### `crates/hardener-core/tests/ssh_executor_tests.rs`

| Line | Current | Fix |
|------|---------|-----|
| 152 | `assert!(result.is_err());` | `assert!(result.is_err(), "Should fail reading non-existent file, got: {result:?}");` |
| 167 | `assert!(result.is_ok());` | `assert!(result.is_ok(), "Should succeed reading /etc/hostname, got: {result:?}");` |
| 174 | `assert!(result.is_ok());` | `assert!(result.is_ok(), "read_file_optional should not error, got: {result:?}");` |

#### `crates/hardener-core/tests/mock_executor_tests.rs`

| Line | Current | Fix |
|------|---------|-----|
| 43 | `assert!(result.is_err());` | `assert!(result.is_err(), "Should fail reading missing file, got: {result:?}");` |
| 197 | `assert!(result.is_err());` | `assert!(result.is_err(), "Unknown command should fail, got: {result:?}");` |
| 259-261 | `assert!(log.files_read.is_empty());` | `assert!(log.files_read.is_empty(), "Log should be cleared, had {} reads", log.files_read.len());` |

#### `crates/hardener-plugins/tests/kernel_mock_tests.rs`

| Line | Current | Fix |
|------|---------|-----|
| 77 | `assert!(result.scan_success);` | `assert!(result.scan_success, "Secure kernel scan should succeed: {result:?}");` |
| 98 | `assert!(result.scan_success);` | `assert!(result.scan_success, "Insecure kernel scan should report success: {result:?}");` |
| 115-117 | `assert!(finding_ids.contains(&"..."));` | `assert!(finding_ids.contains(&"kernel_kernel_randomize_va_space"), "Expected randomize_va_space finding, found: {:?}", finding_ids);` |

#### `crates/hardener-plugins/tests/ssh_integration_tests.rs`

| Line | Current | Fix |
|------|---------|-----|
| 313 | `assert!(exists.is_ok());` | `assert!(exists.is_ok(), "command_exists should succeed, got: {exists:?}");` |

**Pattern to apply globally**: every `assert!(x.is_ok())` / `assert!(x.is_err())` / `assert!(x.is_empty())` should include `{x:?}` in the message.

---

## 2. println!() in Tests (Priority 2 — MEDIUM)

80+ calls across 11 test files. Two strategies:

- **Unit tests / mock tests**: Remove entirely; assertions cover correctness.
- **Integration tests** (ssh_integration_tests, *_tests.rs with live system): Replace with `tracing::info!()` or convert diagnostic output to assertion messages.

### Files with println!() Calls

| File | Lines | Count |
|------|-------|-------|
| `hardener-plugins/tests/firewall_tests.rs` | 51-364 | ~15 |
| `hardener-plugins/tests/ssh_tests.rs` | 47-143 | ~10 |
| `hardener-plugins/tests/kernel_tests.rs` | 40-145 | ~12 |
| `hardener-plugins/tests/services_tests.rs` | 52-177 | ~10 |
| `hardener-plugins/tests/pam_tests.rs` | 49-132 | ~8 |
| `hardener-plugins/tests/permissions_tests.rs` | 51-54 | ~2 |
| `hardener-plugins/tests/audit_tests.rs` | (similar) | ~9 |
| `hardener-plugins/tests/mac_tests.rs` | (similar) | ~5 |
| `hardener-plugins/tests/ssh_integration_tests.rs` | 102-336 | ~12 |
| `hardener-core/tests/plugin_manager_tests.rs` | 38 | 1 (eprintln) |
| `hardener-core/src/context.rs` | 311-315 | 5 (in `#[cfg(test)]`) |
| `hardener-distro/src/lib.rs` | 132-142 | 1 |

### Example Transform

**Before** (`kernel_tests.rs:40-50`):
```rust
let scan_result = result.unwrap();
println!(
    "Scan completed in {}us ({}ms)",
    scan_result.scan_duration_us,
    scan_result.scan_duration_us / 1000
);
println!(
    "Found {} insecure kernel parameters",
    scan_result.scan_findings.len()
);
```

**After**:
```rust
let scan_result = result.unwrap();
assert!(scan_result.scan_duration_us > 0, "Should record scan duration");
// Finding count depends on live system state; no assertion needed
```

---

## 3. Setup Boilerplate (Priority 3 — MEDIUM)

### Pattern A: Kernel Mock Executors

**File**: `hardener-plugins/tests/kernel_mock_tests.rs:14-67`

Three functions (`secure_kernel_executor`, `insecure_kernel_executor`, `partial_kernel_executor`) share ~80% identical code. Only the values differ.

**Fix**: Data-driven approach:
```rust
enum KernelState { Secure, Insecure, Partial }

fn kernel_executor(state: KernelState) -> MockExecutor {
    let base_params = [
        "kernel/randomize_va_space",
        "kernel/kptr_restrict",
        // ... remaining params
    ];
    let values = match state {
        KernelState::Secure => ["2", "2", ...],
        KernelState::Insecure => ["0", "0", ...],
        KernelState::Partial => ["2", ...],  // subset
    };
    let mut executor = MockExecutor::new();
    for (param, value) in base_params.iter().zip(values.iter()) {
        executor = executor.with_file(&format!("/proc/sys/{param}"), value);
    }
    executor
}
```

### Pattern B: SSH Test Config (Duplicated)

**Files**: `hardener-core/tests/ssh_executor_tests.rs:89-104` AND `hardener-plugins/tests/ssh_integration_tests.rs:50-65`

Identical `get_test_config() -> Option<SshConfig>` function in two files.

**Fix**: Extract to shared test helper. Since these are in different crates, best option is to add a `pub fn get_ssh_test_config()` to `hardener-core/tests/common/mod.rs` and have `hardener-plugins` integration tests depend on it, or duplicate with a comment noting the canonical location.

### Pattern C: Plugin + Context Initialisation

10+ tests across multiple files repeat:
```rust
let plugin = XxxPlugin::new();
let ctx = Context::new();
let result = plugin.scan(&ctx).await;
assert!(result.is_ok());
let scan_result = result.unwrap();
assert_eq!(scan_result.scan_plugin_id, PluginId::new("xxx"));
```

**Fix**: Helper function:
```rust
fn assert_scan_structure(result: &ScanResult, expected_id: &PluginId) {
    assert_eq!(&result.scan_plugin_id, expected_id, "Plugin ID mismatch");
    assert!(result.scan_duration_us > 0, "Should record scan timing");
}
```

### Pattern D: TestFixture in hardener-state (Already Good)

`hardener-state/tests/common/mod.rs` has an excellent `TestFixture` struct. This pattern should be replicated in `hardener-plugins` and `hardener-core` test suites.

---

## 4. Bare panic!() (Priority 4 — LOW)

**File**: `hardener-plugins/tests/ssh_tests.rs:172`

```rust
// Current
Err(e) => { panic!("Apply failed: {}", e); }

// Fix — use unwrap_or_else for cleaner pattern
let apply_result = result.unwrap_or_else(|e| {
    panic!("SSH apply failed (expected success with root): {e}")
});
```

---

## 5. Test Naming (Priority 5 — LOW)

Naming is already mostly consistent (`test_<component>_<scenario>`). Only minor variance exists. Optional: add a doc comment at the top of each test file:

```rust
//! Naming convention: test_<component>_<scenario>[_<condition>]
```

---

## Implementation Order

1. Add assertion messages to all 60+ bare `assert!()` calls
2. Remove/replace `println!()` in mock test files first (safest)
3. Extract kernel mock executor boilerplate
4. Fix the single `panic!()` in ssh_tests.rs
5. Optionally add naming convention comments
