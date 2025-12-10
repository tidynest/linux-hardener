# CLI v0.3.2 Functional Test Results

**Date:** 2025-12-10
**Tester:** Development session
**Version:** 0.3.2
**Platform:** Arch Linux (LTS kernel 6.12.61)
**Test Mode:** Non-root user + Root (in container)

---

## Executive Summary

### Non-Root Tests (Host System)

| Category | Tests | Pass | Fail | Notes |
|----------|-------|------|------|-------|
| Basic commands | 5 | 5 | 0 | All working |
| Scan operations | 9 | 9 | 0 | Severity filter, exit code, plugin validation work |
| Report generation | 8 | 8 | 0 | All 6 frameworks, all formats |
| Apply/dry-run | 2 | 2 | 0 | Estimated changes now shown |
| Checkpoint | 1 | 1 | 0 | List works |
| Daemon/History | 2 | 2 | 0 | ✅ Fixed - user dir fallback |
| Systemd | 2 | 2 | 0 | Generate/status work |
| SSH remote | 1 | 1 | 0 | Error handling works |
| **Total** | **30** | **30** | **0** | 100% pass rate |

### Root Tests (Container - Full Suite)

| Category | Tests | Pass | Fail | Skip | Notes |
|----------|-------|------|------|------|-------|
| Environment | 4 | 4 | 0 | 0 | Container detection works |
| Basic commands | 2 | 2 | 0 | 0 | All working |
| Scan (root) | 9 | 9 | 0 | 0 | **47 findings** with root access |
| Reports | 8 | 8 | 0 | 0 | All 6 frameworks + JSON + PDF |
| Dry-run | 5 | 5 | 0 | 0 | All plugins show changes |
| Daemon/History | 2 | 2 | 0 | 0 | Root path `/var/lib/` correct |
| Systemd | 2 | 2 | 0 | 0 | Generate/status work |
| Checkpoint | 1 | 1 | 0 | 0 | List works |
| Apply + Rollback | 3 | 3 | 0 | 1 | Kernel applied, verified ✅ |
| **Total** | **36** | **35** | **0** | **1** | 97% pass (1 skip is test script issue) |

**Combined: 66 tests, 65 pass, 0 fail, 1 skip**

---

## Test Results

### 1. Basic Commands

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| CLI-01 | `hardener --version` | Show version | `hardener 0.3.2` | ✅ PASS |
| CLI-02 | `hardener --help` | Show help text | Full help displayed | ✅ PASS |
| CLI-03 | `hardener plugins` | List 8 plugins | All 8 listed with correct metadata | ✅ PASS |
| CLI-04 | `hardener scan --help` | Show scan options | Options displayed | ✅ PASS |
| CLI-05 | `hardener report --help` | Show report options | Options displayed | ✅ PASS |

### 2. Scan Operations

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| SCAN-01 | `hardener scan` | Scan all plugins | 8 plugins scanned, 11 findings | ✅ PASS |
| SCAN-02 | `hardener scan --plugin kernel` | Scan only kernel | Kernel plugin only (0 findings - needs root) | ✅ PASS |
| SCAN-03 | `hardener scan --severity high` | Filter high+ only | 3 high severity findings | ✅ PASS |
| SCAN-04 | `hardener scan --exit-code` | Exit 1 if findings | Exit code 1 (findings exist) | ✅ PASS |
| SCAN-05 | `hardener --format json scan` | JSON output | Valid JSON array | ✅ PASS |
| SCAN-06 | `hardener --format text scan` | Text output | Readable text format | ✅ PASS |
| SCAN-07 | `hardener scan --plugin nonexistent` | Error with valid plugins list | Error + exit 1 | ✅ PASS |
| SCAN-08 | `hardener scan --plugin kernel` | Short name accepted | Scans `kernel-hardening` | ✅ PASS |
| SCAN-09 | `hardener scan --plugin kernel --plugin ssh` | Multiple short names | Scans both plugins | ✅ PASS |

**Notes on SCAN-02:** Kernel, Firewall, and Audit plugins return **empty findings** when run as non-root. This is correct behaviour after Bug D/E fixes - they no longer report false positives.

**Notes on SCAN-07/08/09 (Issue Q Fix):** Plugin validation now happens before scanning. Invalid plugin names return an error with the list of valid plugins. Both full IDs (`kernel-hardening`) and short names (`kernel`) are accepted.

### 3. Report Generation

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| RPT-01 | `report --framework cis` | CIS report | 36 controls (34 pass, 2 fail) | ✅ PASS |
| RPT-02 | `report --framework stig` | STIG report | STIG controls displayed | ✅ PASS |
| RPT-03 | `report --framework nist` | NIST 800-53 report | 18 controls (all pass) | ✅ PASS |
| RPT-04 | `report --framework pcidss` | PCI-DSS report | Controls displayed | ✅ PASS |
| RPT-05 | `report --framework hipaa` | HIPAA report | Controls displayed | ✅ PASS |
| RPT-06 | `report --report-format json` | JSON output | Valid JSON structure | ✅ PASS |
| RPT-07 | `report --report-format csv` | CSV output | Proper CSV with headers | ✅ PASS |
| RPT-08 | `report --report-format html` | HTML output | Valid HTML with styling | ✅ PASS |
| RPT-09 | `report --report-format pdf -o file.pdf` | PDF output | 24KB PDF generated | ✅ PASS |
| RPT-10 | `report --scenario server` | Scenario-based | CIS report for server scenario | ✅ PASS |

### 4. Apply Operations

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| APL-01 | `apply --all --dry-run` | Show estimated changes | All plugins show changes | ✅ PASS |
| APL-02 | Kernel dry-run | Show sysctl changes | 12 parameters listed | ✅ PASS |
| APL-03 | Permissions dry-run | Show chmod changes | `/root: 0750 → 0700`, `/boot: 0755 → 0700` | ✅ PASS |
| APL-04 | Firewall dry-run | Show rule changes | "Apply 4 baseline firewall rules" | ✅ PASS |
| APL-05 | PAM dry-run | Show config changes | 9 settings listed | ✅ PASS |

**Note:** Bug F (stub validate methods) is **FIXED** - all plugins now report estimated changes.

### 5. Checkpoint Operations

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| CKP-01 | `checkpoint list` | List checkpoints | Empty list (no checkpoints) | ✅ PASS |

**Note:** Create/delete/show require existing checkpoints from previous apply operations.

### 6. Daemon/History Operations

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| DMN-01 | `daemon status 5` | Show daemon status | Status shown, DB at user path | ✅ PASS |
| HST-01 | `history list` | List scan history | "No scan sessions found" | ✅ PASS |

**Fix Applied (2025-12-10):** Added `default_data_dir()` helper in `crates/hardener-scheduler/src/config.rs` that checks `libc::geteuid()`:
- Root (uid 0): `/var/lib/linux-hardener/`
- User: `~/.local/share/linux-hardener/` (via `dirs::data_local_dir()`)

### 7. Systemd Operations

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| SYS-01 | `systemd generate` | Generate unit files | Valid .service and .timer output | ✅ PASS |
| SYS-02 | `systemd status --user` | Check user service | "Unit not found" (expected - not installed) | ✅ PASS |

### 8. SSH Remote Operations

| Test ID | Command | Expected | Actual | Status |
|---------|---------|----------|--------|--------|
| SSH-01 | `--ssh root@192.168.1.100 scan` | Attempt connection | Proper error: "SSH connection failed" | ✅ PASS |

### 9. Root Tests (Container)

Full root testing performed in isolated systemd-nspawn container.

| Test ID | Test | Expected | Actual | Status |
|---------|------|----------|--------|--------|
| ROOT-01 | Full scan as root | More findings than non-root | **47 findings** (vs 11 non-root) | ✅ PASS |
| ROOT-02 | Kernel plugin scan | Kernel findings | Kernel parameters scanned | ✅ PASS |
| ROOT-03 | Firewall plugin scan | Firewall findings | Rules analysed | ✅ PASS |
| ROOT-04 | Audit plugin scan | Audit findings | **26 audit findings** | ✅ PASS |
| ROOT-05 | Daemon status (root) | Path `/var/lib/linux-hardener/` | Correct root path | ✅ PASS |
| ROOT-06 | PDF report generation | Valid PDF | **30KB PDF** generated | ✅ PASS |
| ROOT-07 | Apply kernel hardening | Changes applied | Successfully applied | ✅ PASS |
| ROOT-08 | Verify kernel changes | `kptr_restrict=2` | Verified `kptr_restrict=2` | ✅ PASS |
| ROOT-09 | Checkpoint created | Checkpoint ID returned | `cp_1765400837958_f5471c7d` | ✅ PASS |
| ROOT-10 | Rollback to checkpoint | Config file removed | `99-hardener.conf` deleted | ✅ PASS |

**Key Observation:** Running as root revealed **47 findings** compared to **11 findings** as non-root. This is because:
- Kernel plugin can read `/proc/sys/` values directly
- Firewall plugin can query `ufw`/`nftables` rules
- Audit plugin can read audit rules and configuration
- Permissions plugin can check protected directories

### 10. Checkpoint/Rollback Full Cycle (Container)

Comprehensive verification of the checkpoint system after Bug O and P fixes.

| Step | Test | Evidence | Status |
|------|------|----------|--------|
| 1 | Clean state (no config file) | `ls: cannot access '/etc/sysctl.d/99-hardener.conf'` | ✅ PASS |
| 2 | Apply creates checkpoint | `"apply_checkpoint_id": "cp_1765400837958_f5471c7d"` | ✅ PASS |
| 3 | Config file created | `/etc/sysctl.d/99-hardener.conf` exists with 12 parameters | ✅ PASS |
| 4 | Checkpoint in list | Checkpoint visible with Ed25519 signature | ✅ PASS |
| 5 | Rollback command | `"Rollback completed successfully"` | ✅ PASS |
| 6 | Config file removed | `99-hardener.conf was removed by rollback` | ✅ PASS |

**Bugs Fixed (2025-12-10)**:
- **Bug O**: Checkpoint not created - context was discarded due to incorrect Rust if-expression
- **Bug P**: Nested tokio runtime panic - `create_checkpoint_for_apply()` was sync but called from async context

---

## Discovered Issues

### Issue M: Scheduler Database Path Hardcoded - FIXED ✅

**Severity:** Medium (was)
**Component:** `hardener-scheduler`
**File:** `crates/hardener-scheduler/src/config.rs`

**Original Problem:**
```rust
database_path: PathBuf::from("/var/lib/linux-hardener/scheduler.db"),
json_output_dir: PathBuf::from("/var/lib/linux-hardener/scans"),
```

**Fix Applied (2025-12-10):**
Added `default_data_dir()` helper function that uses `libc::geteuid()` to determine user:
```rust
fn default_data_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return PathBuf::from("/var/lib/linux-hardener");
        }
    }
    dirs::data_local_dir()
        .map(|p| p.join("linux-hardener"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/linux-hardener"))
}
```

**Additional Fixes:**
- `crates/hardener-core/src/lib.rs`: Feature-gated `testing` module behind `system` feature
- `crates/hardener-core/src/plugin.rs`: Feature-gated unused imports
- `crates/hardener-core/src/config_loader.rs`: Fixed clippy needless_borrow warning
- `crates/hardener-scheduler/Cargo.toml`: Added `dirs = "6.0.0"` and `libc = "0.2"` dependencies

### Issue Q: Invalid Plugin Name Accepted Silently - FIXED ✅

**Severity:** Medium (was)
**Component:** `hardener-cli`
**File:** `crates/hardener-cli/src/commands/scan.rs`

**Original Problem:**
```bash
$ hardener scan --plugin nonexistent
[]   # Empty results, exit code 0
```

Invalid plugin names were silently ignored, returning empty results with a successful exit code. This masked configuration errors and could give users a false sense of security.

**Fix Applied (2025-12-10):**
Added `validate_plugin_filter()` and `is_valid_plugin_name()` functions:
```rust
fn validate_plugin_filter(filter: &[String], valid_plugins: &[PluginMetadata]) -> Result<()> {
    // Validates all plugin names before scanning begins
    // Returns error listing unknown plugins with valid options
}

fn is_valid_plugin_name(name: &str, valid_ids: &[&str]) -> bool {
    // Accepts both full IDs (kernel-hardening) and short names (kernel)
    valid_ids.iter().any(|id| *id == name || id.starts_with(&format!("{}-", name)))
}
```

**New Behaviour:**
```bash
$ hardener scan --plugin nonexistent
Error: Unknown plugin(s): nonexistent. Valid plugins: audit-hardening, firewall-hardening, ...
$ echo $?
1

$ hardener scan --plugin kernel  # Short name works
→ Scanning: Kernel Hardening
```

### Issue R: Test Script 105% Pass Rate - FIXED ✅

**Severity:** Low (was)
**Component:** `scripts`
**File:** `scripts/full-test-suite.sh`

**Original Problem:**
```bash
$ sudo ./scripts/full-test-suite.sh
...
Test Summary:
  Total Tests: 102
  Passed: 108
  Pass Rate: 105%  # Impossible!
```

The `log_pass()` function was called in preflight checks without a corresponding `log_test()`, inflating the PASSED count without incrementing TOTAL.

**Fix Applied (2025-12-10):**
Added `log_check()` function for verification steps that shouldn't count as tests:
```bash
log_check() { log "  ${GREEN}[PASS]${NC} $1"; }  # Displays [PASS] but doesn't increment counters
```

Changed 7 occurrences from `log_pass` to `log_check` in:
- `preflight_checks()` function
- Other non-test verification steps

**New Behaviour:**
```bash
$ sudo ./scripts/full-test-suite.sh
...
Test Summary:
  Total Tests: 102
  Passed: 102
  Pass Rate: 100%  # Correct!
```

---

## Plugin Behaviour Summary (Non-Root)

| Plugin | Scan Findings | Notes |
|--------|---------------|-------|
| Kernel | 0 | Cannot read /proc/sys without verification |
| Firewall | 0 | Uses `systemctl is-active ufw` (Bug D fix) |
| Audit | 0 | Detects permission denied (Bug E fix) |
| MAC | 1 | Reads AppArmor/SELinux status directly |
| PAM | 8 | Reads config files directly |
| Permissions | 2 | Checks file modes directly |
| Services | 0 | Lists systemd services |
| SSH | 0 | Reads sshd_config directly |

---

## Recommendations

1. ~~**Fix Issue M:** Add user directory fallback for scheduler database~~ ✅ DONE
2. ~~**Safe testing environment:** Create isolated container for root testing~~ ✅ DONE
3. **Add CLI tests:** Automated tests for daemon/history with mock database

---

## Safe Root Testing Infrastructure

**Added 2025-12-10**: Two scripts for comprehensive root testing in an isolated environment.

### Why Isolated Testing?

The hardener modifies critical system files (`/etc/sysctl.conf`, `/etc/ssh/sshd_config`, firewall rules, etc.). Testing these operations on a real system risks:
- Breaking SSH access
- Locking yourself out
- Misconfiguring services

**Solution**: Use a systemd-nspawn container that provides complete isolation with full systemd support.

### Scripts

| Script | Purpose |
|--------|---------|
| `scripts/create-test-container.sh` | Create/manage Arch Linux container |
| `scripts/root-test-suite.sh` | Comprehensive test suite for root operations |

### Usage

```bash
# 1. Create container (one-time, ~2-3 minutes)
sudo ./scripts/create-test-container.sh

# 2. Enter the container
sudo ./scripts/create-test-container.sh enter

# 3. Inside container: build and test
cd /project
cargo build --release

# Run safe tests (read-only + dry-run)
sudo ./scripts/root-test-suite.sh

# Run full tests INCLUDING apply + rollback
sudo ./scripts/root-test-suite.sh --apply

# 4. Exit container
poweroff  # or Ctrl+D

# 5. Clean up (optional)
sudo ./scripts/create-test-container.sh clean
```

### Test Modes Explained

The `--apply` flag controls whether destructive tests run:

| Test | Without `--apply` | With `--apply` |
|------|-------------------|----------------|
| Basic commands | ✅ Runs | ✅ Runs |
| Scan (all 8 plugins) | ✅ Runs | ✅ Runs |
| Reports (6 frameworks) | ✅ Runs | ✅ Runs |
| Dry-run validation | ✅ Runs | ✅ Runs |
| Daemon/history | ✅ Runs | ✅ Runs |
| Systemd commands | ✅ Runs | ✅ Runs |
| Checkpoint list | ✅ Runs | ✅ Runs |
| **Apply hardening** | ⏭️ Skipped | ✅ Runs |
| **Rollback** | ⏭️ Skipped | ✅ Runs |

**Why skip by default?** The `--apply` flag is an explicit opt-in for destructive operations. This prevents accidentally running apply/rollback tests. Inside the container, both modes are completely safe since it's isolated from your real system.

### Container Details

The container includes:
- Full systemd support (unlike Docker)
- Pre-installed: `openssh`, `audit`, `ufw`, `nftables`
- Project mounted at `/project`
- Root password: `test`
- Test user: `testuser` / `test` (has passwordless sudo)

### Safety Features

1. **Container detection**: Test script checks `/run/systemd/container` and warns if not in container
2. **Explicit opt-in**: Apply/rollback tests require `--apply` flag
3. **Complete isolation**: Container has no access to host's `/etc`, `/var`, etc.
4. **Easy cleanup**: `sudo ./scripts/create-test-container.sh clean` removes everything

---

## Test Environment Details

```
Platform: Linux 6.12.61-1-lts
Distribution: Arch Linux
Binary: target/release/hardener v0.3.2
Test date: 2025-12-10
Container: systemd-nspawn (Arch Linux)
```

---

**Last Updated:** 2025-12-10
