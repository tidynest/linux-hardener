# BUG D & BUG E Analysis: Permission-Denied False Negatives

**Date**: 2026-02-25
**Status**: Both bugs ALREADY FIXED in production code. This document analyses the fix patterns and cross-plugin audit results.

---

## Executive Summary

Both BUG D (firewall) and BUG E (audit) followed the same anti-pattern: a command fails due to insufficient permissions, and the plugin misinterprets the failure as "feature not present / not configured", producing false-negative findings.

Both have been fixed. All 8 plugins have been reviewed for the same class of bug. No further fixes needed.

---

## BUG D: Firewall: Permission Denied Reports "Disabled"

### Location
- **Test**: `crates/hardener-plugins/tests/firewall_mock_tests.rs:142-189`
- **Plugin**: `crates/hardener-plugins/src/firewall/ufw.rs:146-181`
- **Scan logic**: `crates/hardener-plugins/src/firewall/mod.rs:266-302`

### Root Cause
`ufw status` requires root. When run without root, exit code 1 + stderr "You need to be root". The old code treated any failure of `ufw status` as "firewall disabled".

### Fix Strategy: Two-level fallback
1. **Primary**: `systemctl is-active ufw` (doesn't require root)
2. **Secondary**: `ufw status` (requires root, used as fallback)
3. **Error path**: If both fail, propagate "Unable to determine UFW status (permission denied)" instead of "Firewall disabled"

The scan method in `firewall/mod.rs:266-302` checks the error message: only creates a "disabled" finding if the error does NOT contain "permission denied".

### Regression Test
```rust
#[tokio::test]
async fn test_firewall_scan_permission_denied_should_not_report_disabled() {
    // Asserts: no "disabled" finding when permission is denied
}
```

---

## BUG E: Audit: Permission Denied Reports All Rules Missing

### Location
- **Test**: `crates/hardener-plugins/tests/audit_mock_tests.rs:423-473`
- **Plugin**: `crates/hardener-plugins/src/audit/mod.rs:267-301, 499-545`

### Root Cause
`auditctl -l` requires root. When run without root, exit code 1 + stderr "You must be root". The old code created 25 "rule not configured" findings for every rule it couldn't verify.

### Fix Strategy: Enum-based permission detection
```rust
enum AuditRulesResult {
    Rules(Vec<String>),      // Successfully read (may be empty)
    PermissionDenied,         // Can't determine: don't create findings
}
```

The `read_current_audit_rules()` function checks for "root" or "permission" in stderr. The scan method only creates findings in the `Rules(...)` branch. In the `PermissionDenied` branch, it logs a warning and creates zero findings.

### Regression Test
```rust
#[tokio::test]
async fn test_audit_scan_permission_denied_should_not_report_missing_rules() {
    // Asserts: no "rule not configured" findings when permission is denied
}
```

---

## Cross-Plugin Audit Results

| Plugin | Vulnerable? | Why Safe |
|--------|-------------|----------|
| **Firewall** | Fixed (BUG D) | Two-level fallback + permission detection |
| **Audit** | Fixed (BUG E) | Enum-based permission detection |
| **Kernel** | Safe | File-based reads (`/proc/sys/`), not command-based |
| **SSH** | Safe | File-based reads (`/etc/ssh/sshd_config`) |
| **PAM** | Safe | File-based reads (`/etc/security/pwquality.conf`) |
| **Services** | Safe | `systemctl` checks use `.unwrap_or(false)`: missing = no finding |
| **Permissions** | Safe | `chmod` failures tracked as `change_success: false` |
| **MAC** | Safe | Policy-based, system-level error handling |

### Pattern: Why File-Based Plugins Are Immune
Kernel, SSH, PAM, and Permissions plugins read files directly. If a file can't be read, that's a genuine permission error that warrants a finding (unlike command-exit-code inference where failure != absence).

### Pattern: Why Services Plugin Is Safe
Services uses a safe default: if a service isn't found, no finding is created. This avoids the "absence vs. inability to verify" problem entirely.

---

## Design Rule for Future Plugins

Any new plugin that infers state from command exit codes MUST distinguish:

```
Command fails → Is it "permission denied"?
    Yes → Log warning, skip findings for this check
    No  → Is it "feature not present"?
        Yes → Create finding
        No  → Log error, skip findings (conservative)
```

Preferred implementation patterns:
1. **Fallback command** (e.g. `systemctl is-active` before `ufw status`)
2. **Return enum** (e.g. `AuditRulesResult::PermissionDenied`)
3. **Log and skip** (e.g. `warn!("Cannot verify: {e}")`)

Never: treat command failure as confirmed absence.
