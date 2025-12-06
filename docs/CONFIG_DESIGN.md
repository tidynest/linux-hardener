# Configuration System Security Design

**Author:** Eric Jingryd
**Status:** Design Document
**Version:** Draft 1.0
**Date:** 2025-12-01

---

## Executive Summary

This document details the security-conscious design for Linux System Hardener's configuration file system. The design prioritises **transparency over convenience** and ensures that configuration cannot silently weaken security posture.

### Core Principle

> **Configuration annotates findings; it never hides them.**

---

## Problem Statement

When users can configure scan baselines, they could weaken security checks - either intentionally or accidentally. A naive implementation where config simply disables checks creates dangerous failure modes:

- Silent security gaps (issues exist but aren't reported)
- No audit trail (who approved exceptions? when? why?)
- Social engineering vector ("add this to fix those warnings")
- Inherited misconfiguration (new admin doesn't know what's being ignored)

---

## Design Decision: Finding + Policy Annotation

### What This Means

1. **Scan ALWAYS reports objective security state** - findings are never hidden
2. **Config adds policy annotations** - marks findings as "acknowledged" with metadata
3. **Clear separation** - security facts vs. policy decisions are distinct concepts
4. **Explicit acknowledgment required** - must set `allowed: true` with reason

### What Config CANNOT Do

- Hide or suppress findings
- Remove baseline security checks
- Reduce finding severity silently
- Filter findings from output

### What Config CAN Do

- Mark specific findings as "policy exception" with audit metadata
- Add stricter checks beyond baseline
- Add custom checks for organisation-specific requirements
- Configure which plugins are enabled/disabled
- Set scan output preferences

---

## Scan Output Modes

Three distinct modes serve different use cases:

### 1. Default Mode (`hardener scan`)

Shows all findings with policy annotations. Best for day-to-day operations.

```
[CRITICAL] ssh-passwordauthentication
  SSH PasswordAuthentication = yes
  Secure baseline: no
  Current value: yes

  📋 POLICY EXCEPTION ACTIVE
     Reason: Legacy LDAP integration until Q2 2025 migration
     Approved: security-team@company.com (2024-11-01)
     Ticket: SEC-1234

[CRITICAL] kernel-ptrace
  kernel.yama.ptrace_scope = 0
  Secure baseline: 2
  ⚠️  NO POLICY EXCEPTION - requires remediation
```

### 2. Audit Mode (`hardener scan --audit`)

Ignores all config. Pure objective security assessment against secure baselines. Use for:
- Third-party security audits
- Penetration test preparation
- Understanding true security posture
- Comparing against industry standards

### 3. Compliance Mode (`hardener scan --compliance`)

Only shows findings that violate YOUR policy (config). Findings with valid policy exceptions are not shown. Use for:
- CI/CD pipelines (fail on policy violations)
- Daily compliance monitoring
- Verifying policy is being followed

---

## Configuration Schema

### Basic Structure

```toml
# ~/.config/linux-hardener/config.toml
# or /etc/linux-hardener/config.toml

[global]
# Plugins to enable (empty = all)
enabled_plugins = []
# Plugins to explicitly disable
disabled_plugins = []

[ssh]
enabled = true

# Simple directive configuration (uses secure defaults)
[ssh.directives]
PermitRootLogin = "no"
MaxAuthTries = "3"
```

### Policy Exception Structure

When you need to allow a value that deviates from secure baseline:

```toml
[ssh.exceptions.PasswordAuthentication]
value = "yes"                    # The value you're allowing
allowed = true                   # REQUIRED: explicit acknowledgment
reason = "Legacy LDAP integration requires password auth until Q2 2025"  # REQUIRED
approved_by = "security-team@company.com"  # RECOMMENDED
approved_date = "2024-11-01"     # RECOMMENDED
ticket = "SEC-1234"              # OPTIONAL: link to approval ticket
expires = "2025-06-30"           # OPTIONAL: auto-expire exception
```

### Required vs Optional Fields for Exceptions

| Field | Required | Purpose |
|-------|----------|---------|
| `value` | Yes | The non-baseline value being allowed |
| `allowed` | Yes | Explicit acknowledgment (must be `true`) |
| `reason` | Yes | Human-readable justification |
| `approved_by` | Recommended | Accountability - who approved |
| `approved_date` | Recommended | When was this approved |
| `ticket` | Optional | Link to formal approval process |
| `expires` | Optional | Auto-expire exception after date |

### Exception Expiration

If `expires` is set and the date has passed:
- Finding is shown WITHOUT policy exception annotation
- Warning added: "Policy exception expired on {date}"
- Forces periodic review of exceptions

---

## User Scenarios

### Enterprise Security Team

**Situation:** Organisation-wide policy with legitimate exceptions for legacy systems.

**Usage:**
```bash
# Daily compliance check (CI/CD)
hardener scan --compliance --format json

# Quarterly security audit
hardener scan --audit --format html > security-audit-q4.html
```

**Config:** Centralised in `/etc/linux-hardener/config.toml` deployed via Ansible/Puppet.

---

### Compliance Officer

**Situation:** Must demonstrate compliance with CIS/STIG/PCI-DSS.

**Usage:**
```bash
# Generate compliance report
hardener report --framework cis --format pdf

# Check if policy exceptions are documented
hardener scan --format json | jq '.findings[] | select(.has_exception)'
```

**Benefit:** All exceptions have audit trail with approval metadata.

---

### Solo Sysadmin / Home User

**Situation:** Wants simple "make it secure" without complexity.

**Usage:**
```bash
# No config file needed - uses secure defaults
hardener scan
hardener apply --all
```

**Benefit:** Works out-of-box. Config only needed for exceptions.

---

### MSP / Consultant

**Situation:** Manages multiple client systems with different requirements.

**Usage:**
```bash
# Client A - strict policy
hardener scan --config /etc/hardener/client-a.toml

# Client B - has legacy exceptions
hardener scan --config /etc/hardener/client-b.toml

# Pure audit for new client assessment
hardener scan --audit
```

**Benefit:** `--audit` mode ensures objective assessment regardless of any config.

---

### CI/CD Pipeline

**Situation:** Automated security gate in deployment pipeline.

**Usage:**
```bash
# Fail pipeline if policy is violated (exit code non-zero)
hardener scan --compliance --exit-code

# Don't fail on acknowledged exceptions, only unacknowledged issues
```

**Benefit:** Won't fail on documented exceptions, will fail on new/unacknowledged issues.

---

## Security Guarantees

### 1. Cannot Hide Issues

Every security finding is ALWAYS reported in default and audit modes. Config only adds annotations.

### 2. Audit Trail Built-In

Every policy exception includes:
- What was allowed
- Why it was allowed
- Who approved it
- When it was approved
- Optional ticket reference

### 3. Periodic Review Enforced

- Optional `expires` field forces re-evaluation
- Summary always shows count of active exceptions
- Prompt: "X findings have active policy exceptions - review periodically"

### 4. Pure Audit Mode

`--audit` flag completely ignores config, providing objective security assessment.

### 5. Explicit Acknowledgment

Cannot accidentally allow insecure settings:
- Must explicitly set `allowed = true`
- Must provide `reason`
- Simple config without exceptions uses secure defaults

---

## Implementation Notes

### Finding Structure Enhancement

Add to `Finding` struct:

```rust
pub struct Finding {
    // ... existing fields ...

    /// Policy exception if configured
    pub finding_policy_exception: Option<PolicyException>,
}

pub struct PolicyException {
    pub allowed_value: String,
    pub reason: String,
    pub approved_by: Option<String>,
    pub approved_date: Option<String>,
    pub ticket: Option<String>,
    pub expires: Option<String>,
    pub is_expired: bool,
}
```

### Scan Logic

```rust
fn scan_with_config(&self, ctx: &Context, config: &HardenerConfig) -> Result<ScanResult> {
    // 1. Always check against SECURE BASELINE (hardcoded)
    let baseline_value = get_secure_baseline(check_id);
    let current_value = get_current_value(check_id);

    // 2. Create finding if current != baseline
    if current_value != baseline_value {
        let mut finding = Finding::new(/* ... */);

        // 3. Check if policy exception exists
        if let Some(exception) = config.get_exception(check_id) {
            if exception.allowed && current_value == exception.value {
                finding.finding_policy_exception = Some(PolicyException {
                    allowed_value: exception.value,
                    reason: exception.reason,
                    approved_by: exception.approved_by,
                    // ...
                    is_expired: is_exception_expired(&exception),
                });
            }
        }

        findings.push(finding);
    }
}
```

### Output Formatting

```rust
fn format_finding(finding: &Finding, mode: ScanMode) -> String {
    match mode {
        ScanMode::Audit => {
            // Ignore policy exceptions, show raw finding
            format_raw_finding(finding)
        }
        ScanMode::Compliance => {
            // Only show if NO valid exception
            if finding.has_valid_exception() {
                return String::new(); // Skip
            }
            format_raw_finding(finding)
        }
        ScanMode::Default => {
            // Show finding with exception annotation if present
            let mut output = format_raw_finding(finding);
            if let Some(exception) = &finding.finding_policy_exception {
                output += &format_exception_annotation(exception);
            }
            output
        }
    }
}
```

---

## Config File Locations & Precedence

### Load Order (later overrides earlier)

1. **Built-in defaults** - Secure baseline (hardcoded)
2. **System config** - `/etc/linux-hardener/config.toml` (optional)
3. **User config** - `~/.config/linux-hardener/config.toml` (optional)
4. **CLI config** - `--config path/to/file.toml` (optional)
5. **Environment variables** - `HARDENER_*` prefix

### Security Considerations

- System config (`/etc/`) requires root to modify - appropriate for org-wide policy
- User config (`~/.config/`) per-user - only affects that user's scans
- CLI config - explicit choice, could come from anywhere
- `--audit` mode ignores ALL config sources

---

## Example Configurations

### Minimal (No Exceptions)

```toml
# Uses all secure defaults, just configures which plugins to run
[global]
disabled_plugins = ["mac"]  # Skip SELinux/AppArmor on this server
```

### With Policy Exception

```toml
[global]
enabled_plugins = []

[ssh]
enabled = true

[ssh.exceptions.PasswordAuthentication]
value = "yes"
allowed = true
reason = "LDAP integration requires password auth - migration planned Q2 2025"
approved_by = "ciso@company.com"
approved_date = "2024-11-01"
ticket = "SEC-1234"
expires = "2025-06-30"

[ssh.exceptions.X11Forwarding]
value = "yes"
allowed = true
reason = "Development servers require X11 for GUI debugging tools"
approved_by = "dev-lead@company.com"
approved_date = "2024-10-15"
```

### Stricter Than Baseline

```toml
[ssh.directives]
MaxAuthTries = "1"  # Stricter than default of 3
ClientAliveInterval = "60"  # Stricter than default of 300

[kernel.params]
"kernel.yama.ptrace_scope" = "3"  # Stricter than default of 2
```

### Adding Custom Checks

```toml
[ssh.custom_directives]
AllowUsers = "admin,deploy"  # Organisation-specific requirement
Banner = "/etc/ssh/banner.txt"

[kernel.custom_params]
"net.ipv6.conf.all.disable_ipv6" = "1"  # Organisation disables IPv6
```

---

## CLI Interface

```bash
# Default scan - all findings with policy annotations
hardener scan

# Audit mode - ignore config, pure security assessment
hardener scan --audit

# Compliance mode - only policy violations (no valid exception)
hardener scan --compliance

# Compliance with exit code (for CI/CD)
hardener scan --compliance --exit-code

# Use specific config file
hardener scan --config /path/to/config.toml

# Combine: audit mode ignores --config
hardener scan --audit --config /path/to/config.toml  # config is IGNORED
```

### Exit Codes (with --exit-code flag)

| Code | Meaning |
|------|---------|
| 0 | No findings (audit) or no policy violations (compliance) |
| 1 | Findings exist (audit) or policy violations exist (compliance) |
| 2 | Error during scan |

---

## Summary

This design ensures:

1. **Security cannot be silently weakened** - findings are always visible
2. **Full audit trail** - every exception is documented with who/when/why
3. **Flexibility for real-world needs** - legitimate exceptions are supported
4. **Clear separation of concerns** - security facts vs. policy decisions
5. **Multiple modes for different use cases** - audit, compliance, default
6. **Safe defaults** - works securely out-of-box without config

The key insight: **config is for policy management, not security filtering**.

**Last Updated**: 2025-12-03
