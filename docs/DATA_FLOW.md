# Linux System Hardener - Data Flow Documentation

**Last Updated:** 2025-11-26
**Version:** 0.1.0

This document describes the data flow for all major operations in the system.

---

## Table of Contents

1. [Scan Command Flow](#1-scan-command-flow)
2. [Apply Command Flow](#2-apply-command-flow)
3. [Checkpoint Creation Flow](#3-checkpoint-creation-flow)
4. [Rollback Flow](#4-rollback-flow)
5. [Compliance Report Flow](#5-compliance-report-flow)
6. [GUI/Tauri Flow](#6-guitauri-flow)

---

## 1. Scan Command Flow

**Command:** `hardener scan --plugin ssh --severity medium --config /path/to/config.toml`

```
┌──────────────────┐
│   CLI Input      │
│   (arguments)    │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  hardener-cli/src/main.rs                                    │
│  ├─ Parse CLI args with Clap                                 │
│  └─ Route to commands/scan.rs                                │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  hardener-cli/src/commands/scan.rs::run()                    │
│  ├─ Determine scan mode (Default/Audit/Compliance)           │
│  ├─ Load config via ConfigLoader (unless --audit)            │
│  │   └─ Merge: defaults → /etc/ → ~/.config/ → CLI → env     │
│  ├─ Create PluginRegistry                                    │
│  │   └─ Register all 8 plugins                               │
│  ├─ Create Context                                           │
│  │   └─ SystemInfo::detect() reads:                          │
│  │       • /etc/os-release (distro)                          │
│  │       • hostname                                          │
│  │       • kernel version                                    │
│  └─ Filter plugins by --plugin arg                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ For each selected plugin
┌──────────────────────────────────────────────────────────────┐
│  Plugin.scan(&ctx)                                           │
│  ├─ Read system state (READ-ONLY)                            │
│  │   • SSH: /etc/ssh/sshd_config                             │
│  │   • Kernel: /proc/sys/*                                   │
│  │   • Firewall: firewall-cmd/nft/ufw status                 │
│  │   • PAM: /etc/pam.d/*, /etc/security/*                    │
│  │   • Services: systemctl list-unit-files                   │
│  │   • Permissions: stat on critical paths                   │
│  │   • Audit: /etc/audit/rules.d/*                           │
│  │   • MAC: getenforce/aa-status                             │
│  ├─ Compare against secure baseline                          │
│  └─ Generate Finding for each deviation                      │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanResult                                                  │
│  {                                                           │
│    scan_plugin_id: "ssh-hardening",                          │
│    scan_success: true,                                       │
│    scan_findings: [Finding, Finding, ...],                   │
│    scan_duration_us: 1234,                                   │
│    scan_error: None                                          │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Filter by --severity                                        │
│  ├─ Critical ≥ High ≥ Medium ≥ Low ≥ Info                    │
│  └─ Only show findings at or above threshold                 │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Format Output                                               │
│  ├─ --format text: Human-readable table                      │
│  └─ --format json: JSON array of findings                    │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   stdout/file    │
└──────────────────┘
```

### Key Data Types

```rust
struct Finding {
    finding_id: String,           // "ssh-permitrootlogin"
    finding_title: String,        // "Insecure SSH setting: PermitRootLogin"
    finding_category: FindingCategory,
    finding_severity: Severity,
    finding_current_value: String,
    finding_recommended_value: String,
    finding_description: String,
    finding_explanation: String,
    finding_impact: String,
    finding_remediation_steps: Vec<String>,
    finding_compliance: Vec<ComplianceMapping>,
    finding_policy_exception: Option<FindingPolicyException>,  // Policy annotation
}
```

---

## 2. Apply Command Flow

**Command:** `sudo hardener apply --plugin kernel --plugin pam`

```
┌──────────────────┐
│   CLI Input      │
│   (must be root) │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  hardener-cli/src/commands/apply.rs::run()                   │
│  ├─ Verify root privileges (geteuid() == 0)                  │
│  ├─ Create PluginRegistry                                    │
│  ├─ Initialize CheckpointManager                             │
│  │   └─ Opens/creates SQLite DB at:                          │
│  │      ~/.local/share/linux-hardener/checkpoints.db         │
│  └─ Create Context with checkpoint manager                   │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ For each selected plugin
┌──────────────────────────────────────────────────────────────┐
│  Pre-Apply: Create Checkpoint                                │
│  ├─ Identify affected files for this plugin                  │
│  │   • SSH: ["/etc/ssh/sshd_config"]                         │
│  │   • Kernel: ["/etc/sysctl.conf", "/etc/sysctl.d/"]        │
│  │   • Firewall: ["/etc/nftables.conf", "/etc/firewalld/"]   │
│  ├─ CheckpointManager::create_checkpoint()                   │
│  │   ├─ Generate checkpoint ID                               │
│  │   ├─ For each file:                                       │
│  │   │   ├─ Read content                                     │
│  │   │   ├─ Get permissions (stat)                           │
│  │   │   ├─ Get owner UID/GID                                │
│  │   │   └─ Create FileState record                          │
│  │   ├─ Sign checkpoint with Ed25519                         │
│  │   └─ Store in SQLite                                      │
│  └─ Return checkpoint_id                                     │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Plugin.apply(&mut ctx, &config)                             │
│  ├─ Make system changes:                                     │
│  │   • SSH: Write to sshd_config, restart sshd               │
│  │   • Kernel: Write to /proc/sys/*, update sysctl.conf      │
│  │   • Firewall: Apply rules via backend                     │
│  │   • PAM: Update /etc/pam.d/* files                        │
│  │   • Services: systemctl disable/mask                      │
│  │   • Permissions: chmod, chown                             │
│  │   • Audit: Write audit rules, restart auditd              │
│  │   • MAC: setenforce, aa-enforce                           │
│  ├─ Log each change to audit trail                           │
│  └─ Return ApplyResult with changes list                     │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ApplyResult                                                 │
│  {                                                           │
│    apply_plugin_id: "kernel-hardening",                      │
│    apply_success: true,                                      │
│    apply_changes: [                                          │
│      Change { description: "Set kernel.randomize_va_space=2",│
│               change_type: KernelParameter,                  │
│               success: true }                                │
│    ],                                                        │
│    apply_checkpoint_id: Some("cp_1700000000_abc123"),        │
│    apply_error: None                                         │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Audit Log Entry                                             │
│  {                                                           │
│    timestamp: "2024-11-26T12:00:00Z",                        │
│    action_type: Apply,                                       │
│    user: "root",                                             │
│    target: "kernel-hardening",                               │
│    result: Success,                                          │
│    details: { "changes": "12 parameters applied" },          │
│    hash: SHA256(previous_entry + this_entry)                 │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   Output to user │
└──────────────────┘
```

---

## 3. Checkpoint Creation Flow

**Command:** `sudo hardener checkpoint create --name "before-upgrade"`

```
┌──────────────────┐
│   CLI Input      │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  commands/checkpoint.rs::create()                            │
│  └─ CheckpointManager::create_checkpoint(name, paths)        │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Generate Checkpoint ID                                      │
│  format: "cp_{timestamp}_{random_suffix}"                    │
│  example: "cp_1700000000000_a1b2c3d4"                        │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ For each file path
┌──────────────────────────────────────────────────────────────┐
│  Capture File State                                          │
│  ├─ Read file content (or None if not exists)                │
│  ├─ stat() for metadata:                                     │
│  │   • st_mode (permissions)                                 │
│  │   • st_uid (owner)                                        │
│  │   • st_gid (group)                                        │
│  └─ Create FileState struct                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  FileState                                                   │
│  {                                                           │
│    file_path: "/etc/ssh/sshd_config",                        │
│    file_content: Some([bytes...]),                           │
│    file_permissions: 0o600,                                  │
│    file_owner_uid: 0,                                        │
│    file_owner_gid: 0                                         │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Sign Checkpoint                                             │
│  ├─ Serialize checkpoint metadata                            │
│  ├─ Load Ed25519 private key from:                           │
│  │   ~/.local/share/linux-hardener/signing.key               │
│  └─ Sign with ed25519_dalek                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Store in SQLite                                             │
│  ├─ INSERT INTO checkpoints (id, name, timestamp, sig)       │
│  └─ INSERT INTO file_states (checkpoint_id, path, content..) │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Audit Log Entry                                             │
│  {                                                           │
│    action_type: CheckpointCreate,                            │
│    target: "cp_1700000000000_a1b2c3d4",                      │
│    details: { "files_captured": 5, "name": "before-upgrade" }│
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  Return ID       │
└──────────────────┘
```

---

## 4. Rollback Flow

**Command:** `sudo hardener rollback cp_1700000000000_a1b2c3d4`

```
┌──────────────────┐
│   CLI Input      │
│   (checkpoint ID)│
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  commands/checkpoint.rs::rollback()                          │
│  └─ CheckpointManager::rollback(checkpoint_id)               │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Load Checkpoint from SQLite                                 │
│  ├─ SELECT * FROM checkpoints WHERE id = ?                   │
│  └─ SELECT * FROM file_states WHERE checkpoint_id = ?        │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Verify Signature                                            │
│  ├─ Load Ed25519 public key                                  │
│  ├─ Verify signature against checkpoint data                 │
│  └─ Fail if signature invalid (tampered)                     │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ For each FileState
┌──────────────────────────────────────────────────────────────┐
│  Restore File                                                │
│  ├─ If file_content is None:                                 │
│  │   └─ Delete file (it didn't exist at checkpoint time)     │
│  ├─ Else:                                                    │
│  │   ├─ Write file_content to file_path                      │
│  │   ├─ chmod(file_permissions)                              │
│  │   └─ chown(file_owner_uid, file_owner_gid)                │
│  └─ Log restoration                                          │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Restart Affected Services                                   │
│  ├─ SSH: systemctl restart sshd                              │
│  ├─ Kernel: sysctl --system                                  │
│  ├─ Firewall: firewall-cmd --reload / systemctl restart nft  │
│  ├─ Audit: systemctl restart auditd                          │
│  └─ Others as needed                                         │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Audit Log Entry                                             │
│  {                                                           │
│    action_type: Rollback,                                    │
│    target: "cp_1700000000000_a1b2c3d4",                      │
│    result: Success,                                          │
│    details: { "files_restored": 5 }                          │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   Success msg    │
└──────────────────┘
```

---

## 5. Compliance Report Flow

**Command:** `hardener report --framework cis --report-format html --output report.html`

```
┌──────────────────┐
│   CLI Input      │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  commands/report.rs::run()                                   │
│  ├─ Parse framework (CIS, NIST, STIG, etc.)                  │
│  └─ Parse output format (text, json, csv, html, pdf)         │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Run Full Scan (all plugins)                                 │
│  └─ Collect all Finding results                              │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ReportGenerator::generate(findings, framework)              │
│  ├─ Load framework control definitions                       │
│  │   • CIS: 35+ controls                                     │
│  │   • NIST: 20+ controls                                    │
│  │   • STIG: 20+ controls                                    │
│  │   • etc.                                                  │
│  └─ For each control:                                        │
│      ├─ Find related findings via ComplianceMapping          │
│      │   (finding.finding_compliance contains mappings)      │
│      ├─ Determine status:                                    │
│      │   • Pass: No related findings                         │
│      │   • Fail: Has related findings                        │
│      │   • ManualReview: Needs human verification            │
│      │   • NotApplicable: Not relevant to this system        │
│      └─ Create ControlResult                                 │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Calculate Summary                                           │
│  {                                                           │
│    total_controls: 35,                                       │
│    passing: 28,                                              │
│    failing: 5,                                               │
│    manual_review: 2,                                         │
│    not_applicable: 0,                                        │
│    score_percentage: 80.0                                    │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ComplianceReport                                            │
│  {                                                           │
│    framework: CIS,                                           │
│    generated_at: "2024-11-26T12:00:00Z",                     │
│    controls: [ControlResult, ...],                           │
│    summary: ComplianceSummary                                │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Format Output                                               │
│  ├─ TextFormatter: Plain text report                         │
│  ├─ JsonFormatter: JSON structure                            │
│  ├─ CsvFormatter: CSV for spreadsheets                       │
│  ├─ HtmlFormatter: Interactive HTML with styling             │
│  └─ PdfFormatter: Professional PDF with embedded fonts       │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  Write to file   │
│  or stdout       │
└──────────────────┘
```

---

## 6. GUI/Tauri Flow

**User Action:** Click "Run Scan" in desktop app

```
┌──────────────────┐
│   User clicks    │
│   "Run Scan"     │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Leptos Frontend (hardener-ui)                               │
│  ├─ scanner_page.rs handles button click                     │
│  ├─ Calls Tauri invoke("run_scan")                           │
│  └─ Updates loading state                                    │
└────────┬─────────────────────────────────────────────────────┘
         │ IPC via Tauri
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Tauri Backend (src-tauri/src/commands.rs)                   │
│  ├─ #[tauri::command] fn run_scan()                          │
│  ├─ Create PluginRegistry (same as CLI)                      │
│  ├─ Create Context                                           │
│  ├─ Run all plugins.scan()                                   │
│  └─ Return Vec<ScanResult> as JSON                           │
└────────┬─────────────────────────────────────────────────────┘
         │ JSON response
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Leptos Frontend                                             │
│  ├─ Receive ScanResult array                                 │
│  ├─ Update AppState with findings                            │
│  ├─ Render findings_grid component                           │
│  └─ Sort/filter by severity                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   UI displays    │
│   findings       │
└──────────────────┘
```

### Tauri Commands Available

| Command | Parameters | Returns |
|---------|------------|---------|
| `run_scan` | `plugin: Option<String>` | `Vec<ScanResult>` |
| `run_apply` | `plugins: Vec<String>` | `Vec<ApplyResult>` |
| `run_rollback` | `checkpoint_id: String` | `Result<(), String>` |
| `get_checkpoints` | None | `Vec<Checkpoint>` |
| `generate_compliance_report` | `frameworks: Vec<String>` | `Vec<ComplianceReport>` |

---

## Hash Chain Integrity

The audit log uses a hash chain for tamper detection:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Entry #1      │     │   Entry #2      │     │   Entry #3      │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ timestamp       │     │ timestamp       │     │ timestamp       │
│ action: Scan    │     │ action: Apply   │     │ action: Rollback│
│ ...             │     │ ...             │     │ ...             │
│ hash: SHA256(   │────▶│ hash: SHA256(   │────▶│ hash: SHA256(   │
│   "genesis"     │     │   entry1.hash + │     │   entry2.hash + │
│ )               │     │   entry2.data   │     │   entry3.data   │
│                 │     │ )               │     │ )               │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

If any entry is modified, the hash chain breaks and tampering is detected.

---

## File Locations Summary

| Data | Location | Format |
|------|----------|--------|
| Checkpoint DB | `~/.local/share/linux-hardener/checkpoints.db` | SQLite |
| Signing Keys | `~/.local/share/linux-hardener/signing.key` | Ed25519 |
| User Config | `~/.config/linux-hardener/config.toml` | TOML |
| System Config | `/etc/linux-hardener/config.toml` | TOML |
| SSH Config | `/etc/ssh/sshd_config` | OpenSSH |
| Kernel Params | `/proc/sys/*` | Virtual FS |
| PAM Config | `/etc/pam.d/*` | PAM |
| Audit Rules | `/etc/audit/rules.d/*` | auditd |
| Firewall | Varies by backend | Backend-specific |
