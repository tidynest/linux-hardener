# Linux System Hardener - Data Flow Documentation

**Last Updated:** 2025-12-06
**Version:** 0.3.3

This document describes the data flow for all major operations in the system.

---

## Table of Contents

1. [Scan Command Flow](#1-scan-command-flow)
2. [Apply Command Flow](#2-apply-command-flow)
3. [Checkpoint Creation Flow](#3-checkpoint-creation-flow)
4. [Rollback Flow](#4-rollback-flow)
5. [Compliance Report Flow](#5-compliance-report-flow)
6. [GUI/Tauri Flow](#6-guitauri-flow)
7. [SSH Remote Scanning Flow](#7-ssh-remote-scanning-flow)
8. [Scheduled Scanning Flow](#8-scheduled-scanning-flow)
9. [Systemd Unit Generation Flow](#9-systemd-unit-generation-flow)

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
│  ├─ Validate plugin filter (if --plugin specified)           │
│  │   └─ Error if invalid plugin name, accepts short names    │
│  ├─ Create Executor (Local or SSH based on --ssh flag)       │
│  │   └─ LocalExecutor: std::fs + std::process::Command       │
│  │   └─ SshExecutor: openssh crate for remote operations     │
│  ├─ Create Context with executor                             │
│  │   └─ Context::with_executor(executor)                     │
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
│  ├─ analysis_page.rs handles button click                    │
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
| WASM Rustflags | `.cargo/config.toml` | TOML |
| SSH Config | `/etc/ssh/sshd_config` | OpenSSH |
| Kernel Params | `/proc/sys/*` | Virtual FS |
| PAM Config | `/etc/pam.d/*` | PAM |
| Audit Rules | `/etc/audit/rules.d/*` | auditd |
| Firewall | Varies by backend | Backend-specific |

---

## 7. SSH Remote Scanning Flow

**Command:** `hardener --ssh user@hostname --ssh-key ~/.ssh/id_ed25519 scan`

```
┌──────────────────┐
│   CLI Input      │
│   --ssh flag     │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  hardener-cli/src/main.rs                                    │
│  ├─ Parse SSH args (--ssh, --ssh-key, --port, etc.)         │
│  └─ Create SshConnectionConfig from CLI args                 │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  SshExecutor::connect(config)                                │
│  ├─ Establish SSH connection via openssh crate               │
│  ├─ Use SSH agent or key file for authentication             │
│  └─ Verify host key (unless --ssh-no-verify)                 │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Context::with_executor(Arc::new(ssh_executor))              │
│  └─ All plugins now use ctx.executor() for operations        │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ For each plugin operation
┌──────────────────────────────────────────────────────────────┐
│  ctx.executor().read_file(path).await                        │
│  ├─ SshExecutor: Runs `cat {path}` over SSH                  │
│  └─ Returns file content from remote host                    │
│                                                              │
│  ctx.executor().execute_command("sysctl", &["-a"]).await     │
│  ├─ SshExecutor: Runs command on remote host via SSH         │
│  └─ Returns CommandOutput { stdout, stderr, exit_code }      │
│                                                              │
│  ctx.executor().write_file(path, content).await              │
│  ├─ SshExecutor: Pipes content to `cat > {path}` via SSH     │
│  └─ Or uses sudo tee for privileged paths                    │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Plugin scan/apply/rollback results                          │
│  └─ Same ScanResult/ApplyResult as local execution           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   stdout/file    │
│   (local)        │
└──────────────────┘
```

### SSH Executor Method Mapping

| Executor Method | SSH Implementation |
|-----------------|-------------------|
| `read_file(path)` | `cat {path}` |
| `read_file_optional(path)` | `cat {path}` (returns None on error) |
| `write_file(path, content)` | `cat > {path}` with stdin |
| `path_exists(path)` | `test -e {path}` |
| `file_metadata(path)` | `stat -c '%F %a %s' {path}` |
| `execute_command(prog, args)` | Direct SSH command execution |
| `command_exists(prog)` | `command -v {prog}` |

### Key Differences from Local Execution

1. **Checkpoints**: Stored locally on the machine running hardener, not on remote
2. **SystemInfo**: Detected from remote host via SSH commands
3. **Privileged operations**: May require sudo on remote (user configures)
4. **Network latency**: Each operation involves SSH round-trip

---

## 8. Scheduled Scanning Flow

**Trigger:** Cron schedule, systemd timer, or manual `hardener daemon run-once` command

```
┌──────────────────┐
│   Trigger        │
│   (cron/daemon/  │
│    manual)       │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Daemon::start() or Daemon::run_once()                       │
│  ├─ Check daemon_scan_in_progress (AtomicBool guard)         │
│  ├─ If scheduled: tokio-cron-scheduler triggers at interval  │
│  └─ Calls ScanRunner::run()                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanRunner::run(plugin_manager, ctx, trigger_type)          │
│  ├─ Determine plugins to scan (from config or all)           │
│  ├─ Get hostname for session identification                  │
│  └─ Apply minimum severity filter from config                │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanHistoryManager::create_session()                        │
│  ├─ Generate UUID session ID                                 │
│  ├─ Record trigger_type (scheduled/manual/systemd)           │
│  ├─ Record host_identifier                                   │
│  ├─ Record plugins to scan                                   │
│  └─ Set status = "running"                                   │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  PluginManager::execute_scan(ctx)                            │
│  ├─ Resolve dependencies (topological sort)                  │
│  ├─ Execute each plugin's scan() method                      │
│  └─ Collect Vec<ScanResult>                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanRunner::process_findings()                              │
│  ├─ Filter by minimum severity threshold                     │
│  │   (only include findings >= min_severity)                 │
│  ├─ Convert Finding → ScanFinding                            │
│  │   ├─ plugin_id, finding_id, severity                      │
│  │   ├─ title, description, current/recommended values       │
│  │   └─ compliance_mappings: "CIS:1.5.1", "NIST:AC-6"       │
│  └─ Return Vec<ScanFinding>                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanRunner::build_summary()                                 │
│  ├─ Count findings by severity using SeverityCounts          │
│  └─ Create ScanSummary {                                     │
│        session_id, host, plugins_scanned,                    │
│        total_findings, critical_count, high_count,           │
│        medium_count, low_count, info_count,                  │
│        had_errors                                            │
│     }                                                        │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  JsonStore::write(session_id, export_payload)                │
│  ├─ Create timestamped filename: {session_id}_{timestamp}.json│
│  ├─ Serialize JSON with:                                     │
│  │   host, timestamp, min_severity, plugins_scanned,         │
│  │   findings (full details), plugin_errors                  │
│  ├─ Write to storage_json_output_dir                         │
│  └─ Return (file_path, sha256_hash)                          │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanHistoryManager::complete_session()                      │
│  ├─ Store all ScanFinding records in scan_findings table     │
│  ├─ Update session with:                                     │
│  │   completed_at, status = "completed",                     │
│  │   total_findings, severity counts,                        │
│  │   json_file_path, hash                                    │
│  └─ Cleanup old scans (if retention_count exceeded)          │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Return ScanSummary                                          │
│  {                                                           │
│    session_id: "abc123-def456-...",                          │
│    host: "server.example.com",                               │
│    plugins_scanned: ["kernel", "ssh", "firewall"],           │
│    total_findings: 12,                                       │
│    critical_count: 2,                                        │
│    high_count: 5,                                            │
│    medium_count: 4,                                          │
│    low_count: 1,                                             │
│    info_count: 0,                                            │
│    json_path: "/var/lib/hardener/scans/abc123_2025...json",  │
│    json_hash: "sha256:a1b2c3...",                            │
│    had_errors: false                                         │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  NotificationDispatcher::notify(summary)                     │
│  ├─ Check severity threshold (config.min_severity)           │
│  ├─ EmailNotifier: SMTP via lettre (if configured)           │
│  │   └─ Send HTML email with severity counts and findings    │
│  ├─ WebhookNotifier: HTTP POST (if configured)               │
│  │   └─ Format: Slack, Discord, or generic JSON              │
│  └─ Log each result to notification_log table                │
└──────────────────────────────────────────────────────────────┘
```

### Key Types

```rust
/// Trigger source for a scan session.
pub enum TriggerType {
    Scheduled,  // Cron scheduler daemon
    Manual,     // CLI command
    Systemd,    // Systemd timer
}

/// Summary returned after scan completion.
pub struct ScanSummary {
    pub session_id: String,
    pub host: String,
    pub plugins_scanned: Vec<String>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub json_path: Option<String>,
    pub json_hash: Option<String>,
    pub had_errors: bool,
}
```

### Database Tables (hardener-scheduler)

```sql
-- Scan session tracking
CREATE TABLE scan_sessions (
    id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    status TEXT NOT NULL DEFAULT 'running',
    trigger_type TEXT NOT NULL,
    host_identifier TEXT NOT NULL,
    plugins_scanned TEXT NOT NULL,  -- JSON array
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    error_message TEXT,
    json_file_path TEXT,
    hash TEXT
);

-- Individual findings per session
CREATE TABLE scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    current_value TEXT,
    recommended_value TEXT,
    category TEXT,
    compliance_mappings TEXT,  -- JSON array
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id)
);

-- Notification delivery log
CREATE TABLE notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    sent_at INTEGER NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id)
);
```

### Daemon Structure

```rust
pub struct Daemon {
    daemon_config: SchedulerConfig,
    daemon_runner: Arc<ScanRunner>,
    daemon_scheduler: Option<JobScheduler>,
    daemon_shutdown_tx: Option<broadcast::Sender<()>>,
    daemon_scan_in_progress: Arc<AtomicBool>,
}
```

### Daemon Lifecycle

```
┌──────────────────────────────────────────────────────────────┐
│  hardener daemon start                                       │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Daemon::start()                                             │
│  ├─ Validate config.enabled == true                          │
│  ├─ Create JobScheduler with tokio-cron-scheduler            │
│  ├─ Parse cron expression from config.schedule               │
│  ├─ Create broadcast channel for shutdown signalling         │
│  ├─ Spawn signal handler (SIGTERM, SIGINT)                   │
│  └─ scheduler.start() - blocks until shutdown                │
└────────┬─────────────────────────────────────────────────────┘
         │ On schedule trigger
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Daemon::execute_scan()                                      │
│  ├─ Check scan_in_progress.compare_exchange() atomically     │
│  ├─ If already running: skip (warn log)                      │
│  ├─ Run ScanRunner::run() with TriggerType::Scheduled        │
│  └─ Clear scan_in_progress flag on completion                │
└────────┬─────────────────────────────────────────────────────┘
         │ On SIGTERM/SIGINT
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Graceful Shutdown                                           │
│  ├─ Signal handler sends () on broadcast channel             │
│  ├─ Wait for scan_in_progress to clear                       │
│  ├─ scheduler.shutdown()                                     │
│  └─ Return Ok(())                                            │
└──────────────────────────────────────────────────────────────┘
```

### File Locations

| Data | Location | Format |
|------|----------|--------|
| Scan History DB | `~/.local/share/linux-hardener/scheduler/history.db` | SQLite |
| JSON Exports | `~/.local/share/linux-hardener/scheduler/scans/` | JSON with SHA-256 |
| Scheduler Config | `[scheduler]` section in config.toml | TOML |

---

## 9. Systemd Unit Generation Flow

**Command:** `hardener systemd generate` or `hardener systemd install`

```
┌──────────────────┐
│   CLI Input      │
│   (schedule,     │
│    --user flag)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  commands/systemd.rs::generate() or install()                │
│  ├─ Resolve binary path (current exe or --binary)            │
│  ├─ Resolve calendar expression:                             │
│  │   └─ If cron format: cron_to_calendar() conversion        │
│  │   └─ Else: use as-is (e.g., "daily", "*-*-* 02:00:00")    │
│  └─ Create SystemdGenerator                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  SystemdGenerator::generate_service()                        │
│  └─ Returns .service unit content:                           │
│      [Unit]                                                  │
│      Description=Linux System Hardener...                    │
│      After=network.target                                    │
│                                                              │
│      [Service]                                               │
│      Type=oneshot                                            │
│      ExecStart=/path/to/hardener daemon run-once             │
│      NoNewPrivileges=true                                    │
│      ProtectSystem=strict                                    │
│      ...                                                     │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  SystemdGenerator::generate_timer()                          │
│  └─ Returns .timer unit content:                             │
│      [Timer]                                                 │
│      OnCalendar=daily (or custom schedule)                   │
│      Persistent=true                                         │
│      RandomizedDelaySec=300                                  │
│                                                              │
│      [Install]                                               │
│      WantedBy=timers.target                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ (if install command)
┌──────────────────────────────────────────────────────────────┐
│  Install to systemd                                          │
│  ├─ System mode: /etc/systemd/system/                        │
│  └─ User mode: ~/.config/systemd/user/                       │
│                                                              │
│  Post-install:                                               │
│  ├─ systemctl daemon-reload                                  │
│  └─ systemctl enable --now linux-hardener.timer              │
└──────────────────────────────────────────────────────────────┘
```

### Cron to Calendar Conversion

| Cron Expression | Systemd Calendar |
|-----------------|------------------|
| `0 2 * * *` | `*-*-* 02:00:00` |
| `0 0 * * 0` | `Sun *-*-* 00:00:00` |
| `0 3 1 * *` | `*-*-01 03:00:00` |
| `30 14 15 6 *` | `*-06-15 14:30:00` |

### Generated Unit Files

| File | Purpose |
|------|---------|
| `linux-hardener.service` | Runs `hardener daemon run-once` (Type=oneshot) |
| `linux-hardener.timer` | Triggers service on schedule |

**Last Updated**: 2025-12-06
