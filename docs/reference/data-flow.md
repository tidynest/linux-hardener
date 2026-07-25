# Linux System Hardener - Data Flow Documentation

**Last Updated:** 2026-07-24
**Version:** 1.4.0

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
10. [Desktop Fleet Scan Flow](#10-desktop-fleet-scan-flow)

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
         ▼ All selected plugins, concurrently (join_all;
           results rendered in plugin order, not completion order)
┌──────────────────────────────────────────────────────────────┐
│  Plugin.scan(&ctx)                                           │
│  ├─ Read system state (READ-ONLY)                            │
│  │   • SSH: /etc/ssh/sshd_config                             │
│  │   • Kernel: /proc/sys/*                                   │
│  │   • Firewall: firewall-cmd/nft/ufw status                 │
│  │   • PAM: /etc/pam.d/*, /etc/security/*                    │
│  │   • Services: two batched systemctl listings              │
│  │     (list-unit-files + list-units, pattern-filtered)      │
│  │   • Permissions: stat on critical paths                   │
│  │   • Audit: /etc/audit/rules.d/*                           │
│  │   • MAC: getenforce/aa-status                             │
│  ├─ Compare against secure baseline                          │
│  ├─ Generate Finding for each deviation                      │
│  └─ A source blocked at the current privilege level, or a    │
│     check not applicable to this host (e.g. a non-POSIX      │
│     filesystem), yields UncheckedCheck entries instead of a  │
│     false Finding (pam/firewall/audit/ssh/mac/permissions)   │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ScanResult                                                  │
│  {                                                           │
│    scan_plugin_id: "ssh-hardening",                          │
│    scan_success: true,                                       │
│    scan_findings: [Finding, Finding, ...],                   │
│    scan_unchecked: [UncheckedCheck, ...],  // blocked or     │
│                                             // N/A, below    │
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
│  ├─ --format text: Human-readable table; unchecked checks    │
│  │   render dimmed, separate from findings, with a "run with │
│  │   sudo for a full scan" hint when any exist               │
│  ├─ --format json: per-plugin {plugin_id, plugin_name,       │
│  │   findings, unchecked}                                    │
│  └─ --timings: per-plugin timing table on stderr             │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Persist Scan Session (best-effort)                          │
│  ├─ Open ScanHistoryManager via scheduler config             │
│  ├─ Create session: trigger="cli", hostname, plugin list     │
│  ├─ Convert findings → ScanFinding records                   │
│  └─ Complete session (failures silently ignored)             │
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

struct UncheckedCheck {
    unchecked_check_id: String,      // Same id the finding would carry
    unchecked_title: String,
    unchecked_category: FindingCategory,
    unchecked_reason: String,        // e.g. "reading /etc/ssh/sshd_config requires root"
    unchecked_compliance: Vec<ComplianceMapping>,  // Drives ManualReview, see Section 5
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
│  ├─ Verify the executor session is privileged                │
│  │   (id -u == 0 or passwordless sudo; --ssh aware)          │
│  ├─ Create PluginRegistry                                    │
│  ├─ Initialize CheckpointManager                             │
│  │   └─ Opens/creates SQLite DB (root context):              │
│  │      /var/lib/linux-hardener/checkpoints.db               │
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
│  │   • Permissions: chmod, chown (non-POSIX fs skipped       │
│  │     with fstab guidance, not chmodded)                    │
│  │   • Audit: Write audit rules, augenrules --load           │
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
│      Change { change_description:                            │
│                 "Set kernel.randomize_va_space=2",           │
│               change_type: KernelParameter,                  │
│               change_success: true }                         │
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

**Apply honesty and idempotency.** Every plugin apply is state-aware: an
already-compliant setting is recorded as a `ChangeType::Skipped` no-op (config
files are backed up and rewritten only when their content actually changes,
services are not restarted when nothing changed, nftables rules are
presence-checked so they are never duplicated, and SSH/audit rewrites are gated
on drift). The pre-apply checkpoint is recorded once as a
`ChangeType::Checkpoint` bookkeeping entry. `ApplyResult::applied_change_count()`
counts only successful, non-skipped, non-checkpoint changes, so the CLI prints
"N change(s) applied[, M skipped]", "no changes needed" for a plugin whose only
entry was the checkpoint, and "N of M change(s) applied, K failed" on failure -
a checkpoint or a skip is never counted as a hardening change.

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
│  Capture File/Directory State                                │
│  ├─ For directories: capture_directory_entry() (metadata only)│
│  │   └─ file_content: None, permissions/uid/gid from stat()  │
│  ├─ For files: Read content + stat() for metadata            │
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
│  ├─ Load Ed25519 private key (root context):                 │
│  │   /etc/linux-hardener/signing.key                         │
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
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Snapshot Current State (reversible-rollback guarantee)      │
│  ├─ Capture the live state of the files about to be restored │
│  │   (mirrors each entry: content vs metadata-only)          │
│  ├─ Store as a signed checkpoint named after the restored one│
│  └─ Fail closed: if capture fails, abort before any write    │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼ For each FileState
┌──────────────────────────────────────────────────────────────┐
│  Restore File/Directory                                      │
│  ├─ If file_content is None AND path is directory:           │
│  │   └─ Restore permissions/ownership (fall through)         │
│  ├─ If file_content is None AND permissions == 0:            │
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
│  ├─ Audit: augenrules --load (fallback: systemctl restart)   │
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
│  └─ Collect Finding + UncheckedCheck results per plugin      │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ReportGenerator::new(config, coverage)                      │
│    .generate(findings, unchecked)                            │
│  coverage = hardener_plugins::compliance_coverage()          │
│   (union of every plugin's coverage() - the assessed set)    │
│  ├─ Profile translation (config.profile, default generic):   │
│  │   findings' mappings, coverage, and curated catalogue all │
│  │   pass through profiles::translate - rhel10 renders DISA  │
│  │   RHEL 10 STIG V1R1 / CIS v1.0.1 ids; unsourced ids drop  │
│  ├─ Build control catalogue:                                 │
│  │   • CIS / ISO 27001: curated catalogue (full standard)    │
│  │   • STIG/NIST/PCI/HIPAA/GDPR/SOC2/800-171/FedRAMP:       │
│  │     derived from coverage (single id scheme, only         │
│  │     assessed controls)                                    │
│  └─ For each control:                                        │
│      ├─ Find related findings via ComplianceMapping          │
│      │   (finding.finding_compliance contains mappings)      │
│      ├─ Determine status:                                    │
│      │   • Fail: has related findings (always wins, even if  │
│      │     the same control is also unchecked elsewhere)     │
│      │   • ManualReview: no findings, and either the control │
│      │     is NOT in the coverage set (curated CIS/ISO       │
│      │     controls the engine can't assess) OR it is only   │
│      │     covered by an UncheckedCheck (root-only source,   │
│      │     never auto-Pass on an unprivileged scan)          │
│      │   • Pass: no findings, control in coverage set, and   │
│      │     not covered by any UncheckedCheck                 │
│      │   • NotApplicable: not relevant to this system        │
│      └─ Create ControlResult                                 │
│  Safe-failure net: a finding-referenced id absent from the   │
│  catalogue is appended as Fail (never dropped/false-passed).  │
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
│  └─ Return Vec<ScanResult> as JSON, scan_unchecked included  │
└────────┬─────────────────────────────────────────────────────┘
         │ JSON response
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Leptos Frontend                                             │
│  ├─ Receive ScanResult array                                 │
│  ├─ Update AppState with findings                            │
│  ├─ Render via FindingsTab component                         │
│  └─ Sort/filter by severity                                  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   UI displays    │
│   findings       │
└──────────────────┘
```

**Deep scan (privileged re-scan):** if any scan result carries unchecked
checks, `SecurityScore` (components/security_score.rs) renders an inline
honesty line beneath the score bar on the Dashboard, naming the count. Its
"Run with sudo" button calls `invoke_deep_scan`, which invokes
`run_deep_scan` (src-tauri/src/commands.rs) - a pkexec-elevated sibling of
`run_scan` that shells out to `hardener scan --format json` as root exactly
like `run_apply` does for applies, so results match `sudo hardener scan`.
The returned `Vec<ScanResult>` replaces `AppState.scan_results` and a
follow-up `invoke_generate_report` call regenerates compliance reports.
Report generation (`generate_compliance_report` and
`export_compliance_report`) sources findings and unchecked checks from the
latest persisted completed scan session (`latest_or_fresh_findings` in
src-tauri/src/commands.rs); both `run_scan` and `run_deep_scan` persist
their session before returning, so the regenerated report - and the score
derived from it - reflects the deep scan's privileged results, resolving
covered-but-unchecked controls to Pass or Fail instead of ManualReview.
When no completed session exists (fresh install) or the history database
cannot be read, report generation falls back to a fresh unprivileged
in-process scan (`collect_findings()`); a read failure is logged, never
surfaced, and neither path can trigger a privilege prompt. Only `run_scan`
and `run_deep_scan` persist scan history sessions;
`invoke_generate_report` persists nothing.

### Tauri Commands Available

Every command below is gated by a per-command capability ACL (SAM-039): the
command list in `src-tauri/build.rs` (`tauri_build::AppManifest`) autogenerates
`allow-*`/`deny-*` permissions, and `src-tauri/capabilities/default.json` must
grant each one for the main window. Three places must stay in sync when a
command is added or removed: `src/main.rs` (`generate_handler!`), `build.rs`
(`COMMANDS`), and `capabilities/default.json`.

**Scanning**

| Command | Parameters | Returns |
|---------|------------|---------|
| `run_scan` | `plugin_ids: Option<Vec<String>>`, `config_path: Option<String>` | `Vec<ScanResult>` |
| `run_deep_scan` | `plugin_ids: Option<Vec<String>>`, `config_path: Option<String>` | `Vec<ScanResult>` (pkexec, privileged) |
| `get_latest_scan` | None | `Option<Vec<ScanResult>>` |
| `run_apply` | `plugin_ids: Vec<String>`, `config_path: Option<String>` | `Vec<ApplyResult>` |
| `run_apply_dry_run` | `plugin_ids: Vec<String>`, `config_path: Option<String>` | `Vec<ValidationReport>` |
| `run_rollback` | `checkpoint_id: String`, `config_path: Option<String>` | `RollbackResult` |

**Checkpoints**

| Command | Parameters | Returns |
|---------|------------|---------|
| `get_checkpoints` | None | `Vec<CheckpointInfo>` |
| `create_checkpoint` | `name: String` | `String` (checkpoint ID) |
| `delete_checkpoint` | `checkpoint_id: String` | `bool` |
| `get_checkpoint_detail` | `checkpoint_id: String` | `CheckpointDetail` |

**Compliance**

| Command | Parameters | Returns |
|---------|------------|---------|
| `generate_compliance_report` | `frameworks: Vec<String>` | `Vec<ComplianceReport>` |
| `export_compliance_report` | `frameworks: Vec<String>`, `format: String`, `output_path: Option<String>` | `String` (file path) |

**History**

| Command | Parameters | Returns |
|---------|------------|---------|
| `get_scan_history` | `limit: Option<i32>` | `Vec<ScanSessionInfo>` |
| `get_scan_session` | `session_id: String` | `Vec<ScanResult>` |
| `get_host_history` | `host: String`, `limit: Option<u32>` | `Vec<HostSessionInfo>` |

**Plugins**

| Command | Parameters | Returns |
|---------|------------|---------|
| `list_plugins` | None | `Vec<PluginMetadata>` |

**Config**

| Command | Parameters | Returns |
|---------|------------|---------|
| `validate_config` | `path: String` | `ConfigSummary` |
| `pick_config_file` | `app: AppHandle` | `Option<String>` |

**Remote**

| Command | Parameters | Returns |
|---------|------------|---------|
| `list_remote_hosts` | None | `Vec<RemoteHostProfile>` |
| `save_remote_host` | `profile: RemoteHostProfile` | `()` |
| `delete_remote_host` | `name: String` | `()` |
| `connect_remote` | `name: String`, `state: State<RemoteState>` | `RemoteConnectionStatus` |
| `disconnect_remote` | `state: State<RemoteState>` | `()` |
| `run_remote_scan` | `plugin_ids: Option<Vec<String>>`, `state: State<RemoteState>` | `Vec<ScanResult>` |
| `run_fleet_scan` | `host_names: Vec<String>`, `adhoc: Option<Vec<String>>`, `plugin_ids: Option<Vec<String>>` | `Vec<FleetHostScan>` |
| `run_fleet_apply` | `hosts: Vec<String>`, `adhoc: Option<Vec<String>>`, `plugins: Vec<String>`, `execute: bool` | `Vec<ApplyOutcome>` |
| `run_fleet_rollback` | `hosts: Vec<String>`, `adhoc: Option<Vec<String>>`, `plugins: Vec<String>`, `execute: bool` | `Vec<RollbackOutcome>` |

`run_fleet_apply` and `run_fleet_rollback` spawn `hardener batch apply`/`rollback --format json` as a subprocess (no pkexec; remote authentication uses each host's saved SSH profile). The child process output is parsed into `Vec<ApplyOutcome>` / `Vec<RollbackOutcome>` respectively. `execute: false` (the default) is a dry-run preview: it omits `--execute`; the Fleet Apply page enforces a dry-run before showing the confirmation modal. `list_plugins` returns the available plugin metadata and is shared with the Fleet Apply page for its plugin multi-select.

**Scheduler**

| Command | Parameters | Returns |
|---------|------------|---------|
| `get_scheduler_config` | None | `SchedulerUiConfig` |
| `save_scheduler_config` | `config: SchedulerUiConfig` | `String` (saved path) |
| `test_notification` | None | `TestNotificationResult` |

### AppState Reactive Signals

All GUI state lives in `AppState` (`hardener-ui/src/state/mod.rs`). Each field is a Leptos `RwSignal`:

| Signal | Type | Purpose |
|--------|------|---------|
| `scan_results` | `RwSignal<Vec<ScanResult>>` | Latest scan findings |
| `selected_finding` | `RwSignal<Option<Finding>>` | Currently selected finding in detail panel |
| `severity_filter` | `RwSignal<Option<Severity>>` | Client-side severity filter for findings |
| `apply_results` | `RwSignal<Vec<ApplyResult>>` | Results from last apply operation |
| `rollback_result` | `RwSignal<Option<RollbackResult>>` | Result from last rollback operation |
| `is_scanning` | `RwSignal<bool>` | Scan in progress |
| `is_applying` | `RwSignal<bool>` | Apply in progress |
| `compliance_reports` | `RwSignal<Vec<ComplianceReport>>` | Generated compliance reports |
| `is_generating_report` | `RwSignal<bool>` | Report generation in progress |
| `preview_results` | `RwSignal<Vec<ValidationReport>>` | Dry-run preview results |
| `is_previewing` | `RwSignal<bool>` | Preview in progress |
| `show_preview` | `RwSignal<bool>` | Whether preview panel is visible |
| `error_message` | `RwSignal<Option<String>>` | Global error banner message |
| `remote_hosts` | `RwSignal<Vec<RemoteHostProfile>>` | Saved remote host profiles |
| `remote_connection` | `RwSignal<Option<RemoteConnectionInfo>>` | Active remote connection info |
| `remote_scan_results` | `RwSignal<Vec<ScanResult>>` | Remote scan findings |
| `is_connecting` | `RwSignal<bool>` | Remote connection in progress |
| `is_remote_scanning` | `RwSignal<bool>` | Remote scan in progress |
| `scheduler_config` | `RwSignal<Option<SchedulerUiConfig>>` | Loaded scheduler configuration |
| `is_saving_scheduler` | `RwSignal<bool>` | Scheduler config save in progress |
| `is_testing_notification` | `RwSignal<bool>` | Notification test in progress |
| `config_path` | `RwSignal<Option<String>>` | Selected config file path |
| `config_summary` | `RwSignal<Option<ConfigSummary>>` | Validated config file summary |
| `deep_scan_running` | `RwSignal<bool>` | Shared privileged deep-scan button state |
| `theme` | `RwSignal<String>` | Active colour theme id (see `utils::theme::THEMES`); shared by the sidebar quick-switch and the Settings page grid, applied to `<html data-theme>` and persisted by a single `Effect` in `App` |

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
| Checkpoint DB | root: `/var/lib/linux-hardener/checkpoints.db`; unprivileged: `~/.local/share/linux-hardener/checkpoints.db` | SQLite |
| Signing Keys | root: `/etc/linux-hardener/signing.key`; unprivileged: `~/.local/share/linux-hardener/signing.key` | Ed25519 |
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

1. **Checkpoints**: Capture and restore run through the `SshExecutor`, so
   snapshots and file restores target the **remote** host. Checkpoints are keyed
   by host; rollback refuses to restore one host's checkpoint onto another.
   Note: remote chmod/chown/rm run without sudo, so a non-root remote restore
   degrades to content-only for privileged paths; binary files are not
   checkpointed remotely.
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
│  ├─ Execute each plugin's scan() sequentially, in            │
│  │   dependency order (unlike the concurrent CLI paths)      │
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
│  NotificationDispatcher::dispatch(summary)                    │
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
| Scan History DB | `~/.local/share/linux-hardener/scheduler.db` (root: `/var/lib/linux-hardener/scheduler.db`) | SQLite |
| JSON Exports | `~/.local/share/linux-hardener/scans/` (root: `/var/lib/linux-hardener/scans/`) | JSON with SHA-256 |
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

## 10. Desktop Fleet Scan Flow

**User Action:** Select hosts on the Hosts page and click "Scan Selected"

```
┌──────────────────┐
│   HostsPage      │
│   (host select + │
│    scan button)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  hardener-ui/src/pages/hosts_page.rs (merged Remote +        │
│  Fleet; routed /fleet)                                       │
│  ├─ Mostly page-local state; reuses AppState.remote_hosts /  │
│  │   remote_connection for the single-host connect session   │
│  ├─ Multi-select inventory hosts + ad-hoc target input       │
│  └─ On "Scan Selected": invoke_fleet_scan(names, adhoc,      │
│     plugins)                                                 │
└────────┬─────────────────────────────────────────────────────┘
         │ IPC via Tauri (camelCase: hostNames, adhoc, pluginIds)
         ▼
┌──────────────────────────────────────────────────────────────┐
│  src-tauri/src/commands.rs::run_fleet_scan()                 │
│  ├─ #[tauri::command] - registered in main.rs                │
│  ├─ Validates plugin_ids via validate_plugin_ids()           │
│  ├─ Validates host_names + ad-hoc via validate_ipc_string()  │
│  └─ Resolves ad-hoc profiles, then scan_fleet(inventory      │
│     + ad-hoc targets)                                        │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  scan_fleet() - generic bounded-concurrent orchestrator      │
│  ├─ tokio::sync::Semaphore cap 8 (bounded parallelism)       │
│  ├─ Per-host output slots pre-filled (panic-safe ordering)   │
│  ├─ Input order preserved in result Vec                      │
│  └─ Per-host failure isolated (one error ≠ abort all)        │
└────────┬─────────────────────────────────────────────────────┘
         │ For each host (concurrent, up to 8)
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Inventory lookup                                            │
│  ├─ load_hosts() reads ~/.config/linux-hardener/hosts.toml   │
│  └─ SSH params (host, port, user, key) from stored profile   │
│                                                              │
│  SshExecutor::connect(ssh_config)                            │
│  └─ Establishes SSH connection (same as Hosts page / CLI)    │
│                                                              │
│  scan_with_executor(executor, plugin_ids)                    │
│  ├─ Shared helper extracted from run_remote_scan             │
│  ├─ Context::with_executor(Arc::new(ssh_executor))           │
│  │   └─ No CheckpointManager, no AuditLogger in fleet ctx    │
│  │      → apply/rollback paths structurally unreachable      │
│  └─ Runs selected plugins via plugin.scan(&ctx)              │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  FleetHostScan                                               │
│  {                                                           │
│    host_name: "web-01",                                      │
│    status: FleetHostStatus::Ok,                              │
│    tallies: SeverityTallies {                                │
│      critical: 2, high: 5, medium: 3, low: 1, info: 0       │
│    },                                                        │
│    scan_results: Vec<ScanResult>  // full findings           │
│  }                                                           │
│                                                              │
│  On connect/scan error:                                      │
│    status: FleetHostStatus::Failed(sanitised_msg)            │
│    tallies: all zeros                                        │
│    scan_results: []                                          │
└────────┬─────────────────────────────────────────────────────┘
         │ JSON response (Vec<FleetHostScan>)
         ▼
┌──────────────────────────────────────────────────────────────┐
│  hardener-ui/src/components/host_row.rs                      │
│  ├─ One HostRow per selected host (saved or ad-hoc); shows   │
│  │   "Not scanned yet" until a FleetHostScan arrives for it  │
│  ├─ Severity tally badges (critical / high / medium / low)   │
│  ├─ Framework score strip, one cell per compliance framework │
│  └─ Expand row → HostPanel: Compliance detail (per-          │
│     framework score + pass/fail/manual/NA counts) and        │
│     collapsible Findings grouped by severity                 │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   UI displays    │
│   fleet posture  │
└──────────────────┘
```

### Key Types (hardener-types/src/lib.rs)

```rust
/// Status of a single host in a fleet scan.
pub enum FleetHostStatus {
    Ok,
    Failed(String),  // sanitised connect/scan error message
}

/// Per-severity finding counts derived from a host's ScanResults.
pub struct SeverityTallies {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityTallies {
    pub fn from_results(results: &[ScanResult]) -> Self;
}

/// Per-framework compliance posture for a fleet host (summary only, no
/// per-control detail, which already travels in `FleetHostScan::scan_results`).
pub struct FleetFrameworkPosture {
    pub framework: ComplianceFramework,
    /// Score percentage plus pass/fail/manual/NA control counts.
    pub summary: ComplianceSummary,
}

/// Result for one host in a fleet scan.
pub struct FleetHostScan {
    pub host_name: String,
    pub status: FleetHostStatus,
    pub tallies: SeverityTallies,
    pub scan_results: Vec<ScanResult>,
    /// Per-framework compliance postures derived from `scan_results` in-process.
    pub compliance: Vec<FleetFrameworkPosture>,
}
```

### Fleet Mutation Types (hardener-types/src/lib.rs)

```rust
/// One host's outcome from a fleet apply (or dry-run validation).
pub struct ApplyOutcome {
    pub name: String,    // inventory host name
    pub target: String,  // user@host:port
    pub status: ApplyStatus,
}

/// Result of applying (or validating) one host.
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ApplyStatus {
    Validated { plugins: usize, would_change: usize, failed: usize },
    Applied   { ok: usize, failed: usize },
    Failed    { error: String },
}

/// One host's outcome from a fleet rollback (or dry-run preview).
pub struct RollbackOutcome {
    pub name: String,
    pub target: String,
    pub status: RollbackStatus,
}

/// Result of rolling back (or previewing) one host.
#[serde(tag = "state", rename_all = "lowercase")]
pub enum RollbackStatus {
    Previewed   { checkpoints: usize },
    RolledBack  { restored: usize, failed: usize },
    NothingToDo,
    Failed      { error: String },
}
```

### Key Differences: Single-Host Session vs Bulk Fleet Scan

Both modes live on the merged Hosts page (`hosts_page.rs`); this table
compares the two behaviours, not two separate screens.

| Aspect | Single-host connect session | Bulk fleet scan |
|--------|--------------------------|------------------------|
| Connection | Persistent: connect once, scan, disconnect | Per-scan: connect, scan, drop |
| Concurrency | Sequential (one host at a time) | Up to 8 hosts in parallel |
| State | `AppState` remote signals | Page-local Leptos signals |
| Checkpoint/Audit | N/A (scan only) | N/A (scan only, structurally) |
| Ad-hoc hosts | Yes (any saved profile or `--ssh`) | Yes (inventory + ad-hoc `user@host[:port]`) |
| History persistence | No | No (read-only posture view) |

---

**Last Updated**: 2026-07-24
