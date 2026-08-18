# Linux Hardener - Data Flow Documentation

**Last Updated**: 2026-08-16
**Version:** 1.5.1

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
│  │   • Permissions: stat on critical paths, and on the       │
│  │     /usr/etc copy of any /etc path the host does not hold │
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
    finding_exception: ExceptionOutcome,          // NotConfigured, Applied, or Declined
    finding_exception_key: Option<String>,       // The `exceptions` key that accepts it
}

struct UncheckedCheck {
    unchecked_check_id: String,      // Same id the finding would carry
    unchecked_title: String,
    unchecked_category: FindingCategory,
    unchecked_reason: String,        // e.g. "reading /etc/ssh/sshd_config requires root"
    unchecked_blocker: UncheckedBlocker, // What stopped it? Only the producer knows
    // Privilege   -> not privileged now, a privileged re-run would reach it
    // Environment -> privilege is not what is missing, so sudo changes nothing
    // Unknown     -> the producer did not determine which, so nothing is claimed
    unchecked_compliance: Vec<ComplianceMapping>,  // Drives ManualReview, see Section 5
}
```

**Two layers, one finding.** `permissions` asks the filesystem about each
critical path, and where `/etc` holds nothing at all it asks the `/usr/etc`
counterpart through `hardener_common::vendor_config::vendor_path_for`. A
distribution that reserves `/etc` for administrator overrides keeps the file in
force under `/usr/etc`, so a confirmed absence from `/etc` is not the same as
there being nothing to report. A violating vendor mode becomes a `Finding` keyed
on the `/etc` path, which is what keeps the id, the compliance mappings and the
differential suite all asking by one name, while the title and explanation name
the vendor file the operator actually has to look at. Nothing follows from it in
`/usr/etc`: the remediation is an install into `/etc` at the required mode,
because the vendor file is package owned and the next update would revert an
edit made there. `apply` is unchanged and still leaves a path absent from `/etc`
alone, so `apply --dry-run` says nothing about a vendor violation either. A path
absent from both layers stays silent, and a vendor path whose existence or mode
could not be read is reported as an `UncheckedCheck` rather than as an absence.

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
│  │   • SSH: ["/etc/ssh/sshd_config",                         │
│  │            "/etc/ssh/sshd_config.d/00-hardener.conf"]     │
│  │   • Kernel: ["/etc/sysctl.conf", "/etc/sysctl.d",         │
│  │               "/etc/sysctl.d/99-hardener.conf"]           │
│  │   • Firewall: the selected backend's own                  │
│  │     checkpoint_paths(), which probes the boot path, never │
│  │     all three: a row recorded absent is an instruction to │
│  │     delete                                                │
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
│  │     with fstab guidance, not chmodded); a path absent     │
│  │     from /etc is left alone and the /usr/etc copy is      │
│  │     never written, so a vendor violation is scan only     │
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
│    apply_checkpoint_id: Some("cp_1700000000000_a1b2c3d4"),   │
│    apply_error: None                                         │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Audit Log Entry                                             │
│  {                                                           │
│    entry_timestamp: "2024-11-26T12:00:00Z",                  │
│    entry_action_type: Apply,                                 │
│    entry_user: "root",                                       │
│    entry_target: "Kernel Hardening",                         │
│    entry_result: Success,                                    │
│    entry_details: {},                                        │
│    entry_hash: SHA256(prev_entry + this_entry)               │
│  }                                                           │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│   Output to user │
└──────────────────┘
```

**Apply honesty and idempotency.** Every plugin apply is state-aware: an
already-compliant setting is recorded as a `ChangeType::Skipped` no-op, unless
its separator needs repairing in place, which still counts as a change (config
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

**Command:** `sudo hardener checkpoint create "before-upgrade"`

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
│  ├─ Every captured path is asked read_link (link_target_of). │
│  │   A symlink stores its TARGET and no content; a read_link │
│  │   that cannot answer refuses the capture rather than      │
│  │   recording "not a link"                                  │
│  ├─ For directories: capture_directory_entry() (metadata only)│
│  │   └─ file_content: None, permissions/uid/gid from stat()  │
│  ├─ For files: Read content + stat() for metadata            │
│  │   • st_mode (permissions)                                 │
│  │   • st_uid (owner)                                        │
│  │   • st_gid (group)                                        │
│  ├─ A path a plugin's apply may CREATE: record it absent,    │
│  │   as content None with permissions 0, so the rollback     │
│  │   reads that row as "remove this"                         │
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
│    file_owner_gid: 0,                                        │
│    file_link_target: None   // Some(target) for a symlink,   │
│                             // whose content is never stored │
│    file_content_absence: None // why there are no bytes,     │
│                             // when there are none and the   │
│                             // path was there: ByDesign for  │
│                             // a metadata-only capture,      │
│                             // ReadFailed when the read      │
│                             // could not be made. None on a  │
│                             // row that carries bytes, and   │
│                             // on any row written before     │
│                             // this field existed            │
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
│  ├─ INSERT INTO checkpoints (id, name, timestamp, signature) │
│  └─ INSERT INTO file_states (checkpoint_id, file_path, ...)  │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Audit Log Entry                                             │
│  {                                                           │
│    entry_action_type: CheckpointCreate,                      │
│    entry_target: "before-upgrade",                           │
│    entry_details: {},                                        │
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
│  Sort Targets Before Any Write (rollback_target_refusal)     │
│  ├─ Path outside the rollback allowlist, relative, or        │
│  │   containing `..`: Skipped with a named reason            │
│  ├─ A row carrying link_target, or recorded absent: admitted │
│  │   without the symlink check, since `ln -sfn` and `rm -f`  │
│  │   land on the path itself and follow nothing              │
│  ├─ Otherwise ask the EXECUTOR, so a remote rollback asks    │
│  │   the target host and never the controller, at the        │
│  │   privilege its own write uses: `link_target_as_writer`.  │
│  │   `Ok(None)` is not a symlink; `Ok(Some(p))` is where it  │
│  │   leads, every component resolved. `Err` could not be     │
│  │   determined, and refuses rather than guessing: fail      │
│  │   closed                                                  │
│  └─ Nothing admitted at all: abort, so no orphan snapshot    │
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
│  Restore File/Directory (restore_file_state_tracked)         │
│  ├─ If file_link_target is Some: recreate the LINK           │
│  │   └─ mkdir -p on the parent, then `ln -sfn target path`;  │
│  │      never write, chmod or chown through a symlink        │
│  ├─ If file_content_absence is ReadFailed: the permissions   │
│  │   are restored and the shortfall is REPORTED, so the      │
│  │   rollback does not call itself a success for bytes it    │
│  │   never held                                              │
│  ├─ If file_content is None AND permissions == 0:            │
│  │   └─ "Absent at capture", so remove the path, EXCEPT for  │
│  │      UNDELETABLE_ROLLBACK_PATHS (account databases,       │
│  │      /etc/ssh, /etc/sudoers and similar): those are       │
│  │      probed first and deleted only on a positively        │
│  │      confirmed absence. A probe error, or a path that     │
│  │      exists now, is Skipped, never guessed                │
│  ├─ If file_content is None otherwise (directory, or a file  │
│  │   present but unreadable at capture):                     │
│  │   └─ Re-apply permissions/ownership only                  │
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
│  ├─ Firewall: firewall-cmd --reload / nft -f / ufw reload    │
│  ├─ Audit: augenrules --load (fallback: systemctl restart)   │
│  └─ Others as needed                                         │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Audit Log Entry                                             │
│  {                                                           │
│    entry_action_type: Rollback,                              │
│    entry_target: "cp_1700000000000_a1b2c3d4",                │
│    entry_result: Success,                                    │
│    entry_details: {},                                        │
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
│      ├─ Determine status (a finding carrying a matching      │
│      │   policy exception is a documented deviation, not a   │
│      │   failure, so only LIVE findings count below):        │
│      │   • Fail: has a live related finding (always wins,    │
│      │     even if the control is also unchecked elsewhere)  │
│      │   • ManualReview: no live findings, and either the    │
│      │     control is NOT in the coverage set (curated       │
│      │     CIS/ISO controls the engine can't assess) OR it   │
│      │     is only covered by an UncheckedCheck (root-only   │
│      │     source, never auto-Pass on an unprivileged scan)  │
│      │   • Pass: no live findings, control in coverage set,  │
│      │     and not covered by any UncheckedCheck             │
│      │   • NotApplicable: not relevant to this system        │
│      └─ Create ControlResult                                 │
│  Safe-failure net: a live-finding-referenced id absent from  │
│  the catalogue is appended as Fail (never dropped or         │
│  false-passed). An id referenced only by excepted findings   │
│  is skipped, not appended.                                   │
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
| `run_rollback` | `checkpoint_id: String` | `RollbackResult` |

**Checkpoints**

| Command | Parameters | Returns |
|---------|------------|---------|
| `get_checkpoints` | None | `CheckpointList` (`checkpoints: Vec<CheckpointInfo>` plus `system_unreadable`, so an unprivileged caller can tell "no privileged checkpoints exist" from "the system database could not be read") |
| `create_checkpoint` | `name: String` | `String` (checkpoint ID) |
| `delete_checkpoint` | `checkpoint_id: String` | `bool` |
| `get_checkpoint_detail` | `checkpoint_id: String` | `CheckpointDetail` |

**Compliance**

| Command | Parameters | Returns |
|---------|------------|---------|
| `generate_compliance_report` | `frameworks: Vec<String>` | `Vec<ComplianceReport>` |
| `export_compliance_report` | `frameworks: Vec<String>`, `format: String`, `output_path: Option<String>` | `String` (file path) |

**Policy exceptions**

Both are pkexec-elevated and are fired by the Accept/Remove control on a finding
row (`components/findings_tab.rs`). The desktop sends nothing describing the
host: the CLI re-reads it and pins the value it observes, and refuses a key no
live finding carries, which is why neither command needs an allow-list here.

| Command | Parameters | Returns |
|---------|------------|---------|
| `add_policy_exception` | `plugin_id: String`, `exception_key: String`, `reason: String`, `approved_by: Option<String>`, `ticket: Option<String>`, `expires: Option<String>` | `WrittenException` |
| `remove_policy_exception` | `plugin_id: String`, `exception_key: String` | `()` |

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
| `run_fleet_scan` | `host_names: Vec<String>`, `adhoc: Option<Vec<String>>`, `plugin_ids: Option<Vec<String>>`, `app: AppHandle` | `Vec<FleetHostScan>` (`app` emits per-host progress on `FLEET_PROGRESS_EVENT`, `"fleet-progress"` in `hardener-types/src/remote.rs`) |
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
| `is_connecting` | `RwSignal<bool>` | Remote connection in progress |
| `is_remote_scanning` | `RwSignal<bool>` | Remote scan in progress |
| `scheduler_config` | `RwSignal<Option<SchedulerUiConfig>>` | Loaded scheduler configuration |
| `is_saving_scheduler` | `RwSignal<bool>` | Scheduler config save in progress |
| `is_testing_notification` | `RwSignal<bool>` | Notification test in progress |
| `config_path` | `RwSignal<Option<String>>` | Selected config file path |
| `config_summary` | `RwSignal<Option<ConfigSummary>>` | Validated config file summary |
| `deep_scan_running` | `RwSignal<bool>` | Shared privileged deep-scan button state |
| `theme` | `RwSignal<String>` | Active colour theme id (see `utils::theme::THEMES`); shared by the sidebar quick-switch and the Settings page grid, applied to `<html data-theme>` and persisted by a single `Effect` in `App` |

**Not in `AppState`, deliberately.** Two results that a reader might expect here
are held locally by the component that owns them, because nothing else reads
them: a `RollbackResult` lives in the `Stage::Result` variant of
`components/rollback_modal.rs` for as long as that modal is open, and a
single-host remote scan is folded into the page-local `FleetHostScan` map in
`pages/hosts_page.rs` so one row renders the same way whether it came from a
session scan or a fleet scan. `AppState` keeps only the `is_remote_scanning`
flag for the latter.

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
│   0x00 * 32 +   │     │   entry1.hash + │     │   entry2.hash + │
│   entry1.data   │     │   entry2.data   │     │   entry3.data   │
│ )               │     │ )               │     │ )               │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

If any entry is modified, the hash chain breaks and tampering is detected.

**Modification is detected; truncation of the tail is not.** Verification starts
from the `0x00 * 32` genesis above and stops at end-of-file, holding no expected
length and no anchor outside the file, so a prefix of a valid chain is itself a
valid chain. Measured 2026-08-18: deleting the last of three entries left
`verify_integrity` returning `true` and the log reporting 2 entries. Deleting the
first returned `false`, because the survivor no longer links to the genesis.
Keeping the tail honest is the deployment's job: as root the log sits in a 0700
directory, but an unprivileged run writes it under the user's own data directory,
where the user the entries describe can rewrite the chain from genesis. The
ceiling is recorded in
[evidence-ledger.md](evidence-ledger.md).

---

## File Locations Summary

| Data | Location | Format |
|------|----------|--------|
| Checkpoint DB | root: `/var/lib/linux-hardener/checkpoints.db`; unprivileged: `~/.local/share/linux-hardener/checkpoints.db` | SQLite |
| Signing Keys | root: `/etc/linux-hardener/signing.key`; unprivileged: `~/.local/share/linux-hardener/signing.key`. A `signing.pub` sits beside each one, and a reader that cannot read the private key uses it to verify without signing | Ed25519 |
| Audit Log | root: `/var/log/linux-hardener/audit.log`; unprivileged: `~/.local/share/linux-hardener/audit.log` | JSONL hash chain |
| Scan History DB | root: `/var/lib/linux-hardener/scheduler.db`; unprivileged: `~/.local/share/linux-hardener/scheduler.db` | SQLite (scheduler, host-aware; see section 8) |
| User Config | `~/.config/linux-hardener/config.toml` | TOML |
| Host Inventory | `~/.config/linux-hardener/hosts.toml` | TOML |
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
│  ├─ SshExecutor: `sudo tee {path} > /dev/null` fed by a      │
│  │   quoted heredoc, so content is never re-expanded         │
│  └─ One write path, not two: sudo is always used             │
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

Every path is shell-escaped before interpolation (`shell_escape` in
`hardener-core/src/executor/ssh.rs`).

| Executor Method | SSH Implementation |
|-----------------|-------------------|
| `read_file(path)` | `cat {path}` |
| `read_file_optional(path)` | `cat {path} 2>/dev/null` |
| `write_file(path, content)` | `sudo tee {path} > /dev/null` fed by a quoted heredoc (`tee_command`) |
| `path_exists(path)` | `test -e {path} && echo yes \|\| echo no` |
| `file_metadata(path)` | `test -e {path} && echo E \|\| echo N; stat -c '%F %a %s %u %g' {path} 2>/dev/null \|\| true` (`metadata_probe_command`) |
| `read_dir(path)` | `find {path} -mindepth 1 -maxdepth 1 2>/dev/null` |
| `execute_command(prog, args)` | Direct SSH command execution |
| `read_link(path)` | `readlink -n -- {path}` (trait default, not SSH-specific) |
| `link_target_as_writer(path)` | `sh -c <probe> _ {path} "sudo -n"`, with the path and the elevation both passed as positional arguments. The probe runs its whole body inside one `sudo -n sh -c` invocation, so it answers at the privilege `write_file` writes at (trait default; a local executor passes an empty elevation instead) |
| `command_exists(prog)` | `sh -c <probe> sh {prog}`, a `command -v` probe with the name passed as a positional argument so metacharacters cannot alter what runs (trait default) |

`file_metadata` asks two questions in one round trip on purpose: the `E`/`N`
marker positively confirms existence, and a parsed `stat` line is stronger
evidence still, so a `stat` that merely failed is never read as absence.
`read_link`, `link_target_as_writer` and `command_exists` are provided methods
on `SystemExecutor` in `hardener-common`, so local and remote answer them
identically. `link_target_as_writer` is the only one of the three that
elevates, and it elevates exactly when the executor's own `write_file` does.

### Key Differences from Local Execution

1. **Checkpoints**: Capture and restore run through the `SshExecutor`, so
   snapshots and file restores target the **remote** host. Checkpoints are keyed
   by host; rollback refuses to restore one host's checkpoint onto another.
   Note: remote chmod/chown/rm run without sudo, so a non-root remote restore
   degrades to content-only for privileged paths; binary files are not
   checkpointed remotely.
2. **SystemInfo**: Local only, and unread. `Context::with_executor` calls
   `SystemInfo::detect()` whatever the executor, and every field is a local
   reading: `/etc/os-release` through `std::fs` rather than the executor,
   `gethostname`, `uname`, and an architecture that is the controller binary's
   compile-time constant. **No plugin consults it and nothing formats it into a
   report.** `Context::system_info` has no callers, which the compiler confirms:
   made private, it warns `method system_info is never used`. The struct derives
   only `Clone` and `Debug`, so it cannot be serialised into a report either.
   This is an abstraction leak rather than an observable defect, and it would
   become one the moment a plugin started branching on it. The plugins that do
   need the target's identity ask the executor: see `detect_host_profile` in
   `hardener-cli`, which reads the target's own `/etc/os-release` through it
3. **Scan history is keyed by the TARGET, not by the controller.**
   `persist_scan_session` runs unconditionally after a scan and asks
   `session_host_key`. A **remote** is keyed by `host_key_for`, the same
   derivation that scopes checkpoints, so the key is unique per target and
   independent of anything the remote reports: `/etc/hostname` is neither
   unique (two fresh Rocky hosts both answer `localhost.localdomain`) nor
   stable (a session that could not read it would key the same host
   differently). A host reached both by name and by address gets two rows,
   which loses continuity but corrupts nothing, and matches `batch`. A **local**
   scan keeps the host's own `/etc/hostname` so that history written by earlier
   releases keeps its rows, falling back to `host_key_for` when that is
   unreadable or empty, rather than to the literal `localhost` it used before. Until
   this was fixed the remote's findings landed under the operator's own host
   name, where they collided with the operator's own rows and corrupted any
   per-host trend or regression built on that database. `batch` never shared the
   path: it keys on the host profile
4. **Privileged operations**: May require sudo on remote (user configures)
5. **Network latency**: Each operation involves SSH round-trip

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
│  PluginManager::execute_scan(ctx, config)                    │
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
│  ├─ Filename: scan_{YYYYMMDD_HHMMSS}_{session_id[..8]}.json   │
│  ├─ Serialize JSON with:                                     │
│  │   host, timestamp, min_severity, plugins_scanned,         │
│  │   findings (full details), plugin_errors                  │
│  ├─ Write to config.storage.json_output_dir                  │
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
│    json_path: ".../scan_20260801_143022_abc123de.json",      │
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
    /// Set only when this scan regressed against the host's previous one;
    /// omitted from JSON otherwise. Carries the previous scan's start time and
    /// total, plus a per-severity delta where positive means worse.
    pub regression: Option<RegressionInfo>,
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
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

-- Notification delivery log
CREATE TABLE notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    channel TEXT NOT NULL,   -- which notifier ran (email, webhook)
    status TEXT NOT NULL,    -- textual outcome, not a 0/1 success flag
    sent_at INTEGER,
    error_message TEXT,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);
```

**This is `scheduler.db`, not `checkpoints.db`.** These three tables belong to
`hardener_scheduler::db` and are host-aware: `scan_sessions.host_identifier`
records which machine a session describes, which is what lets `batch` and the
scheduler store a fleet's worth of scans in one file. The desktop's own local
scan history lives in `hardener-state`'s `checkpoints.db` alongside the
checkpoint tables, has no host column, and uses a different `scan_sessions`
shape (see `docs/architecture/architecture.md`, Database Schema). The two are
never interchangeable, and the desktop proves it by reading both: the
`get_scan_history` and `get_scan_session` commands open the user-local
`checkpoints.db` through `create_scan_history_manager`, while `get_host_history`
opens `scheduler.db` through `scheduler_db_path` so it sees the history
`batch scan` wrote.

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
│  ├─ Check scan_in_progress.swap(true, SeqCst) atomically     │
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
│      Description=Linux Hardener...                    │
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
│  └─ Expand row → HostPanel, four sections: Compliance        │
│     detail (per-framework score + pass/fail/manual/NA        │
│     counts); one collapsible control list per framework      │
│     (FleetFrameworkPosture::controls); Findings grouped      │
│     by severity; and the per-host Scan history timeline,     │
│     read from scheduler.db via get_host_history              │
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
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl SeverityTallies {
    pub fn from_results(results: &[ScanResult]) -> Self;
}

/// Per-framework compliance posture for a fleet host: the summary, plus one
/// verdict per control so the count can be drilled into. The findings behind
/// each verdict are NOT here - they already travel in
/// `FleetHostScan::scan_results`, and `ControlOutcome` says how to join the two.
pub struct FleetFrameworkPosture {
    pub framework: ComplianceFramework,
    /// Score percentage plus pass/fail/manual/NA control counts.
    pub summary: ComplianceSummary,
    /// One verdict per control the summary counted, in the generator's order.
    pub controls: Vec<ControlOutcome>,
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
    Validated { plugins: usize, would_change: usize, compliant: usize, failed: usize },
    Applied   { ok: usize, failed: usize, plugins: Vec<PluginOutcome> },
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

**Last Updated**: 2026-08-16
