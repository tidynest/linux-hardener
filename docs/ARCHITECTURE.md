# Linux System Hardener - Architecture Documentation

**Last Updated:** 2025-11-27
**Version:** 0.1.0

---

## Overview

Linux System Hardener is a modular security hardening tool for Linux systems, providing:
- Plugin-based scanning and hardening across multiple security domains
- Checkpoint/rollback functionality for safe changes
- Compliance framework mapping (CIS, NIST, STIG, HIPAA, PCI-DSS, GDPR)
- Multiple interfaces: CLI, GUI (Tauri/Leptos), and programmatic APIs
- Cryptographically signed audit logs and tamper-proof state management

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interfaces                          │
├────────────────────┬──────────────────────┬─────────────────────┤
│  CLI (hardener-cli)│  GUI (src-tauri)     │  Programmatic API   │
│   └─ Scan          │   └─ Leptos + Tauri  │   └─ hardener-core  │
│   └─ Apply         │   └─ Dashboard       │   └─ hardener-state │
│   └─ Rollback      │   └─ Scanner Page    │                     │
│   └─ Checkpoint    │   └─ Configuration   │                     │
│   └─ Report        │   └─ Compliance      │                     │
│                    │   └─ Checkpoints     │                     │
└────────────────────┴──────────────────────┴─────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Engine                              │
├─────────────────────────────────────────────────────────────────┤
│  hardener-core                                                  │
│  ├─ HardeningPlugin trait (universal plugin interface)          │
│  ├─ PluginRegistry (central plugin registry)                    │
│  ├─ PluginManager (orchestration, dependency resolution)        │
│  ├─ Context (execution context, system info, audit logging)     │
│  ├─ SystemExecutor trait (local/remote abstraction)             │
│  └─ Finding/ScanResult/ApplyResult types                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Plugin System                              │
├─────────────────────────────────────────────────────────────────┤
│  hardener-plugins                                               │
│  ├─ Audit (auditd configuration)                                │
│  ├─ Firewall (nftables, firewalld, ufw backends)                │
│  ├─ Kernel (sysctl hardening)                                   │
│  ├─ MAC (SELinux, AppArmor)                                     │
│  ├─ PAM (authentication hardening)                              │
│  ├─ Permissions (file permissions auditing)                     │
│  ├─ Services (service minimisation)                             │
│  └─ SSH (sshd_config hardening)                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────────────┐
│   State Management      │     │     Supporting Services         │
├─────────────────────────┤     ├─────────────────────────────────┤
│ hardener-state          │     │ hardener-common                 │
│ ├─ Checkpoint system    │     │ ├─ Error types                  │
│ ├─ CheckpointManager    │     │ ├─ Logging utilities            │
│ ├─ Hash chain auditing  │     │ ├─ File utilities               │
│ ├─ Ed25519 signing      │     │ └─ Severity/Category enums      │
│ └─ SQLite database      │     │                                 │
│                         │     │ hardener-distro                 │
│                         │     │ ├─ Distribution detection       │
│                         │     │ └─ Package managers             │
│                         │     │                                 │
│                         │     │ hardener-compliance             │
│                         │     │ ├─ Framework implementations    │
│                         │     │ ├─ Report generation            │
│                         │     │ └─ Output formatters (Text,     │
│                         │     │    JSON, CSV, HTML, PDF)        │
└─────────────────────────┘     └─────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     System Interface                            │
├─────────────────────────────────────────────────────────────────┤
│  Linux System APIs                                              │
│  ├─ /proc/sys (kernel parameters)                               │
│  ├─ /etc (config files)                                         │
│  ├─ systemctl (service management)                              │
│  ├─ auditctl (audit rules)                                      │
│  ├─ nftables/firewalld/ufw (firewall)                           │
│  └─ File system operations                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Crate Overview

| Crate | Purpose | Key Exports |
|-------|---------|-------------|
| `hardener-core` | Plugin framework, execution context, config | `HardeningPlugin`, `Context`, `PluginManager`, `HardenerConfig`, `ConfigLoader`, `SystemExecutor`, `LocalExecutor`, `SshExecutor` |
| `hardener-common` | Shared types and utilities | `Severity`, `FindingCategory`, `HardeningError`, `FindingPolicyException` |
| `hardener-plugins` | 8 security plugin implementations | All plugin structs |
| `hardener-state` | Checkpoint and audit system | `CheckpointManager`, `AuditLogger` |
| `hardener-compliance` | Compliance framework mapping | `ReportGenerator`, frameworks |
| `hardener-distro` | Distribution detection | `Distribution`, `DistroFamily` |
| `hardener-cli` | Command-line interface | Binary entry point |
| `hardener-ui` | Leptos web components | Frontend components |
| `src-tauri` | Desktop app backend | Tauri commands |

---

## Key Traits

### HardeningPlugin

The core interface all plugins implement:

```rust
pub trait HardeningPlugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    fn dependencies(&self) -> Vec<PluginId>;
    fn scan(&self, ctx: &Context) -> Result<ScanResult>;
    fn apply(&self, ctx: &mut Context, config: &Config) -> Result<ApplyResult>;
    fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()>;
    fn validate(&self, config: &Config) -> Result<ValidationReport>;
}
```

### SystemExecutor

Abstraction for local and remote system operations:

```rust
#[async_trait]
pub trait SystemExecutor: Send + Sync {
    fn description(&self) -> String;
    fn is_remote(&self) -> bool;
    async fn read_file(&self, path: &Path) -> Result<String>;
    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>>;
    async fn write_file(&self, path: &Path, content: &str) -> Result<()>;
    async fn path_exists(&self, path: &Path) -> Result<bool>;
    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata>;
    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput>;
    async fn command_exists(&self, program: &str) -> Result<bool>;
}
```

Implementations:
- `LocalExecutor` - Wraps `std::fs` and `std::process::Command`
- `SshExecutor` - Runs operations over SSH on remote hosts

### FirewallBackend

Abstraction for different firewall systems:

```rust
pub trait FirewallBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    fn detect(&self) -> Result<bool>;
    fn is_enabled(&self) -> Result<()>;
    fn enable(&self) -> Result<()>;
    fn list_rules(&self) -> Result<Vec<Rule>>;
    fn apply_rules(&self, rules: &[Rule]) -> Result<Vec<Change>>;
    fn get_default_rules(&self) -> Vec<Rule>;
}
```

---

## Plugins

| Plugin | Category | Checks |
|--------|----------|--------|
| `AuditHardeningPlugin` | Audit | auditd rules for time, users, permissions, modules |
| `FirewallHardeningPlugin` | Network | Firewall enabled, baseline rules |
| `KernelHardeningPlugin` | Kernel | ASLR, kptr_restrict, dmesg_restrict, ptrace_scope |
| `MacHardeningPlugin` | MAC | SELinux/AppArmor status |
| `PamHardeningPlugin` | Auth | Password complexity, lockout, reuse |
| `PermissionsHardeningPlugin` | FileSystem | Critical paths, SUID/SGID |
| `ServicesHardeningPlugin` | Services | Unnecessary services |
| `SshHardeningPlugin` | Network | PermitRootLogin, PasswordAuthentication |

---

## State Management

### Storage Locations

| Component | Location | Purpose |
|-----------|----------|---------|
| Checkpoints | `~/.local/share/linux-hardener/checkpoints.db` | System state snapshots |
| Audit Log | Same DB, `audit_log` table | Tamper-proof action history |
| Signing Keys | `~/.local/share/linux-hardener/signing.key` | Ed25519 keys |

### Database Schema

```sql
-- Checkpoint metadata
CREATE TABLE checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    checkpoint_name TEXT NOT NULL,
    checkpoint_timestamp INTEGER NOT NULL,
    checkpoint_username TEXT NOT NULL,
    checkpoint_signature BLOB NOT NULL
);

-- Captured file states
CREATE TABLE file_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_content BLOB,
    file_permissions INTEGER NOT NULL,
    file_owner_uid INTEGER NOT NULL,
    file_owner_gid INTEGER NOT NULL,
    FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(checkpoint_id)
);

-- Tamper-proof audit trail
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_timestamp TIMESTAMP NOT NULL,
    entry_action_type TEXT NOT NULL,
    entry_user TEXT NOT NULL,
    entry_target TEXT NOT NULL,
    entry_result TEXT NOT NULL,
    entry_details JSON,
    entry_hash BLOB NOT NULL  -- SHA-256 hash chain
);
```

---

## Compliance Frameworks

| Framework | Controls | Description |
|-----------|----------|-------------|
| CIS | 35+ | Center for Internet Security Benchmarks |
| STIG | 20+ | DISA Security Technical Implementation Guides |
| NIST 800-53 | 20+ | US Federal security controls |
| PCI-DSS | 20+ | Payment Card Industry standards |
| HIPAA | 15+ | Healthcare security requirements |
| GDPR | 12+ | EU data protection (Article 32) |

---

## Configuration System

The configuration system follows a security-first design where **configuration annotates findings; it never hides them**.

### Config Loading Order (later overrides earlier)

1. Built-in defaults (secure baseline)
2. System config: `/etc/linux-hardener/config.toml`
3. User config: `~/.config/linux-hardener/config.toml`
4. CLI config: `--config /path/to/file.toml`
5. Environment: `HARDENER_*` variables

### Scan Modes

| Mode | Flag | Behaviour |
|------|------|-----------|
| Default | (none) | Shows all findings with policy annotations |
| Audit | `--audit` | Ignores all config, pure security assessment |
| Compliance | `--compliance` | Only shows findings without valid policy exceptions |

### Key Types

```rust
pub struct HardenerConfig {
    pub global: GlobalConfig,
    pub plugins: HashMap<String, PluginConfig>,
}

pub struct PolicyException {
    pub exception_allowed_value: String,
    pub exception_reason: String,
    pub exception_approved_by: Option<String>,
    pub exception_expires: Option<String>,
}
```

---

## Security Features

1. **Cryptographic Signatures**: Ed25519 signatures on all checkpoints
2. **Hash Chain Audit Log**: SHA-256 chain makes tampering detectable
3. **Privilege Separation**: Scan runs unprivileged, apply requires root
4. **Atomic Operations**: File changes use atomic write patterns
5. **Rollback Safety**: Full state restoration from any checkpoint
6. **Transparent Config**: Configuration cannot hide security findings, only annotate them

---

## CI/CD Infrastructure

### GitHub Actions

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR to main/master | Tests, clippy, fmt, security audit, build |
| `release.yml` | Tag `v*` | Multi-target builds, GitHub releases |

### GitLab CI

| Stage | Jobs | Purpose |
|-------|------|---------|
| check | check, fmt, clippy | Code quality |
| test | test, security-audit | Testing |
| build | build:linux-* | Release binaries |
| release | release | Create GitLab release |

### Release Artifacts

| Artifact | Target | Description |
|----------|--------|-------------|
| `hardener-linux-x86_64.tar.gz` | x86_64-unknown-linux-gnu | Standard Linux binary |
| `hardener-linux-x86_64-musl.tar.gz` | x86_64-unknown-linux-musl | Static binary (portable) |
| `hardener-linux-aarch64.tar.gz` | aarch64-unknown-linux-gnu | ARM64 Linux binary |

### Branch Strategy

Both `main` and `master` branches are kept in sync on GitHub and GitLab. The release script (`scripts/release.sh`) automatically syncs both branches on both remotes.

---

## See Also

- `docs/DATA_FLOW.md` - Detailed data flow diagrams
- `docs/CONFIG_DESIGN.md` - Configuration system security design
- `docs/RELEASING.md` - Versioning and release process
- `PLAN.md` - Development roadmap
- `README.md` - User documentation
