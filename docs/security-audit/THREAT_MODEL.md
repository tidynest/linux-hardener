# Threat Model — Linux System Hardener

**Document Version:** 1.0
**Date:** 2026-02-25
**Auditor:** Security Audit Agent 1 — Threat Model
**Scope:** Full workspace (11 crates + Tauri desktop app)

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Trust Boundaries](#2-trust-boundaries)
3. [Attack Surfaces](#3-attack-surfaces)
4. [Data Flow Analysis](#4-data-flow-analysis)
5. [Privilege Transitions](#5-privilege-transitions)
6. [Asset Inventory](#6-asset-inventory)
7. [Threat Actors](#7-threat-actors)
8. [Risk Matrix](#8-risk-matrix)
9. [Preliminary Findings](#9-preliminary-findings)

---

## 1. System Overview

Linux System Hardener is a modular security auditing and hardening tool for Linux systems. It provides 8 security plugins covering kernel, SSH, firewall, PAM, services, audit, permissions, and MAC (SELinux/AppArmor). The tool ships with a CLI binary and a Tauri v2 desktop application.

### Architecture Summary

```
User (unprivileged)                Root (privileged)
   │                                    │
   ├── GUI (Leptos/WASM)                │
   │     │                              │
   │     └── Tauri IPC ─────────────────┤
   │           │                        │
   │           ├── Scan (in-process)    │
   │           ├── Apply ──pkexec──► hardener CLI (root)
   │           ├── Rollback ─pkexec──► hardener CLI (root)
   │           └── Read DBs (user+sys)  │
   │                                    │
   ├── CLI (direct invocation)          │
   │     ├── Scan (user-level)          │
   │     ├── Apply (needs root)         │
   │     ├── Rollback (needs root)      │
   │     └── Daemon (needs root)        │
   │                                    │
   └── SSH Remote ─────────────────► Remote Host
         (openssh crate)                (scan/apply via SSH)
```

### Crate Responsibility Map

| Crate | Security Relevance | Privilege Level |
|-------|-------------------|-----------------|
| `hardener-cli` | Entry point, argument parsing, output | User or Root |
| `hardener-core` | Plugin trait, executor abstraction, config loading | Inherited |
| `hardener-plugins` | System file reads/writes, command execution | Root (apply) |
| `hardener-state` | Crypto signing, checkpoint DB, audit log | Root (write), User (read) |
| `hardener-scheduler` | Daemon, SMTP, webhooks, systemd generation | Root (daemon) |
| `hardener-compliance` | Report generation (HTML, PDF, CSV, JSON, text) | User |
| `hardener-distro` | Package manager commands | Root (install/remove) |
| `hardener-common` | File utilities, atomic writes | Inherited |
| `hardener-types` | Shared DTOs (WASM-safe) | None |
| `hardener-ui` | Leptos WASM frontend | Browser sandbox |
| `src-tauri` | Tauri backend, IPC commands, pkexec bridge | User |

---

## 2. Trust Boundaries

### TB-1: User Space to Root (pkexec)

**Boundary:** GUI user-level process spawns `pkexec hardener <command>` which runs the CLI binary as root.

**Location:** `src-tauri/src/commands.rs:181-219` (`run_privileged_command()`)

**Data crossing:** CLI arguments constructed from user-provided plugin IDs and config paths are passed as command-line arguments to the root process.

**Risk:** Argument injection into a root-level process. If plugin IDs or config paths are not sanitised before being passed to pkexec, a malicious string could alter command behaviour.

### TB-2: WASM Frontend to Tauri Backend (IPC)

**Boundary:** Leptos WASM code in the browser sandbox calls Tauri IPC commands via `window.__TAURI__.core.invoke()`.

**Location:** `crates/hardener-ui/src/tauri_bindings.rs` -> `src-tauri/src/commands.rs`

**Data crossing:** JSON-serialised arguments (plugin IDs, config paths, checkpoint IDs, remote host profiles, scheduler configs) flow from untrusted WASM to trusted Tauri backend.

**Risk:** The Tauri IPC boundary is the primary interface between untrusted frontend code and privileged backend operations. Malformed or malicious IPC payloads could trigger unexpected behaviour.

### TB-3: Local System to Remote Host (SSH)

**Boundary:** The SshExecutor sends commands over SSH to a remote host. File contents and command outputs flow back.

**Location:** `crates/hardener-core/src/executor/ssh.rs`

**Data crossing:** Shell commands (including file paths) are sent via SSH. Remote file contents and command outputs are received and parsed.

**Risk:** Command injection on the remote host if file paths are not properly escaped. Compromised remote data could influence local behaviour (e.g., scan results displayed in UI).

### TB-4: Application to System Files

**Boundary:** The hardener CLI (running as root) reads and writes system configuration files in `/etc/`, `/proc/sys/`, and manages systemd services.

**Location:** All plugin `apply()` methods, `LocalExecutor::write_file()`, `LocalExecutor::execute_command()`

**Data crossing:** Configuration values from the hardener config (user-provided) are written to system files.

**Risk:** Malicious configuration directives could be written to system files if config validation is insufficient.

### TB-5: Application to Network (Notifications)

**Boundary:** The scheduler sends HTTP POST requests to webhook URLs and SMTP connections to email servers.

**Location:** `crates/hardener-scheduler/src/notification/webhook.rs`, `crates/hardener-scheduler/src/notification/email.rs`

**Data crossing:** Scan summaries (host, findings, session IDs) are sent to external endpoints. Webhook URLs and SMTP credentials come from config.

**Risk:** SSRF via webhook URLs, credential exposure, information leakage of scan results to attacker-controlled endpoints.

### TB-6: User Database to System Database

**Boundary:** The GUI reads from both `~/.local/share/linux-hardener/checkpoints.db` (user) and `/var/lib/linux-hardener/checkpoints.db` (system).

**Location:** `src-tauri/src/commands.rs:479-520` (`get_checkpoints()`)

**Data crossing:** Checkpoint data from the root-owned system database is merged with user database data for display.

**Risk:** If the user database is world-writable or symlinked, a malicious checkpoint could be injected. The system database is trusted but read by the unprivileged GUI.

---

## 3. Attack Surfaces

### AS-1: CLI Arguments

**Entry point:** `hardener-cli/src/main.rs` via Clap parser.

**Inputs:** `--ssh`, `--ssh-key`, `--port`, `--config`, `--plugin`, `--format`, `--output`, checkpoint IDs, session IDs, and all subcommand arguments.

**Validation:** Clap provides structural validation. Plugin names are validated via `is_valid_plugin_name()`. Config paths are passed to `ConfigLoader` which reads files but does not sanitise paths.

### AS-2: Configuration Files (TOML)

**Entry points:**
- `/etc/linux-hardener/config.toml` (system, root-owned)
- `~/.config/linux-hardener/config.toml` (user-owned)
- `--config <path>` (arbitrary path)
- `~/.config/linux-hardener/hosts.toml` (SSH host profiles)

**Inputs:** Plugin enable/disable flags, directive overrides, custom directives, policy exceptions, scheduler configuration, webhook URLs, SMTP settings.

**Validation:** TOML parsing via `toml` crate. `ConfigLoader::load()` merges configs but does not validate directive values against allowed ranges. Policy exceptions require `allowed: true` and `reason` fields but values are not sanitised for command injection.

### AS-3: Tauri IPC Commands (25 commands)

**Entry point:** `src-tauri/src/commands.rs` — all `#[tauri::command]` functions.

**Inputs:**
- `run_scan`: plugin IDs (Vec<String>), config path (Option<String>)
- `run_apply`: plugin IDs (Vec<String>), config path (Option<String>)
- `run_rollback`: checkpoint ID (String), config path (Option<String>)
- `validate_config`: path (String) — arbitrary filesystem path
- `save_remote_host`: profile (RemoteHostProfile) — hostname, user, key file, port
- `save_scheduler_config`: config (SchedulerUiConfig) — cron expr, webhook URLs, SMTP settings
- `export_compliance_report`: frameworks, format, output path (Option<String>)
- `connect_remote`: name (String) — used to look up SSH host profile
- All checkpoint/session ID lookups

**Validation:** Minimal. Plugin IDs are string-matched against registry. Paths are not sanitised for traversal. The `export_compliance_report` command writes to user-specified paths.

### AS-4: SSH Remote Command Execution

**Entry point:** `crates/hardener-core/src/executor/ssh.rs`

**Inputs:** File paths are interpolated into shell commands using single-quote wrapping:
- `cat '{path}'` (read_file)
- `sudo tee '{path}' > /dev/null << 'HARDENER_EOF'\n{content}\nHARDENER_EOF` (write_file)
- `stat -c '%F %a %s' '{path}'` (file_metadata)
- `{program} {args.join(" ")}` (execute_command — no quoting)

**Validation:** File paths are formatted using `path.display()` inside single quotes. However, paths containing single quotes would break the quoting. The `execute_command` method concatenates arguments with spaces and NO quoting.

### AS-5: Webhook and Email Endpoints

**Entry point:** `crates/hardener-scheduler/src/notification/webhook.rs`, `email.rs`

**Inputs:** Webhook URLs from config, custom HTTP headers with `${VAR}` environment variable expansion, SMTP credentials from environment.

**Validation:** Webhook URL emptiness is checked. No URL scheme validation (could be `file://`, `gopher://`, or internal network addresses). Headers support environment variable expansion which could leak secrets if variable names are guessable.

### AS-6: SQLite Databases

**Entry points:**
- `~/.local/share/linux-hardener/checkpoints.db` (user DB)
- `/var/lib/linux-hardener/checkpoints.db` (system DB)
- Scheduler database (configurable path)

**Inputs:** Checkpoint data, file states (including file contents as BLOBs), scan results, findings.

**Validation:** SQLx parameterised queries are used throughout (no SQL injection). However, database file permissions and symlink following are not explicitly checked.

### AS-7: Signing Key

**Entry point:** `crates/hardener-state/src/signing.rs`

**Inputs:** Ed25519 signing key at `/var/lib/linux-hardener/signing.key` (default) or `~/.local/share/linux-hardener/signing.key`.

**Validation:** Key is generated with `rand::rng()`, stored with 0600 permissions. Key file path is hardcoded or derived from data directory.

### AS-8: Audit Log (JSONL file)

**Entry point:** `crates/hardener-state/src/audit.rs`

**Inputs:** JSONL file at `~/.local/share/linux-hardener/audit.log`.

**Validation:** Hash chain provides tamper detection but not prevention. An attacker with write access can truncate the file and rebuild a valid chain from scratch.

### AS-9: HTML Report Output

**Entry point:** `crates/hardener-compliance/src/output/html.rs`

**Inputs:** Finding titles, descriptions, control IDs, section names.

**Validation:** `html_escape()` function escapes `&`, `<`, `>`, `"`. Does not escape single quotes (`'`). The `finding.finding_severity` field is rendered directly in HTML at line 115 without escaping (interpolated inside `[...]`).

### AS-10: Systemd Unit Generation

**Entry point:** `crates/hardener-scheduler/src/systemd.rs`

**Inputs:** Binary path, schedule (cron expression), config path.

**Validation:** Binary path and config paths are interpolated into systemd unit file templates. If these contain shell metacharacters, they could alter the unit file behaviour.

---

## 4. Data Flow Analysis

### DF-1: Scan Flow (Read-Only)

```
Config Files ──► ConfigLoader ──► HardenerConfig
                                        │
                                        ▼
System Files ──► Executor.read_file() ──► Plugin.scan() ──► ScanResult
/proc/sys/*                                     │               │
/etc/*                                          │               ▼
                                                │         GUI/CLI Output
                                                ▼
                                          SQLite DB (persist)
```

**Trust notes:** Scan is primarily read-only. File content from the system is parsed and classified. Malformed system files could cause parsing errors but should not lead to code execution (Rust's memory safety protects here).

### DF-2: Apply Flow (Write, Root Required)

```
GUI ──► Tauri IPC ──► pkexec ──► hardener CLI (root)
                                       │
                                       ▼
ConfigLoader ──► HardenerConfig ──► PluginConfig
                                       │
                                       ▼
                              Plugin.apply(ctx, config)
                                       │
                                 ┌─────┴──────┐
                                 ▼             ▼
                          Checkpoint      System Writes
                          (pre-snapshot)  (/etc/*, sysctl, etc.)
                                 │
                                 ▼
                          SQLite + Signing Key
```

**Trust notes:** User-supplied configuration values flow through pkexec into root-level file writes. The config path itself (`--config`) is passed through pkexec as a CLI argument. The root process reads the file — if the path points to an attacker-controlled file, malicious directives could be applied.

### DF-3: Rollback Flow (Write, Root Required)

```
GUI ──► Tauri IPC ──► pkexec ──► hardener CLI (root)
                                       │
                                       ▼
                              CheckpointManager.rollback()
                                       │
                                       ▼
                              SQLite DB ──► FileState records
                                       │
                                       ▼
                              fs::write() + chown() + chmod()
                              (restores file content, perms, ownership)
```

**Trust notes:** File content from the SQLite database is written directly to system paths stored in the `file_path` column. If the database is compromised (see AS-6), arbitrary files could be overwritten with arbitrary content as root.

### DF-4: Remote SSH Scan Flow

```
Host Config ──► SshConfig ──► SshExecutor.connect()
                                    │
                                    ▼
                              Remote Shell Commands
                              cat, stat, sysctl, etc.
                                    │
                                    ▼
                              CommandOutput (stdout, stderr, exit code)
                                    │
                                    ▼
                              Plugin.scan() ──► ScanResult ──► GUI
```

**Trust notes:** Data from the remote host is untrusted. A compromised remote host could return crafted output designed to exploit parsing logic. Remote scan results are displayed in the GUI without secondary validation.

### DF-5: Notification Flow

```
ScanSummary ──► NotificationDispatcher
                      │
                ┌─────┴──────┐
                ▼             ▼
          EmailNotifier   WebhookNotifier
          (SMTP)          (HTTP POST)
                │             │
                ▼             ▼
          SMTP Server    Webhook URL
          (credentials)  (scan data)
```

**Trust notes:** Scan summaries including hostname, session ID, and finding counts are sent to external services. Webhook URLs are user-configured and could point to internal network addresses (SSRF).

---

## 5. Privilege Transitions

### PT-1: GUI to Root via pkexec

| Operation | Trigger | Mechanism | Target |
|-----------|---------|-----------|--------|
| Apply hardening | User clicks "Apply" in GUI | `pkexec /path/to/hardener apply --plugin X --format json` | CLI runs as root |
| Rollback | User clicks "Rollback" in GUI | `pkexec /path/to/hardener rollback <id> --format json` | CLI runs as root |
| Create checkpoint | User clicks "Create Checkpoint" | `pkexec /path/to/hardener checkpoint create --format json <name>` | CLI runs as root |
| Delete checkpoint (system DB) | User clicks delete | `pkexec /path/to/hardener checkpoint delete <id>` | CLI runs as root |

**Binary resolution:** `get_hardener_binary_path()` in `src-tauri/src/commands.rs:106-140`:
1. Checks sibling of current executable
2. In debug builds: checks `CARGO_MANIFEST_DIR/../target/debug/hardener`
3. Falls back to PATH lookup via `which hardener`

### PT-2: CLI Direct Root Execution

| Operation | Privilege Required | Reason |
|-----------|-------------------|--------|
| `hardener apply` | Root | Writes to `/etc/`, runs `sysctl -w`, `systemctl` |
| `hardener rollback` | Root | Restores files with `chown()` |
| `hardener daemon start` | Root | Binds to system paths, runs periodic scans |
| `hardener systemd install` | Root | Installs systemd unit files |
| `hardener scan` | Partial | Most scans work as user; some require root for `/etc/shadow`, auditd |

### PT-3: SSH Remote Privilege

| Operation | Local Privilege | Remote Privilege |
|-----------|----------------|-----------------|
| Remote scan | User | User (reads `/etc/`, `/proc/sys/`) |
| Remote write | User | `sudo tee` (requires sudo on remote) |

---

## 6. Asset Inventory

### Cryptographic Assets

| Asset | Location | Protection | Sensitivity |
|-------|----------|------------|-------------|
| Ed25519 signing key | `/var/lib/linux-hardener/signing.key` | 0600 permissions | Critical — forges checkpoint signatures |
| SMTP password | `HARDENER_SMTP_PASSWORD` env var | Process environment | High — email credential |
| SSH private keys | User-configured paths | File system permissions | Critical — remote host access |

### Data Stores

| Asset | Location | Protection | Sensitivity |
|-------|----------|------------|-------------|
| System checkpoint DB | `/var/lib/linux-hardener/checkpoints.db` | Root-owned directory | Critical — contains system file backups |
| User checkpoint DB | `~/.local/share/linux-hardener/checkpoints.db` | User-owned | High — scan results, some file states |
| Audit log | `~/.local/share/linux-hardener/audit.log` | User-owned | High — tamper-evident operation history |
| Hosts config | `~/.config/linux-hardener/hosts.toml` | User-owned | High — SSH connection details |
| Hardener config | `~/.config/linux-hardener/config.toml` | User-owned | Medium — policy exceptions, webhook URLs |
| System config | `/etc/linux-hardener/config.toml` | Root-owned | Medium — org-wide policy |
| Scheduler DB | Configurable path | Depends on config | Medium — scan history |

### System Files Modified (Apply Operations)

| File/Path | Plugin | Modification |
|-----------|--------|-------------|
| `/etc/ssh/sshd_config` | SSH | Directive changes |
| `/etc/sysctl.d/*.conf`, `/proc/sys/*` | Kernel | Sysctl parameters |
| `/etc/pam.d/*` | PAM | Authentication config |
| `/etc/audit/rules.d/*.rules` | Audit | Audit rules |
| nftables/firewalld/ufw rules | Firewall | Firewall rules |
| File permissions (various) | Permissions | Mode bits |
| Services (systemctl) | Services | Service stop/disable |
| SELinux/AppArmor status | MAC | Enforcement mode |

### Generated Outputs

| Asset | Type | Sensitivity |
|-------|------|-------------|
| Compliance reports (HTML/PDF/CSV/JSON) | Files | Medium — system security posture |
| Systemd unit files | Service config | Low — but controls execution |
| JSON scan output | Files | Medium — finding details |

---

## 7. Threat Actors

### TA-1: Malicious Local User (Low Privilege)

**Motivation:** Privilege escalation, system disruption, data exfiltration.

**Capabilities:**
- Can modify user-owned config files (`~/.config/linux-hardener/`)
- Can modify user-owned databases (`~/.local/share/linux-hardener/`)
- Can craft malicious TOML config files and pass via `--config`
- Can modify or symlink the audit log
- Can trigger pkexec (but must authenticate)
- Can interact with the GUI if running under their session

**Relevant attack surfaces:** AS-2, AS-3, AS-6, AS-8

### TA-2: Compromised Remote Host

**Motivation:** Lateral movement, local system compromise.

**Capabilities:**
- Controls all SSH command outputs (stdout, stderr, exit codes)
- Can return crafted file contents for `cat` commands
- Can return crafted `stat` output
- Can attempt to exploit parsing logic in plugins

**Relevant attack surfaces:** AS-4

### TA-3: Network Attacker (MitM)

**Motivation:** Data interception, SSRF, credential theft.

**Capabilities:**
- Can intercept webhook HTTP requests if not HTTPS
- Can intercept SMTP if TLS is disabled
- Can intercept SSH if host key verification is disabled

**Relevant attack surfaces:** AS-5, AS-4

### TA-4: Malicious Configuration Author

**Motivation:** Weaken security posture, inject malicious settings.

**Capabilities:**
- Can craft TOML config with malicious directive values
- Can set webhook URLs to internal network addresses
- Can set config paths to symlinks or special files
- Can set SSH host profiles with attacker-controlled hosts

**Relevant attack surfaces:** AS-2, AS-5, AS-10

### TA-5: Supply Chain Attacker

**Motivation:** Backdoor the tool itself.

**Capabilities:**
- Compromise a Cargo dependency
- Tamper with build artifacts
- Poison CI/CD pipeline

**Relevant attack surfaces:** External to application code; mitigated by `cargo audit` and `cargo deny`.

---

## 8. Risk Matrix

Risks are categorised by likelihood (L1-L5) and impact (I1-I5), where 5 is highest.

| Risk ID | Description | Likelihood | Impact | Rating | Trust Boundary |
|---------|-------------|-----------|--------|--------|----------------|
| R-01 | SSH command injection via file paths with single quotes | L2 | I5 | **High** | TB-3 |
| R-02 | SSH execute_command() concatenates args without quoting | L3 | I4 | **High** | TB-3 |
| R-03 | SSRF via webhook URL pointing to internal network | L3 | I3 | **Medium** | TB-5 |
| R-04 | Signing key accessible to unprivileged user (user-mode path) | L2 | I4 | **High** | TB-4 |
| R-05 | Config path argument passed to root process without sanitisation | L2 | I4 | **High** | TB-1 |
| R-06 | Checkpoint DB poisoning via user-writable database | L2 | I4 | **High** | TB-6 |
| R-07 | Audit log truncation and rebuild (no append-only enforcement) | L2 | I3 | **Medium** | AS-8 |
| R-08 | Rollback writes DB-stored content to arbitrary paths as root | L2 | I5 | **Critical** | TB-4 |
| R-09 | Webhook env var expansion leaks secrets via header values | L2 | I3 | **Medium** | TB-5 |
| R-10 | HTML report missing single-quote escape | L1 | I2 | **Low** | AS-9 |
| R-11 | validate_config reads arbitrary filesystem paths | L2 | I2 | **Low** | AS-3 |
| R-12 | export_compliance_report writes to user-specified path | L2 | I3 | **Medium** | AS-3 |
| R-13 | TOCTOU in atomic file writes (backup + rename) | L1 | I3 | **Low** | AS-4 |
| R-14 | Policy exception JSON silently ignored on corruption | L1 | I2 | **Low** | AS-6 |
| R-15 | No signature verification on checkpoint before rollback | L2 | I5 | **Critical** | TB-4 |
| R-16 | Symlink following in file operations | L2 | I4 | **High** | TB-4 |
| R-17 | Systemd unit generation with unescaped paths | L1 | I3 | **Medium** | AS-10 |
| R-18 | auth_admin_keep allows repeated pkexec without re-auth | L2 | I2 | **Low** | TB-1 |
| R-19 | No rate limiting on Tauri IPC commands | L2 | I2 | **Low** | TB-2 |
| R-20 | Webhook URL scheme not validated (file://, gopher://) | L2 | I3 | **Medium** | TB-5 |

---

## 9. Preliminary Findings

The following security concerns were identified during the threat model analysis. These are documented here for further investigation by the detailed audit agents. **No fixes have been applied.**

---

### SA-001: SSH Command Injection via File Paths Containing Single Quotes

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:105-106`
- **Description:** The `read_file()` method constructs shell commands by interpolating file paths inside single quotes: `format!("cat '{}'", path.display())`. If a file path contains a single quote character, the quoting is broken, allowing shell command injection on the remote host.
- **Attack Scenario:** An attacker who controls a file path (e.g., via config directive) could craft a path like `/etc/'; rm -rf / #` to execute arbitrary commands on the remote host.

---

### SA-002: SSH execute_command() Concatenates Arguments Without Shell Escaping

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:186-192`
- **Description:** The `execute_command()` method joins program name and arguments with spaces: `format!("{} {}", program, args.join(" "))`. Arguments are not shell-escaped, meaning any argument containing shell metacharacters (`;`, `|`, `$()`, backticks) will be interpreted by the remote shell.
- **Attack Scenario:** A plugin passing a user-influenced value as a command argument could enable command injection. For example, if a package name or service name from config is passed to `execute_command("systemctl", &["stop", malicious_name])`.

---

### SA-003: SSH write_file() Heredoc Injection

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:126-133`
- **Description:** The `write_file()` method uses a heredoc pattern: `sudo tee '{path}' > /dev/null << 'HARDENER_EOF'\n{content}\nHARDENER_EOF`. If the file content contains the exact string `HARDENER_EOF` on a line by itself, the heredoc terminates early, and subsequent text is interpreted as shell commands executed with `sudo`.
- **Attack Scenario:** An attacker providing config content that contains `\nHARDENER_EOF\nmalicious_command\n` could execute arbitrary commands as root on the remote host.

---

### SA-004: Checkpoint Signature Not Verified Before Rollback

- **Severity:** Critical
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/manager.rs:602-628`
- **Description:** The `rollback()` method retrieves the checkpoint and file states from SQLite and restores them directly. The checkpoint signature is stored in the database but is never verified before writing file contents to the filesystem. The signing infrastructure exists (`CheckpointSigner::verify()`) but is not called during rollback.
- **Attack Scenario:** An attacker with write access to the checkpoint database (either user or system DB) could insert a forged checkpoint with malicious file contents. When the user triggers a rollback, arbitrary content would be written to arbitrary system paths as root.

---

### SA-005: Rollback Writes to Arbitrary Paths From Database Content

- **Severity:** Critical
- **CWE:** CWE-22 (Path Traversal), CWE-73 (External Control of File Name or Path)
- **Location:** `crates/hardener-state/src/manager.rs:524-583` (`restore_file_state_tracked()`)
- **Description:** During rollback, the `file_path` value from the `file_states` database table is used directly as the target path for `fs::write()`, `fs::set_permissions()`, and `nix::unistd::chown()`. No validation is performed on the path (e.g., checking it is within expected directories, checking for symlinks, checking for `..` traversal).
- **Attack Scenario:** Combined with SA-004, an attacker could insert a checkpoint with `file_path: "/etc/shadow"` and arbitrary content, then trigger a rollback to overwrite the system password file.

---

### SA-006: Signing Key Default Path in User-Writable Location

- **Severity:** Medium
- **CWE:** CWE-732 (Incorrect Permission Assignment)
- **Location:** `crates/hardener-state/src/signing.rs:16`
- **Description:** The `DEFAULT_KEY_PATH` is `/var/lib/linux-hardener/signing.key`, which requires root to create. However, when running as a non-root user (e.g., for scan-only operations), the key path falls back to user-local directories. The `CheckpointManager::new()` at `manager.rs:23` calls `CheckpointSigner::new()` which uses the default path. If the `/var/lib/` path is not writable, the key creation fails, which could cause the fallback to a user-writable location depending on calling code.
- **Attack Scenario:** If the signing key ends up in a user-writable location, any local user could replace the key and forge checkpoint signatures.

---

### SA-007: SSRF via Webhook URL Without Scheme Validation

- **Severity:** Medium
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:28-39`
- **Description:** The `WebhookNotifier::new()` method only checks that the URL is non-empty. The `reqwest` client will follow the URL to any scheme and any host, including `http://127.0.0.1`, `http://169.254.169.254` (cloud metadata), or internal network addresses.
- **Attack Scenario:** An attacker who can modify the config file (TA-1 or TA-4) could set a webhook URL to `http://169.254.169.254/latest/meta-data/` to exfiltrate cloud instance metadata via scan notifications.

---

### SA-008: Config Path Passed Through pkexec Without Sanitisation

- **Severity:** Medium
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src-tauri/src/commands.rs:349-386` (`run_apply()`)
- **Description:** The `config_path` parameter from the Tauri IPC call is passed directly as `--config <path>` to the pkexec-elevated CLI process. The path is not validated for traversal, symlinks, or existence before being passed to the root process.
- **Attack Scenario:** A malicious frontend (or compromised WASM) could pass `--config /tmp/malicious.toml` where the file contains directives that weaken security. Since pkexec prompts for authentication, the user must approve — but the config file contents are opaque at that point.

---

### SA-009: Audit Log Hash Chain Can Be Rebuilt After Truncation

- **Severity:** Medium
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
- **Location:** `crates/hardener-state/src/hash_chain.rs`, `crates/hardener-state/src/audit.rs`
- **Description:** The hash chain uses SHA-256 chaining where each entry's hash depends on the previous entry's hash. However, the genesis hash is a fixed known value (32 zero bytes). An attacker with write access to the audit log file can truncate it and rebuild a valid chain from scratch with fabricated entries. There is no external anchor (e.g., timestamped signature published to a remote server) to prevent this.
- **Attack Scenario:** An attacker with local file access (same user) truncates the audit log and creates a new valid chain that omits evidence of their activities.

---

### SA-010: Webhook Environment Variable Expansion Could Leak Secrets

- **Severity:** Medium
- **CWE:** CWE-200 (Information Exposure)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:46-63`
- **Description:** The `expand_env_vars()` function replaces `${VAR}` patterns in webhook header values with the corresponding environment variable values. If an attacker can control the header configuration (via config file), they can set headers like `X-Leak: ${HARDENER_SMTP_PASSWORD}` to exfiltrate environment variables to their webhook endpoint.
- **Attack Scenario:** An attacker who modifies the config file sets a webhook URL to their server and a header value of `Bearer ${HARDENER_SMTP_PASSWORD}`. When a scan runs and triggers notifications, the SMTP password is sent to the attacker's server.

---

### SA-011: HTML Report Severity Field Not Escaped

- **Severity:** Low
- **CWE:** CWE-79 (Cross-Site Scripting)
- **Location:** `crates/hardener-compliance/src/output/html.rs:112-117`
- **Description:** In the HTML formatter, the `finding.finding_severity` field is interpolated directly into HTML: `"→ [{}]"`. The `Severity` enum is an internal type rendered via `Display` trait, so current values are safe. However, if severity representation ever includes user-influenced data, this becomes an XSS vector. The `html_escape()` function is applied to `finding_title` but not to `finding_severity`.
- **Attack Scenario:** Currently theoretical. Would require a code change that introduces user-controlled data into severity display.

---

### SA-012: Database File Permissions Not Verified Before Read

- **Severity:** Medium
- **CWE:** CWE-732 (Incorrect Permission Assignment)
- **Location:** `src-tauri/src/commands.rs:237-241` (`create_checkpoint_manager()`), `crates/hardener-state/src/db.rs:89-118` (`init_db()`)
- **Description:** The `init_db()` function creates the database directory and file with `create_if_missing(true)` but does not check or set restrictive permissions on the database file itself. The system database at `/var/lib/linux-hardener/` could have overly permissive permissions if the directory was created by a different process. The user database inherits the user's umask.
- **Attack Scenario:** If `/var/lib/linux-hardener/checkpoints.db` is world-readable, any local user can read checkpoint file contents (which may include sensitive system configuration). If world-writable, they can inject malicious checkpoints (see SA-004, SA-005).

---

### SA-013: LocalExecutor write_file() Does Not Preserve Original Permissions

- **Severity:** Low
- **CWE:** CWE-732 (Incorrect Permission Assignment)
- **Location:** `crates/hardener-core/src/executor/local.rs:41-44`
- **Description:** The `LocalExecutor::write_file()` method uses `std::fs::write()` which creates files with the process's umask. When overwriting an existing system file (e.g., `/etc/ssh/sshd_config`), the original file's permissions are not preserved. The new file may have different ownership and mode bits.
- **Attack Scenario:** After a hardening apply, a system config file that was originally 0644 root:root could end up with 0644 but owned by the current user, or with different mode bits depending on umask, potentially relaxing security.

---

### SA-014: Polkit Policy Uses auth_admin_keep for Active Sessions

- **Severity:** Low (Informational)
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Location:** `data/com.tidynest.linux-hardener.policy:14`
- **Description:** The polkit policy specifies `<allow_active>auth_admin_keep</allow_active>`, which caches the authentication for a period after the first successful authentication. During this window, subsequent pkexec invocations do not require re-authentication.
- **Attack Scenario:** If the GUI session is compromised (e.g., via browser vulnerability or malicious script) within the polkit cache window, the attacker can invoke privileged operations without the user seeing an authentication prompt.

---

### SA-015: export_compliance_report Writes to User-Specified Path

- **Severity:** Low
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src-tauri/src/commands.rs:641-703` (`export_compliance_report()`)
- **Description:** The `output_path` parameter is used directly as the target for `std::fs::write()`. While the Tauri process runs as the GUI user (not root), the path is not validated against a set of allowed directories. Writing to sensitive user-owned files could cause damage.
- **Attack Scenario:** A compromised WASM frontend could export a report to `~/.bashrc` or `~/.ssh/authorized_keys`, overwriting the file with report content and disrupting the user's shell or SSH access.

---

### SA-016: scan_manager Silently Ignores Corrupted JSON in Database

- **Severity:** Low
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Location:** `crates/hardener-state/src/scan_manager.rs:232-245`
- **Description:** When reading scan findings from the database, `remediation_steps` and `compliance_mappings` JSON fields use `unwrap_or_default()` on parse failures, and `policy_exception` uses `.ok()` which silently discards errors. A corrupted database entry will produce findings with missing data rather than signalling an error.
- **Attack Scenario:** An attacker who can modify the database could corrupt the JSON fields to hide critical compliance mappings or remediation guidance, causing users to underestimate the security posture.

---

### SA-017: get_hardener_binary_path() PATH Lookup Could Resolve to Malicious Binary

- **Severity:** Medium
- **CWE:** CWE-426 (Untrusted Search Path)
- **Location:** `src-tauri/src/commands.rs:106-140`
- **Description:** The `get_hardener_binary_path()` function falls back to a PATH-based lookup using `which hardener`. If an attacker can modify the user's PATH (e.g., by placing a malicious `hardener` binary in a directory that precedes the legitimate one), the Tauri app will pass this malicious binary to pkexec.
- **Attack Scenario:** An attacker places a malicious `hardener` binary at `~/.local/bin/hardener`. When the GUI triggers pkexec, the user authenticates (thinking they're running the real hardener), but the malicious binary runs as root instead.

---

### SA-018: Checkpoint Manager Uses USER Environment Variable for Username

- **Severity:** Low (Informational)
- **CWE:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)
- **Location:** `crates/hardener-state/src/manager.rs:265`
- **Description:** The checkpoint username is derived from `std::env::var("USER")`, which can be trivially spoofed by any user. This value is included in the signed checkpoint data but does not reflect the actual effective UID.
- **Attack Scenario:** A user could set `USER=admin` before running the tool, creating checkpoints that appear to have been created by a different user, undermining audit trail integrity.

---

### SA-019: No Input Validation on Checkpoint Name

- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `crates/hardener-state/src/manager.rs:248-295` (`create_checkpoint()`)
- **Description:** The `checkpoint_name` parameter is stored directly in SQLite without length limits, character validation, or sanitisation. Extremely long names or names containing control characters could cause display issues or SQLite performance problems.
- **Attack Scenario:** A user could create a checkpoint with a very long name or with ANSI escape sequences that could affect terminal display when listed.

---

### SA-020: Tauri CSP Allows unsafe-inline Styles

- **Severity:** Low (Informational)
- **CWE:** CWE-79 (Cross-Site Scripting)
- **Location:** `src-tauri/tauri.conf.json:24`
- **Description:** The Content Security Policy includes `style-src 'self' 'unsafe-inline'`, which allows inline style attributes. While necessary for Leptos's runtime styling, it widens the attack surface if an XSS vulnerability is found elsewhere. The `script-src` is properly restricted to `'self' 'wasm-unsafe-eval'`.
- **Attack Scenario:** If an XSS vector is found (e.g., via unsanitised data in the UI), the attacker could inject inline styles for phishing UI modifications, though script execution would be blocked by the CSP.

---

*End of Threat Model Document*
