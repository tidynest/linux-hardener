# Security Audit: File System & State (Agent 3)

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Auditor:** Agent 3 -- File System & State
**Date:** 2026-02-25
**Scope:** Path traversal, symlink attacks, TOCTOU races, atomic write failures, SQLite integrity, checkpoint/rollback safety, deserialization attacks
**Files Reviewed:** 25 source files across 7 crates (hardener-common, hardener-state, hardener-core, hardener-plugins, hardener-scheduler, hardener-cli, src-tauri)

---

## Table of Contents

1. [Validation of Prior Agent Findings](#1-validation-of-prior-agent-findings)
2. [Checkpoint & Rollback Safety](#2-checkpoint--rollback-safety)
3. [Path Traversal & Symlink Attacks](#3-path-traversal--symlink-attacks)
4. [TOCTOU Races](#4-toctou-races)
5. [Atomic Write & File Operation Failures](#5-atomic-write--file-operation-failures)
6. [SQLite & Database Integrity](#6-sqlite--database-integrity)
7. [Signing & Cryptographic Integrity](#7-signing--cryptographic-integrity)
8. [Audit Log Integrity](#8-audit-log-integrity)
9. [Deserialization & Data Integrity](#9-deserialization--data-integrity)
10. [Summary Matrix](#10-summary-matrix)

---

## 1. Validation of Prior Agent Findings

### SA-004 (Agent 1): Checkpoint Signatures Never Verified Before Rollback

**Confirmed -- Critical.**

`manager.rs:602-628` -- The `rollback()` method calls `get_checkpoint()` to retrieve the checkpoint and file states, then immediately proceeds to `restore_file_state_tracked()` for each file. At no point is the `checkpoint_signature` field (retrieved at line 431) passed to `signer.verify()`. The signature is stored in the DB and retrieved, but never checked.

The `CheckpointSigner::verify()` method exists (signing.rs:115-134) and is fully implemented, but has zero call sites in production code. This means a DB-level attacker (or SQLite corruption) can modify stored file contents and the rollback will blindly write them to disk as root.

**Deepened analysis:** The signature covers `checkpoint_id + name + timestamp + username + file_content_hashes` (manager.rs:214-232). To verify, the rollback path would need to recompute the SHA-256 digest from the retrieved data and call `signer.verify(digest, checkpoint.checkpoint_signature)`. This is straightforward to implement but is currently absent.

### SA-005 (Agent 1): Rollback Writes DB-Stored Content to Arbitrary Paths as Root

**Confirmed -- Critical.**

`manager.rs:524-583` -- `restore_file_state_tracked()` constructs a `Path` directly from `file_state.file_path` (a `String` loaded from SQLite) at line 530:

```rust
let path = Path::new(&file_state.file_path);
```

There is zero validation:
- No canonicalization (no `canonicalize()`, no `realpath`)
- No allowlist check against known system config directories
- No rejection of `..` components
- No symlink detection (`std::fs::metadata` follows symlinks; `std::fs::symlink_metadata` is never used)

The path is then used for `fs::write(path, content)` (line 551), `fs::set_permissions(path, ...)` (line 560), and `nix::unistd::chown(path, ...)` (line 571). All run as root.

If the SQLite database is writable by an attacker (SA-057 below), they can insert arbitrary paths like `/etc/shadow` or `/root/.ssh/authorized_keys` with controlled content, then trigger rollback to overwrite them.

### SA-033 (Agent 2): TOCTOU on File Permissions

**Confirmed -- Medium.** See SA-049 below for expanded analysis.

### SA-034 (Agent 2): Backup-Write Race

**Confirmed -- Medium.** See SA-050 below for expanded analysis.

### SA-035 (Agent 2): Non-Atomic write_file()

**Confirmed -- High.** See SA-048 below for expanded analysis.

---

## 2. Checkpoint & Rollback Safety

### SA-042: Rollback Does Not Verify Checkpoint Signature Before File Writes
- **Severity:** Critical
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/manager.rs:602-628`
- **Description:** The `rollback()` method retrieves checkpoint data from SQLite and restores files without verifying the Ed25519 signature. The `CheckpointSigner::verify()` method exists but is never called.
- **Attack Scenario:** An attacker with write access to the SQLite database (e.g., through a local privilege escalation or the user-writable DB) injects malicious file contents into `file_states`. When rollback is triggered (running as root), the tampered content is written to system files.
- **Remediation:** Before any file writes in `rollback()`, recompute the SHA-256 digest from retrieved checkpoint metadata and file states, then call `self.signer.verify(digest, checkpoint.checkpoint_signature)`. Abort rollback if verification fails.
- **Status:** Open

### SA-043: Rollback Path Not Validated -- Arbitrary File Write as Root
- **Severity:** Critical
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Location:** `crates/hardener-state/src/manager.rs:530`
- **Description:** `restore_file_state_tracked()` uses `file_state.file_path` (from SQLite) directly as a write target without any path validation, canonicalization, or allowlisting.
- **Attack Scenario:** An attacker modifies the checkpoint database to include `file_path = "/etc/shadow"` with content containing a known password hash. Triggering rollback as root overwrites `/etc/shadow`, giving the attacker root access.
- **Remediation:** Validate all paths against an allowlist of known system configuration directories (e.g., `/etc/ssh/`, `/etc/sysctl.d/`, `/etc/security/`, `/etc/audit/`, `/etc/pam.d/`). Reject paths containing `..`, paths that resolve outside allowed prefixes after canonicalization, and paths that are symlinks (check with `symlink_metadata`).
- **Status:** Open

### SA-044: Rollback File Restore Uses fs::write() Instead of Atomic Write
- **Severity:** High
- **CWE:** CWE-367 (TOCTOU Race Condition) / CWE-459 (Incomplete Cleanup)
- **Location:** `crates/hardener-state/src/manager.rs:550-552`
- **Description:** `restore_file_state_tracked()` uses `fs::write(path, content)` to restore file contents. This is a non-atomic write: if the process is interrupted mid-write (crash, signal, power loss), the target file is left in a partially-written, potentially invalid state. This is especially dangerous for critical system files like `sshd_config` (could lock out SSH access) or `sysctl.conf`.
- **Attack Scenario:** System crash during rollback leaves `/etc/ssh/sshd_config` truncated. SSH daemon fails to start, locking out remote administrators.
- **Remediation:** Use `update_file_atomically()` from `hardener-common::file_utils` (which does temp file + fsync + rename) instead of raw `fs::write()`.
- **Status:** Open

### SA-045: Rollback Continues After Individual File Restore Failures
- **Severity:** Medium
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Location:** `crates/hardener-state/src/manager.rs:607-620`
- **Description:** The rollback loop uses `map()` over all file states. If one file fails to restore (e.g., permission denied, disk full), the loop continues to the next file. While individual failures are tracked in `FileRestoreResult`, the partially-rolled-back system state may be inconsistent. For instance, SSH config might be restored but sysctl config not, leaving conflicting security posture.
- **Attack Scenario:** An attacker places an immutable attribute on one config file (`chattr +i /etc/sysctl.d/99-hardener.conf`). Rollback of sysctl fails, but SSH rollback succeeds. System is in an inconsistent and unexpected security state.
- **Remediation:** Consider implementing a two-phase rollback: first validate all files can be written (permissions, disk space), then perform the actual writes. If validation fails, abort before any changes. Alternatively, create a pre-rollback checkpoint so the partial rollback itself can be reverted.
- **Status:** Open

### SA-046: Checkpoint File Capture Follows Symlinks (capture_single_file)
- **Severity:** Medium
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **Location:** `crates/hardener-state/src/manager.rs:63-99`
- **Description:** `capture_single_file()` uses `fs::metadata()` (line 81) which follows symlinks, then `fs::read()` (line 85) which also follows symlinks. If an attacker replaces a config file with a symlink to a sensitive file (e.g., `/etc/shadow`) between the existence check and the read, the checkpoint captures the content of the symlink target. On rollback, the captured content is written to the original path, potentially exposing sensitive data or causing data loss.
- **Attack Scenario:** During checkpoint creation for SSH config, an attacker with write access to `/etc/ssh/` replaces `sshd_config` with a symlink to `/root/.ssh/id_rsa`. The checkpoint captures the private key content. The checkpoint data is now accessible to anyone who can read the SQLite database.
- **Remediation:** Use `fs::symlink_metadata()` instead of `fs::metadata()` to detect symlinks. Refuse to capture files that are symlinks, or resolve them with `canonicalize()` and verify the resolved path is within expected directories. Use `O_NOFOLLOW` semantics where possible.
- **Status:** Open

### SA-047: delete_checkpoint Does Not Cascade in Application Code
- **Severity:** Low
- **CWE:** CWE-404 (Improper Resource Shutdown or Release)
- **Location:** `crates/hardener-state/src/manager.rs:506-522`
- **Description:** `delete_checkpoint()` manually deletes from `file_states` then `checkpoints` in two separate queries without a transaction. The `file_states` table has a `FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id)` but without `ON DELETE CASCADE`. If the second DELETE fails (e.g., database lock timeout), orphaned checkpoint metadata remains while file states are already deleted. Additionally, SQLite foreign key enforcement requires `PRAGMA foreign_keys = ON` which is never set.
- **Attack Scenario:** Database lock contention causes the second DELETE to fail, leaving an orphaned checkpoint record with no file states. Attempting to rollback to this checkpoint would succeed (no files to restore), misleading the operator.
- **Remediation:** Wrap both DELETEs in a transaction (`BEGIN ... COMMIT`). Add `ON DELETE CASCADE` to the `file_states` FK constraint. Enable `PRAGMA foreign_keys = ON` in `init_db()`.
- **Status:** Open

---

## 3. Path Traversal & Symlink Attacks

### SA-048: LocalExecutor::write_file() Non-Atomic, No Path Validation
- **Severity:** High
- **CWE:** CWE-22 (Path Traversal) / CWE-73 (External Control of File Name or Path)
- **Location:** `crates/hardener-core/src/executor/local.rs:41-43`
- **Description:** `write_file()` is `std::fs::write(path, content)` with no validation. The `path` parameter comes from plugin code which constructs it from constants (safe) or from configuration data. The kernel plugin builds paths from `param.replace('.', "/")` (kernel/mod.rs:331) using user-controllable `config.directives` keys. While the base path `/proc/sys/` is hardcoded, a malicious directive key like `../../etc/shadow` combined with the path construction would produce `/proc/sys/../../etc/shadow` = `/etc/shadow`. Additionally, `write_file` uses non-atomic `std::fs::write()` while the codebase has `update_file_atomically()` available.
- **Attack Scenario:** An attacker who controls the TOML configuration file (user config at `~/.config/linux-hardener/config.toml`) adds a directive override key containing path traversal characters. When the kernel plugin applies, the traversal path is written to with attacker-controlled content.
- **Remediation:** Add path validation to `write_file()` (reject paths containing `..` after canonicalization). For the kernel plugin specifically, validate that sysctl parameter names only contain `[a-zA-Z0-9._]`. Consider using `update_file_atomically()` for config file writes.
- **Status:** Open

### SA-049: Permissions Plugin TOCTOU Between path_exists/file_metadata and chmod
- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-plugins/src/permissions/mod.rs:196-212`
- **Description:** `apply_path_permissions()` calls `path_exists()` (line 198), then `file_metadata()` (line 203), then `execute_command("chmod", ...)` (line 214). Between these calls, an attacker could replace the target path with a symlink. The `path_exists()` and `file_metadata()` calls follow symlinks by default. Since permissions paths are hardcoded system directories (`/root`, `/boot`, `/etc/ssh`, etc.), the window is narrow but non-zero.
- **Attack Scenario:** An attacker with access to create symlinks in `/etc/sudoers.d/` races the permissions check: between `file_metadata()` returning the current mode and `chmod` executing, the attacker replaces the directory with a symlink to another target. The `chmod` then changes permissions on the symlink target.
- **Remediation:** Use `fchmod()` with a file descriptor opened with `O_NOFOLLOW | O_PATH` to ensure the operation targets the exact inode checked. Alternatively, verify the inode hasn't changed between check and operation.
- **Status:** Open

### SA-050: Backup File Race in file_utils::backup_file() and safe_modify_file()
- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition) / CWE-377 (Insecure Temporary File)
- **Location:** `crates/hardener-common/src/file_utils.rs:296-306`, `330-365`
- **Description:** `backup_file()` creates a backup at a predictable path (`{original}.backup`). An attacker can pre-create a symlink at the backup path pointing to a sensitive file. `std::fs::copy()` follows symlinks at the destination, so the attacker's symlink target gets overwritten with the original file content. Similarly, `create_timestamped_backup()` uses a predictable path `{original}.backup.{unix_timestamp}` -- the timestamp is predictable to second granularity.
- **Attack Scenario:** Attacker creates `/etc/ssh/sshd_config.backup` as a symlink to `/etc/crontab`. When the SSH plugin runs `backup_file()`, the sshd_config content is written to `/etc/crontab`, corrupting the cron schedule.
- **Remediation:** Check that the backup destination is not a symlink before copying. Better: use `O_CREAT | O_EXCL` semantics (like `NamedTempFile`) for backup creation. Reject if the backup path already exists.
- **Status:** Open

### SA-051: Kernel Plugin sysctl Path Construction From Config Directives
- **Severity:** Medium
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `crates/hardener-plugins/src/kernel/mod.rs:331`
- **Description:** The kernel plugin constructs `/proc/sys/` paths using `param_name.replace('.', "/")` and then writes `target_value` (from `config.directives`) to this path. The `param_name` values come from the hardcoded `KERNEL_PARAMS` array (safe), but `target_value` is user-controllable via config directives. While `/proc/sys/` files are pseudo-filesystem entries that typically reject unexpected content, the write is still performed with arbitrary string content as root. More critically, the `config.directives` HashMap keys could theoretically be iterated if the merge logic changes in the future.
- **Attack Scenario:** A user sets `kernel.directives."../../../etc/malicious"` = "payload" in their config TOML. Since `KERNEL_PARAMS` keys are hardcoded, this specific attack is currently blocked -- but the architecture relies on the hardcoded list rather than input validation.
- **Remediation:** Validate sysctl parameter names match `^[a-zA-Z0-9_.]+$` before path construction. Validate that constructed paths resolve within `/proc/sys/` after canonicalization.
- **Status:** Open

### SA-052: Audit Plugin write_audit_rules_file Has No Path Validation
- **Severity:** Low
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `crates/hardener-plugins/src/audit/mod.rs:304-337`
- **Description:** `write_audit_rules_file()` uses the constant `AUDIT_RULES_PATH` (`/etc/audit/rules.d/hardening.rules`) which is safe. However, it creates a backup at `format!("{}.backup.{}", AUDIT_RULES_PATH, timestamp)` without checking if the backup destination is a symlink. The `cp` command is used via `execute_command("cp", ...)` which follows symlinks.
- **Attack Scenario:** Similar to SA-050 -- attacker pre-creates symlink at the predictable backup path.
- **Remediation:** Verify backup destination does not exist and is not a symlink before creating backups.
- **Status:** Open

---

## 4. TOCTOU Races

### SA-053: Checkpoint capture_file_state Existence Check Then Read
- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-state/src/manager.rs:68, 80-85`
- **Description:** `capture_single_file()` checks `file_path.exists()` (line 68), then calls `fs::metadata()` (line 80) and `fs::read()` (line 85) separately. Between the existence check and the read, the file could be replaced, deleted, or substituted with a symlink. The `exists()` call also follows symlinks, so a symlink-to-nothing would return `false` while a symlink-to-existing-file would return `true` (capturing the wrong content).
- **Attack Scenario:** During checkpoint creation for `/etc/ssh/sshd_config`, an attacker replaces the file between `exists()` and `fs::read()`, causing the checkpoint to store incorrect content. When this checkpoint is later used for rollback, the wrong content is restored.
- **Remediation:** Open the file once with `std::fs::File::open()`, then use the file descriptor for both metadata (`file.metadata()`) and content reading. This eliminates the TOCTOU window.
- **Status:** Open

### SA-054: SSH Plugin Read-Modify-Write Race on sshd_config
- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-plugins/src/ssh/mod.rs:369-471`
- **Description:** The SSH plugin reads `sshd_config` (line 369), modifies it in memory (lines 380-445), then writes it back (line 449). Between the read and write, another process (or a concurrent hardener invocation) could modify the file. The write would then silently overwrite those changes with stale content. This pattern is used identically by the PAM plugin for `/etc/security/pwquality.conf` and `/etc/login.defs`.
- **Attack Scenario:** An administrator manually edits `sshd_config` while the hardener is running. The hardener's write overwrites the admin's changes with the pre-read content plus hardening directives.
- **Remediation:** Use file locking (`flock()` or `fcntl()`) on config files during the read-modify-write cycle. Consider using `safe_modify_file()` from `file_utils` which at least provides atomic write, though it doesn't address the read-then-write race.
- **Status:** Open

### SA-055: Signing Key Save -- Write Then chmod Race
- **Severity:** Medium
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Location:** `crates/hardener-state/src/signing.rs:86-91`
- **Description:** `save_key()` first writes the key bytes with `fs::write()` (line 87), then sets permissions to 0600 with `fs::set_permissions()` (line 91). Between these two operations, the file is world-readable (using the process umask, typically 0644 or 0022). Another user could read the private signing key during this window.
- **Attack Scenario:** On a multi-user system, a local attacker monitors the key directory and reads the signing key file in the window between creation and permission restriction. With the signing key, they can forge checkpoint signatures.
- **Remediation:** Set umask to 0077 before writing, or use `std::fs::OpenOptions` with `mode(0o600)` (via the `unix` extension `OpenOptionsExt::mode()`) to create the file with correct permissions atomically.
- **Status:** Open

---

## 5. Atomic Write & File Operation Failures

### SA-056: update_file_atomically Does Not Preserve File Permissions
- **Severity:** Medium
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Location:** `crates/hardener-common/src/file_utils.rs:30-63`
- **Description:** `update_file_atomically()` creates a `NamedTempFile` in the same directory and persists it to the target path. The `NamedTempFile` is created with the default umask permissions (typically 0644). When it replaces the original file via `persist()` (rename), the new file inherits the temp file's permissions, not the original file's. For security-sensitive files like `sshd_config` (should be 0600) or signing keys, this silently loosens permissions.
- **Attack Scenario:** `sshd_config` is 0600. After `update_file_atomically()`, it becomes 0644, readable by all users. Sensitive SSH configuration (e.g., authentication settings, key paths) is exposed.
- **Remediation:** Before writing the temp file, read the original file's permissions with `fs::metadata()`. After `persist()`, restore the original permissions with `fs::set_permissions()`. Or use `NamedTempFile`'s builder to set permissions before writing.
- **Status:** Open

### SA-057: JsonStore::write() Non-Atomic File Write
- **Severity:** Low
- **CWE:** CWE-459 (Incomplete Cleanup)
- **Location:** `crates/hardener-scheduler/src/json_store.rs:48-50`
- **Description:** `JsonStore::write()` uses `tokio::fs::write()` which is not atomic. If the process crashes mid-write, the JSON file is left partially written and corrupt. The SHA-256 hash computed beforehand (line 46) would not match the partial content, so `verify()` would detect corruption -- but the file itself would be unusable.
- **Attack Scenario:** Crash during scan result export leaves a corrupt JSON file. Subsequent `list()` returns it, and `read()` fails with a parse error.
- **Remediation:** Write to a temporary file in the same directory, then atomically rename. The `tempfile` crate is already in the dependency tree.
- **Status:** Open

---

## 6. SQLite & Database Integrity

### SA-058: Foreign Keys Not Enforced (PRAGMA foreign_keys Never Set)
- **Severity:** Medium
- **CWE:** CWE-1286 (Improper Validation of Syntactic Correctness of Input)
- **Location:** `crates/hardener-state/src/db.rs:99-117`
- **Description:** The schema defines `FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id)` in `file_states` and `FOREIGN KEY ... ON DELETE CASCADE` in `scan_results` and `scan_findings`. However, SQLite does not enforce foreign keys by default -- `PRAGMA foreign_keys = ON` must be set per connection. This pragma is never executed. This means: (1) `file_states` rows can reference nonexistent checkpoints; (2) `ON DELETE CASCADE` does not work, so deleting a `scan_session` leaves orphaned `scan_results` and `scan_findings` rows; (3) The manual two-step delete in `delete_checkpoint()` is the only thing preventing orphaned data.
- **Attack Scenario:** Foreign key violations accumulate over time. Orphaned rows in `file_states` consume disk space. More critically, an attacker could insert `file_states` rows with a checkpoint_id that doesn't exist -- these would be ignored by normal operations but could cause confusion in auditing.
- **Remediation:** Execute `PRAGMA foreign_keys = ON;` immediately after establishing each connection. With sqlx, this can be done via `SqliteConnectOptions::pragma("foreign_keys", "ON")` or by executing the pragma after pool creation.
- **Status:** Open

### SA-059: Checkpoint Store/Delete Not Wrapped in Transactions
- **Severity:** Medium
- **CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
- **Location:** `crates/hardener-state/src/manager.rs:342-398` (store), `506-522` (delete)
- **Description:** `store_checkpoint()` performs one INSERT into `checkpoints` then N INSERTs into `file_states` without wrapping them in a transaction. If the process crashes after inserting the checkpoint but before all file states are inserted, the database contains a partial checkpoint. Similarly, `delete_checkpoint()` DELETEs from `file_states` then `checkpoints` without a transaction -- if the second DELETE fails, orphaned metadata remains.
- **Attack Scenario:** Power loss during `create_checkpoint()` leaves a checkpoint with missing file states. When this checkpoint is used for rollback, some files are not restored, leaving the system in a partially-hardened state that appears fully rolled back.
- **Remediation:** Wrap all multi-statement operations in `sqlx::Transaction`. For `store_checkpoint()`: `BEGIN`, insert checkpoint, insert all file_states, `COMMIT`. For `delete_checkpoint()`: `BEGIN`, delete file_states, delete checkpoint, `COMMIT`.
- **Status:** Open

### SA-060: No SQL Injection -- Parameterized Queries Throughout (Positive Finding)
- **Severity:** Informational
- **CWE:** N/A
- **Location:** All SQL in `manager.rs`, `scan_manager.rs`, `db.rs`
- **Description:** All SQL queries use `sqlx::query()` with `.bind()` for parameters. No string concatenation is used to build SQL. The one exception -- `cleanup_old_sessions()` in scan_manager.rs:325 -- dynamically constructs an `IN (?, ?, ...)` clause but binds values with `.bind()`, which is safe. This is a **positive finding**.
- **Status:** N/A (No issue)

### SA-061: Database Path User-Writable for GUI Operations
- **Severity:** Medium
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Location:** `src-tauri/src/commands.rs:222-227`, `crates/hardener-state/src/db.rs:96`
- **Description:** The user-local database (`~/.local/share/linux-hardener/checkpoints.db`) is created with default permissions (determined by umask, typically world-readable). The `init_db()` function calls `create_dir_all()` for the parent directory but does not set restrictive permissions on the database file. Since `rollback()` reads file paths and content from this database and writes them as root (via pkexec), an attacker with write access to the user's database can inject malicious checkpoint data that will be written to system files when the user triggers a rollback through the GUI.
- **Attack Scenario:** Attacker gains write access to user's home directory (e.g., compromised user account). They modify `~/.local/share/linux-hardener/checkpoints.db` to inject a checkpoint with `file_path="/etc/sudoers"` and content granting them root. User triggers rollback via GUI, pkexec elevates, and the malicious content is written.
- **Remediation:** Set database file permissions to 0600 after creation. More importantly, SA-042 (signature verification) would prevent this attack even if the DB is writable -- fixing SA-042 is the primary defence, and restrictive permissions are defence-in-depth.
- **Status:** Open

---

## 7. Signing & Cryptographic Integrity

### SA-062: Signing Key and Checkpoint DB on Same Trust Boundary
- **Severity:** High
- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **Location:** `crates/hardener-state/src/signing.rs:16`, `crates/hardener-state/src/db.rs:10`
- **Description:** The signing key (`/var/lib/linux-hardener/signing.key`) and the checkpoint database (`/var/lib/linux-hardener/checkpoints.db`) are stored in the same directory. An attacker who gains write access to the directory (e.g., through a vulnerability in the hardener itself) can replace both the database and the signing key. With control of the signing key, they can generate valid signatures for forged checkpoints, defeating the signature verification even if SA-042 is fixed.
- **Attack Scenario:** Attacker exploits a path traversal in the hardener (e.g., via SA-043) to write to `/var/lib/linux-hardener/`. They replace the signing key with their own, forge checkpoints with malicious content, and trigger rollback.
- **Remediation:** Store the signing key in a different location with more restrictive access (e.g., `/etc/linux-hardener/signing.key` owned by a dedicated system account). Consider using a hardware-backed key store or at minimum ensure the key file has 0400 permissions (read-only for root). Alternatively, use asymmetric verification where the signing private key is only loaded during checkpoint creation, and a separate public key (immutable on disk) is used for verification during rollback.
- **Status:** Open

### SA-063: Signature Does Not Cover File Permissions or Ownership
- **Severity:** Medium
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/manager.rs:222-229`
- **Description:** `generate_signature()` hashes: `checkpoint_id`, `name`, `timestamp`, `username`, and for each file: `file_path` and `file_content`. It does **not** hash `file_permissions`, `file_owner_uid`, or `file_owner_gid`. An attacker who modifies the database can change file permissions (e.g., from 0600 to 0777) or ownership (e.g., from root:root to attacker:attacker) without invalidating the signature.
- **Attack Scenario:** Attacker modifies the checkpoint DB to change `permissions` for `/etc/shadow` from 0640 to 0644. Even with signature verification (SA-042 fixed), the tampered permissions would pass verification. On rollback, `/etc/shadow` becomes world-readable.
- **Remediation:** Include `file_permissions`, `file_owner_uid`, and `file_owner_gid` in the hash computation:
  ```rust
  hash_context.update(&file_state.file_permissions.to_be_bytes());
  hash_context.update(&file_state.file_owner_uid.to_be_bytes());
  hash_context.update(&file_state.file_owner_gid.to_be_bytes());
  ```
- **Status:** Open

---

## 8. Audit Log Integrity

### SA-064: Audit Log Path Passed as &str Without Validation
- **Severity:** Low
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `crates/hardener-state/src/audit.rs:225`
- **Description:** `AuditLogger::new(log_path: &str)` accepts an arbitrary string path and opens it in append mode with `OpenOptions::new().create(true).append(true)`. There is no validation that the path is within an expected logging directory. The same applies to `verify_integrity(log_path)` and `query(log_path)`.
- **Attack Scenario:** If a caller passes a user-controlled log path, the audit logger could be directed to append to arbitrary files (e.g., appending JSON to a shell script). In the current codebase, the log path appears to be hardcoded by callers, mitigating the risk.
- **Remediation:** Validate the log path is within an expected directory (e.g., `/var/log/hardener/`). Consider taking a `&Path` instead of `&str` and performing canonicalization.
- **Status:** Open

### SA-065: Hash Chain Restarted From Genesis on Each AuditLogger Instantiation
- **Severity:** Medium
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
- **Location:** `crates/hardener-state/src/audit.rs:233-236`
- **Description:** `AuditLogger::new()` always initializes the `HashChain` with `HashChain::new()` (genesis zero hash). It does not read the existing log file to determine the last hash. This means if the application restarts, the hash chain restarts from the genesis hash. An attacker who appends entries to the log between restarts can create valid-looking entries because the verification walks the whole file and would detect the discontinuity -- but only the entries _within_ a single session are chained. The verification in `verify_integrity()` reads from the beginning and walks the chain, so it would detect a session break as a hash mismatch.

  However, this also means that **every application restart produces a verification failure** for the first entry of the new session, since its `previous_hash` is the genesis hash but the actual previous entry has a different hash. This makes `verify_integrity()` return `false` after any restart, rendering the tamper detection useless in practice.
- **Attack Scenario:** The audit log always fails verification after the first restart, causing operators to ignore verification failures ("it always fails"). An attacker then tampers with the log knowing verification results are ignored.
- **Remediation:** On startup, read the last entry from the existing log file and initialize the `HashChain` with its hash value. If the log file doesn't exist, start from genesis.
- **Status:** Open

---

## 9. Deserialization & Data Integrity

### SA-066: Corrupted JSON in scan_findings Silently Produces Empty Vectors
- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `crates/hardener-state/src/scan_manager.rs:232-245`
- **Description:** When loading scan findings from the database, `remediation_steps` and `compliance_mappings` are deserialized from JSON strings. If the JSON is corrupted, the code logs a warning and returns an empty `Vec`. Similarly, `policy_exception` silently returns `None` on parse failure (line 248). This means corrupted data is silently dropped rather than surfaced as an error.
- **Attack Scenario:** Database corruption (or intentional modification) causes findings to appear as having no remediation steps or compliance mappings. This could mislead operators into thinking an issue is less serious than it is.
- **Remediation:** Consider returning an error for corrupted data rather than empty defaults, or at minimum include a visual indicator in the UI that data was corrupted.
- **Status:** Open

### SA-067: Config Directives Not Validated Before Use in Plugin Apply
- **Severity:** Medium
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `crates/hardener-core/src/config.rs:53` (HashMap<String, String>), multiple plugin apply() methods
- **Description:** `PluginConfig.directives` is a `HashMap<String, String>` deserialized directly from the TOML config file. Plugin `apply()` methods use these values without validation. For example, the permissions plugin (permissions/mod.rs:357) parses octal mode strings with `u32::from_str_radix(mode_str, 8).unwrap_or(directive.permission_mode)` -- invalid values silently fall back to defaults. The kernel plugin writes directive values directly to `/proc/sys/` files. The firewall plugin uses directive values for port, source, protocol, and action fields (firewall/mod.rs:155-167) which are passed to backend commands.
- **Attack Scenario:** An attacker who controls the user config TOML sets `firewall.directives."ssh.port" = "; rm -rf /"`. If the firewall backend passes this value unsanitized to a shell command, it becomes a command injection. (Note: the current backends appear to use structured command arguments rather than shell expansion, partially mitigating this.)
- **Remediation:** Add validation functions for each directive type. Sysctl values should match `^[0-9]+$`. Permission modes should match `^[0-7]{3,4}$`. Firewall ports should match `^[0-9]+(-[0-9]+)?$`. Reject invalid values at config load time rather than at apply time.
- **Status:** Open

### SA-068: User Config Loaded Without Integrity Check
- **Severity:** Low
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-core/src/config_loader.rs:60-63`
- **Description:** The user config file (`~/.config/linux-hardener/config.toml`) is loaded and merged with higher precedence than the system config. Since this file is in the user's home directory, it can be modified by the user or any process running as that user. While this is by design (users can customize their hardening profile), it means a compromised user account can weaken hardening for all subsequent operations, including privileged ones via pkexec.
- **Attack Scenario:** Malware running as the user modifies `~/.config/linux-hardener/config.toml` to add exceptions for all security checks. The next GUI-initiated hardening operation uses pkexec but applies the weakened configuration.
- **Remediation:** When running as root (via pkexec), only load the system config (`/etc/linux-hardener/config.toml`) and ignore user config. The CLI `--config` flag should take precedence, but default operation should not trust user-writable config for root-level operations.
- **Status:** Open

---

## 10. Summary Matrix

| ID | Severity | CWE | Component | Finding |
|----|----------|-----|-----------|---------|
| SA-042 | Critical | CWE-345 | manager.rs:602 | Checkpoint signature never verified before rollback |
| SA-043 | Critical | CWE-22 | manager.rs:530 | Rollback writes to arbitrary paths as root |
| SA-044 | High | CWE-367 | manager.rs:551 | Rollback uses non-atomic fs::write() |
| SA-045 | Medium | CWE-755 | manager.rs:607 | Partial rollback leaves inconsistent state |
| SA-046 | Medium | CWE-59 | manager.rs:63 | Checkpoint capture follows symlinks |
| SA-047 | Low | CWE-404 | manager.rs:506 | delete_checkpoint not transactional |
| SA-048 | High | CWE-22 | local.rs:41 | LocalExecutor::write_file() non-atomic, no path validation |
| SA-049 | Medium | CWE-367 | permissions/mod.rs:196 | Permissions TOCTOU between check and chmod |
| SA-050 | Medium | CWE-367 | file_utils.rs:296 | Backup file race with predictable path |
| SA-051 | Medium | CWE-22 | kernel/mod.rs:331 | sysctl path construction from config |
| SA-052 | Low | CWE-22 | audit/mod.rs:304 | Audit rules backup path symlink |
| SA-053 | Medium | CWE-367 | manager.rs:68 | Checkpoint TOCTOU between exists() and read() |
| SA-054 | Medium | CWE-367 | ssh/mod.rs:369 | Read-modify-write race on sshd_config |
| SA-055 | Medium | CWE-367 | signing.rs:86 | Signing key write-then-chmod race |
| SA-056 | Medium | CWE-732 | file_utils.rs:30 | Atomic write does not preserve file permissions |
| SA-057 | Low | CWE-459 | json_store.rs:48 | JsonStore non-atomic write |
| SA-058 | Medium | CWE-1286 | db.rs:99 | PRAGMA foreign_keys never enabled |
| SA-059 | Medium | CWE-362 | manager.rs:342 | DB operations not wrapped in transactions |
| SA-060 | Info | N/A | All SQL files | Parameterized queries throughout (positive) |
| SA-061 | Medium | CWE-276 | commands.rs:222 | User-writable database feeds root-level rollback |
| SA-062 | High | CWE-522 | signing.rs:16, db.rs:10 | Signing key co-located with checkpoint DB |
| SA-063 | Medium | CWE-345 | manager.rs:222 | Signature does not cover permissions/ownership |
| SA-064 | Low | CWE-22 | audit.rs:225 | Audit log path not validated |
| SA-065 | Medium | CWE-354 | audit.rs:233 | Hash chain resets on restart, breaks verification |
| SA-066 | Low | CWE-20 | scan_manager.rs:232 | Corrupted JSON silently produces empty data |
| SA-067 | Medium | CWE-20 | config.rs:53 | Config directives not validated before plugin use |
| SA-068 | Low | CWE-345 | config_loader.rs:60 | User config loaded for root operations |

**Totals:** 27 findings (2 Critical, 3 High, 14 Medium, 7 Low, 1 Informational)

### Priority Remediation Order

1. **SA-042 + SA-043** (Critical): Fix together -- verify signature before rollback AND validate paths against allowlist. These are the highest-impact findings; together they enable arbitrary file write as root from a compromised database.
2. **SA-062** (High): Move signing key to a separate, more restricted location.
3. **SA-063** (Medium): Include permissions/ownership in signature hash -- easy fix, high value.
4. **SA-044 + SA-048** (High): Replace `fs::write()` with atomic write in rollback and LocalExecutor.
5. **SA-059 + SA-058** (Medium): Add transactions and enable foreign key enforcement.
6. **SA-055 + SA-056** (Medium): Fix permission races in key creation and atomic writes.
7. **Remaining Medium/Low findings** in priority order by exploitability.
