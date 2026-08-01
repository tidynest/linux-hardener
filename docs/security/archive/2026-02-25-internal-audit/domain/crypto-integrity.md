# Security Audit: Cryptography & Integrity

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Agent:** 4 -- Crypto & Integrity
**Date:** 2026-02-25
**Scope:** Ed25519 signing, SHA-256 hash chain, key management, randomness, checkpoint integrity, audit log integrity, JSON store integrity
**Files audited:** 14 source files across `hardener-state`, `hardener-scheduler`, `hardener-cli`, `hardener-core`, `src-tauri`

---

## Executive Summary

The cryptographic subsystem has **correct algorithm choices** (Ed25519, SHA-256, CSPRNG via `rand 0.9.2`) and uses well-maintained crates (`ed25519-dalek 2.2.0`, `ring 0.17.14`). However, the signing and integrity verification mechanisms are **never invoked in production code paths**, reducing the entire crypto layer to security theatre. Signatures are generated and stored but never verified before rollback. The audit log hash chain resets on every process restart, and the `AuditLogger` itself is never instantiated outside tests. These are systemic design gaps, not implementation bugs.

**Finding Count:** 18 findings (3 Critical, 4 High, 7 Medium, 3 Low, 1 Informational)

---

## Table of Contents

1. [Validation of Prior Findings](#1-validation-of-prior-findings)
2. [Signature Verification Gaps](#2-signature-verification-gaps)
3. [Key Management](#3-key-management)
4. [Hash Chain Integrity](#4-hash-chain-integrity)
5. [Audit Logger](#5-audit-logger)
6. [Serialisation & Canonicalisation](#6-serialisation--canonicalisation)
7. [Database Integrity](#7-database-integrity)
8. [JSON Store Integrity](#8-json-store-integrity)
9. [Dependency Audit](#9-dependency-audit)
10. [Memory Safety of Key Material](#10-memory-safety-of-key-material)

---

## 1. Validation of Prior Findings

### SA-004 / SA-042 -- CONFIRMED and DEEPENED

**Original claim:** `signer.verify()` exists but has zero production call sites; rollback never checks signatures.

**Verification:** Exhaustive `grep` across all 11 crates confirms `signer.verify()` appears only in `crates/hardener-state/tests/signing_tests.rs` (5 call sites, all test code). The production `rollback()` method at `crates/hardener-state/src/manager.rs:602` calls `self.get_checkpoint()` which retrieves the signature from the database but **discards it**. The `Checkpoint` struct carries `checkpoint_signature: Vec<u8>` but no consumer reads it.

**Deepened finding:** Even `get_checkpoint()` faithfully loads the signature at line 431 (`checkpoint_signature: checkpoint_row.get("signature")`), creating the false impression of verification readiness. The signature flows into the `Checkpoint` struct, gets serialised to JSON for the GUI, and is never verified anywhere in the entire call chain: CLI rollback (`crates/hardener-cli/src/commands/checkpoint.rs:95`), Tauri rollback (`src-tauri/src/commands.rs:466`), or the core `CheckpointManager::rollback()`.

### SA-005 / SA-043 -- CONFIRMED (out of crypto scope, but relevant)

Rollback at `manager.rs:550-551` writes `fs::write(path, content)` where both `path` and `content` come from the database. Without signature verification (SA-004), a compromised database leads directly to arbitrary file writes as root.

### SA-055 -- CONFIRMED and DEEPENED

**Original claim:** Signing key created world-readable then chmod'd to 0600 (race window).

**Verification:** At `crates/hardener-state/src/signing.rs:87-91`:
```rust
fs::write(key_path, key_bytes).map_err(HardeningError::System)?;
let permissions = fs::Permissions::from_mode(0o600);
fs::set_permissions(key_path, permissions).map_err(HardeningError::System)?;
```
`fs::write()` creates the file with the process umask (typically `0022`, yielding `0644`). Between `write()` and `set_permissions()`, any local user can read the 32-byte private key. See SA-069 for the deepened analysis.

### SA-062 -- CONFIRMED and DEEPENED

**Original claim:** Signing key co-located with checkpoint database -- single compromise point.

**Verification:** Both are in `/var/lib/linux-hardener/`:
- `signing.key` -- at `signing.rs:16`
- `checkpoints.db` -- at `db.rs:10`

The CLI `get_checkpoint_manager()` at `crates/hardener-cli/src/commands/checkpoint.rs:22-23` constructs both paths in the same directory. Compromising the directory gives access to both the key and the data it is meant to protect. See SA-076 for deepened analysis.

### SA-063 -- CONFIRMED and DEEPENED

**Original claim:** Signature covers only file content, not permissions or ownership.

**Verification:** At `crates/hardener-state/src/manager.rs:211-237`, the `generate_signature()` function hashes:
- `checkpoint_id` (line 217)
- `checkpoint_name` (line 218)
- `checkpoint_timestamp` (line 220)
- `checkpoint_username` (line 221)
- For each file: `file_path` (line 225) and `file_content` (line 227)

It does **not** hash:
- `file_permissions` (mode bits)
- `file_owner_uid`
- `file_owner_gid`

An attacker who modifies permissions/ownership in the database would not be detected even if signature verification were enabled. See SA-077 for full analysis.

### SA-065 -- CONFIRMED and DEEPENED

**Original claim:** Audit hash chain resets on every restart; `verify_integrity()` useless in practice.

**Verification:** At `audit.rs:235`, `AuditLogger::new()` always starts with `HashChain::new()` (genesis: 32 zero bytes). It never reads the existing log to recover the last hash. This means `verify_integrity()` only works correctly if called against a log written in a single process lifetime. After a restart, the next entry's hash is computed against the genesis hash instead of the last entry's hash, breaking the chain. See SA-079 for deepened analysis.

---

## 2. Signature Verification Gaps

### SA-069 -- Checkpoint Signature Never Verified Before Rollback

- **Severity:** Critical
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Location:** `crates/hardener-state/src/manager.rs:602-628`
- **Description:** The `rollback()` method retrieves a checkpoint and its file states from the database, then restores files without verifying the checkpoint's Ed25519 signature. The signature is loaded from the DB at line 431 and stored in `checkpoint.checkpoint_signature` but never passed to `signer.verify()`.
- **Attack Scenario:** An attacker with write access to the SQLite database (e.g., via SQL injection through a compromised extension, local privilege escalation to the db file owner, or physical access) modifies the `content` column in `file_states` and the `file_path` column. On the next rollback, the tampered content is written to arbitrary paths as root. The signature check that would detect this tampering is implemented but never called.
- **Remediation:** Add signature verification in `rollback()` before restoring any files:
  ```rust
  let (checkpoint, file_states) = self.get_checkpoint(checkpoint_id).await?;
  // Recompute the hash of checkpoint data + file states
  let expected_sig = self.generate_signature(
      &checkpoint.checkpoint_id, &checkpoint.checkpoint_name,
      checkpoint.checkpoint_timestamp, &checkpoint.checkpoint_username,
      &file_states,
  )?;
  // Verify the stored signature matches
  self.signer.verify(&expected_sig_hash, &checkpoint.checkpoint_signature)?;
  ```
  Note: `generate_signature` currently signs the hash internally; refactor to separate hash computation from signing so verification can recompute the hash and call `signer.verify()`.
- **Status:** Open

### SA-070 -- Checkpoint Signature Verified by Same Key That Created It

- **Severity:** High
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Location:** `crates/hardener-state/src/signing.rs:115-134`, `crates/hardener-state/src/manager.rs:18-19`
- **Description:** The `CheckpointManager` holds a single `CheckpointSigner` which is used both to sign and (if verification were added) to verify. The same private key that creates signatures is used to derive the verification key. If the signing key is compromised, an attacker can forge valid signatures for tampered checkpoints. There is no separate trust anchor, no public key pinning, and no way to verify checkpoints against a key that the checkpoint manager does not control.
- **Attack Scenario:** Attacker gains read access to `/var/lib/linux-hardener/signing.key` (32 bytes, the full Ed25519 private key). They can now sign arbitrary checkpoint data, completely bypassing integrity verification. Combined with SA-069 (no verification anyway), this is currently theoretical but would remain a flaw even after SA-069 is fixed.
- **Remediation:** Consider separating the signing key from the verification path. Options: (a) store only the public key alongside the database and keep the private key in a more restricted location or HSM; (b) embed the public key in the binary at build time for offline verification; (c) at minimum, store the public key hash in a separate root-only location for cross-verification.
- **Status:** Open

### SA-071 -- No Signature Verification in GUI Checkpoint Read Path

- **Severity:** Medium
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Location:** `src-tauri/src/commands.rs:237-241`, `src-tauri/src/commands.rs:479-519`
- **Description:** The Tauri `create_checkpoint_manager()` helper at line 237 calls `CheckpointManager::new(pool)` which loads the signing key from the default path. The `get_checkpoints()` command at line 479 reads from both user and system databases, listing checkpoints without verifying signatures. A tampered database would display fabricated checkpoint metadata in the GUI.
- **Attack Scenario:** An attacker modifies the user-local database (`~/.local/share/linux-hardener/checkpoints.db`) to insert a malicious checkpoint. The GUI displays it as legitimate. The user triggers rollback on this fake checkpoint, writing attacker-controlled content to system files.
- **Remediation:** Verify signatures when displaying checkpoints in the GUI. Flag unverifiable checkpoints with a warning indicator.
- **Status:** Open

---

## 3. Key Management

### SA-072 -- Key File Created with TOCTOU Permission Race

- **Severity:** Medium
- **CWE:** CWE-377 (Insecure Temporary File) / CWE-362 (Race Condition)
- **Location:** `crates/hardener-state/src/signing.rs:86-91`
- **Description:** The key file is created via `fs::write()` which uses the process umask (typically `0022` on Linux, yielding mode `0644`). The file is then restricted to `0600` via a separate `fs::set_permissions()` call. Between these two operations, the private key is readable by any user in the same group or world-readable depending on umask.
- **Attack Scenario:** On a multi-user system, a local attacker runs an inotify watcher on `/var/lib/linux-hardener/` waiting for `signing.key` to appear. When the file is created, they read the 32-byte Ed25519 private key before permissions are tightened. This is a narrow but exploitable window, especially on systems where the hardener is first installed.
- **Remediation:** Set restrictive permissions before writing:
  ```rust
  use std::fs::File;
  use std::os::unix::fs::OpenOptionsExt;
  let file = std::fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(0o600)
      .open(key_path)?;
  file.write_all(&key_bytes)?;
  ```
  This atomically creates the file with `0600` permissions. The `create_new(true)` flag also prevents overwriting an existing key.
- **Status:** Open

### SA-073 -- Parent Directory Created with Default Permissions

- **Severity:** Medium
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Location:** `crates/hardener-state/src/signing.rs:81-83`, `crates/hardener-state/src/db.rs:95-97`
- **Description:** Both `save_key()` and `init_db()` call `fs::create_dir_all(parent)` without specifying restrictive permissions. The directory `/var/lib/linux-hardener/` is created with the default umask, typically `0755`, making it world-readable. This means any local user can list files in the directory and potentially read the database file.
- **Attack Scenario:** A local attacker can read `/var/lib/linux-hardener/checkpoints.db` (created by SQLite with umask-default permissions) to extract checkpoint file contents, which may include sensitive configuration data like SSH keys or PAM rules.
- **Remediation:** Create the directory with restrictive permissions:
  ```rust
  use std::os::unix::fs::DirBuilderExt;
  std::fs::DirBuilder::new()
      .recursive(true)
      .mode(0o700)
      .create(parent)?;
  ```
- **Status:** Open

### SA-074 -- No Key Rotation Mechanism

- **Severity:** Low
- **CWE:** CWE-324 (Use of a Key Past its Expiration Date)
- **Location:** `crates/hardener-state/src/signing.rs:19-42`
- **Description:** The signing key is generated once and used indefinitely. There is no mechanism to rotate keys, no key version tracking, and no way to re-sign existing checkpoints with a new key. If a key is compromised, there is no recovery path other than deleting the key file (which breaks verification of all existing checkpoints).
- **Attack Scenario:** A key compromise goes undetected for months. All checkpoints created in that period may have been forged. Without key rotation or versioning, there is no way to distinguish pre-compromise from post-compromise checkpoints.
- **Remediation:** Implement key versioning: store a `key_version` column in the checkpoints table, allow key rotation via a CLI command, and verify each checkpoint against the key version it was signed with.
- **Status:** Open

### SA-075 -- Private Key Stored as Raw Bytes Without Encryption

- **Severity:** Medium
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Location:** `crates/hardener-state/src/signing.rs:86-87`
- **Description:** The Ed25519 private key is stored as raw 32 bytes at `/var/lib/linux-hardener/signing.key`. There is no encryption envelope, no passphrase protection, and no key derivation. Anyone who reads the file has the complete private key.
- **Attack Scenario:** A backup process, log aggregation tool, or misconfigured file sharing copies the key file to a less-protected location. The raw bytes are immediately usable without any decryption step.
- **Remediation:** Encrypt the key at rest using a passphrase-derived key (e.g., Argon2 + AES-256-GCM). The `argon2` crate is already a workspace dependency. Alternatively, use OS-level secret storage (e.g., Linux kernel keyring via `keyctl`).
- **Status:** Open

### SA-076 -- Signing Key Co-located with Protected Data

- **Severity:** High
- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **Location:** `crates/hardener-state/src/signing.rs:16`, `crates/hardener-state/src/db.rs:10`
- **Description:** The signing key (`signing.key`) and the checkpoint database (`checkpoints.db`) reside in the same directory (`/var/lib/linux-hardener/`). The key exists solely to protect the integrity of the database contents. Co-locating them means a single directory compromise gives an attacker both the data to tamper with and the key to forge signatures over the tampered data, nullifying the entire signing scheme.
- **Attack Scenario:** An attacker gains write access to `/var/lib/linux-hardener/` (e.g., via a vulnerability in a process running as the same user). They read `signing.key`, modify `checkpoints.db` to inject malicious file content, re-sign the checkpoint, and the integrity check (if it existed) would pass.
- **Remediation:** Store the signing key in a separate location with different access controls. Options: (a) `/etc/linux-hardener/signing.key` (root:root 0400, separate from the data dir); (b) Linux kernel keyring; (c) TPM-backed key storage.
- **Status:** Open

---

## 4. Hash Chain Integrity

### SA-077 -- Signature Does Not Cover Permissions or Ownership

- **Severity:** High
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/manager.rs:211-237`
- **Description:** The `generate_signature()` method hashes checkpoint metadata and file content but excludes `file_permissions`, `file_owner_uid`, and `file_owner_gid`. These values are stored in the database and used during rollback to restore file permissions (`manager.rs:560-562`) and ownership (`manager.rs:571-580`).
- **Attack Scenario:** An attacker modifies `file_states.permissions` in the database to set a file to mode `0777` (world-writable). After rollback, the file is restored with the correct content but world-writable permissions, creating a privilege escalation vector. Even with signature verification enabled, this tampering would go undetected.
- **Remediation:** Include permissions and ownership in the signed hash:
  ```rust
  for file_state in file_states {
      hash_context.update(file_state.file_path.as_bytes());
      hash_context.update(&file_state.file_permissions.to_be_bytes());
      hash_context.update(&file_state.file_owner_uid.to_be_bytes());
      hash_context.update(&file_state.file_owner_gid.to_be_bytes());
      if let Some(content) = &file_state.file_content {
          hash_context.update(content);
      }
  }
  ```
- **Status:** Open

### SA-078 -- Hash Chain Comparison Uses Non-Constant-Time Equality

- **Severity:** Low
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Location:** `crates/hardener-state/src/hash_chain.rs:75`
- **Description:** The `verify_entry()` function compares hashes using `==` (byte-by-byte with early exit):
  ```rust
  expected_hash.as_ref() == claimed_hash
  ```
  This leaks information about which byte position differs first, potentially allowing a timing side-channel attack to forge valid hashes incrementally.
- **Attack Scenario:** Theoretical in this context -- the hash chain protects an append-only log on the local filesystem. An attacker with network access to a timing oracle (e.g., a remote verification API) could incrementally determine the correct hash. In the current local-only usage, exploitation is impractical, but the code sets a bad precedent.
- **Remediation:** Use constant-time comparison. The `subtle` crate (already a transitive dependency via `ed25519-dalek`) provides `ConstantTimeEq`:
  ```rust
  use subtle::ConstantTimeEq;
  expected_hash.as_ref().ct_eq(claimed_hash).into()
  ```
- **Status:** Open

### SA-079 -- Hash Chain Resets on Every Process Restart

- **Severity:** High
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
- **Location:** `crates/hardener-state/src/audit.rs:233-236`
- **Description:** `AuditLogger::new()` always initialises the hash chain with `HashChain::new()` (genesis hash: 32 zero bytes). It never reads the existing log file to recover the last entry's hash. After a process restart, the next audit entry is chained from the genesis hash instead of the previous entry's hash. This means `verify_integrity()` will report tampering for any log that spans multiple process lifetimes, even if no tampering occurred.
- **Attack Scenario:** Because `verify_integrity()` always fails for multi-session logs, operators learn to ignore its output or stop calling it. An attacker can then freely tamper with audit entries between restart boundaries (inserting, deleting, or modifying entries), knowing that the broken verification provides no meaningful detection. Additionally, an attacker could truncate the log to the last restart boundary and append forged entries starting from the genesis hash -- the chain would verify correctly.
- **Remediation:** On initialisation, read the last entry from the existing log file and recover its hash to continue the chain:
  ```rust
  pub async fn new(log_path: &str) -> Result<AuditLogger> {
      let mut chain = HashChain::new();
      // Recover chain state from existing log
      if let Ok(file) = tokio::fs::File::open(log_path).await {
          let reader = BufReader::new(file);
          let mut lines = reader.lines();
          while let Some(line) = lines.next_line().await? {
              if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                  chain.update(entry.entry_hash);
              }
          }
      }
      // Then open for append
      let file = OpenOptions::new().create(true).append(true).open(log_path).await?;
      Ok(AuditLogger { file: Mutex::new(file), hash_chain: Mutex::new(chain) })
  }
  ```
- **Status:** Open

---

## 5. Audit Logger

### SA-080 -- AuditLogger Never Instantiated in Production

- **Severity:** Critical
- **CWE:** CWE-778 (Insufficient Logging)
- **Location:** All production call sites (searched: `hardener-cli`, `hardener-core`, `hardener-plugins`, `hardener-scheduler`, `src-tauri`)
- **Description:** The `AuditLogger` struct, its `log_action()` and `log_failure()` methods, and its `verify_integrity()` method are never called outside of test files. No audit entries are ever written during production scan, apply, rollback, or configuration operations. The entire tamper-proof audit logging system is dead code in production.
- **Attack Scenario:** An attacker performs destructive operations (rollback to a malicious checkpoint, applying harmful hardening rules) with zero audit trail. There is no forensic evidence of what was done, when, or by whom.
- **Remediation:** Integrate `AuditLogger` into the critical code paths:
  - CLI `apply` command: log each plugin apply with result
  - CLI `rollback` command: log checkpoint ID and success/failure
  - CLI `checkpoint create/delete`: log creation and deletion
  - Tauri commands: log IPC-triggered operations
  Create a shared `AuditLogger` instance (e.g., in `Context` or as a static) and pass it through the call chain.
- **Status:** Open

### SA-081 -- Audit Log File Created Without Restrictive Permissions

- **Severity:** Medium
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Location:** `crates/hardener-state/src/audit.rs:227-231`
- **Description:** The audit log file is created via `OpenOptions::new().create(true).append(true).open(log_path)` without specifying restrictive permissions. The file is created with the default umask, typically `0644`, making it world-readable. The audit log may contain sensitive information (usernames, file paths, error messages).
- **Attack Scenario:** A local attacker reads the audit log to learn which files were modified by the hardener, which checkpoint IDs exist, and which operations failed, providing reconnaissance for a targeted attack on the checkpoint database.
- **Remediation:** Set permissions to `0600` on creation using `OpenOptionsExt::mode(0o600)`, similar to the fix for SA-072.
- **Status:** Open

---

## 6. Serialisation & Canonicalisation

### SA-082 -- Hash Input Uses Non-Canonical Serialisation

- **Severity:** Medium
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/audit.rs:260-261`, `crates/hardener-state/src/audit.rs:305-312`
- **Description:** The data hashed for the audit chain is a `serde_json::to_vec()` serialisation of a tuple. JSON serialisation via `serde_json` produces deterministic output for the same Rust types, but the hash input structure differs between `log_action()` (5-element tuple) and `log_failure()` (6-element tuple). The `verify_integrity()` function must reverse-engineer which serialisation format was used by checking `entry.entry_result`. More critically, the timestamp used for hashing (`Utc::now().timestamp()` at line 260) differs from the timestamp stored in `AuditEntry` (`Utc::now()` at `AuditEntry::new()` line 69), because `Utc::now()` is called twice -- once for the hash input and once for the entry constructor.
- **Attack Scenario:** The TOCTOU between the two `Utc::now()` calls means the hashed timestamp (seconds precision) and the stored timestamp can differ by up to 1 second at a second boundary. During verification, the code uses `entry.entry_timestamp.timestamp()` (derived from the stored timestamp), which may not match the value that was originally hashed. This can cause false-positive tampering alerts, eroding trust in the verification system.
- **Remediation:** Compute the timestamp once and pass it to both the hash computation and the entry constructor. Use a canonical serialisation format (e.g., deterministic CBOR or a purpose-built byte layout) rather than relying on JSON tuple serialisation.
- **Status:** Open

### SA-083 -- Signature Input Order Depends on FileState Iteration Order

- **Severity:** Low
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Location:** `crates/hardener-state/src/manager.rs:224-229`
- **Description:** The `generate_signature()` function iterates over `file_states` in the order they are provided. If file states are reordered (e.g., due to filesystem readdir ordering changes between capture and verification), the hash would differ even though the same files are present. Currently this is not exploitable because files are stored and retrieved in database insertion order, but it makes the signature fragile.
- **Attack Scenario:** No immediate exploit, but a future code change that sorts or reorders file states before verification would silently break signature verification without any test catching it.
- **Remediation:** Sort `file_states` by `file_path` before hashing to ensure canonical ordering, or include a file count and per-file separators in the hash input.
- **Status:** Open

---

## 7. Database Integrity

### SA-084 -- SQLite Database Created Without Restrictive Permissions

- **Severity:** Medium
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Location:** `crates/hardener-state/src/db.rs:100-102`
- **Description:** The SQLite database is created by `sqlx` via `SqliteConnectOptions::new().create_if_missing(true)`. SQLite creates the file with the process umask, typically yielding `0644`. The database contains sensitive data: full file contents of `/etc/ssh/sshd_config`, `/etc/pam.d/*`, audit rules, and other security-critical configuration files stored as BLOBs in the `file_states.content` column.
- **Attack Scenario:** A local unprivileged user reads `/var/lib/linux-hardener/checkpoints.db` and extracts SSH configuration, PAM rules, and other sensitive system configuration from checkpoint snapshots.
- **Remediation:** Set the database file permissions to `0600` after creation. Additionally, consider enabling SQLite encryption (e.g., SQLCipher) for data-at-rest protection.
- **Status:** Open

### SA-085 -- No Foreign Key Enforcement in SQLite

- **Severity:** Informational
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `crates/hardener-state/src/db.rs:13-78`
- **Description:** The schema defines `FOREIGN KEY` constraints, but SQLite does not enforce them by default. The `PRAGMA foreign_keys = ON` statement is never executed. This means the `file_states.checkpoint_id` foreign key is not enforced, allowing orphaned file states or file states referencing non-existent checkpoints.
- **Attack Scenario:** An attacker or bug creates file state rows with arbitrary `checkpoint_id` values. While not directly a crypto issue, it weakens the integrity model that the signing system is meant to protect.
- **Remediation:** Add `PRAGMA foreign_keys = ON;` as the first statement in the schema, or set it via the SQLite connection options.
- **Status:** Open

---

## 8. JSON Store Integrity

### SA-086 -- JSON Store Hash Never Verified in Production

- **Severity:** Critical
- **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
- **Location:** `crates/hardener-scheduler/src/json_store.rs:88-94`, `crates/hardener-scheduler/src/runner.rs:240-253`
- **Description:** The `JsonStore::write()` method returns `(file_path, sha256_hash)`. The runner at `runner.rs:240-253` stores the hash in the database via `complete_session()`. However, the `JsonStore::verify()` method that checks a file against its stored hash is **never called in production code** -- it only appears in test files (`json_store.rs:161-162`). This means JSON scan exports could be tampered with on disk and the tampering would never be detected.
- **Attack Scenario:** An attacker modifies exported JSON scan files to hide critical findings or inject false findings. When these files are consumed by external tools or compliance auditors, they see fabricated data. The stored hash exists in the database but is never checked.
- **Remediation:** Verify the hash when reading JSON files back. Add verification to any code path that consumes stored scan exports.
- **Status:** Open

---

## 9. Dependency Audit

All cryptographic dependencies are current and well-maintained:

| Crate | Version | Status |
|-------|---------|--------|
| `ed25519-dalek` | 2.2.0 | Current (latest: 2.2.0). Uses `zeroize` for key material. |
| `ring` | 0.17.14 | Current. Used for SHA-256 digest. |
| `rand` | 0.9.2 | Current. Uses `rand_chacha` (ChaCha20-based CSPRNG) backed by `getrandom`. |
| `curve25519-dalek` | 4.1.3 | Current (transitive). Uses `subtle` for constant-time operations. |

**Randomness quality:** `rand 0.9.2` uses `rand_chacha 0.9.0` with `getrandom` backend, which reads from `/dev/urandom` on Linux. This is cryptographically secure. The `rand::rng().fill_bytes()` call at `signing.rs:49` correctly uses the thread-local CSPRNG.

**`rand::random::<u32>()`** at `manager.rs:50` and `scan_history.rs:33` uses the same CSPRNG for ID generation. While this is not security-critical (IDs are not secrets), the randomness quality is adequate.

No known CVEs affect the versions in use.

---

## 10. Memory Safety of Key Material

### SA-087 -- Secret Key Bytes Not Zeroed After Use in generate_key()

- **Severity:** Low
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Location:** `crates/hardener-state/src/signing.rs:48-53`
- **Description:** In `generate_key()`, the `secret_bytes` array is filled with random bytes and passed to `SigningKey::from_bytes()`. The `secret_bytes` local variable is not explicitly zeroed after use. While `ed25519-dalek` uses `zeroize` internally for its `SigningKey` (confirmed in `Cargo.lock`: `ed25519-dalek` depends on `zeroize`), the local `secret_bytes` array on the stack is not zeroed and may persist in memory after the function returns.
- **Attack Scenario:** A memory disclosure vulnerability (e.g., in a Tauri webview or FFI boundary) could leak stack memory containing the raw key bytes. The window is small (the function is called once during initialisation) but the key is long-lived.
- **Remediation:** Use `zeroize` on the local buffer:
  ```rust
  use zeroize::Zeroize;
  let mut secret_bytes = [0u8; 32];
  rand::rng().fill_bytes(&mut secret_bytes);
  let signing_key = SigningKey::from_bytes(&secret_bytes);
  secret_bytes.zeroize();
  ```
  Add `zeroize` as a direct dependency of `hardener-state`.
- **Status:** Open

---

## Findings Summary

| ID | Severity | CWE | Location | Title |
|----|----------|-----|----------|-------|
| SA-069 | Critical | CWE-347 | manager.rs:602-628 | Checkpoint signature never verified before rollback |
| SA-070 | High | CWE-295 | signing.rs:115-134 | Signature verified by same key that created it (no trust separation) |
| SA-071 | Medium | CWE-347 | src-tauri/commands.rs:237-241 | No signature verification in GUI checkpoint read path |
| SA-072 | Medium | CWE-377 | signing.rs:86-91 | Key file created with TOCTOU permission race |
| SA-073 | Medium | CWE-276 | signing.rs:81-83, db.rs:95-97 | Parent directory created with default permissions |
| SA-074 | Low | CWE-324 | signing.rs:19-42 | No key rotation mechanism |
| SA-075 | Medium | CWE-312 | signing.rs:86-87 | Private key stored as raw bytes without encryption |
| SA-076 | High | CWE-522 | signing.rs:16, db.rs:10 | Signing key co-located with protected data |
| SA-077 | High | CWE-345 | manager.rs:211-237 | Signature does not cover permissions or ownership |
| SA-078 | Low | CWE-208 | hash_chain.rs:75 | Hash comparison uses non-constant-time equality |
| SA-079 | High | CWE-354 | audit.rs:233-236 | Hash chain resets on every process restart |
| SA-080 | Critical | CWE-778 | (all production code) | AuditLogger never instantiated in production |
| SA-081 | Medium | CWE-276 | audit.rs:227-231 | Audit log file created without restrictive permissions |
| SA-082 | Medium | CWE-345 | audit.rs:260-261 | Hash input uses non-canonical serialisation with TOCTOU |
| SA-083 | Low | CWE-345 | manager.rs:224-229 | Signature input order depends on iteration order |
| SA-084 | Medium | CWE-276 | db.rs:100-102 | SQLite database created without restrictive permissions |
| SA-085 | Informational | CWE-20 | db.rs:13-78 | No foreign key enforcement in SQLite |
| SA-086 | Critical | CWE-354 | json_store.rs:88-94 | JSON store hash never verified in production |
| SA-087 | Low | CWE-316 | signing.rs:48-53 | Secret key bytes not zeroed after use |

**Totals:** 3 Critical, 4 High, 7 Medium, 3 Low, 1 Informational

---

## Priority Remediation Order

1. **SA-069** (Critical) -- Add signature verification before rollback. This is the single highest-impact fix because it gates an arbitrary-file-write-as-root operation.
2. **SA-077** (High) -- Extend signature to cover permissions/ownership. Must be done alongside SA-069 or the verification would still miss metadata tampering.
3. **SA-080** (Critical) -- Wire up AuditLogger in production. Without audit logs, there is no forensic trail.
4. **SA-086** (Critical) -- Wire up JSON store hash verification. Dead verification code provides zero protection.
5. **SA-079** (High) -- Fix hash chain restart behaviour. Without this, the audit hash chain is fundamentally broken.
6. **SA-076** (High) + **SA-072** (Medium) + **SA-073** (Medium) -- Key storage improvements: separate location, atomic creation with correct permissions, directory permissions.
7. **SA-070** (High) -- Trust anchor separation. Longer-term architectural improvement.
8. **SA-084** (Medium) + **SA-081** (Medium) -- File permission hardening for DB and audit log.
9. **SA-075** (Medium) -- Key encryption at rest.
10. Remaining Low/Informational findings.
