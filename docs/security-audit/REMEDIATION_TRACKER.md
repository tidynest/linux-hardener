# Remediation Tracker -- Linux System Hardener Security Audit

**Version:** 1.0
**Date:** 2026-02-25
**Source:** `SECURITY_AUDIT_REPORT.md` (consolidated from 6 domain agent reports)

---

## 1. Priority Order

Findings are ordered by remediation priority, which considers severity, cascade impact (one fix resolving multiple findings), and realistic exploitability. Fixes earlier in the list should be implemented first.

### Remediation Table

| Priority | SAM-ID | Severity | Title | Effort | Cascade Fixes | Status |
|----------|--------|----------|-------|--------|---------------|--------|
| 1 | SAM-001 | Critical | Checkpoint signature never verified before rollback | S | SAM-032 (partially) | Fixed |
| 2 | SAM-002 | Critical | Rollback writes to arbitrary paths as root | S | -- | Fixed |
| 3 | SAM-012 | High | Signature does not cover permissions/ownership | S | SAM-056 (related) | Fixed |
| 4 | SAM-005 | High | SSH executor uses shell-interpreted raw commands | L | SAM-006, SAM-007, SAM-008, SAM-048 | Fixed |
| 5 | SAM-009 | High | Config directive values flow unsanitised to commands | M | SAM-021, SAM-049 (partially) | Fixed |
| 6 | SAM-011 | High | Signing key co-located with checkpoint DB | S | SAM-014 (partially) | Fixed |
| 7 | SAM-003 | Critical | AuditLogger never instantiated in production | M | SAM-013, SAM-031 (enables) | Fixed |
| 8 | SAM-004 | Critical | JSON store hash never verified in production | S | -- | Fixed |
| 9 | SAM-015 | Medium | No IPC input validation before pkexec | M | SAM-077, SAM-078 | Fixed |
| 10 | SAM-016 | Medium | Config path traversal to root process | S | SAM-071 | Fixed |
| 11 | SAM-010 | High | SSRF via webhook URL | M | -- | Fixed |
| 12 | SAM-024 | Medium | Signing key TOCTOU permission race | S | -- | Fixed |
| 13 | SAM-026 | Medium | Parent dir default permissions | S | -- | Fixed |
| 14 | SAM-027 | Medium | SQLite DB default permissions | S | -- | Fixed |
| 15 | SAM-013 | High | Hash chain resets on restart | M | -- | Fixed |
| 16 | SAM-028 | Medium | DB operations not in transactions | M | -- | Fixed |
| 17 | SAM-029 | Medium | Foreign keys not enforced | S | -- | Fixed |
| 18 | SAM-017 | Medium | Binary path TOCTOU and PATH fallback | M | -- | Fixed |
| 19 | SAM-025 | Medium | Atomic write loses file permissions | S | -- | Fixed |
| 20 | SAM-038 | Medium | withGlobalTauri exposes IPC | S | SAM-039 (related) | Fixed |
| 21 | SAM-042 | Medium | No concurrency guards on privileged ops | S | -- | Fixed |
| 22 | SAM-044 | Medium | No rate limiting on pkexec commands | M | -- | Fixed |
| 23 | SAM-043 | Medium | SSH key file path credential exfiltration | S | -- | Fixed |
| 24 | SAM-040 | Medium | Export report arbitrary file write | S | -- | Fixed |
| 25 | SAM-033 | Medium | Webhook env var leaks secrets | S | -- | Fixed |
| 26 | SAM-034 | Medium | Webhook header injection | S | -- | Fixed |
| 27 | SAM-035 | Medium | SMTP hostname injection | S | -- | Fixed |
| 28 | SAM-036 | Medium | CSV formula injection | S | -- | Fixed |
| 29 | SAM-037 | Medium | No config file size limit | S | SAM-062 (related) | Fixed |
| 30 | SAM-030 | Medium | Private key unencrypted at rest | M | -- | Fixed |
| 31 | SAM-014 | High | No signing trust separation | L | -- | Fixed |
| 32 | SAM-018 | Medium | Partial rollback inconsistency | M | -- | Fixed |
| 33 | SAM-019 | Medium | Checkpoint capture follows symlinks | S | -- | Fixed |
| 34 | SAM-020 | Medium | Backup file symlink race | S | SAM-050 (same pattern) | Fixed |
| 35 | SAM-022 | Medium | Checkpoint TOCTOU exists-then-read | S | -- | Fixed |
| 36 | SAM-023 | Medium | Config read-modify-write race | M | -- | Fixed |
| 37 | SAM-041 | Medium | Mutex deadlock risk in async | S | -- | Fixed |
| 38 | SAM-045 | Medium | Permissions TOCTOU | M | -- | Fixed |
| 39 | SAM-046 | Medium | SSH no-verify missing warning | S | -- | Fixed |
| 40 | SAM-032 | Medium | GUI checkpoint display no verification | M | -- | Fixed |
| 41 | SAM-047 | Low | Non-atomic write_file | S | -- | Fixed |
| 42 | SAM-060 | Low | Bare command names / env inheritance | M | -- | Fixed |
| 43 | SAM-053 | Low | User config for root operations | M | -- | Fixed |
| 44 | SAM-052 | Low | Corrupted JSON silent fallback | S | -- | Fixed |
| 45 | SAM-058 | Low | HTML report unescaped fields | S | SAM-059 (same fix pattern) | Fixed |
| 46 | SAM-069 | Low | Error messages contain internal paths | M | SAM-068, SAM-075 (same pattern) | Fixed |
| 47 | SAM-057 | Low | Key bytes not zeroed | S | -- | Fixed |
| 48 | SAM-054 | Low | No key rotation | L | -- | Fixed |
| 49 | SAM-055 | Low | Non-constant-time hash compare | S | -- | Fixed |
| 50+ | Remaining | Low | See sections below | S-M | -- | Partially Fixed |

**Effort Key:** S = Small (< 1 hour, localised change), M = Medium (1-4 hours, touches multiple files), L = Large (> 4 hours, architectural change)

---

## 2. Quick Wins

These findings can be fixed with minimal, localised code changes -- often a single function or a few lines. They should be addressed first within each severity tier.

| SAM-ID | Severity | Fix Description | Estimated Lines Changed |
|--------|----------|----------------|------------------------|
| SAM-001 | Critical | Add `signer.verify()` call in `rollback()` before file writes | ~15 lines in `manager.rs` |
| SAM-002 | Critical | Add path allowlist check in `restore_file_state_tracked()` | ~20 lines in `manager.rs` |
| SAM-012 | High | Add `file_permissions`, `file_owner_uid`, `file_owner_gid` to hash in `generate_signature()` | ~6 lines in `manager.rs` |
| SAM-004 | Critical | Add `JsonStore::verify()` call in read path | ~5 lines in `runner.rs` |
| SAM-024 | Medium | Replace `fs::write()` + `set_permissions()` with `OpenOptions::new().mode(0o600).create_new(true)` in `save_key()` | ~8 lines in `signing.rs` |
| SAM-026 | Medium | Replace `create_dir_all()` with `DirBuilder::new().mode(0o700)` | ~4 lines in `signing.rs` + `db.rs` |
| SAM-027 | Medium | Set DB file permissions to `0600` after `init_db()` | ~5 lines in `db.rs` |
| SAM-029 | Medium | Add `PRAGMA foreign_keys = ON;` after connection | ~1 line in `db.rs` |
| SAM-025 | Medium | Read original permissions before `persist()`, restore after | ~8 lines in `file_utils.rs` |
| SAM-010 | High | Add URL scheme validation and IP blocklist in `WebhookNotifier::new()` | ~25 lines in `webhook.rs` |
| SAM-016 | Medium | Validate `config_path` against allowed directories | ~10 lines in `commands.rs` |
| SAM-019 | Medium | Replace `fs::metadata()` with `fs::symlink_metadata()` in `capture_single_file()` | ~3 lines in `manager.rs` |
| SAM-038 | Medium | Change `"withGlobalTauri": true` to `false` | 1 line in `tauri.conf.json` |
| SAM-047 | Low | Replace `fs::write()` with `update_file_atomically()` | ~5 lines each in `local.rs` + `manager.rs` |
| SAM-058 | Low | Add `html_escape()` to severity and framework name | ~4 lines in `html.rs` |
| SAM-055 | Low | Replace `==` with `subtle::ConstantTimeEq` | ~3 lines in `hash_chain.rs` |
| SAM-057 | Low | Add `secret_bytes.zeroize()` after key creation | ~2 lines in `signing.rs` |
| SAM-046 | Medium | Add `eprintln!("WARNING: ...")` when `--ssh-no-verify` is active | ~3 lines in `cli.rs` |
| SAM-036 | Medium | Prefix formula-triggering cells with tab in `escape_csv_field()` | ~5 lines in `csv.rs` |
| SAM-037 | Medium | Add `metadata.len() > 1_048_576` check before `read_to_string()` | ~5 lines in `config_loader.rs` |
| SAM-033 | Medium | Add env var allowlist in `expand_env_vars()` | ~10 lines in `webhook.rs` |
| SAM-034 | Medium | Add regex validation for header keys and values | ~8 lines in `webhook.rs` |
| SAM-041 | Medium | Replace `std::sync::Mutex` with `tokio::sync::Mutex` | ~5 lines in `commands.rs` |
| SAM-042 | Medium | Add `AtomicBool` operation lock | ~15 lines in `commands.rs` |
| SAM-056 | Low | Sort file states by path before hashing | ~3 lines in `manager.rs` |

---

## 3. Architectural Changes

These findings require design-level changes that touch multiple components or alter fundamental patterns.

### 3.1 SSH Executor Rewrite (SAM-005)

**Resolves:** SAM-005, SAM-006, SAM-007, SAM-008, SAM-048

**Description:** Replace `session.raw_command()` with `session.command().arg()` for all SSH operations. For file transfers, use SFTP via `openssh-sftp-client` instead of shell-based `cat`/`tee`. This eliminates the entire class of SSH command injection vulnerabilities.

**Scope:**
- Rewrite `SshExecutor` methods: `read_file`, `read_file_optional`, `write_file`, `path_exists`, `file_metadata`, `execute_command`
- Add `openssh-sftp-client` dependency
- Update all plugin code that calls `execute_command` to ensure arguments are properly separated
- Comprehensive testing against actual SSH servers

**Estimated Effort:** Large (8-16 hours)

---

### 3.2 Config Directive Validation Framework (SAM-009)

**Resolves:** SAM-009, SAM-021, SAM-049 (partially)

**Description:** Add a validation layer at config load time that validates directive values against per-plugin schemas. Each plugin defines its allowed directive keys and value patterns. Invalid values are rejected at load time rather than at apply time.

**Scope:**
- Define `DirectiveValidator` trait or validation functions per plugin
- Add validation call in `ConfigLoader::load()` after merge
- Define regex patterns: sysctl values `^[0-9]+$`, permission modes `^[0-7]{3,4}$`, firewall ports `^[0-9]+(-[0-9]+)?$`, SSH directives (single-token, no newlines), PAM values (single-line, numeric)
- Reject directive values containing shell metacharacters or newlines

**Estimated Effort:** Medium (4-8 hours)

---

### 3.3 Signing Trust Separation (SAM-014, SAM-011)

**Resolves:** SAM-014, SAM-011

**Description:** Separate the signing key from the verification path. Store the signing key in a different location from the checkpoint database. Consider embedding the public key hash in the binary for independent verification.

**Scope:**
- Move signing key to `/etc/linux-hardener/signing.key` (or separate directory)
- Implement public-key-only verification mode
- Add key versioning to checkpoints table
- Migration path for existing installations

**Estimated Effort:** Large (8-16 hours)

---

### 3.4 Audit Logger Integration (SAM-003, SAM-013)

**Resolves:** SAM-003, SAM-013, SAM-031

**Description:** Wire up `AuditLogger` in all production code paths and fix the hash chain restart behaviour. Create a shared logger instance and pass it through the execution context.

**Scope:**
- Fix `AuditLogger::new()` to recover chain state from existing log
- Fix timestamp TOCTOU (compute once, pass to both hash and entry)
- Add `AuditLogger` to `Context` or create a static instance
- Add `log_action()` calls in: CLI apply, rollback, checkpoint create/delete
- Add `log_action()` calls in: Tauri IPC commands
- Set audit log file permissions to `0600`

**Estimated Effort:** Medium-Large (6-12 hours)

---

### 3.5 IPC Input Validation Layer (SAM-015, SAM-016)

**Resolves:** SAM-015, SAM-016, SAM-040, SAM-043, SAM-071, SAM-072, SAM-077, SAM-078

**Description:** Create a centralised input validation layer in the Tauri backend that validates all IPC parameters before they are used in operations or passed to pkexec.

**Scope:**
- Create `validate_plugin_id()`, `validate_checkpoint_id()`, `validate_checkpoint_name()`, `validate_config_path()`, `validate_output_path()`, `validate_ipc_string()` helpers
- Apply validation in every `#[tauri::command]` function
- Add `"--"` separator before positional arguments in pkexec commands
- Restrict SSH key file paths to `~/.ssh/`
- Restrict config paths to known config directories
- Restrict export paths to safe directories

**Estimated Effort:** Medium (4-8 hours)

---

## 4. Defence in Depth

These are lower-priority findings that improve overall security posture without
addressing immediate vulnerabilities. All are now resolved except one explicitly
deferred item (SAM-039). The **Status** column replaces the original scheduling
hints, reconciled against the §1 Remediation Table (items also tracked there) and
[remaining-work.md](../plans/remaining-work.md) §2 for the six items unique to this
section (SAM-061/062/063/070/074/076), then spot-verified in code.

| SAM-ID | Category | Description | Status |
|--------|----------|-------------|--------|
| SAM-030 | Key Management | Encrypt private key at rest with passphrase-derived key | Fixed |
| SAM-054 | Key Management | Implement key versioning and rotation | Fixed |
| SAM-060 | Environment | Use absolute paths for all system commands | Fixed |
| SAM-061 | Environment | Use passwd lookup instead of HOME env var | Fixed |
| SAM-053 | Config Trust | Ignore user config when running as root via pkexec | Fixed |
| SAM-039 | Capability | Define explicit Tauri capability ACLs for custom commands | **Deferred** (post-v1.0) |
| SAM-044 | Rate Limiting | Add minimum interval between privileged operations | Fixed |
| SAM-035 | Email | Sanitise hostname in email subject | Fixed |
| SAM-020 | File Safety | Use O_CREAT O_EXCL for backup file creation | Fixed (randomised suffix, no-dereference) |
| SAM-022 | TOCTOU | Open file once for both metadata and content in capture | Fixed |
| SAM-023 | TOCTOU | Add flock() for config read-modify-write cycles | Fixed |
| SAM-045 | TOCTOU | Use fchmod() with O_NOFOLLOW for permissions changes | Fixed |
| SAM-018 | Rollback | Implement two-phase rollback with pre-validation | Fixed |
| SAM-032 | GUI | Show signature verification status in checkpoint list | Fixed |
| SAM-069 | Error Handling | Map internal errors to user-friendly messages | Fixed |
| SAM-052 | Data Integrity | Return errors for corrupted JSON instead of empty defaults | Fixed |
| SAM-062 | DoS | Bound directive/exception map sizes after parsing | Fixed |
| SAM-063 | Config | Validate env var override plugin IDs against registry | Fixed |
| SAM-070 | CSP | Remove unsafe-inline from style-src if possible | Fixed |
| SAM-074 | Frontend | Validate theme from localStorage against allowlist | Fixed |
| SAM-076 | Code Quality | Standardise IPC parameter key casing | Fixed |

> **SAM-039 (deferred):** explicit per-command Tauri capability ACLs require
> refactoring all custom commands into a dedicated Tauri plugin. The current
> `default.json` capability grants only `core:default` + `dialog:default`; the
> existing `PrivilegedOpGuard` + pkexec + IPC input validation is sufficient for
> the v1.x threat model. Revisit post-v1.0 — see
> [remaining-work.md](../plans/remaining-work.md) §2.

---

## 5. Implementation Phases

### Phase 1: Critical Path (Estimated: 2-3 days)

Fix the rollback attack chain and dead crypto verification:

1. SAM-001: Add signature verification before rollback
2. SAM-002: Add path allowlist in rollback
3. SAM-012: Extend signature to cover permissions/ownership
4. SAM-004: Wire up JSON store hash verification
5. SAM-024 + SAM-026 + SAM-027: Fix file/directory permission creation

### Phase 2: Injection Prevention (Estimated: 3-5 days)

Eliminate command injection and input validation gaps:

6. SAM-005: Rewrite SSH executor (architectural -- resolves SAM-006/007/008/048)
7. SAM-009: Add config directive validation framework
8. SAM-015 + SAM-016: Add IPC input validation layer
9. SAM-010: Add webhook URL validation with SSRF protection

### Phase 3: Integrity Infrastructure (Estimated: 2-3 days)

Enable the audit trail and fix signing:

10. SAM-003 + SAM-013: Wire up AuditLogger and fix hash chain
11. SAM-011: Move signing key to separate location
12. SAM-028 + SAM-029: Add transactions and foreign key enforcement

### Phase 4: Frontend Hardening (Estimated: 1-2 days)

Tighten the frontend trust boundary:

13. SAM-038: Disable withGlobalTauri
14. SAM-042: Add operation serialisation lock
15. SAM-043: Validate remote host profile fields
16. SAM-040: Validate export report output path
17. SAM-017: Fix binary path resolution

### Phase 5: Defence in Depth (Ongoing)

Address remaining Medium, Low, and Informational findings as part of regular development cycles.

---

## 6. Verification Criteria

Each fix should be verified against these criteria before marking as complete:

- [ ] Unit test added that exercises the fix
- [ ] Attack scenario from the finding is no longer reproducible
- [ ] No regression in existing test suite (648+ tests)
- [ ] Clippy passes with `-D clippy::unwrap_used`
- [ ] Both native and WASM builds compile cleanly
- [ ] Cross-distro test suite passes (if applicable)

---

*End of Remediation Tracker*
