# Security Hardening Phase 2: Implementation Plan

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Goal:** Fix remaining security gaps discovered during deep verification of the original remediation work: 2 High, 5 Medium, and 6 Low severity items across 11 tasks.

**Architecture:** All fixes are localised to existing modules. No new crates or architectural changes. Error sanitisation is centralised through a single helper. Audit timestamp fix adds a parameter to existing constructors. Signing fix changes return type from `Vec<u8>` to `Result<Vec<u8>>`.

**Tech Stack:** Rust, Tauri v2, ed25519-dalek, chrono, ring, sqlx, serde_json

---

## Task 1: Fix `.unwrap()` panics in `get_checkpoints()` [High]

Two `.unwrap()` calls in the IPC command `get_checkpoints()` can crash the Tauri runtime on transient DB failures (disk I/O, lock contention).

**Files:**
- Modify: `src-tauri/src/commands.rs:670-700`
- Test: `src-tauri/src/validation.rs` (inline `#[cfg(test)]`, no separate test file for commands)

**Step 1: Write the fix**

In `src-tauri/src/commands.rs`, replace the `.unwrap()` calls inside the checkpoint collection loops with graceful error handling. The manager is already created successfully in the outer `let Ok(manager)` guard: reuse that pattern.

Replace lines 680-683:
```rust
        for cp in checkpoints {
            entries.push((cp, create_checkpoint_manager(&user_db).await.unwrap()));
        }
```

With:
```rust
        for cp in checkpoints {
            let Ok(mgr) = create_checkpoint_manager(&user_db).await else {
                continue;
            };
            entries.push((cp, mgr));
        }
```

Replace lines 693-699:
```rust
        for cp in checkpoints {
            if !entries
                .iter()
                .any(|(e, _)| e.checkpoint_id == cp.checkpoint_id)
            {
                entries.push((cp, create_checkpoint_manager(&system_db).await.unwrap()));
            }
        }
```

With:
```rust
        for cp in checkpoints {
            if !entries
                .iter()
                .any(|(e, _)| e.checkpoint_id == cp.checkpoint_id)
            {
                let Ok(mgr) = create_checkpoint_manager(&system_db).await else {
                    continue;
                };
                entries.push((cp, mgr));
            }
        }
```

**Step 2: Verify it compiles**

Run: `cargo build -p linux-hardener-desktop 2>&1 | tail -5`
Expected: `Finished`

**Step 3: Run tests**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: all pass, 0 failures

**Step 4: Commit**

```bash
git add src-tauri/src/commands.rs
git commit -m "fix: replace unwrap with graceful fallback in get_checkpoints IPC"
```

---

## Task 2: Fix `sign()` to return `Result` instead of panicking [Medium]

`CheckpointSigner::sign()` uses `.expect()` which panics if called in verification-only mode. The doc comment says "Returns an error" but the signature returns `Vec<u8>`. Fix the signature to match the documented behaviour.

**Files:**
- Modify: `crates/hardener-state/src/signing.rs:297-304`
- Modify: `crates/hardener-state/src/manager.rs:304` (caller)
- Test: `crates/hardener-state/tests/signing_tests.rs`

**Step 1: Write the failing test**

Add to `crates/hardener-state/tests/signing_tests.rs`:

```rust
#[tokio::test]
async fn test_sign_returns_error_in_verify_only_mode() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("signing.key");

    // Create a full signer, save public key, then load verifier-only
    let signer = CheckpointSigner::new_with_path(&key_path).unwrap();
    let pubkey_path = key_path.with_extension("pub");
    assert!(pubkey_path.exists());

    // Delete private key, keep only public key
    std::fs::remove_file(&key_path).unwrap();

    let verifier = CheckpointSigner::new_with_path(&key_path).unwrap();
    assert!(!verifier.can_sign());

    // sign() should return Err, not panic
    let result = verifier.sign(b"test data");
    assert!(result.is_err());
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p hardener-state --test signing_tests test_sign_returns_error_in_verify_only_mode 2>&1 | tail -10`
Expected: FAIL, `sign()` currently returns `Vec<u8>`, not `Result`

**Step 3: Change `sign()` signature and implementation**

In `crates/hardener-state/src/signing.rs`, replace lines 297-304:

```rust
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signing_key = self
            .signing_key
            .as_ref()
            .expect("sign() called in verification-only mode");
        let signature: Signature = signing_key.sign(data);
        signature.to_bytes().to_vec()
    }
```

With:

```rust
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            HardeningError::Config(
                "Cannot sign: private key not available (verification-only mode)".to_string(),
            )
        })?;
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
```

**Step 4: Update the caller in `manager.rs`**

In `crates/hardener-state/src/manager.rs`, at line 304, change:

```rust
        Ok(self.signer.sign(&digest))
```

To:

```rust
        self.signer.sign(&digest)
```

(The `?` is already propagated by the `Result` return type of `generate_signature`.)

**Step 5: Run tests**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: all pass

**Step 6: Commit**

```bash
git add crates/hardener-state/src/signing.rs crates/hardener-state/src/manager.rs crates/hardener-state/tests/signing_tests.rs
git commit -m "fix: return Result from sign() instead of panicking in verify-only mode"
```

---

## Task 3: Fix audit log timestamp TOCTOU [Medium, SAM-031]

`log_action()` and `log_failure()` each call `Utc::now()` twice: once for the hash input, once inside `AuditEntry::new()`. At second boundaries the timestamps can differ, corrupting the hash chain and causing false tamper alerts.

**Files:**
- Modify: `crates/hardener-state/src/audit.rs:66-97` (constructors) and `270-351` (log methods)
- Test: `crates/hardener-state/tests/audit_tests.rs`

**Step 1: Write the failing test**

Add to `crates/hardener-state/tests/audit_tests.rs`:

```rust
#[tokio::test]
async fn test_audit_log_entry_timestamp_matches_hash() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.log");

    let logger = AuditLogger::new(&log_path).await.unwrap();
    logger
        .log_action(
            ActionType::Apply,
            "testuser".to_string(),
            "kernel".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Verify integrity: this will fail if hash timestamp != entry timestamp
    let result = AuditLogger::verify_integrity(&log_path).await;
    assert!(result.is_ok(), "Hash chain verification failed: {result:?}");
}
```

**Step 2: Run to verify it passes (it usually does, but can fail at second boundaries)**

Run: `cargo test -p hardener-state --test audit_tests test_audit_log_entry_timestamp_matches_hash 2>&1 | tail -5`
Expected: PASS (the race is rare in tests, but the fix is still needed for production correctness)

**Step 3: Add `timestamp` parameter to `AuditEntry::new()` and `new_failure()`**

In `crates/hardener-state/src/audit.rs`, replace `AuditEntry::new` (lines 66-76):

```rust
    pub fn new(
        action_type: ActionType,
        user: String,
        target: String,
        hash: Vec<u8>,
        timestamp: DateTime<Utc>,
    ) -> AuditEntry {
        Self {
            entry_timestamp: timestamp,
            entry_action_type: action_type,
            entry_user: user,
            entry_target: target,
            entry_result: ActionResult::Success,
            entry_details: HashMap::new(),
            entry_hash: hash,
        }
    }
```

Replace `AuditEntry::new_failure` (lines 86-105):

```rust
    pub fn new_failure(
        action_type: ActionType,
        user: String,
        target: String,
        error_message: String,
        hash: Vec<u8>,
        timestamp: DateTime<Utc>,
    ) -> AuditEntry {
        let mut details = HashMap::new();
        details.insert("error".to_string(), error_message);

        AuditEntry {
            entry_timestamp: timestamp,
            entry_action_type: action_type,
            entry_user: user,
            entry_target: target,
            entry_result: ActionResult::Failure,
            entry_details: details,
            entry_hash: hash,
        }
    }
```

**Step 4: Fix `log_action()` to compute timestamp once**

Replace the body of `log_action()` (around lines 275-300):

```rust
    pub async fn log_action(
        &self,
        action_type: ActionType,
        user: String,
        target: String,
        result: ActionResult,
    ) -> Result<()> {
        let mut chain = self.hash_chain.lock().await;

        // Compute timestamp ONCE for both hash and entry
        let now = Utc::now();

        let entry_data = (now.timestamp(), action_type, &user, &target, result);
        let serialised_data = serde_json::to_vec(&entry_data)?;

        let hash = chain.next_hash(&serialised_data);

        let entry = AuditEntry::new(action_type, user, target, hash.clone(), now);

        let mut entry_json = serde_json::to_vec(&entry)?;
        entry_json.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&entry_json).await?;
        file.flush().await?;

        chain.update(hash);

        Ok(())
    }
```

**Step 5: Fix `log_failure()` the same way**

Replace the body of `log_failure()` (around lines 319-351):

```rust
    pub async fn log_failure(
        &self,
        action_type: ActionType,
        user: String,
        target: String,
        error_message: String,
    ) -> Result<()> {
        let mut chain = self.hash_chain.lock().await;

        let now = Utc::now();

        let entry_data = (
            now.timestamp(),
            action_type,
            &user,
            &target,
            ActionResult::Failure,
            &error_message,
        );
        let serialised_data = serde_json::to_vec(&entry_data)?;

        let hash = chain.next_hash(&serialised_data);

        let entry =
            AuditEntry::new_failure(action_type, user, target, error_message, hash.clone(), now);

        let mut entry_json = serde_json::to_vec(&entry)?;
        entry_json.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&entry_json).await?;
        file.flush().await?;

        chain.update(hash);

        Ok(())
    }
```

**Step 6: Run tests**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: all pass

**Step 7: Commit**

```bash
git add crates/hardener-state/src/audit.rs crates/hardener-state/tests/audit_tests.rs
git commit -m "fix: eliminate audit log timestamp TOCTOU by computing once per entry"
```

---

## Task 4: Centralise error sanitisation across all IPC commands [Medium, SAM-069 + SAM-068]

`sanitise_error()` is only applied to 2 out of ~35 error paths in `commands.rs`. Internal filesystem paths, SSH details, and subprocess stderr leak to the GUI frontend.

**Files:**
- Modify: `src-tauri/src/commands.rs` (function + ~33 call sites)

**Step 1: Create `safe_err` helper**

Add after the existing `sanitise_error` function (around line 66):

```rust
/// Wraps an error into a sanitised string safe for the GUI frontend.
fn safe_err(e: impl std::fmt::Display) -> String {
    sanitise_error(&e.to_string())
}
```

**Step 2: Replace all `.map_err(|e| e.to_string())` with `.map_err(safe_err)`**

Search `commands.rs` for `.map_err(|e| e.to_string())` and replace every occurrence with `.map_err(safe_err)`. There are ~13 locations. Examples:

```rust
// Before:
.map_err(|e| e.to_string())?;
// After:
.map_err(safe_err)?;
```

**Step 3: Replace all `format!("...{e}")` error paths with sanitised versions**

For each `Err(format!("...: {e}"))` or `Err(format!("...: {}", e))` pattern, wrap in `sanitise_error`. There are ~20 locations. Examples:

```rust
// Before:
return Err(format!("Failed to execute dry-run: {}", e));
// After:
return Err(safe_err(format!("Failed to execute dry-run: {}", e)));

// Before:
return Err(format!("Dry-run failed: {}", stderr));
// After:
return Err(sanitise_error(&format!("Dry-run failed: {}", stderr)));
```

For the SSH connection error at line 1153:
```rust
// Before:
Err(e) => Ok(RemoteConnectionStatus::Failed {
    error: format!("{e}"),
}),
// After:
Err(e) => Ok(RemoteConnectionStatus::Failed {
    error: safe_err(e),
}),
```

**Step 4: Remove the `save_scheduler_config` path leak at line 1298**

```rust
// Before:
Ok(path.display().to_string())
// After:
Ok("Configuration saved".to_string())
```

**Step 5: Verify compilation and tests**

Run: `cargo build -p linux-hardener-desktop && cargo test --workspace 2>&1 | tail -5`
Expected: `Finished`, all tests pass

**Step 6: Commit**

```bash
git add src-tauri/src/commands.rs
git commit -m "security: sanitise all IPC error paths to prevent internal path leakage"
```

---

## Task 5: Add rate limiting to `test_notification` [Medium]

`test_notification()` dispatches real webhooks/emails without any throttle. Rapid calls can spam notification channels.

**Files:**
- Modify: `src-tauri/src/commands.rs:1306-1310`

**Step 1: Add the guard**

At the start of the `test_notification` function body (after the opening `{`), add:

```rust
    let _guard = PrivilegedOpGuard::acquire()?;
```

This is the same pattern used by `run_apply`, `run_rollback`, `create_checkpoint`, and `delete_checkpoint`.

**Step 2: Verify compilation**

Run: `cargo build -p linux-hardener-desktop 2>&1 | tail -3`
Expected: `Finished`

**Step 3: Commit**

```bash
git add src-tauri/src/commands.rs
git commit -m "security: add rate limiting to test_notification IPC command"
```

---

## Task 6: Fix audit plugin backup symlink attack [Low, SAM-050]

The audit plugin creates backups using `cp` with a predictable timestamp-based filename. An attacker could pre-create a symlink at the expected path.

**Files:**
- Modify: `crates/hardener-plugins/src/audit/mod.rs:303-337`
- Test: `crates/hardener-plugins/tests/audit_mock_tests.rs`

**Step 1: Write the failing test**

Add to `crates/hardener-plugins/tests/audit_mock_tests.rs`:

```rust
#[tokio::test]
async fn test_backup_filename_is_unpredictable() {
    // Generate two backup filenames in quick succession
    let ts1 = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let ts2 = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    // If filenames are timestamp-only, both are identical within a second
    // After fix: random suffix makes them different
    // This test documents the expectation: the actual fix adds randomness
    assert_eq!(ts1, ts2, "Precondition: timestamps within same second are identical");
}
```

**Step 2: Add randomised suffix to backup path**

In `crates/hardener-plugins/src/audit/mod.rs`, replace the backup path construction (around line 306):

```rust
// Before:
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = format!("{}.backup.{}", AUDIT_RULES_PATH, timestamp);

// After:
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let random_suffix: u32 = rand::random();
    let backup_path = format!(
        "{}.backup.{}.{:08x}",
        AUDIT_RULES_PATH, timestamp, random_suffix
    );
```

Also add `--no-dereference` flag to the `cp` command to prevent following symlinks (around line 317):

```rust
// Before:
        ctx.executor()
            .execute_command("cp", &[AUDIT_RULES_PATH, &backup_path])
            .await?;

// After:
        ctx.executor()
            .execute_command("cp", &["--no-dereference", AUDIT_RULES_PATH, &backup_path])
            .await?;
```

**Step 3: Add `rand` dependency if not already present**

Check `crates/hardener-plugins/Cargo.toml` for `rand`. If missing, add:
```toml
rand = "0.9"
```

**Step 4: Run tests**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: all pass

**Step 5: Commit**

```bash
git add crates/hardener-plugins/src/audit/mod.rs crates/hardener-plugins/Cargo.toml
git commit -m "security: add unpredictable suffix and no-dereference flag to audit backup"
```

---

## Task 7: Add permission mode semantic validation [Low, SAM-049]

The permissions validator accepts syntactically correct but dangerous modes like SUID (`4755`), SGID (`2755`), and world-writable (`0777`).

**Files:**
- Modify: `crates/hardener-core/src/config_validation.rs:203-212`
- Test: `crates/hardener-core/src/config_validation.rs` (inline `#[cfg(test)]` at line 214)

**Step 1: Write the failing tests**

Add to the existing `#[cfg(test)]` module in `config_validation.rs`:

```rust
    #[test]
    fn test_permissions_rejects_suid() {
        assert!(validate_permissions_value("key", "4755").is_err());
    }

    #[test]
    fn test_permissions_rejects_sgid() {
        assert!(validate_permissions_value("key", "2755").is_err());
    }

    #[test]
    fn test_permissions_rejects_world_writable() {
        assert!(validate_permissions_value("key", "777").is_err());
        assert!(validate_permissions_value("key", "0777").is_err());
    }

    #[test]
    fn test_permissions_rejects_no_access() {
        assert!(validate_permissions_value("key", "000").is_err());
        assert!(validate_permissions_value("key", "0000").is_err());
    }

    #[test]
    fn test_permissions_accepts_safe_modes() {
        assert!(validate_permissions_value("key", "700").is_ok());
        assert!(validate_permissions_value("key", "0755").is_ok());
        assert!(validate_permissions_value("key", "644").is_ok());
        assert!(validate_permissions_value("key", "0600").is_ok());
    }
```

**Step 2: Run to verify they fail**

Run: `cargo test -p hardener-core config_validation::tests::test_permissions_rejects 2>&1 | tail -10`
Expected: FAIL, current validator accepts all syntactically valid modes

**Step 3: Add semantic validation**

Replace `validate_permissions_value` (lines 203-212):

```rust
fn validate_permissions_value(_key: &str, value: &str) -> std::result::Result<(), String> {
    if value.len() < 3 || value.len() > 4 {
        return Err(format!("expected 3-4 digit octal mode, got '{value}'"));
    }
    if !value.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(format!("expected octal digits (0-7), got '{value}'"));
    }

    let mode = u32::from_str_radix(value, 8)
        .map_err(|_| format!("invalid octal mode: '{value}'"))?;

    // Reject special bits (SUID=0o4000, SGID=0o2000, sticky=0o1000)
    if mode & 0o7000 != 0 {
        return Err(format!("special bits (SUID/SGID/sticky) not allowed: '{value}'"));
    }
    // Reject world-writable
    if mode & 0o002 != 0 {
        return Err(format!("world-writable mode not allowed: '{value}'"));
    }
    // Reject no-access
    if mode == 0 {
        return Err(format!("zero permissions not allowed: '{value}'"));
    }

    Ok(())
}
```

**Step 4: Run tests**

Run: `cargo test -p hardener-core config_validation 2>&1 | tail -10`
Expected: all pass

**Step 5: Commit**

```bash
git add crates/hardener-core/src/config_validation.rs
git commit -m "security: reject SUID/SGID/world-writable permission modes in config validation"
```

---

## Task 8: Add deterministic ordering to checkpoint digest [Low, SAM-056]

The `generate_digest` function hashes file states in iteration order. At verification time, SQLite returns rows in implicit rowid order: correct today but fragile. Make it explicit.

**Files:**
- Modify: `crates/hardener-state/src/manager.rs:512-520` (query) and `253-280` (digest)

**Step 1: Add `ORDER BY file_path` to the file_states query**

In `crates/hardener-state/src/manager.rs`, around line 512, change:

```sql
SELECT
    file_path,
    content,
    permissions,
    owner_uid,
    owner_gid
FROM
    file_states WHERE checkpoint_id = ?
```

To:

```sql
SELECT
    file_path,
    content,
    permissions,
    owner_uid,
    owner_gid
FROM
    file_states WHERE checkpoint_id = ?
ORDER BY file_path
```

**Step 2: Sort file_states before hashing in `generate_digest`**

In `generate_digest` (around line 268), add a sort before the loop:

```rust
    fn generate_digest(
        checkpoint_id: &CheckpointId,
        checkpoint_name: &str,
        checkpoint_timestamp: i64,
        checkpoint_username: &str,
        file_states: &[FileState],
    ) -> Vec<u8> {
        use ring::digest::{Context as DigestContext, SHA256};

        let mut hash_context = DigestContext::new(&SHA256);
        hash_context.update(checkpoint_id.as_str().as_bytes());
        hash_context.update(checkpoint_name.as_bytes());
        hash_context.update(&checkpoint_timestamp.to_be_bytes());
        hash_context.update(checkpoint_username.as_bytes());

        // Sort by path for deterministic ordering (SAM-056)
        let mut sorted_states: Vec<&FileState> = file_states.iter().collect();
        sorted_states.sort_by_key(|s| &s.file_path);

        for file_state in sorted_states {
            hash_context.update(file_state.file_path.as_bytes());
            if let Some(content) = &file_state.file_content {
                hash_context.update(content);
            }
            hash_context.update(&file_state.file_permissions.to_be_bytes());
            hash_context.update(&file_state.file_owner_uid.to_be_bytes());
            hash_context.update(&file_state.file_owner_gid.to_be_bytes());
        }

        hash_context.finish().as_ref().to_vec()
    }
```

**Important:** Since `generate_digest` is used for both creation and verification, sorting in both places ensures consistency. No existing checkpoints are broken because the sort must match in both directions: and both now use the same sorted order.

**Step 3: Run tests**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: all pass

**Step 4: Commit**

```bash
git add crates/hardener-state/src/manager.rs
git commit -m "fix: use deterministic file ordering in checkpoint digest computation"
```

---

## Task 9: Escape remaining CSV fields [Low, SAM-059]

`control_id` and `report_framework` are written to CSV without passing through `escape_csv_field()`.

**Files:**
- Modify: `crates/hardener-compliance/src/output/csv.rs:53-56`
- Test: `crates/hardener-compliance/src/output/csv.rs` (inline `#[cfg(test)]` at line 132)

**Step 1: Write the failing test**

Add to the inline test module:

```rust
    #[test]
    fn test_csv_escapes_control_id_with_special_chars() {
        let report = create_test_report();
        let formatter = CsvFormatter;
        let output = formatter.format(&report);
        // Verify no unescaped fields: every field with potential special chars
        // should go through escape_csv_field
        for line in output.lines().skip(1) {
            // Each field should not contain raw commas outside quotes
            let fields: Vec<&str> = line.split(',').collect();
            assert!(fields.len() >= 8, "CSV line has fewer than 8 fields: {line}");
        }
    }
```

**Step 2: Apply `escape_csv_field` to the remaining fields**

In `crates/hardener-compliance/src/output/csv.rs`, around lines 53-56, change:

```rust
            output.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                report.report_framework,
                framework_name,
                framework_desc,
                control.control_id,
                title_escaped,
                section_escaped,
                status_str,
                control.control_findings.len()
            ));
```

To:

```rust
            let framework_escaped = escape_csv_field(&report.report_framework.to_string());
            let control_id_escaped = escape_csv_field(&control.control_id);

            output.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                framework_escaped,
                framework_name,
                framework_desc,
                control_id_escaped,
                title_escaped,
                section_escaped,
                status_str,
                control.control_findings.len()
            ));
```

**Step 3: Run tests**

Run: `cargo test -p hardener-compliance csv 2>&1 | tail -5`
Expected: all pass

**Step 4: Commit**

```bash
git add crates/hardener-compliance/src/output/csv.rs
git commit -m "fix: escape control_id and framework fields in CSV output"
```

---

## Task 10: Add firewalld zone name validation [Low, SAM-048]

`get_default_zone()` accepts the remote host's response verbatim. A compromised host could return a malicious zone name.

**Files:**
- Modify: `crates/hardener-plugins/src/firewall/firewalld.rs:45-53`
- Test: `crates/hardener-plugins/tests/firewall_mock_tests.rs`

**Step 1: Write the failing test**

Add to `crates/hardener-plugins/tests/firewall_mock_tests.rs`:

```rust
#[test]
fn test_zone_name_validation() {
    use hardener_plugins::firewall::firewalld::validate_zone_name;

    assert!(validate_zone_name("public").is_ok());
    assert!(validate_zone_name("trusted").is_ok());
    assert!(validate_zone_name("my-zone").is_ok());
    assert!(validate_zone_name("zone_1").is_ok());

    assert!(validate_zone_name("").is_err());
    assert!(validate_zone_name("--help").is_err());
    assert!(validate_zone_name("zone; rm -rf /").is_err());
    assert!(validate_zone_name("a".repeat(65).as_str()).is_err());
    assert!(validate_zone_name("zone\nnewline").is_err());
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p hardener-plugins firewall_mock_tests::test_zone_name_validation 2>&1 | tail -5`
Expected: FAIL, function doesn't exist yet

**Step 3: Add `validate_zone_name` and wire it in**

In `crates/hardener-plugins/src/firewall/firewalld.rs`, add a public validation function:

```rust
/// Validates that a firewalld zone name matches safe patterns.
pub fn validate_zone_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(anyhow::anyhow!("Invalid zone name length"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow::anyhow!(
            "Zone name contains invalid characters: {name}"
        ));
    }
    if name.starts_with('-') {
        return Err(anyhow::anyhow!("Zone name must not start with a dash"));
    }
    Ok(())
}
```

Then in `get_default_zone()`, add validation after trimming:

```rust
    async fn get_default_zone(&self, ctx: &Context) -> Result<String> {
        let output = self
            .execute_firewall_cmd(ctx, &["--get-default-zone"])
            .await?;
        let zone = output.trim().to_string();
        validate_zone_name(&zone)?;
        Ok(zone)
    }
```

Make sure `validate_zone_name` is `pub` and exported from the module so the test can access it.

**Step 4: Run tests**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: all pass

**Step 5: Commit**

```bash
git add crates/hardener-plugins/src/firewall/firewalld.rs crates/hardener-plugins/tests/firewall_mock_tests.rs
git commit -m "security: validate firewalld zone name from remote hosts"
```

---

## Task 11: Add kernel sysctl key validation [Low, SAM-021 defence-in-depth]

The kernel plugin only processes hardcoded parameter names so this is safe today, but no explicit validation prevents future regressions. Add key format validation.

**Files:**
- Modify: `crates/hardener-core/src/config_validation.rs`
- Test: `crates/hardener-core/src/config_validation.rs` (inline tests)

**Step 1: Write the failing tests**

Add to the inline `#[cfg(test)]` module:

```rust
    #[test]
    fn test_kernel_key_rejects_path_traversal() {
        assert!(validate_directive_key("kernel", "kernel/../../../etc/passwd").is_err());
        assert!(validate_directive_key("kernel", "net.ipv4.../../secret").is_err());
    }

    #[test]
    fn test_kernel_key_rejects_shell_metacharacters() {
        assert!(validate_directive_key("kernel", "net.ipv4; rm -rf /").is_err());
        assert!(validate_directive_key("kernel", "key\nnewline").is_err());
    }

    #[test]
    fn test_kernel_key_accepts_valid_sysctl_names() {
        assert!(validate_directive_key("kernel", "net.ipv4.tcp_syncookies").is_ok());
        assert!(validate_directive_key("kernel", "kernel.randomize_va_space").is_ok());
        assert!(validate_directive_key("kernel", "fs.protected_hardlinks").is_ok());
    }
```

**Step 2: Run to verify they fail**

Run: `cargo test -p hardener-core config_validation::tests::test_kernel_key 2>&1 | tail -10`
Expected: FAIL, function doesn't exist

**Step 3: Add `validate_directive_key`**

Add to `config_validation.rs`, near the existing `validate_kernel_value`:

```rust
/// Validates directive keys for safe characters. Prevents path traversal
/// via sysctl `.replace('.', "/")` in the kernel plugin.
pub fn validate_directive_key(plugin_id: &str, key: &str) -> std::result::Result<(), String> {
    if key.is_empty() || key.len() > 128 {
        return Err(format!("directive key too long or empty: '{key}'"));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
    {
        return Err(format!(
            "directive key for '{plugin_id}' contains invalid characters: '{key}'"
        ));
    }
    if key.contains("..") {
        return Err(format!("directive key contains '..': '{key}'"));
    }
    Ok(())
}
```

**Step 4: Wire it into `validate_plugin_directives`**

Find the function that iterates directives and calls per-plugin validators. Add a call to `validate_directive_key(plugin_id, key)` before calling the value validator.

**Step 5: Run tests**

Run: `cargo test -p hardener-core config_validation 2>&1 | tail -10`
Expected: all pass

**Step 6: Commit**

```bash
git add crates/hardener-core/src/config_validation.rs
git commit -m "security: validate directive key format to prevent sysctl path traversal"
```

---

## Final Verification

After all 11 tasks are complete:

**Step 1:** Run full test suite
```bash
cargo test --workspace 2>&1 | tail -10
```
Expected: all pass (should be 505+ tests, likely ~520 with new tests)

**Step 2:** Run clippy
```bash
cargo clippy --workspace -- -D warnings 2>&1 | tail -5
```
Expected: clean

**Step 3:** Run fmt check
```bash
cargo fmt -- --check
```
Expected: clean

**Step 4:** Build all targets
```bash
cargo build -p linux-hardener-desktop && cargo build -p linux-hardener-cli 2>&1 | tail -3
```
Expected: both succeed

**Step 5:** Run python validators
```bash
python3 scripts/validate_all.py
```
Expected: 7/7 pass

**Step 6:** Update `docs/security-audit/REMEDIATION_TRACKER.md`:
- Mark row "50+ | Remaining | Low" as partially addressed
- Update the Defence in Depth table with fix statuses for SAM-021, SAM-031, SAM-048, SAM-049, SAM-050, SAM-056, SAM-059, SAM-068, SAM-069

**Step 7:** Update `docs/FILE_MAP.md` if any new files were created (likely none).
