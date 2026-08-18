//! Audit logging with tamper-evident hash chain.
//!
//! Evident, not proof: the chain detects a change to a recorded entry, it does
//! not prevent one. It also does not detect every change. [`AuditLogger::
//! verify_integrity`] walks from a fixed genesis and holds no expected length
//! and no anchor outside the file, so **a prefix of a valid chain is itself a
//! valid chain** and deleting entries from the end is undetectable. Deleting
//! them from the front is caught, because the survivor no longer links to the
//! genesis. Both measured 2026-08-18, `true` and `false` respectively.
//!
//! Protecting the tail is the deployment's job, not this module's: as root the
//! log sits in a 0700 directory, but an unprivileged run writes it under the
//! user's own data directory, where the user the entries describe can rewrite
//! the whole chain from genesis.

use crate::HashChain;
use chrono::{DateTime, Utc};
use hardener_common::error::{HardeningError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tokio::{
    fs::OpenOptions,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
};

/// Type of action being audited.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionType {
    /// System scan operation
    Scan,
    /// Hardening application
    Apply,
    /// Rollback to checkpoint
    Rollback,
    /// Configuration change
    ConfigChange,
    /// Checkpoint creation
    CheckpointCreate,
    /// Checkpoint deletion
    CheckpointDelete,
    /// A compliance control declared not applicable, or that declaration
    /// withdrawn. Kept distinct from `ConfigChange` because an auditor's
    /// question is "which exclusions were in force and who set them", and a
    /// filter over a variant shared with every other configuration edit
    /// cannot answer it.
    ScopeExclusion,
}

/// Result of an audited action.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionResult {
    /// Action completed successfully
    Success,
    /// Action failed
    Failure,
}

/// A single entry in the tamper-evident audit log
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEntry {
    /// When the action occurred (UTC)
    pub entry_timestamp: DateTime<Utc>,
    /// Type of action performed
    pub entry_action_type: ActionType,
    /// User who performed the action
    pub entry_user: String,
    /// Target of the action (e.g. file path, plugin name)
    pub entry_target: String,
    /// Whether the action succeeded or failed
    pub entry_result: ActionResult,
    /// Additional details (e.g., error messages, parameters)
    pub entry_details: HashMap<String, String>,
    /// Hash chain value for this entry (SHA-256)
    pub entry_hash: Vec<u8>,
}

impl AuditEntry {
    /// Creates a new audit entry for a successful action.
    ///
    /// # Arguments
    /// * `action_type` - Type of action being audited
    /// * `user`        - Username performing the action
    /// * `target`      - Target of the action
    /// * `hash`        - Hash chain value for this entry
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

    /// Creates a new audit entry for a failed action.
    ///
    /// # Arguments
    /// * `action_type` - Type of action being audited
    /// * `user` - Username performing the action
    /// * `target` - Target of the action
    /// * `error_message` - Description of the failure
    /// * `hash` - Hash chain value for this entry
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

    /// Adds additional detail to the audit entry.
    ///
    /// # Arguments
    /// * `key`   - Detail key
    /// * `value` - Detail value
    pub fn add_detail(&mut self, key: String, value: String) {
        self.entry_details.insert(key, value);
    }
}

/// Filter criteria for querying audit logs.
#[derive(Clone, Debug, Default)]
pub struct QueryFilter {
    /// Filter by action type (None means no filter)
    pub filter_action_type: Option<ActionType>,
    /// Filter by maximum timestamp (inclusive)
    pub filter_end_time: Option<DateTime<Utc>>,
    /// Filter by action result (None means no filter)
    pub filter_result: Option<ActionResult>,
    /// Filter by minimum timestamp (inclusive)
    pub filter_start_time: Option<DateTime<Utc>>,
    /// Filter by user (None means no filter)
    pub filter_user: Option<String>,
}

impl QueryFilter {
    /// Creates a new empty filter (matches all entries)
    pub fn new() -> QueryFilter {
        Self::default()
    }

    /// Filters by action type.
    pub fn with_action_type(mut self, action_type: ActionType) -> QueryFilter {
        self.filter_action_type = Some(action_type);
        self
    }

    /// Filters by user.
    pub fn with_user(mut self, user: String) -> QueryFilter {
        self.filter_user = Some(user);
        self
    }

    /// Filters by time range (start).
    pub fn with_start_time(mut self, start_time: DateTime<Utc>) -> QueryFilter {
        self.filter_start_time = Some(start_time);
        self
    }

    /// Filters by time range (end).
    pub fn with_end_time(mut self, end_time: DateTime<Utc>) -> QueryFilter {
        self.filter_end_time = Some(end_time);
        self
    }

    /// Filters by action result.
    pub fn with_result(mut self, result: ActionResult) -> QueryFilter {
        self.filter_result = Some(result);
        self
    }

    /// Checks if an entry matches this filter.
    fn matches(&self, entry: &AuditEntry) -> bool {
        // Check action type filter
        if let Some(action_type) = self.filter_action_type
            && entry.entry_action_type != action_type
        {
            return false;
        }

        // Check user filter
        if let Some(ref user) = self.filter_user
            && &entry.entry_user != user
        {
            return false;
        }

        // Check start time filter
        if let Some(start) = self.filter_start_time
            && entry.entry_timestamp < start
        {
            return false;
        }

        // Check end time filter
        if let Some(end) = self.filter_end_time
            && entry.entry_timestamp > end
        {
            return false;
        }

        // Check result filter
        if let Some(result) = self.filter_result
            && entry.entry_result != result
        {
            return false;
        }

        true
    }
}

/// Tamper-evident audit logger using hash chain.
pub struct AuditLogger {
    /// Append-only audit log file
    file: tokio::sync::Mutex<tokio::fs::File>,
    /// Hash chain for tamper detection
    hash_chain: tokio::sync::Mutex<HashChain>,
}

impl AuditLogger {
    /// Creates a new audit logger
    ///
    /// # Arguments
    /// * `log_path` - Path to the audit log file (will be created if it doesn't exist)
    ///
    /// # Returns
    /// A new AuditLogger instance, or an error if file cannot be opened
    pub async fn new(log_path: &str) -> Result<AuditLogger> {
        let chain = Self::recover_chain(log_path).await;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .await?;

        Ok(AuditLogger {
            file: tokio::sync::Mutex::new(file),
            hash_chain: tokio::sync::Mutex::new(chain),
        })
    }

    /// Recovers the hash chain state from the last entry in an existing log.
    ///
    /// Walks the full log to rebuild the chain position. Falls back to
    /// genesis if the file doesn't exist, is empty, or can't be parsed.
    async fn recover_chain(log_path: &str) -> HashChain {
        let Ok(content) = tokio::fs::read_to_string(log_path).await else {
            return HashChain::new();
        };

        let mut chain = HashChain::new();
        for line in content.lines() {
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                chain.update(entry.entry_hash);
            }
        }
        chain
    }

    /// Logs an action to the audit log with hash chain.
    ///
    /// # Arguments
    /// * `action_type` - Type of action being logged
    /// * `user` - Username performing the action
    /// * `target` - Target of the action
    /// * `result` - Whether the action succeeded or failed
    ///
    /// # Returns
    /// Ok(()) if logged successfully, or an error
    pub async fn log_action(
        &self,
        action_type: ActionType,
        user: String,
        target: String,
        result: ActionResult,
    ) -> Result<()> {
        // The same trap the details-bearing writer refuses, and it predates
        // both: the hash below covers the caller's `result`, while
        // `AuditEntry::new` hard-codes `entry_result: Success`. A `Failure`
        // passed here therefore stores one result and hashes another, and
        // `verify_integrity` recomputes from the stored one, so the entry could
        // never verify and the append-only log would read as tampered from that
        // point on. Unreachable when this was written, because every failure
        // path uses `log_failure`, which is why nothing caught it.
        if result == ActionResult::Failure {
            return Err(HardeningError::Validation(
                "a failed action cannot be logged through log_action: the entry would record \
                 Success while its hash covered Failure, so it could never verify. Use \
                 log_failure instead."
                    .to_string(),
            ));
        }

        // Lock the hash chain
        let mut chain = self.hash_chain.lock().await;

        // Compute timestamp ONCE for both hash and entry
        let now = Utc::now();

        // Routed through the same helper the details-bearing writer and
        // verification use, so one function is the only definition of what a
        // success entry hashes over.
        let serialised_data =
            Self::hashable(now, action_type, &user, &target, result, &HashMap::new())?;

        let hash = chain.next_hash(&serialised_data);

        let entry = AuditEntry::new(action_type, user, target, hash.clone(), now);

        // Serialise the complete entry for writing
        let mut entry_json = serde_json::to_vec(&entry)?;
        entry_json.push(b'\n'); // Add newline for line-based format

        // Write to file
        let mut file = self.file.lock().await;
        file.write_all(&entry_json).await?;
        file.flush().await?;

        // Update chain state
        chain.update(hash);

        Ok(())
    }

    /// Logs an action that carries structured details, with those details
    /// inside the hash.
    ///
    /// Details are serialised through a `BTreeMap` because `HashMap` iteration
    /// order is not stable and an unstable order would produce a different hash
    /// for identical content, breaking verification at random.
    ///
    /// They join the hashed tuple **only when non-empty**. Every success entry
    /// written before this method existed carries an empty map and was hashed
    /// as a five-tuple, so an unconditional sixth element would invalidate
    /// every historical log.
    ///
    /// # Successes only, and the restriction must stay
    ///
    /// `result` must be [`ActionResult::Success`]; a `Failure` is rejected with
    /// [`HardeningError::Validation`] and belongs in
    /// [`log_failure`](Self::log_failure). This is not tidiness. The failure
    /// branch of [`verify_integrity`](Self::verify_integrity) never reaches
    /// [`hashable`](Self::hashable): it hashes a fixed six-tuple whose last
    /// element is the `error` detail as a **string**, and it takes that branch
    /// on `entry_result == Failure` alone. This writer hashes through
    /// `hashable`, which branches on whether `details` is empty and never on
    /// `result`, so no input exists for which the two agree. Empty details give
    /// a five-tuple against the verifier's six; any details at all give a JSON
    /// object in the sixth slot against the verifier's bare string, `{"error":
    /// "..."}` included. The log is append-only, so one such entry would make
    /// `verify_integrity` return `false` for the whole file forever.
    ///
    /// Relaxing this by emitting the legacy error-only six-tuple here is the
    /// wrong repair: it would drop `reason`, `review_by`, `approved_by` and
    /// `ticket` out of the hash, which is precisely the defect this method
    /// exists to remove. Logging a details-bearing failure needs the verifier
    /// taught the new shape first, with a format version to keep released logs
    /// verifying.
    ///
    /// # Arguments
    /// * `action_type` - Type of action being logged
    /// * `user`        - Username performing the action
    /// * `target`      - Target of the action
    /// * `result`      - Must be `ActionResult::Success`
    /// * `details`     - Structured context recorded inside the hash chain
    ///
    /// # Returns
    /// Ok(()) if logged successfully, or an error
    ///
    /// # Errors
    /// [`HardeningError::Validation`] if `result` is `ActionResult::Failure`.
    pub async fn log_action_with_details(
        &self,
        action_type: ActionType,
        user: String,
        target: String,
        result: ActionResult,
        details: HashMap<String, String>,
    ) -> Result<()> {
        if result == ActionResult::Failure {
            return Err(HardeningError::Validation(
                "a failed action cannot be logged with structured details: verify_integrity \
                 hashes every Failure entry as the legacy six-tuple ending in the `error` string, \
                 so such an entry could never verify. Use log_failure instead."
                    .to_string(),
            ));
        }

        let mut chain = self.hash_chain.lock().await;
        let now = Utc::now();

        let serialised_data = Self::hashable(now, action_type, &user, &target, result, &details)?;
        let hash = chain.next_hash(&serialised_data);

        let entry = AuditEntry {
            entry_timestamp: now,
            entry_action_type: action_type,
            entry_user: user,
            entry_target: target,
            entry_result: result,
            entry_details: details,
            entry_hash: hash.clone(),
        };

        let mut entry_json = serde_json::to_vec(&entry)?;
        entry_json.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&entry_json).await?;
        file.flush().await?;

        chain.update(hash);
        Ok(())
    }

    /// The bytes a success entry hashes over.
    ///
    /// One function so the writer and [`verify_integrity`](Self::verify_integrity)
    /// cannot drift. They did not share one before, which is exactly how a
    /// details-bearing entry would have hashed one way and verified another.
    ///
    /// Successes only. `result` is here because it is an element of the hashed
    /// tuple, not because this helper handles both outcomes: a failure hashes
    /// the six-tuple built in [`log_failure`](Self::log_failure), which the
    /// failure branch of `verify_integrity` mirrors without ever calling this.
    ///
    /// The `details.is_empty()` guard is load-bearing compatibility, not a
    /// micro-optimisation. Deleting it changes the hash of every detail-free
    /// success entry, so every `audit.log` written by a released binary would
    /// report `verify_integrity == false`. The golden-fixture test
    /// `a_v1_5_1_entry_still_verifies` holds a line emitted by the pre-change
    /// code and goes red if the guard is removed.
    fn hashable(
        timestamp: DateTime<Utc>,
        action_type: ActionType,
        user: &str,
        target: &str,
        result: ActionResult,
        details: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        if details.is_empty() {
            return Ok(serde_json::to_vec(&(
                timestamp.timestamp(),
                action_type,
                user,
                target,
                result,
            ))?);
        }
        let ordered: BTreeMap<&str, &str> = details
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        Ok(serde_json::to_vec(&(
            timestamp.timestamp(),
            action_type,
            user,
            target,
            result,
            &ordered,
        ))?)
    }

    /// Logs a failed action with an error message.
    ///
    /// This is a convenience wrapper around log_action() that creates
    /// a failure entry and includes the error message in details.
    ///
    /// # Arguments
    /// * `action_type` - Type of action being logged
    /// * `user` - Username performing the action
    /// * `target` - Target of the action
    /// * `error_message` - Description of the failure
    pub async fn log_failure(
        &self,
        action_type: ActionType,
        user: String,
        target: String,
        error_message: String,
    ) -> Result<()> {
        // Lock the hash chain
        let mut chain = self.hash_chain.lock().await;

        // Compute timestamp ONCE for both hash and entry
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

        // Serialise and write
        let mut entry_json = serde_json::to_vec(&entry)?;
        entry_json.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&entry_json).await?;
        file.flush().await?;

        // Update chain state
        chain.update(hash);

        Ok(())
    }

    /// Verifies that every entry still links to the one before it.
    ///
    /// Reads all entries and recalculates the hash chain. `true` means no
    /// recorded entry was altered or reordered; it does **not** mean the log is
    /// complete. Verification starts from a fixed genesis and stops at
    /// end-of-file, comparing against no expected length, so a log with entries
    /// removed from the end verifies exactly as a whole one does. See the module
    /// header for what that leaves to the deployment.
    ///
    /// A `Failure` entry is additionally rejected if its details map carries
    /// any key other than `error`, because only `error` is inside that entry's
    /// hash. See the comment on the failure branch below.
    ///
    /// # Arguments
    /// * `log_path` - Path to the audit log file to verify
    ///
    /// # Returns
    /// `true` if every entry present links correctly, `false` if one was altered,
    /// reordered, removed from the front, or carries a detail outside its own hash
    pub async fn verify_integrity(log_path: &str) -> Result<bool> {
        // Open file for reading
        let file = tokio::fs::File::open(log_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Start with genesis hash
        let mut previous_hash = vec![0u8; 32];

        // Read and verify each entry
        while let Some(line) = lines.next_line().await? {
            // Parse the entry
            let entry: AuditEntry = serde_json::from_str(&line)?;

            // Serialise entry data (without hash) for verification
            // Must match the serialisation used when creating the hash
            let serialised_data = if entry.entry_result == ActionResult::Failure {
                // A Failure hashes the legacy six-tuple whose last element is
                // the `error` string, so every OTHER key of the details map
                // sits outside the hash and could be added or edited on disk
                // with the chain arithmetic still checking out. `query` would
                // return an appended `"approved_by": "security-team"` as part
                // of an authentic refusal.
                //
                // The shape is the evidence. No writer can emit a second key:
                // `log_failure` builds the map with exactly `error` and
                // `log_action_with_details` refuses a `Failure` outright. So an
                // entry carrying one did not come from this program, and the
                // log is not intact. This is the cheap guard, not the repair -
                // the repair is hashing the whole map behind a format version,
                // deferred on `log_action_with_details` where released logs
                // make it a migration rather than a change.
                if entry.entry_details.keys().any(|k| k.as_str() != "error") {
                    return Ok(false);
                }

                // For failures, include the error message (matches log_failure)
                let error_msg = entry
                    .entry_details
                    .get("error")
                    .map(|s| s.as_str())
                    .unwrap_or("");

                serde_json::to_vec(&(
                    entry.entry_timestamp.timestamp(),
                    entry.entry_action_type,
                    &entry.entry_user,
                    &entry.entry_target,
                    entry.entry_result,
                    error_msg,
                ))?
            } else {
                // Successes hash through the same helper the writer uses, so a
                // details-bearing entry verifies and a detail-free one keeps
                // its original five-tuple hash.
                Self::hashable(
                    entry.entry_timestamp,
                    entry.entry_action_type,
                    &entry.entry_user,
                    &entry.entry_target,
                    entry.entry_result,
                    &entry.entry_details,
                )?
            };

            // Verify this entry's hash
            if !HashChain::verify_entry(&previous_hash, &serialised_data, &entry.entry_hash) {
                return Ok(false); // Tampering detected!
            }

            // Move to next entry
            previous_hash = entry.entry_hash;
        }

        Ok(true) // All entries verified successfully
    }

    /// Queries the audit log with optional filters.
    ///
    /// Reads all entries from the log file and returns those matching the filter criteria.
    ///
    /// # Arguments
    /// * `log_path` - Path to the audit log file to query
    /// * `filter`   - Filter criteria (use `QueryFilter::new()` for all entries)
    ///
    /// # Returns
    /// A vector of matching audit entries, or an error if the file cannot be read
    ///
    /// # Examples
    /// ```no_run
    /// # use hardener_state::{ActionType, AuditLogger};
    /// # use hardener_state::audit::QueryFilter;
    /// # async fn example() -> hardener_common::error::Result<()> {
    /// // Get all scan operations
    /// let filter  = QueryFilter::new().with_action_type(ActionType::Scan);
    /// let entries = AuditLogger::query("/var/log/hardener/audit.log", filter).await?;
    ///
    /// // Get all actions by a specific user
    /// let filter  = QueryFilter::new().with_user("root".to_string());
    /// let entries = AuditLogger::query("/var/log/hardener/audit.log", filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(log_path: &str, filter: QueryFilter) -> Result<Vec<AuditEntry>> {
        // Open file for reading
        let file = tokio::fs::File::open(log_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut matching_entries = Vec::new();

        // Read and filter each entry
        while let Some(line) = lines.next_line().await? {
            // Parse the entry
            let entry: AuditEntry = serde_json::from_str(&line)?;

            // Check if it matches the filter
            if filter.matches(&entry) {
                matching_entries.push(entry);
            }
        }

        Ok(matching_entries)
    }
}

#[cfg(test)]
mod tests;
