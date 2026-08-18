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
use hardener_common::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
        // Lock the hash chain
        let mut chain = self.hash_chain.lock().await;

        // Compute timestamp ONCE for both hash and entry
        let now = Utc::now();

        let entry_data = (now.timestamp(), action_type, &user, &target, result);
        let serialised_data = serde_json::to_vec(&entry_data)?;

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
    /// # Arguments
    /// * `log_path` - Path to the audit log file to verify
    ///
    /// # Returns
    /// `true` if every entry present links correctly, `false` if one was altered,
    /// reordered, or removed from the front
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
                // For successes, don't include error message (matches log_action)
                serde_json::to_vec(&(
                    entry.entry_timestamp.timestamp(),
                    entry.entry_action_type,
                    &entry.entry_user,
                    &entry.entry_target,
                    entry.entry_result,
                ))?
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
