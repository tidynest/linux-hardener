//! Audit logging with tamper-proof hash chain.

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

/// A single entry in the tamper-proof audit log
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEntry {
    /// When the action occurred (UTC)
    pub entry_timestamp: DateTime<Utc>,
    /// Type of action performed
    pub entry_action_type: ActionType,
    /// Use who performed the action
    pub entry_user: String,
    /// Target of the action (e.g., file path, plugin name)
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
    pub fn new(action_type: ActionType, user: String, target: String, hash: Vec<u8>) -> AuditEntry {
        Self {
            entry_timestamp: Utc::now(),
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
    ) -> AuditEntry {
        let mut details = HashMap::new();
        details.insert("error".to_string(), error_message);

        AuditEntry {
            entry_timestamp: Utc::now(),
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

    /// Serialises the entry data (excluding hash) for hash computation.
    ///
    /// This is used by the HashChain to compute the entry's hash.
    /// We exclude the hash field itself since we're computing it.
    pub fn serialise_for_hash(&self) -> Vec<u8> {
        let data = (
            self.entry_timestamp.timestamp(),
            &self.entry_action_type,
            &self.entry_user,
            &self.entry_target,
            &self.entry_result,
            &self.entry_details,
        );

        serde_json::to_vec(&data).unwrap_or_default()
    }
}

/// Filter criteria fir querying audit logs.
#[derive(Clone, Debug, Default)]
pub struct QueryFilter {
    /// Filter by action type (None means no filter)
    pub filter_action_type: Option<ActionType>,
    /// Filter by minimum timestamp (inclusive)
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
        if let Some(action_type) = self.filter_action_type {
            if entry.entry_action_type != action_type {
                return false;
            }
        }

        // Check user filter
        if let Some(ref user) = self.filter_user {
            if &entry.entry_user != user {
                return false;
            }
        }

        // Check start time filter
        if let Some(start) = self.filter_start_time {
            if entry.entry_timestamp < start {
                return false;
            }
        }

        // Check end time filter
        if let Some(end) = self.filter_end_time {
            if entry.entry_timestamp > end {
                return false;
            }
        }

        // Check result filter
        if let Some(result) = self.filter_result {
            if entry.entry_result != result {
                return false;
            }
        }

        true
    }
}

/// Tamper-proof audit logger using hash chain.
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
        // Open file in append mode (create if it doesn't exist)
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .await?;

        Ok(AuditLogger {
            file: tokio::sync::Mutex::new(file),
            hash_chain: tokio::sync::Mutex::new(HashChain::new()),
        })
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

        // Serialise entry data for hashing (without the hash itself)
        let entry_data = (Utc::now().timestamp(), action_type, &user, &target, result);
        let serialised_data = serde_json::to_vec(&entry_data)?;

        // Compute hash for this entry
        let hash = chain.next_hash(&serialised_data);

        // Create the full entry with the hash
        let entry = AuditEntry::new(action_type, user, target, hash.clone());

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

        // Serialise entry data for hashing
        let entry_data = (
            Utc::now().timestamp(),
            action_type,
            &user,
            &target,
            ActionResult::Failure,
            &error_message,
        );
        let serialised_data = serde_json::to_vec(&entry_data)?;

        // Compute hash for this entry
        let hash = chain.next_hash(&serialised_data);

        // Create failure entry with error message
        let entry = AuditEntry::new_failure(action_type, user, target, error_message, hash.clone());

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

    /// Verifies the integrity of the entire audit log.
    ///
    /// Reads all entries and recalculates the hash chain to detect tampering.
    ///
    /// # Arguments
    /// * `log_path` - Path to the audit log file to verify
    ///
    /// # Returns
    /// `true` if the log is intact, `false` if tampering detected
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
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_audit_logger_basic() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log a successful action
        logger
            .log_action(
                ActionType::Scan,
                "testuser".to_string(),
                "/etc/ssh/sshd_config".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Verify integrity
        let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_multiple_entries_appending() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log multiple different actions
        logger
            .log_action(
                ActionType::Scan,
                "alice".to_string(),
                "/etc/ssh/sshd_config".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Apply,
                "bob".to_string(),
                "kernel_hardening".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_failure(
                ActionType::Rollback,
                "alice".to_string(),
                "checkpoint_123".to_string(),
                "Checkpoint not found".to_string(),
            )
            .await
            .unwrap();

        // Query all entries
        let all_entries = AuditLogger::query(log_path, QueryFilter::new())
            .await
            .unwrap();

        // Should have exactly 3 entries
        assert_eq!(all_entries.len(), 3);

        // Verify the entries are in order
        assert_eq!(all_entries[0].entry_action_type, ActionType::Scan);
        assert_eq!(all_entries[0].entry_user, "alice");
        assert_eq!(all_entries[0].entry_result, ActionResult::Success);

        assert_eq!(all_entries[1].entry_action_type, ActionType::Apply);
        assert_eq!(all_entries[1].entry_user, "bob");

        assert_eq!(all_entries[2].entry_action_type, ActionType::Rollback);
        assert_eq!(all_entries[2].entry_result, ActionResult::Failure);
        assert_eq!(
            all_entries[2].entry_details.get("error").unwrap(),
            "Checkpoint not found"
        );

        // Verify integrity is still valid
        let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_query_filter_by_action_type() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log various action types
        logger
            .log_action(
                ActionType::Scan,
                "user1".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Apply,
                "user2".to_string(),
                "target2".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Scan,
                "user3".to_string(),
                "target3".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::CheckpointCreate,
                "user1".to_string(),
                "cp_001".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Query only Scan actions
        let scan_filter = QueryFilter::new().with_action_type(ActionType::Scan);
        let scan_entries = AuditLogger::query(log_path, scan_filter).await.unwrap();

        // Should have exactly 2 Scan entries
        assert_eq!(scan_entries.len(), 2);
        assert!(scan_entries
            .iter()
            .all(|e| e.entry_action_type == ActionType::Scan));

        // Query only Apply actions
        let apply_filter = QueryFilter::new().with_action_type(ActionType::Apply);
        let apply_entries = AuditLogger::query(log_path, apply_filter).await.unwrap();

        // Should have exactly 1 Apply entry
        assert_eq!(apply_entries.len(), 1);
        assert_eq!(apply_entries[0].entry_action_type, ActionType::Apply);
        assert_eq!(apply_entries[0].entry_user, "user2");
    }

    #[tokio::test]
    async fn test_query_filter_by_user() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log actions by different users
        logger
            .log_action(
                ActionType::Scan,
                "alice".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Apply,
                "bob".to_string(),
                "target2".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Rollback,
                "alice".to_string(),
                "target3".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::CheckpointCreate,
                "charlie".to_string(),
                "cp_001".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Query actions by alice
        let alice_filter = QueryFilter::new().with_user("alice".to_string());
        let alice_entries = AuditLogger::query(log_path, alice_filter).await.unwrap();

        // Should have exactly 2 entries for alice
        assert_eq!(alice_entries.len(), 2);
        assert!(alice_entries.iter().all(|e| e.entry_user == "alice"));

        // Query actions by bob
        let bob_filter = QueryFilter::new().with_user("bob".to_string());
        let bob_entries = AuditLogger::query(log_path, bob_filter).await.unwrap();

        // Should have exactly 1 entry for bob
        assert_eq!(bob_entries.len(), 1);
        assert_eq!(bob_entries[0].entry_user, "bob");
        assert_eq!(bob_entries[0].entry_action_type, ActionType::Apply);
    }

    #[tokio::test]
    async fn test_query_filter_by_result() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log mix of successful and failed actions
        logger
            .log_action(
                ActionType::Scan,
                "user1".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_failure(
                ActionType::Apply,
                "user2".to_string(),
                "target2".to_string(),
                "Permission denied".to_string(),
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Rollback,
                "user3".to_string(),
                "target3".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_failure(
                ActionType::CheckpointCreate,
                "user4".to_string(),
                "cp_001".to_string(),
                "Disk full".to_string(),
            )
            .await
            .unwrap();

        // Query only successful actions
        let success_filter = QueryFilter::new().with_result(ActionResult::Success);
        let success_entries = AuditLogger::query(log_path, success_filter).await.unwrap();

        // Should have exactly 2 successful entries
        assert_eq!(success_entries.len(), 2);
        assert!(success_entries
            .iter()
            .all(|e| e.entry_result == ActionResult::Success));

        // Query only failed actions
        let failure_filter = QueryFilter::new().with_result(ActionResult::Failure);
        let failure_entries = AuditLogger::query(log_path, failure_filter).await.unwrap();

        // Should have exactly 2 failed entries
        assert_eq!(failure_entries.len(), 2);
        assert!(failure_entries
            .iter()
            .all(|e| e.entry_result == ActionResult::Failure));

        // Verify error messages are present in failures
        assert!(failure_entries[0].entry_details.contains_key("error"));
        assert!(failure_entries[1].entry_details.contains_key("error"));
    }

    #[tokio::test]
    async fn test_query_combined_filters() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log various combinations
        logger
            .log_action(
                ActionType::Scan,
                "alice".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_failure(
                ActionType::Scan,
                "alice".to_string(),
                "target2".to_string(),
                "Error occurred".to_string(),
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Scan,
                "bob".to_string(),
                "target3".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Apply,
                "alice".to_string(),
                "target4".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Query: Scan actions by alice that were successful
        let combined_filter = QueryFilter::new()
            .with_action_type(ActionType::Scan)
            .with_user("alice".to_string())
            .with_result(ActionResult::Success);

        let entries = AuditLogger::query(log_path, combined_filter).await.unwrap();

        // Should have exactly 1 entry matching all criteria
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_action_type, ActionType::Scan);
        assert_eq!(entries[0].entry_user, "alice");
        assert_eq!(entries[0].entry_result, ActionResult::Success);
        assert_eq!(entries[0].entry_target, "target1");
    }

    #[tokio::test]
    async fn test_tamper_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log some entries
        logger
            .log_action(
                ActionType::Scan,
                "alice".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Apply,
                "bob".to_string(),
                "target2".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Verify integrity before tampering
        let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
        assert!(is_valid);

        // Now tamper with the log file by modifying an entry
        let content = tokio::fs::read_to_string(log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();

        // Modify the first entry (change user from "alice" to "eve")
        let mut first_entry: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        first_entry.entry_user = "eve".to_string();

        // Write the tampered entry back
        let tampered_line = serde_json::to_string(&first_entry).unwrap();
        let mut new_content = String::new();
        new_content.push_str(&tampered_line);
        new_content.push('\n');
        new_content.push_str(lines[1]);
        new_content.push('\n');

        tokio::fs::write(log_path, new_content).await.unwrap();

        // Verify integrity after tampering - should detect tampering
        let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
        assert!(!is_valid, "Tampering should have been detected!");
    }

    #[tokio::test]
    async fn test_query_filter_by_time_range() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log first entry
        logger
            .log_action(
                ActionType::Scan,
                "user1".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Wait a bit to create time separation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let middle_time = Utc::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Log second entry (after middle_time)
        logger
            .log_action(
                ActionType::Apply,
                "user2".to_string(),
                "target2".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Log third entry (even later)
        logger
            .log_action(
                ActionType::Rollback,
                "user3".to_string(),
                "target3".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Query entries after middle_time
        let filter = QueryFilter::new().with_start_time(middle_time);
        let entries = AuditLogger::query(log_path, filter).await.unwrap();

        // Should have 2 entries (the last two)
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_action_type, ActionType::Apply);
        assert_eq!(entries[1].entry_action_type, ActionType::Rollback);

        // Query entries before middle_time
        let filter = QueryFilter::new().with_end_time(middle_time);
        let entries = AuditLogger::query(log_path, filter).await.unwrap();

        // Should have 1 entry (the first one)
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_action_type, ActionType::Scan);
    }

    #[tokio::test]
    async fn test_query_empty_filter_returns_all() {
        let temp_file = NamedTempFile::new().unwrap();
        let log_path = temp_file.path().to_str().unwrap();

        let logger = AuditLogger::new(log_path).await.unwrap();

        // Log 5 different entries
        logger
            .log_action(
                ActionType::Scan,
                "user1".to_string(),
                "target1".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_failure(
                ActionType::Apply,
                "user2".to_string(),
                "target2".to_string(),
                "Error".to_string(),
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::Rollback,
                "user3".to_string(),
                "target3".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::CheckpointCreate,
                "user4".to_string(),
                "cp_001".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        logger
            .log_action(
                ActionType::ConfigChange,
                "user5".to_string(),
                "config.toml".to_string(),
                ActionResult::Success,
            )
            .await
            .unwrap();

        // Query with empty filter (should return all)
        let all_entries = AuditLogger::query(log_path, QueryFilter::new())
            .await
            .unwrap();

        // Should have all 5 entries
        assert_eq!(all_entries.len(), 5);
    }
}
