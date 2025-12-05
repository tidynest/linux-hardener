//! Types for GUI scan history persistence.
//!
//! These types mirror `hardener-types::ScanResult` and `Finding` but are
//! optimised for database storage. The CLI remains stateless; these are
//! used exclusively by the Tauri GUI backend.

use serde::{Deserialize, Serialize};

/// Unique identifier for a scan session.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ScanSessionId(String);

impl ScanSessionId {
    /// Creates a new scan session ID from a string.
    pub fn new(id: impl Into<String>) -> ScanSessionId {
        Self(id.into())
    }

    /// Returns the string representation of the session ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Generates a unique session ID using timestamp and random suffix.
    pub fn generate() -> ScanSessionId {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let random_suffix: u32 = rand::random();
        Self::new(format!("scan_{}_{:08x}", timestamp, random_suffix))
    }
}

impl From<&str> for ScanSessionId {
    fn from(s: &str) -> ScanSessionId {
        Self(s.to_string())
    }
}

impl From<String> for ScanSessionId {
    fn from(s: String) -> ScanSessionId {
        Self(s)
    }
}

/// Status of a scan session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ScanStatus {
    /// Scan is currently in progress.
    Running,
    /// Scan completed successfully.
    Completed,
    /// Scan failed with an error.
    Failed,
}

impl ScanStatus {
    /// Converts status to database string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Running => "running",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
        }
    }

    /// Parses status from database string.
    pub fn from_str(s: &str) -> ScanStatus {
        match s {
            "completed" => ScanStatus::Completed,
            "failed" => ScanStatus::Failed,
            _ => ScanStatus::Running,
        }
    }
}

/// A scan session representing one execution of the security scanner.
///
/// Sessions track metadata about scan runs and link to their results.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanSession {
    /// Unique identifier for this session.
    pub session_id: ScanSessionId,
    /// Unix timestamp when scan started.
    pub session_started_at: i64,
    /// Unix timestamp when scan completed (None if still running).
    pub session_completed_at: Option<i64>,
    /// Total number of findings across all plugins.
    pub session_total_findings: i32,
    /// Total number of plugins scanned.
    pub session_total_plugins: i32,
    /// Current status of the scan.
    pub session_status: ScanStatus,
}
