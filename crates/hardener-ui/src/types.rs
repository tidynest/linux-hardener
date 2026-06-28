//! Re-export backend types for UI use.
//!
//! The UI uses types from hardener-types for WASM compatibility.

// Re-export all types from hardener-types
pub use hardener_types::scheduler::{
    EmailUiConfig, NotificationUiConfig, SchedulerUiConfig, TestNotificationResult, WebhookUiConfig,
};
pub use hardener_types::{
    ApplyOutcome, ApplyResult, Change, ChangeType, ComplianceFramework, ComplianceMapping,
    ComplianceReport, ComplianceSummary, ConfigSummary, ControlResult, ControlStatus,
    FileRestoreAction, FileRestoreResult, Finding, FindingCategory, FindingPolicyException,
    FleetFrameworkPosture, FleetHostScan, FleetHostStatus, PluginId, PluginMetadata,
    RollbackOutcome, RollbackResult, ScanResult, Severity, SeverityTallies, ValidationIssue,
    ValidationReport,
};

/// Checkpoint information for UI display.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
}

/// Scan session metadata for history display.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ScanSessionInfo {
    pub session_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_findings: i32,
    pub total_plugins: i32,
    pub status: String,
}

/// Detailed checkpoint information including captured files.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CheckpointDetail {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
    pub file_count: usize,
    pub files: Vec<CheckpointFileInfo>,
}

/// Individual file state within a checkpoint.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CheckpointFileInfo {
    pub path: String,
    pub permissions: String,
    pub has_content: bool,
}
