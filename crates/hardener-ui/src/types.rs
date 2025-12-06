//! Re-export backend types for UI use.
//!
//! The UI uses types from hardener-types for WASM compatibility.

// Re-export all types from hardener-types
pub use hardener_types::{
    ApplyResult, Change, ChangeType, ComplianceFramework, ComplianceMapping, ComplianceReport,
    ComplianceSummary, ControlResult, ControlStatus, Finding, FindingCategory,
    FindingPolicyException, PluginId, PluginMetadata, ScanResult, Severity, ValidationIssue,
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
