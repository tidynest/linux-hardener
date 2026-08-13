//! Re-export backend types for UI use.
//!
//! The UI uses types from hardener-types for WASM compatibility. Nothing is
//! defined here: a hand-written mirror of a backend struct lost a field twice
//! (#156, #157) before the checkpoint types moved into `hardener-types`.

// Re-export all types from hardener-types
pub use hardener_types::scheduler::{
    EmailUiConfig, NotificationUiConfig, SchedulerUiConfig, TestNotificationResult, WebhookUiConfig,
};
pub use hardener_types::{
    ApplyOutcome, ApplyResult, Change, ChangeType, CheckpointDetail, CheckpointFileInfo,
    CheckpointInfo, CheckpointList, ComplianceFramework, ComplianceMapping, ComplianceReport,
    ComplianceSummary, ConfigSummary, ControlResult, ControlStatus, DivergenceState,
    ExceptionOutcome, FileRestoreAction, FileRestoreResult, Finding, FindingCategory,
    FindingPolicyException, FleetFrameworkPosture, FleetHostScan, FleetHostStatus, PluginId,
    PluginMetadata, RollbackDivergence, RollbackOutcome, RollbackResult, ScanResult,
    ScanSessionInfo, Severity, SeverityTallies, ValidationIssue, ValidationReport,
    WrittenException,
};
