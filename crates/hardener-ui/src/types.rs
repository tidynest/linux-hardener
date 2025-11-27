//! Re-export backend types for UI use.
//!
//! The UI uses the same types as the backend for seamless serialisation.

pub use hardener_common::types::{FindingCategory, PluginId, Severity};
pub use hardener_core::plugin::{ApplyResult, Change, Finding, ScanResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
}

pub use hardener_common::types::{ComplianceFramework, ControlStatus};
pub use hardener_compliance::{ComplianceReport, ComplianceSummary, ControlResult};
