//! Common types used across the hardening tool.
//!
//! This module re-exports types from `hardener-types` for backwards compatibility.
//! All type definitions are in `hardener-types` to ensure WASM compatibility.

// Re-export all types from hardener-types
pub use hardener_types::{
    ComplianceFramework, ComplianceMapping, ComplianceProfile, ControlStatus, FindingCategory,
    FindingPolicyException, PluginId, Severity, UNDELETABLE_ROLLBACK_PATHS,
};
