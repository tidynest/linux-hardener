//! Compliance framework definitions and control mappings.
//!
//! Each framework module defines the controls that can be checked
//! and maps them to plugin findings.

pub mod cis;
pub mod gdpr;
pub mod hipaa;
pub mod nist;
pub mod pci;
pub mod stig;

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Frameworks whose controls the hardening engine assesses automatically.
///
/// Scan findings are only ever tagged with controls from these frameworks —
/// today that is CIS alone, as every plugin emits CIS compliance mappings. A
/// control belonging to any *other* framework cannot be evaluated from scan
/// findings, so the report generator marks it `ManualReview` instead of
/// fabricating a `Pass` (which would misreport an insecure system as fully
/// compliant).
///
/// This is the single source of truth for automated compliance coverage. As
/// plugins gain mappings for further frameworks, extend this list (or move to
/// per-control coverage). See the compliance-coverage task in `NEXT.md`.
pub const AUTOMATED_FRAMEWORKS: &[ComplianceFramework] = &[ComplianceFramework::CIS];

/// Returns true if the engine automatically assesses the given framework's
/// controls from scan findings.
pub fn is_automated(framework: &ComplianceFramework) -> bool {
    AUTOMATED_FRAMEWORKS.contains(framework)
}

/// Returns all control definitions for a given framework.
pub fn get_controls(framework: &ComplianceFramework) -> Vec<ComplianceMapping> {
    match framework {
        ComplianceFramework::CIS => cis::get_controls(),
        ComplianceFramework::STIG => stig::get_controls(),
        ComplianceFramework::NIST => nist::get_controls(),
        ComplianceFramework::PCIDSS => pci::get_controls(),
        ComplianceFramework::HIPAA => hipaa::get_controls(),
        ComplianceFramework::GDPR => gdpr::get_controls(),
        ComplianceFramework::ISO27001 => vec![], // Future
    }
}
