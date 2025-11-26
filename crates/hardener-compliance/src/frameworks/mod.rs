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
