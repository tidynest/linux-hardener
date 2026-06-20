//! Compliance framework definitions and control mappings.
//!
//! Only CIS and ISO/IEC 27001:2022 ship a hand-curated control catalogue. Every
//! other framework's catalogue is *derived* from the live plugin coverage set at
//! report time (see `generator::ReportGenerator`), so the controls it reports are
//! exactly the ones the engine actually assesses — a single source of truth, no
//! hand-maintained crosswalk to drift out of sync.

pub mod cis;
pub mod iso27001;

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns the hand-curated control catalogue for a framework, if one exists.
///
/// CIS and ISO/IEC 27001:2022 are published in full so their reports show the
/// complete standard (assessed controls as `Pass`/`Fail`, the rest as
/// `ManualReview`). All other frameworks return `None`: their catalogue is
/// derived from plugin coverage so it never lists a control the engine cannot
/// assess. This is the reconciliation that keeps catalogue and findings on one
/// identifier scheme.
pub fn curated_controls(framework: &ComplianceFramework) -> Option<Vec<ComplianceMapping>> {
    match framework {
        ComplianceFramework::CIS => Some(cis::get_controls()),
        ComplianceFramework::ISO27001 => Some(iso27001::get_controls()),
        _ => None,
    }
}
