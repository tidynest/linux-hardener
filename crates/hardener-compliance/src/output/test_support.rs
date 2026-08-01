#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Fixtures shared by the formatter test modules.
//!
//! Split out of `output/mod.rs`. That file *is* the module `output`, so this
//! sits in the directory it already owns. It holds no tests of its own: the
//! five formatter test modules reach it by its absolute path,
//! `crate::output::test_support`, which the move left untouched.

use hardener_types::{Finding, FindingCategory, FindingPolicyException, Severity};

/// A finding as a scan emits it. Passing `exception` mirrors what
/// `Plugin::scan` attaches when the config documents the deviation.
pub(crate) fn finding(title: &str, excepted: bool) -> Finding {
    Finding {
        finding_category: FindingCategory::Network,
        finding_current_value: "yes".to_string(),
        finding_description: "Test finding".to_string(),
        finding_explanation: "Test explanation".to_string(),
        finding_id: format!("test-{title}"),
        finding_impact: "Test impact".to_string(),
        finding_recommended_value: "no".to_string(),
        finding_remediation_steps: vec!["Fix it".to_string()],
        finding_severity: Severity::High,
        finding_title: title.to_string(),
        finding_compliance: vec![],
        finding_policy_exception: excepted.then(FindingPolicyException::default),
    }
}
