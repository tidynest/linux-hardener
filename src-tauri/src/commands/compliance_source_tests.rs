#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Compliance-source tests for [`commands`](super).
//!
//! Split out of `commands.rs`, which carried three test modules under three
//! different names. Each keeps its own name in its own file, following
//! `acl_tests.rs`, which has sat beside `main.rs` since 2026-07-18 and is
//! this repository's precedent for a split-out unit test module. `super`
//! still resolves to `crate::commands`.

use super::*;
use hardener_types::ControlStatus;

fn failed_scan_of(plugin_id: &str) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new(plugin_id),
        scan_success: false,
        scan_findings: vec![],
        scan_unchecked: vec![],
        scan_duration_us: 0,
        scan_error: Some("reading /etc/ssh/sshd_config requires root".to_string()),
        scan_skipped: None,
    }
}

/// The CIS controls `plugin_id` declares it assesses that `results` make the
/// generator report as `Pass`.
///
/// Asserting through the real generator rather than on the unchecked list is
/// deliberate: the defect is not a missing entry, it is a control reported as
/// satisfied on evidence nobody collected.
///
/// It takes the scan results as they came back, because that is what
/// `generate` takes now. The flatten it used to do here is inside the
/// generator, which is the whole point: this test can no longer pass by
/// flattening correctly in a way the shipping path does not.
fn controls_passed_on_behalf_of(plugin_id: &str, results: &[ScanResult]) -> Vec<String> {
    let covered: std::collections::HashSet<String> = hardener_plugins::coverage_for(plugin_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::CIS)
        .map(|m| m.compliance_control_id)
        .collect();

    let config = ReportConfig {
        scenario: Scenario::Custom(vec![ComplianceFramework::CIS]),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile: ComplianceProfile::Generic,
    };

    ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        ComplianceConfig::default(),
    )
    .generate(results, &[])
    .into_iter()
    .flat_map(|report| report.report_controls)
    .filter(|c| c.control_status == ControlStatus::Pass && covered.contains(&c.control_id))
    .map(|c| c.control_id)
    .collect()
}

/// The desktop sources its compliance report from the latest persisted
/// session. `scan_success` survives the round trip through the database, and
/// flattening threw it away, so a plugin whose scan failed contributed no
/// findings and the generator passed every control it covers on the silence
/// that failure caused.
#[test]
fn a_failed_plugin_in_a_persisted_session_cannot_pass_its_controls() {
    let passed = controls_passed_on_behalf_of("ssh-hardening", &[failed_scan_of("ssh-hardening")]);

    assert!(
        passed.is_empty(),
        "controls reported Pass for a scan that never completed: {passed:?}"
    );
}

/// The other direction, without which the test above would pass against a
/// generator that reported nothing as satisfied ever.
#[test]
fn a_completed_scan_of_every_plugin_does_pass_controls() {
    let results: Vec<ScanResult> = create_plugin_registry()
        .list()
        .expect("the registry lists on this build")
        .iter()
        .map(|m| ScanResult {
            scan_plugin_id: m.plugin_id.clone(),
            scan_success: true,
            scan_findings: vec![],
            scan_unchecked: vec![],
            scan_duration_us: 0,
            scan_error: None,
            scan_skipped: None,
        })
        .collect();

    let passed = controls_passed_on_behalf_of("ssh-hardening", &results);

    assert!(
        !passed.is_empty(),
        "a clean scan covering every plugin must pass something, or the test \
         above is comparing two empty lists"
    );
}
