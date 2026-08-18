#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`report`](super).
//!
//! Split out of `commands/report.rs`. This file sits in the `report/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::report` and every import carried
//! across unchanged, private items included.

use super::*;
use hardener_common::types::{ControlStatus, FindingCategory, PluginId, Severity};
use hardener_core::config::scope::ComplianceConfig;
use hardener_core::{MockExecutor, PolicyException};
use hardener_types::ExceptionOutcome;
use std::sync::Arc;

#[test]
fn finding_to_scan_finding_uses_display_strings() {
    let meta = PluginMetadata {
        plugin_category: FindingCategory::FileSystem,
        plugin_description: "test".to_string(),
        plugin_id: PluginId::new("test-plugin"),
        plugin_name: "Test".to_string(),
        plugin_version: "0.0.0".to_string(),
    };
    let finding = Finding {
        finding_id: "TEST-001".to_string(),
        finding_category: FindingCategory::FileSystem,
        finding_severity: Severity::Critical,
        finding_title: "title".to_string(),
        finding_description: "description".to_string(),
        finding_explanation: "explanation".to_string(),
        finding_impact: "impact".to_string(),
        finding_current_value: "current".to_string(),
        finding_recommended_value: "recommended".to_string(),
        finding_remediation_steps: vec![],
        finding_compliance: vec![],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    };

    let row = finding_to_scan_finding(&meta, &finding);

    assert_eq!(
        row.severity, "CRITICAL",
        "severity must persist via Display, not Debug"
    );
    assert_eq!(
        row.category.as_deref(),
        Some("File System"),
        "category must persist via Display, not Debug"
    );
}

#[test]
fn parse_profile_accepts_known_values_and_rejects_unknown() {
    assert_eq!(parse_profile("rhel10").unwrap(), ComplianceProfile::Rhel10);
    assert_eq!(
        parse_profile("generic").unwrap(),
        ComplianceProfile::Generic
    );
    let err = parse_profile("rhel9").unwrap_err().to_string();
    assert!(err.contains("Valid options: generic, rhel10"), "{err}");
}

#[test]
fn profile_line_prefers_framework_labels() {
    // Frameworks with a labelled RHEL 10 scheme name it outright.
    let stig = Scenario::Custom(vec![ComplianceFramework::STIG]);
    assert_eq!(
        profile_line(ComplianceProfile::Rhel10, &stig),
        "DISA RHEL 10 STIG V1R1 identifiers"
    );
    // Profile-invariant frameworks fall back to the plain profile name.
    let nist = Scenario::Custom(vec![ComplianceFramework::NIST]);
    assert_eq!(profile_line(ComplianceProfile::Rhel10, &nist), "rhel10");
}

#[tokio::test]
async fn scan_grouped_keeps_plugin_grouping_and_flattening_matches() {
    let exec = Arc::new(MockExecutor::new());
    let default_config = HardenerConfig::default();
    let grouped = scan_grouped(true, exec.clone(), &CliOutputFormat::Json, &default_config)
        .await
        .unwrap();
    // Every group carries its plugin metadata (so plugin_id is preserved).
    for (meta, _result) in &grouped.results {
        assert!(!meta.plugin_id.as_str().is_empty(), "group has a plugin id");
    }
    // Every registered plugin appears, including any whose scan failed:
    // dropping one is what let a failure read as a clean result. The
    // default config enables them all, so nothing is skipped here.
    assert_eq!(
        grouped.results.len(),
        create_plugin_registry().list().unwrap().len(),
        "no plugin may be missing from the grouped results"
    );
    assert!(
        grouped.skipped.is_empty(),
        "default config disables nothing"
    );

    // run_scan_with_unchecked returns the same findings and unchecked
    // entries, each flattened across plugins, plus one synthesised
    // unchecked entry per plugin whose scan did not complete.
    let (findings, unchecked) =
        run_scan_with_unchecked(true, exec, &CliOutputFormat::Json, &default_config)
            .await
            .unwrap();
    let grouped_findings: usize = grouped
        .results
        .iter()
        .map(|(_, r)| r.scan_findings.len())
        .sum();
    let grouped_unchecked: usize = grouped
        .results
        .iter()
        .map(|(_, r)| r.scan_unchecked.len())
        .sum();
    let failed = grouped
        .results
        .iter()
        .filter(|(_, r)| !r.scan_success)
        .count();
    assert_eq!(findings.len(), grouped_findings, "findings flatten");
    assert_eq!(
        unchecked.len(),
        grouped_unchecked + failed,
        "unchecked flatten, plus one entry per incomplete scan"
    );
    // The bare MockExecutor has no fixture data, so this exercises the
    // failure path rather than asserting a vacuous equality.
    assert!(failed > 0, "expected at least one plugin scan to fail here");
}

/// A plugin whose scan did not complete must not hand its controls a Pass.
///
/// The generator decides Pass from static plugin-declared coverage plus the
/// absence of a finding. A failed scan produces no findings, so without the
/// failure reaching the report the two are indistinguishable and every
/// control that plugin covers passes on evidence nobody collected. This is
/// the compliance-report face of the same conflation `scan` hit: silence
/// standing for both "verified" and "never checked".
#[tokio::test]
async fn a_failed_plugin_scan_cannot_pass_its_compliance_controls() {
    // No sshd_config on this executor, so the ssh plugin's scan reports
    // scan_success = false and returns no findings.
    let executor: Arc<dyn SystemExecutor> = Arc::new(MockExecutor::new());
    let report_config = ReportConfig {
        scenario: Scenario::Custom(vec![ComplianceFramework::CIS]),
        formats: vec![OutputFormat::Json],
        output_dir: None,
        profile: ComplianceProfile::default(),
    };

    let (findings, unchecked) = run_scan_with_unchecked(
        true,
        executor,
        &CliOutputFormat::Json,
        &HardenerConfig::default(),
    )
    .await
    .unwrap();

    let report = ReportGenerator::new(
        report_config,
        hardener_plugins::compliance_coverage(),
        ComplianceConfig::default(),
    )
    .generate(&findings, &unchecked)
    .into_iter()
    .next()
    .expect("one report");
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "5.2.10")
        .expect("CIS 5.2.10 is covered by the ssh plugin");

    assert_ne!(
        control.control_status,
        ControlStatus::Pass,
        "CIS 5.2.10 passed on a host whose ssh scan never completed"
    );
    assert_eq!(
        control.control_status,
        ControlStatus::ManualReview,
        "a control whose covering scan failed is exactly the manual-review case"
    );
}

#[test]
fn every_canonical_framework_id_parses() {
    // Guards the shared enum ids against drift: the UI builds its picker
    // and auto-report requests from ComplianceFramework::ALL, so every
    // canonical id must stay accepted by the CLI parser.
    // The canonical list is the single source the pickers, the CLI parser and
    // this layer all build from, so a framework added to or removed from it
    // must be re-checked here rather than silently skipping this layer. The
    // count is pinned to say so: the loop below covers whatever ALL holds,
    // and an ALL that changed size is exactly the case nobody looked at.
    assert_eq!(
        ComplianceFramework::ALL.len(),
        10,
        "the canonical framework list changed size; confirm the CLI's parse_framework still \
         accepts every id"
    );
    for framework in ComplianceFramework::ALL {
        assert_eq!(
            parse_framework(framework.id()).unwrap(),
            framework,
            "canonical id '{}' must parse to its framework",
            framework.id()
        );
    }
}

#[test]
fn parse_framework_accepts_legacy_aliases() {
    // Every spelling the flag historically accepted must keep working
    // now that parsing delegates to ComplianceFramework::from_id.
    for (alias, expected) in [
        ("pcidss", ComplianceFramework::PCIDSS),
        ("pci-dss", ComplianceFramework::PCIDSS),
        ("pci", ComplianceFramework::PCIDSS),
        ("iso", ComplianceFramework::ISO27001),
        ("soc-2", ComplianceFramework::SOC2),
        ("nist800171", ComplianceFramework::NIST800171),
        ("nist-800-171", ComplianceFramework::NIST800171),
        ("fed-ramp", ComplianceFramework::FedRAMP),
        ("PCI-DSS", ComplianceFramework::PCIDSS),
    ] {
        assert_eq!(
            parse_framework(alias).unwrap(),
            expected,
            "alias '{alias}' must still parse"
        );
    }
}

#[test]
fn parse_framework_rejects_unknown() {
    let err = parse_framework("nonsense").unwrap_err().to_string();
    assert!(err.contains("Unknown framework 'nonsense'"), "{err}");
}

/// Proves the report scan path is config-aware end to end: a config that
/// excepts a known finding changes the mapped control's outcome, which
/// `PluginConfig::default()` (Task 1's placeholder) could never do.
#[tokio::test]
async fn report_scan_path_honours_config_exceptions() {
    // A genuine CIS 1.5.1 violation: ASLR disabled. No other plugin has
    // fixture data on this MockExecutor; scan_grouped tolerates and skips
    // a plugin whose scan errors, so only this finding is at play.
    let executor: Arc<dyn SystemExecutor> =
        Arc::new(MockExecutor::new().with_file("/proc/sys/kernel/randomize_va_space", "0"));
    let coverage = hardener_plugins::compliance_coverage();
    let report_config = ReportConfig {
        scenario: Scenario::Custom(vec![ComplianceFramework::CIS]),
        formats: vec![OutputFormat::Json],
        output_dir: None,
        profile: ComplianceProfile::default(),
    };

    // Baseline: an unexcepted violation fails the control.
    let (findings, unchecked) = run_scan_with_unchecked(
        true,
        executor.clone(),
        &CliOutputFormat::Json,
        &HardenerConfig::default(),
    )
    .await
    .unwrap();
    let report = ReportGenerator::new(
        report_config.clone(),
        coverage.clone(),
        ComplianceConfig::default(),
    )
    .generate(&findings, &unchecked)
    .into_iter()
    .next()
    .expect("one report");
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("CIS 1.5.1 is covered by the kernel plugin");
    assert_eq!(
        control.control_status,
        ControlStatus::Fail,
        "an unexcepted ASLR violation must fail CIS 1.5.1"
    );

    // A real config excepting the exact finding the kernel plugin reports.
    let mut config = HardenerConfig::default();
    config.kernel.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "0".to_string(),
            allowed: true,
            reason: "test exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let (findings, unchecked) =
        run_scan_with_unchecked(true, executor, &CliOutputFormat::Json, &config)
            .await
            .unwrap();
    let report = ReportGenerator::new(report_config, coverage, ComplianceConfig::default())
        .generate(&findings, &unchecked)
        .into_iter()
        .next()
        .expect("one report");
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("CIS 1.5.1 remains covered");
    assert_eq!(
        control.control_status,
        ControlStatus::Pass,
        "an excepted finding must not fail its mapped control"
    );
}

/// `--output report.json` under the default `--report-format text` wrote a
/// human text report into a file named `.json`, exited 0 and said "Report saved
/// to". The extension was added when absent and never checked when present.
#[test]
fn an_output_path_naming_another_format_is_refused() {
    let refusal =
        refuse_extension_that_contradicts(std::path::Path::new("report.json"), OutputFormat::Text)
            .expect_err("a .json path under --report-format text must be refused");
    let refusal = refusal.to_string();

    assert!(
        refusal.contains("json") && refusal.contains("txt"),
        "the refusal names both documents by extension, which is the vocabulary \
         `--report-format` itself accepts; got: {refusal}"
    );
    assert!(
        refuse_extension_that_contradicts(std::path::Path::new("report.json"), OutputFormat::Json,)
            .is_ok(),
        "the same path agrees with --report-format json and must be allowed"
    );
}

/// The control against the check being made too broad. `Path::extension`
/// answers "what follows the last dot", not "what document is this", so a dated
/// or versioned name asks for nothing and must not be refused. Judged against
/// the closed list of formats this tool actually renders, exactly as
/// `history export` judges its own.
#[test]
fn an_output_path_that_names_no_document_is_left_alone() {
    // Judged against Json, not against the default Text: a list broadened to
    // map `03` to Text would leave this green under Text, because the mapping
    // would then agree with the selection and nothing would contradict.
    for path in ["report.2026.08.03", "session-1.5.1", "report", "a.tar.gz"] {
        assert!(
            refuse_extension_that_contradicts(std::path::Path::new(path), OutputFormat::Json)
                .is_ok(),
            "'{path}' names no document this tool renders and must not be refused"
        );
    }
    assert!(
        refuse_extension_that_contradicts(std::path::Path::new("REPORT.HTML"), OutputFormat::Text)
            .is_err(),
        "the comparison is case-insensitive, so an upper-case extension is still a document"
    );
    assert!(
        refuse_extension_that_contradicts(std::path::Path::new("report.htm"), OutputFormat::Html)
            .is_ok(),
        "htm and html are one document type, so neither contradicts the other"
    );
}

/// `--report-format` wins whenever it is given, and the global `-f/--format`
/// decides only when it is not.
///
/// The middle two cases are the ones #160 got wrong. `report --format json`
/// was accepted, exited 0, suppressed the progress rendering, and printed the
/// text report, because `--report-format` carried a clap `default_value` and
/// the command could not tell a defaulted "text" from an unstated one.
#[test]
fn the_global_format_decides_only_when_report_format_is_unstated() {
    // Unstated: the global flag decides. Both directions, so a function that
    // ignored its argument and returned a constant fails one of them.
    assert_eq!(
        resolve_output_format(None, OutputFormat::Json).unwrap(),
        OutputFormat::Json,
        "report --format json must render JSON, as it does for every other verb"
    );
    assert_eq!(
        resolve_output_format(None, OutputFormat::Text).unwrap(),
        OutputFormat::Text,
        "no flags at all still means text"
    );

    // Stated: it wins, including when it names the value the other flag
    // contradicts. Both directions again, for the same reason.
    assert_eq!(
        resolve_output_format(Some("text"), OutputFormat::Json).unwrap(),
        OutputFormat::Text,
        "an explicit --report-format text is a choice, not an absence, and \
         must not be overridden by the global flag"
    );
    assert_eq!(
        resolve_output_format(Some("json"), OutputFormat::Text).unwrap(),
        OutputFormat::Json,
        "an explicit --report-format json wins over a global text"
    );

    // The three formats the global flag cannot express still work when named,
    // and are unreachable through the None arm because `GlobalFormat` narrows
    // the global flag to Text or Json at parse time.
    for (spelling, expected) in [
        ("csv", OutputFormat::Csv),
        ("html", OutputFormat::Html),
        ("pdf", OutputFormat::Pdf),
        ("TXT", OutputFormat::Text),
        ("JSON", OutputFormat::Json),
    ] {
        assert_eq!(
            resolve_output_format(Some(spelling), OutputFormat::Text).unwrap(),
            expected,
            "'{spelling}' must still resolve, case-insensitively"
        );
    }

    assert!(
        resolve_output_format(Some("xml"), OutputFormat::Json).is_err(),
        "a value no renderer implements is still refused, and is not quietly \
         replaced by the global flag"
    );
}
