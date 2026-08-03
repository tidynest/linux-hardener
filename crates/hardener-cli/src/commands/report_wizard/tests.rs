#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`report_wizard`](super).
//!
//! Split out of `commands/report_wizard.rs`. This file sits in the `report_wizard/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::report_wizard` and every import carried
//! across unchanged, private items included.

use super::*;
use hardener_common::types::ComplianceProfile;
use std::collections::HashSet;

/// The custom picker must offer every supported framework. This guards the
/// regression where ISO 27001 was defined everywhere except this table.
#[test]
fn frameworks_table_is_complete_and_unique() {
    let listed: HashSet<ComplianceFramework> = FRAMEWORKS.iter().map(|f| f.framework).collect();
    assert_eq!(
        listed.len(),
        FRAMEWORKS.len(),
        "duplicate framework in the picker table"
    );
    assert_eq!(listed.len(), 10, "picker must list all 10 frameworks");
    assert!(
        listed.contains(&ComplianceFramework::ISO27001),
        "ISO 27001 missing from the picker table"
    );
}

/// Regression guard: colouring the score string before formatting it
/// with `{:.1}` truncated "75.0" down to "7" (precision on a Display
/// applies as a max-width truncation, not decimal rounding).
#[test]
fn format_score_renders_full_number() {
    assert_eq!(format_score(75.0), "75.0");
    assert_eq!(format_score(68.18181818), "68.2");
    assert_eq!(format_score(16.666), "16.7");
    assert_eq!(format_score(0.0), "0.0");
    assert_eq!(format_score(100.0), "100.0");
}

/// Regression guard: `~/` with no further input used to save a literal
/// file named `~.txt` in the current directory instead of expanding to
/// the home directory.
#[test]
fn resolve_output_path_expands_home_dir() {
    let home = dirs::home_dir().expect("test host must have a home directory");
    let resolved = resolve_output_path("~/");
    assert_eq!(resolved, home.join("compliance-report"));
}

#[test]
fn resolve_output_path_expands_tilde_in_nested_file_path() {
    let home = dirs::home_dir().expect("test host must have a home directory");
    let resolved = resolve_output_path("~/reports/out");
    assert_eq!(resolved, home.join("reports/out"));
}

#[test]
fn resolve_output_path_joins_default_name_for_existing_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().to_str().expect("utf8 tempdir path");
    let resolved = resolve_output_path(input);
    assert_eq!(resolved, dir.path().join("compliance-report"));
}

#[test]
fn resolve_output_path_leaves_plain_file_path_unchanged() {
    let resolved = resolve_output_path("/tmp/some/report.json");
    assert_eq!(resolved, PathBuf::from("/tmp/some/report.json"));
}

/// A wizard state that has got as far as generating a report: a scenario is
/// chosen, because the wizard refuses to go on without one.
fn chosen_state() -> WizardState {
    WizardState {
        scenario: Some(Scenario::Server),
        output_formats: vec![OutputFormat::Json],
        output_path: None,
    }
}

#[tokio::test]
async fn the_wizard_scores_the_host_it_scanned() {
    // The scanned host decides the identifier set, exactly as it does for the
    // non-interactive `hardener report`. This used to be
    // ComplianceProfile::default(), so a RHEL 10 host was scored against the
    // generic identifiers by one surface and the RHEL 10 ones by the other.
    let rocky = hardener_core::MockExecutor::new().with_file(
        "/etc/os-release",
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
    );

    let config = wizard_report_config(&chosen_state(), &rocky, None)
        .await
        .expect("a state carrying a scenario yields a config");

    assert_eq!(config.profile, ComplianceProfile::Rhel10);
}

#[tokio::test]
async fn a_remote_wizard_run_resolves_the_remote_profile() {
    // The whole point of taking the caller's executor: with --ssh the profile
    // comes off the far end's os-release, not the controller's. The positive
    // control below is the same call against a host that has no os-release at
    // all, so a resolver that had stopped resolving could not pass both.
    let remote = hardener_core::MockExecutor::new().remote().with_file(
        "/etc/os-release",
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
    );

    let config = wizard_report_config(&chosen_state(), &remote, None)
        .await
        .expect("a state carrying a scenario yields a config");
    let generic = wizard_report_config(&chosen_state(), &hardener_core::MockExecutor::new(), None)
        .await
        .expect("a host with no os-release still yields a config");

    assert_eq!(config.profile, ComplianceProfile::Rhel10);
    assert_eq!(
        generic.profile,
        ComplianceProfile::Generic,
        "an unreadable os-release resolves to Generic rather than failing the run"
    );
}

#[tokio::test]
async fn a_state_with_no_scenario_is_refused_rather_than_scored() {
    let empty = WizardState::default();

    let refused = wizard_report_config(&empty, &hardener_core::MockExecutor::new(), None).await;

    assert!(refused.is_err(), "no scenario means no report");
}

#[tokio::test]
async fn an_explicit_profile_wins_over_the_detected_one() {
    // `hardener report --profile generic` on a RHEL host scores against the
    // generic identifiers; the wizard behind the same flag used to detect
    // regardless, so one surface honoured the operator and the other overruled
    // them without saying so. The mock is the RHEL host, so a detector that
    // ignored the override would answer Rhel10 here.
    let rocky = hardener_core::MockExecutor::new().with_file(
        "/etc/os-release",
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
    );

    let config = wizard_report_config(&chosen_state(), &rocky, Some(ComplianceProfile::Generic))
        .await
        .expect("a state carrying a scenario yields a config");

    assert_eq!(config.profile, ComplianceProfile::Generic);
}
