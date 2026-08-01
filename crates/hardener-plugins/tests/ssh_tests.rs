use hardener_common::types::{FindingCategory, PluginId};
use hardener_core::{PluginConfig, context::Context, plugin::HardeningPlugin};
use hardener_plugins::ssh::SshHardeningPlugin;

#[test]
fn test_ssh_plugin_metadata() {
    let plugin = SshHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("ssh-hardening"));
    assert_eq!(metadata.plugin_name, "SSH Hardening");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(metadata.plugin_category, FindingCategory::Network);

    assert!(!metadata.plugin_description.is_empty());
}

#[test]
fn test_ssh_plugin_has_no_dependencies() {
    let plugin = SshHardeningPlugin::new();
    let deps = plugin.dependencies();

    assert!(deps.is_empty(), "SSH plugin should have no dependencies");
}

#[tokio::test]
async fn test_ssh_scan_reads_configuration() {
    let plugin = SshHardeningPlugin::new();
    let ctx = Context::new();

    // This runs against whatever `/etc/ssh` the host actually has, so what it
    // can assert is limited to what is true on every host.
    //
    // It used to assert `scan_success` outright, with an `Err` arm excusing a
    // machine that has no `sshd_config`. That arm has been unreachable since
    // the scan started reporting an incomplete run through `ScanResult`
    // instead of `Err`: a host the scan cannot complete on now lands in the
    // `Ok` arm and fails the success assertion. So the test really asserted
    // "this machine has a readable sshd_config and readable drop-ins", which
    // is a property of the machine, not of the plugin, and it duly passed on a
    // developer host and failed on a CI runner.
    //
    // The property that holds everywhere is that the two outcomes stay
    // distinguishable: a completed scan carries no error, and an incomplete one
    // says why. That is the whole point of `scan_success` existing, and it is
    // what a machine consumer relies on. The fixture-driven coverage of what
    // the scan finds lives in `ssh_mock_tests.rs`, where the config is known.
    let scan_result = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("the ssh scan reports an incomplete run through ScanResult, never as Err");

    assert_eq!(scan_result.scan_plugin_id, PluginId::new("ssh-hardening"));
    assert!(
        scan_result.scan_duration_us > 0,
        "Scan should take measurable time"
    );

    if scan_result.scan_success {
        assert!(
            scan_result.scan_error.is_none(),
            "a completed scan must carry no error, got: {:?}",
            scan_result.scan_error
        );
    } else {
        // Printed rather than merely counted: an incomplete scan here is a
        // fact about this host, and the next person to see it in CI needs the
        // reason without having to reproduce the environment.
        let reason = scan_result.scan_error.as_deref().unwrap_or_default();
        assert!(
            !reason.is_empty(),
            "an incomplete scan must say why it did not complete, or it is \
             indistinguishable from a clean one"
        );
    }
}

#[tokio::test]
async fn ssh_validate_on_this_host_smoke_test() {
    let plugin = SshHardeningPlugin::new();
    let ctx = Context::new();
    let config = PluginConfig::default();

    // A declared environment smoke test, and named so nobody grows it back:
    // it validates whatever `/etc/ssh` the host executing it happens to have,
    // so the only things it may assert are the ones true on every host. What a
    // report says about a known configuration is settled deterministically in
    // `ssh_mock_tests.rs`, where the executor is a fixture instead of a machine.
    //
    // It used to `match` the result with an `Err(_) => {}` arm excused by a
    // comment about a machine with no `sshd_config`. That arm asserted nothing
    // and could never run anyway: `validate` reports an absent or unreadable
    // config as a Critical issue inside an `Ok` report and has no `Err` path
    // left, exactly as the scan above stopped reporting an incomplete run as
    // `Err`. The surviving assertion in the `Ok` arm then sat behind
    // `if validation_report_is_valid`, so on any host carrying a single
    // validation issue the whole test asserted one plugin id and exited 0.
    let report = plugin
        .validate(&ctx, &config)
        .await
        .expect("ssh validate reports an unusable config through ValidationReport, never as Err");

    assert_eq!(
        report.validation_report_plugin_id,
        PluginId::new("ssh-hardening")
    );

    // The property the conditional was reaching for, stated so that it runs on
    // every host rather than only on a clean one: validity is defined as having
    // no issues, so the two must never disagree in either direction. A report
    // calling itself valid while listing issues is the failure an operator acts
    // on, and it is the one the old `if` could not see.
    //
    // Its ceiling, declared here rather than left to be discovered from a green
    // log: it RUNS everywhere but can only FAIL on a host whose ssh
    // configuration produces at least one issue. On a clean host both sides read
    // true and the comparison holds no matter what `validate` decided, which was
    // measured rather than reasoned: replacing the whole computation with
    // `let valid = true;` left this test green on this machine. The version that
    // discriminates needs a fixture that forces an issue, and that is
    // `ssh_mock_tests.rs`'s `test_ssh_validate_file_missing`.
    assert_eq!(
        report.validation_report_is_valid,
        report.validation_report_issues.is_empty(),
        "a valid report lists no issues and an invalid one must say what they are, got: {:?}",
        report.validation_report_issues
    );
}

#[tokio::test]
#[ignore] // Requires root privileges - run with: cargo test --test ssh_tests -- --ignored
async fn test_ssh_apply_requires_root() {
    let plugin = SshHardeningPlugin::new();
    let mut ctx = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id, PluginId::new("ssh-hardening"));

            // Verify all changes succeeded
            assert!(
                apply_result.apply_success,
                "All changes should succeed with root privileges"
            );

            assert!(
                apply_result.apply_error.is_none(),
                "Should not have overall error"
            );

            // Should have at least: backup + config write + service restart

            assert!(
                apply_result.apply_changes.len() >= 3,
                "Should have multiple changes recorded"
            );

            // Verify service restart was attempted
            let has_service_restart = apply_result.apply_changes.iter().any(|c| {
                c.change_description.contains("SSH service")
                    || c.change_description.contains("Restart")
            });
            assert!(has_service_restart, "Should include SSH service restart");
        }
        Err(e) => {
            panic!("Apply failed: {}", e);
        }
    }
}

/// Confirms the SSH coverage set carries both SOC 2 criteria the plugin
/// mirrors: CC6.1 for the authentication/access directives and CC6.6 for the
/// crypto and forwarding directives, filed under their TSC series.
#[test]
fn ssh_coverage_maps_soc2_access_and_boundary_criteria() {
    use hardener_common::types::ComplianceFramework;

    let soc2: Vec<_> = hardener_plugins::ssh::coverage()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::SOC2)
        .collect();

    for id in ["CC6.1", "CC6.6"] {
        let mapping = soc2
            .iter()
            .find(|m| m.compliance_control_id == id)
            .unwrap_or_else(|| panic!("SSH coverage must include SOC 2 {id}"));
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Logical and Physical Access Controls")
        );
    }
}

/// Confirms the SSH coverage set carries the 800-171r3 crypto requirements
/// translated from its existing 800-53 entries: SC-13 → 3.13.11 and
/// SC-8 → 3.13.8, filed under their official family.
#[test]
fn ssh_coverage_maps_nist_800_171_crypto_requirements() {
    use hardener_common::types::ComplianceFramework;

    let nist171: Vec<_> = hardener_plugins::ssh::coverage()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::NIST800171)
        .collect();

    for id in ["3.13.11", "3.13.8"] {
        let mapping = nist171
            .iter()
            .find(|m| m.compliance_control_id == id)
            .unwrap_or_else(|| panic!("SSH coverage must include 800-171 {id}"));
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("System and Communications Protection")
        );
    }
}

/// Confirms the SSH coverage set carries the FedRAMP crypto controls: SC-13
/// and SC-8 are both GSA rev5 Moderate baseline members, mirrored verbatim
/// from the existing 800-53 entries under their official family.
#[test]
fn ssh_coverage_maps_fedramp_moderate_crypto_controls() {
    use hardener_common::types::ComplianceFramework;

    let fedramp: Vec<_> = hardener_plugins::ssh::coverage()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
        .collect();

    for id in ["SC-13", "SC-8"] {
        let mapping = fedramp
            .iter()
            .find(|m| m.compliance_control_id == id)
            .unwrap_or_else(|| panic!("SSH coverage must include FedRAMP {id}"));
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("System and Communications Protection")
        );
    }
}
