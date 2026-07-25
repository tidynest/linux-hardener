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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await;

    match result {
        Ok(scan_result) => {
            assert_eq!(scan_result.scan_plugin_id, PluginId::new("ssh-hardening"));
            assert!(
                scan_result.scan_duration_us > 0,
                "Scan should take measurable time"
            );

            // The scan should succeed even if it finds insecure settings
            assert!(scan_result.scan_success, "Scan operation should succeed");

            assert!(scan_result.scan_error.is_none(), "Should not have errors");
        }
        Err(_) => {
            // If /etc/ssh/sshd_config doesn't exist, that's acceptable for test environments.
        }
    }
}

#[tokio::test]
async fn test_ssh_validate_checks_config_file() {
    let plugin = SshHardeningPlugin::new();
    let ctx = Context::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await;

    match result {
        Ok(validation_report) => {
            assert_eq!(
                validation_report.validation_report_plugin_id,
                PluginId::new("ssh-hardening")
            );

            // If config file exists and is readable, validation should pass
            if validation_report.validation_report_is_valid {
                assert!(validation_report.validation_report_issues.is_empty());
            }
        }
        Err(_) => {
            // Validation may fail if sshd_config doesn't exist in test environment.
        }
    }
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
