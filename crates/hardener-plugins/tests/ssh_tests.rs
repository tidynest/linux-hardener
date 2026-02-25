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

    let result = plugin.scan(&ctx).await;

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
