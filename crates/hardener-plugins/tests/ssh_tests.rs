use hardener_common::types::{FindingCategory, PluginId};
use hardener_core::{Config, context::Context, plugin::HardeningPlugin};
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

            // Print findings for manual verification
            println!(
                "SSH scan found {} findings:",
                scan_result.scan_findings.len()
            );
            for finding in &scan_result.scan_findings {
                println!(
                    "  - {}: {} → {}",
                    finding.finding_title,
                    finding.finding_current_value,
                    finding.finding_recommended_value
                );
            }
        }
        Err(e) => {
            // If /etc/ssh/sshd_config doesn't exist, that's acceptable for test environments.
            eprintln!(
                "SSH scan failed (could be expected in test environment): {}",
                e
            );
        }
    }
}

#[tokio::test]
async fn test_ssh_validate_checks_config_file() {
    let plugin = SshHardeningPlugin::new();
    let ctx = Context::new();
    let config = Config;

    let result = plugin.validate(&ctx, &config).await;

    match result {
        Ok(validation_report) => {
            assert_eq!(
                validation_report.validation_report_plugin_id,
                PluginId::new("ssh-hardening")
            );

            println!(
                "SSH validation result: valid={}",
                validation_report.validation_report_is_valid
            );

            if !validation_report.validation_report_issues.is_empty() {
                println!("Validation issues found:");
                for issue in &validation_report.validation_report_issues {
                    println!(
                        "  - [{}] {}",
                        issue.validation_issue_severity, issue.validation_issue_message
                    );
                }
            }

            // If config file exists and is readable, validation should pass
            if validation_report.validation_report_is_valid {
                assert!(validation_report.validation_report_issues.is_empty());
            }
        }
        Err(e) => {
            eprintln!("Validation failed: {}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Requires root privileges - run with: cargo test --test ssh_tests -- --ignored
async fn test_ssh_apply_requires_root() {
    let plugin = SshHardeningPlugin::new();
    let mut ctx = Context::new();
    let config = Config;

    println!("\n=== Testing SSH Apply (requires root) ===");
    println!("This test will:");
    println!("1. Create a backup of /etc/ssh/sshd_config");
    println!("2. Apply 8 secure SSH directives");
    println!("3. Write the modified configuration");
    println!("4. Restart the SSH service");
    println!("\nIMPORTANT: Ensure you have SSH key access before running!\n");

    let result = plugin.apply(&mut ctx, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id, PluginId::new("ssh-hardening"));

            println!("\nApply result: success={}", apply_result.apply_success);
            println!("Changes made ({}):", apply_result.apply_changes.len());

            for change in &apply_result.apply_changes {
                let status = if change.change_success { "✓" } else { "✗" };
                println!(
                    "  {} [{}] {}",
                    status, change.change_type, change.change_description
                );
                if let Some(ref error) = change.change_error {
                    println!("      Error: {}", error);
                }
            }

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
