//! SSH Integration Tests for Plugins.
//!
//! These tests verify that plugins work correctly when executed over SSH.
//!
//! # Running These Tests
//!
//! These tests require an accessible SSH host. They are marked `#[ignore]`
//! by default and must be run explicitly.
//!
//! ## Using Docker (recommended)
//!
//! ```bash
//! # Start an SSH-enabled container
//! docker run -d --name hardener-ssh-test \
//!     -p 2222:22 \
//!     -e SSH_USERS="testuser:testpass" \
//!     -e SUDO_ACCESS="testuser" \
//!     panubo/sshd:latest
//!
//! # Run tests
//! SSH_TEST_HOST=localhost \
//! SSH_TEST_PORT=2222 \
//! SSH_TEST_USER=testuser \
//!     cargo test -p hardener-plugins --test ssh_integration_tests -- --ignored
//!
//! # Cleanup
//! docker stop hardener-ssh-test && docker rm hardener-ssh-test
//! ```
//!
//! ## Using a real host
//!
//! ```bash
//! SSH_TEST_HOST=myserver.example.com \
//! SSH_TEST_USER=admin \
//! SSH_TEST_KEY=~/.ssh/id_ed25519 \
//!     cargo test -p hardener-plugins --test ssh_integration_tests -- --ignored
//! ```

use hardener_core::{
    Context,
    executor::ssh::{SshConfig, SshExecutor},
    plugin::HardeningPlugin,
};
use hardener_plugins::{KernelHardeningPlugin, ServicesHardeningPlugin, SshHardeningPlugin};
use std::env;
use std::sync::Arc;
use std::time::Duration;

/// Get SSH configuration from environment variables.
fn get_ssh_config() -> Option<SshConfig> {
    let host = env::var("SSH_TEST_HOST").ok()?;

    Some(SshConfig {
        host,
        port: env::var("SSH_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(22),
        user: env::var("SSH_TEST_USER").ok(),
        identity_file: env::var("SSH_TEST_KEY").ok(),
        connect_timeout: Duration::from_secs(15),
        // Note: known_hosts stays as default (Strict) for security
        ..Default::default()
    })
}

/// Helper to create a Context with SSH executor.
async fn create_ssh_context() -> Context {
    let config = get_ssh_config().expect("SSH_TEST_HOST environment variable required");
    let executor = SshExecutor::connect(config)
        .await
        .expect("Failed to connect via SSH");

    Context::with_executor(Arc::new(executor))
}

// =============================================================================
// KERNEL PLUGIN OVER SSH
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_kernel_plugin_scan_over_ssh() {
    let ctx = create_ssh_context().await;
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await;

    assert!(
        result.is_ok(),
        "Kernel scan should succeed: {:?}",
        result.err()
    );

    let scan_result = result.unwrap();
    assert!(scan_result.scan_success, "Scan should report success");
    assert!(
        scan_result.scan_duration_us > 0,
        "Duration should be recorded"
    );

}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_kernel_plugin_validate_over_ssh() {
    let ctx = create_ssh_context().await;
    let plugin = KernelHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await;

    assert!(
        result.is_ok(),
        "Kernel validate should succeed: {:?}",
        result.err()
    );

    let report = result.unwrap();
    assert!(!report.validation_report_plugin_id.as_str().is_empty());
}

// =============================================================================
// SSH PLUGIN OVER SSH (meta!)
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_plugin_scan_over_ssh() {
    let ctx = create_ssh_context().await;
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await;

    assert!(
        result.is_ok(),
        "SSH plugin scan should succeed: {:?}",
        result.err()
    );

    let scan_result = result.unwrap();
    // Note: scan might fail if sshd_config doesn't exist on target
    // That's okay - we're testing the remote execution path

    // Scan might fail if sshd_config doesn't exist on target - that's OK
    assert_eq!(
        scan_result.scan_plugin_id.as_str(),
        "ssh-hardening"
    );
}

// =============================================================================
// SERVICES PLUGIN OVER SSH
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_services_plugin_scan_over_ssh() {
    let ctx = create_ssh_context().await;
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await;

    assert!(
        result.is_ok(),
        "Services scan should succeed: {:?}",
        result.err()
    );

    let scan_result = result.unwrap();
    assert!(scan_result.scan_success, "Scan should report success");

}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_services_plugin_validate_over_ssh() {
    let ctx = create_ssh_context().await;
    let plugin = ServicesHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await;

    assert!(
        result.is_ok(),
        "Services validate should succeed: {:?}",
        result.err()
    );

    let report = result.unwrap();
    assert!(!report.validation_report_plugin_id.as_str().is_empty());
}

// =============================================================================
// MULTI-PLUGIN WORKFLOW
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_multiple_plugins_sequential_over_ssh() {
    let ctx = create_ssh_context().await;

    let plugins: Vec<Box<dyn HardeningPlugin>> = vec![
        Box::new(KernelHardeningPlugin::new()),
        Box::new(ServicesHardeningPlugin::new()),
    ];

    for plugin in &plugins {
        let metadata = plugin.metadata();

        let result = plugin.scan(&ctx).await;
        assert!(
            result.is_ok(),
            "{} scan failed: {:?}",
            metadata.plugin_name,
            result.err()
        );

        let scan_result = result.unwrap();
        assert!(scan_result.scan_success, "{} scan should succeed", metadata.plugin_name);
    }
}

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_executor_error_handling_over_ssh() {
    let ctx = create_ssh_context().await;

    // Try to read a file that definitely doesn't exist
    let result = ctx
        .executor()
        .read_file(std::path::Path::new(
            "/this/path/definitely/does/not/exist/anywhere",
        ))
        .await;

    assert!(result.is_err(), "Reading non-existent file should fail");

    // read_file_optional should return None instead of error
    let result = ctx
        .executor()
        .read_file_optional(std::path::Path::new(
            "/this/path/definitely/does/not/exist/anywhere",
        ))
        .await;

    assert!(result.is_ok(), "read_file_optional should succeed");
    assert!(
        result.unwrap().is_none(),
        "Should return None for missing file"
    );
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_command_not_found_over_ssh() {
    let ctx = create_ssh_context().await;

    let exists = ctx
        .executor()
        .command_exists("this_command_definitely_does_not_exist")
        .await;
    assert!(exists.is_ok(), "command_exists should not return error, got: {exists:?}");
    assert!(!exists.unwrap(), "Non-existent command should return false");
}

// =============================================================================
// CONNECTION FAILURE TESTS
// =============================================================================

#[tokio::test]
async fn test_ssh_connection_failure() {
    // Try to connect to a host that doesn't exist
    let config = SshConfig {
        host: "192.0.2.1".to_string(), // TEST-NET-1, guaranteed not to route
        port: 22,
        user: Some("test".to_string()),
        connect_timeout: Duration::from_secs(2), // Short timeout
        ..Default::default()
    };

    let result = SshExecutor::connect(config).await;

    assert!(result.is_err(), "Connection to invalid host should fail");
}

#[tokio::test]
async fn test_ssh_connection_wrong_port() {
    let host = env::var("SSH_TEST_HOST").unwrap_or_else(|_| "localhost".to_string());

    let config = SshConfig {
        host,
        port: 65534, // Almost certainly not an SSH server
        user: Some("test".to_string()),
        connect_timeout: Duration::from_secs(2),
        ..Default::default()
    };

    let result = SshExecutor::connect(config).await;

    // Should fail - either connection refused or timeout
    assert!(result.is_err(), "Connection to wrong port should fail");
}
