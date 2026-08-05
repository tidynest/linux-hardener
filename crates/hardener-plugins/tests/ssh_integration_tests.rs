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

mod common;

use common::test_checkpoint_manager;
use hardener_core::{
    Context, PluginConfig, SystemExecutor,
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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await;

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await;

    assert!(
        result.is_ok(),
        "SSH plugin scan should succeed: {:?}",
        result.err()
    );

    let scan_result = result.unwrap();
    // Note: scan might fail if sshd_config doesn't exist on target
    // That's okay - we're testing the remote execution path

    // Scan might fail if sshd_config doesn't exist on target - that's OK
    assert_eq!(scan_result.scan_plugin_id.as_str(), "ssh-hardening");
}

// =============================================================================
// SERVICES PLUGIN OVER SSH
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_services_plugin_scan_over_ssh() {
    let ctx = create_ssh_context().await;
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await;

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
    // The count is asserted rather than assumed: every assertion below lives
    // inside the loop, so a list that lost an entry would still pass, and the
    // point of this test is that BOTH plugins survive one shared connection.
    assert_eq!(
        plugins.len(),
        2,
        "both plugins must run over the one context"
    );

    for plugin in &plugins {
        let metadata = plugin.metadata();

        let result = plugin.scan(&ctx, &PluginConfig::default()).await;
        assert!(
            result.is_ok(),
            "{} scan failed: {:?}",
            metadata.plugin_name,
            result.err()
        );

        let scan_result = result.unwrap();
        assert!(
            scan_result.scan_success,
            "{} scan should succeed",
            metadata.plugin_name
        );
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
    assert!(
        exists.is_ok(),
        "command_exists should not return error, got: {exists:?}"
    );
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

// =============================================================================
// CHECKPOINT / ROLLBACK INTEGRATION
// =============================================================================

/// Verifies that a remote `apply` captures a checkpoint through the SSH executor
/// and that `rollback` restores the original remote file byte-for-byte.
///
/// Requires a booted SSH container or host with `sshd` running and write
/// access to `/etc/ssh/sshd_config`. See the module-level doc for setup.
#[tokio::test]
#[ignore = "requires SSH_TEST_HOST (booted container)"]
async fn remote_apply_then_rollback_restores_remote_file() {
    let Some(ssh_cfg) = get_ssh_config() else {
        return;
    };

    let executor = std::sync::Arc::new(
        SshExecutor::connect(ssh_cfg)
            .await
            .expect("SSH connect failed"),
    );

    let manager = test_checkpoint_manager().await;
    let mut ctx = Context::with_executor_and_checkpoint(executor.clone(), manager);

    let path = std::path::Path::new("/etc/ssh/sshd_config");

    // Capture the remote file's content before any changes.
    let before = executor
        .read_file(path)
        .await
        .expect("read remote sshd_config before apply");

    // Apply the SSH hardening plugin: this writes the hardened sshd_config
    // and, because a CheckpointManager is present in the context, also
    // captures a checkpoint of the original file via the SSH executor.
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();
    plugin
        .apply(&mut ctx, &config)
        .await
        .expect("SSH plugin apply failed");

    // The remote file must have changed after apply.
    let after = executor
        .read_file(path)
        .await
        .expect("read remote sshd_config after apply");
    assert_ne!(
        before, after,
        "apply must change the remote sshd_config; \
         if they are equal the plugin made no modifications"
    );

    // Retrieve the latest checkpoint (list is newest-first).
    let manager = ctx
        .checkpoint_manager()
        .expect("CheckpointManager must be present")
        .clone();

    let checkpoints = manager
        .list_checkpoints()
        .await
        .expect("list_checkpoints failed");
    let latest_id = checkpoints
        .first()
        .expect("at least one checkpoint must exist after apply")
        .checkpoint_id
        .clone();

    // Roll back through the SSH executor: writes must target the remote host.
    let result = manager
        .rollback(executor.as_ref(), &latest_id)
        .await
        .expect("rollback failed");
    assert!(
        result.rollback_success,
        "rollback reported failure: {:?}",
        result
            .rollback_files
            .iter()
            .filter(|f| !f.restore_success)
            .collect::<Vec<_>>()
    );

    // The remote file must now match the original content byte-for-byte.
    let restored = executor
        .read_file(path)
        .await
        .expect("read remote sshd_config after rollback");
    assert_eq!(
        before, restored,
        "rollback must restore the remote file to its original content"
    );
}

// =============================================================================
// FIREWALL PLUGIN OVER SSH - the regression test for #92
// =============================================================================

/// The live regression test for issue #92, and the one thing in this branch a
/// mock cannot stand in for.
///
/// #92 was a remote apply locking the operator out of the host it was
/// hardening: `enable()` installed an input chain with `policy drop` and no
/// rules, before `apply_rules` added the accepts, so over SSH the drop policy
/// went live and severed the connection carrying the rest of the apply. The
/// baseline rule named "Allow SSH to prevent lockout" was never installed.
///
/// **A `MockExecutor` cannot sever its own transport.** It answers from a table
/// the test author wrote, so it will happily report success for a ruleset that
/// would have cut the wire. The only honest evidence is a real apply over a
/// real SSH connection, asserting the connection is still there afterwards, so
/// that is what this does.
///
/// Before the fix the red is a HANG, not a failure: the apply blocks until the
/// SSH timeout because the reply never arrives. To reproduce it, check out
/// `main`'s `crates/hardener-plugins/src/firewall/nftables.rs` alongside this
/// test.
///
/// # Running it
///
/// Needs root to bring the container up, and the fixture that makes nftables
/// the selected backend rather than ufw:
///
/// ```bash
/// sudo ./scripts/containers/nftables-fixture.sh hardener-test-debian
/// NFTABLES_LIVE_APPLY_HOST=10.242.117.2 \
/// SSH_TEST_USER=root SSH_TEST_KEY=~/.ssh/hardener_test_ed25519 \
///     cargo test -p hardener-plugins --test ssh_integration_tests -- --ignored \
///     the_remote_apply_keeps_the_connection_it_arrived_on
/// ```
///
/// **Gated on its own variable, deliberately.** Every other test in this file
/// scans or validates, or writes one file it restores; this one installs a
/// firewall with a default-drop policy. Sharing `SSH_TEST_HOST` with them would
/// mean anyone running the suite against a host they care about gets a firewall
/// applied to it. `NFTABLES_LIVE_APPLY_HOST` has to be set on purpose, and the
/// container address is the only value it is ever meant to hold.
#[tokio::test]
#[ignore = "Requires NFTABLES_LIVE_APPLY_HOST and a container from nftables-fixture.sh"]
async fn the_remote_apply_keeps_the_connection_it_arrived_on() {
    let host = match env::var("NFTABLES_LIVE_APPLY_HOST") {
        Ok(host) => host,
        Err(_) => panic!(
            "NFTABLES_LIVE_APPLY_HOST must name the fixture container. This test \
             applies a default-drop firewall to whatever it points at, so it \
             refuses to guess and never falls back to SSH_TEST_HOST."
        ),
    };

    let executor = Arc::new(
        SshExecutor::connect(SshConfig {
            host,
            port: env::var("SSH_TEST_PORT")
                .ok()
                .and_then(|port| port.parse().ok())
                .unwrap_or(22),
            user: env::var("SSH_TEST_USER").ok(),
            identity_file: env::var("SSH_TEST_KEY").ok(),
            connect_timeout: Duration::from_secs(15),
            ..Default::default()
        })
        .await
        .expect("SSH connect to the fixture container failed"),
    );
    let mut ctx = Context::with_executor(executor.clone());

    // The fixture asserts exactly one input hook before this runs, in its own
    // table, so nftables is the backend selection will choose and the reading
    // below is of nftables rather than of ufw driving iptables-nft.
    let before = executor
        .execute_command("nft", &["list", "ruleset"])
        .await
        .expect("reading the ruleset before the apply must succeed");
    assert!(
        before.stdout.contains("hardener_fixture"),
        "the fixture's own table must be loaded before the apply, or this test \
         is measuring a host it was not set up on: ruleset\n{}",
        before.stdout
    );

    let result = hardener_plugins::FirewallHardeningPlugin::new()
        .apply(&mut ctx, &hardener_core::PluginConfig::default())
        .await
        .expect("the remote apply must return rather than hang");

    assert!(
        result.apply_success,
        "the remote apply must report success, failed changes: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|change| !change.change_success)
            .collect::<Vec<_>>()
    );

    // THE ASSERTION THIS TEST EXISTS FOR. Anything above here could be reported
    // by a host that had already dropped the connection, because the apply's
    // own result is assembled before the reply is read. Issuing a NEW command
    // over the SAME connection is what proves the transport survived its own
    // hardening.
    let after = executor
        .execute_command("nft", &["list", "ruleset"])
        .await
        .expect(
            "the connection the apply arrived on must still carry a command \
             afterwards: this failing is issue #92",
        );

    assert!(
        after.stdout.contains("table inet linux_hardener"),
        "the apply must have loaded its own table, or the success above was \
         reported for a ruleset that never reached the kernel: ruleset\n{}",
        after.stdout
    );
    assert!(
        after.stdout.contains("tcp dport 22 accept"),
        "the rule named \"Allow SSH to prevent lockout\" must be in force in the \
         loaded ruleset, which is the whole of #92: ruleset\n{}",
        after.stdout
    );
    // #95, live. The scoped replacement must leave a table this plugin does not
    // own exactly where it was; a `flush ruleset` or a delete naming another
    // table takes this with it.
    assert!(
        after.stdout.contains("hardener_fixture"),
        "the administrator's own table must survive the apply: ruleset\n{}",
        after.stdout
    );
}

/// A second remote apply changes nothing and stacks nothing, against a real
/// `nft` rather than a fixture's idea of one.
///
/// The idempotency claim rests on `nft list chain` printing a rule back in the
/// same spelling `build_nft_rule_args` produced. Every mock in this repository
/// asserts the author's model of that output against itself, so only a live
/// host can refute it. Runs under the same variable and after the same fixture
/// as the test above.
#[tokio::test]
#[ignore = "Requires NFTABLES_LIVE_APPLY_HOST and a container from nftables-fixture.sh"]
async fn a_second_remote_apply_reports_every_rule_already_present() {
    let host = env::var("NFTABLES_LIVE_APPLY_HOST")
        .expect("NFTABLES_LIVE_APPLY_HOST must name the fixture container");

    let executor = Arc::new(
        SshExecutor::connect(SshConfig {
            host,
            port: env::var("SSH_TEST_PORT")
                .ok()
                .and_then(|port| port.parse().ok())
                .unwrap_or(22),
            user: env::var("SSH_TEST_USER").ok(),
            identity_file: env::var("SSH_TEST_KEY").ok(),
            connect_timeout: Duration::from_secs(15),
            ..Default::default()
        })
        .await
        .expect("SSH connect to the fixture container failed"),
    );
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = hardener_plugins::FirewallHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    plugin
        .apply(&mut ctx, &config)
        .await
        .expect("the first apply must return");
    let second = plugin
        .apply(&mut ctx, &config)
        .await
        .expect("the second apply must return");

    assert!(second.apply_success, "the second apply must report success");
    assert_eq!(
        second.applied_change_count(),
        0,
        "a second apply against an unchanged host must report nothing applied, \
         or the diff disagrees with what nft prints back: changes {:?}",
        second.apply_changes
    );

    let ruleset = executor
        .execute_command("nft", &["list", "chain", "inet", "linux_hardener", "input"])
        .await
        .expect("reading the chain after two applies must succeed");
    assert_eq!(
        ruleset.stdout.matches("tcp dport 22 accept").count(),
        1,
        "two applies must leave exactly one SSH accept, not a stacked \
         duplicate: chain\n{}",
        ruleset.stdout
    );
}
