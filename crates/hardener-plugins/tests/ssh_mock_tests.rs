//! SSH plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching the real filesystem.

use hardener_common::types::{PluginId, Severity};
use hardener_core::executor::CommandOutput;
use hardener_core::{Context, MockExecutor, SystemExecutor, plugin::HardeningPlugin};
use hardener_plugins::ssh::{
    SshHardeningPlugin, select_algorithms, supported_algorithms, validate_sshd_config,
};
use std::sync::Arc;

/// Creates a mock executor with a typical secure SSH config.
///
/// Includes strong crypto directives so the baseline scan reports no findings.
/// Each crypto value uses only algorithms from the plugin's strong allow-list.
fn secure_ssh_executor() -> MockExecutor {
    MockExecutor::new().with_file(
        "/etc/ssh/sshd_config",
        r#"
# Secure SSH configuration
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
Protocol 2
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
"#,
    )
}

/// Creates a mock executor with an insecure SSH config.
fn insecure_ssh_executor() -> MockExecutor {
    MockExecutor::new().with_file(
        "/etc/ssh/sshd_config",
        r#"
# Default SSH configuration (insecure)
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
"#,
    )
}

/// Creates a mock executor with no SSH config file.
fn missing_ssh_executor() -> MockExecutor {
    MockExecutor::new()
    // No /etc/ssh/sshd_config file
}

#[tokio::test]
async fn test_ssh_scan_secure_config_no_findings() {
    let executor = secure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "secure SSH scan should succeed");
    assert_eq!(result.scan_plugin_id, PluginId::new("ssh-hardening"));
    assert!(
        result.scan_error.is_none(),
        "secure SSH scan should have no error, got: {:?}",
        result.scan_error
    );
    assert!(
        result.scan_findings.is_empty(),
        "Secure config should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_ssh_scan_insecure_config_finds_issues() {
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "insecure SSH scan should succeed");
    assert!(
        !result.scan_findings.is_empty(),
        "Should find insecure settings"
    );

    // Check for specific findings
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    assert!(
        finding_ids.contains(&"ssh-permitrootlogin"),
        "Should flag PermitRootLogin yes"
    );
    assert!(
        finding_ids.contains(&"ssh-passwordauthentication"),
        "Should flag PasswordAuthentication yes"
    );
    assert!(
        finding_ids.contains(&"ssh-x11forwarding"),
        "Should flag X11Forwarding yes"
    );

    // Verify severity is correct
    let root_login = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .unwrap();
    assert_eq!(root_login.finding_severity, Severity::Critical);
    assert_eq!(root_login.finding_current_value, "yes");
    assert_eq!(root_login.finding_recommended_value, "no");
}

#[tokio::test]
async fn test_ssh_scan_missing_config_file() {
    let executor = missing_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Scan should return gracefully with an error message
    assert!(
        !result.scan_success,
        "scan with missing config should not succeed"
    );
    assert!(
        result.scan_error.is_some(),
        "scan with missing config should have an error message"
    );
    assert!(
        result.scan_error.unwrap().contains("Failed to read"),
        "error should mention failed read"
    );
}

#[tokio::test]
async fn test_ssh_scan_missing_directives_flagged() {
    // Config with only one directive set
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "scan with partial config should succeed"
    );

    // Missing directives should be flagged
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // PermitRootLogin is set correctly, shouldn't be flagged
    assert!(
        !finding_ids.contains(&"ssh-permitrootlogin"),
        "correctly set PermitRootLogin should not be flagged"
    );

    // These are missing, should be flagged
    assert!(
        finding_ids.contains(&"ssh-passwordauthentication"),
        "missing PasswordAuthentication should be flagged"
    );
    assert!(
        finding_ids.contains(&"ssh-permitemptypasswords"),
        "missing PermitEmptyPasswords should be flagged"
    );
    assert!(
        finding_ids.contains(&"ssh-protocol"),
        "missing Protocol should be flagged"
    );

    // Verify "not set" current value
    let password_auth = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-passwordauthentication")
        .unwrap();
    assert_eq!(password_auth.finding_current_value, "not set");
}

#[tokio::test]
async fn test_ssh_validate_file_exists() {
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "# config");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        result.validation_report_is_valid,
        "validation with existing config should be valid"
    );
    assert!(
        result.validation_report_issues.is_empty(),
        "validation with existing config should have no issues, found: {:?}",
        result.validation_report_issues
    );
}

#[tokio::test]
async fn test_ssh_validate_file_missing() {
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !result.validation_report_is_valid,
        "validation with missing config should be invalid"
    );
    assert!(
        !result.validation_report_issues.is_empty(),
        "validation with missing config should have issues"
    );

    // MockExecutor returns FileMetadata { exists: false, is_file: false } for missing files
    // So the first issue is "not a regular file", and the second is "Cannot read"
    let messages: Vec<_> = result
        .validation_report_issues
        .iter()
        .map(|i| i.validation_issue_message.as_str())
        .collect();

    assert!(
        messages
            .iter()
            .any(|m| m.contains("not a regular file") || m.contains("Cannot read")),
        "Expected validation error about missing file, got: {:?}",
        messages
    );

    // All issues should be critical severity
    for issue in &result.validation_report_issues {
        assert_eq!(issue.validation_issue_severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_ssh_validate_not_regular_file() {
    let executor = MockExecutor::new().with_directory("/etc/ssh/sshd_config"); // Directory instead of file

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !result.validation_report_is_valid,
        "directory as config should make validation invalid"
    );

    let issue = &result.validation_report_issues[0];
    assert!(
        issue
            .validation_issue_message
            .contains("not a regular file"),
        "issue should mention 'not a regular file', got: {}",
        issue.validation_issue_message
    );
}

#[tokio::test]
async fn test_ssh_scan_logs_file_read() {
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin no");

    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = SshHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    // Verify the plugin read the config file
    let log = executor.log();
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap() == "/etc/ssh/sshd_config"),
        "Plugin should read /etc/ssh/sshd_config"
    );
}

#[tokio::test]
async fn test_ssh_scan_compliance_mappings() {
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Find PermitRootLogin finding
    let root_login = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .expect("Should have PermitRootLogin finding");

    // Verify compliance mapping
    assert!(
        !root_login.finding_compliance.is_empty(),
        "PermitRootLogin finding should have compliance mappings"
    );
    let cis_mapping = &root_login.finding_compliance[0];
    assert_eq!(cis_mapping.compliance_control_id, "5.2.10");
    assert!(
        cis_mapping.compliance_control_title.contains("root login"),
        "CIS mapping title should mention root login, got: {}",
        cis_mapping.compliance_control_title
    );
}

#[tokio::test]
async fn test_ssh_scan_duration_recorded() {
    let executor = secure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "Scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_ssh_scan_with_remote_executor() {
    // Simulate scanning a remote system
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_file(
            "/etc/ssh/sshd_config",
            "PermitRootLogin no\nPasswordAuthentication no\n",
        );

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();
    assert!(result.scan_success, "remote SSH scan should succeed");
}

// === Cryptographic-algorithm hardening (anti-lockout) tests ===

/// Convenience: build a successful CommandOutput from stdout.
fn ok_output(stdout: &str) -> CommandOutput {
    CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: 0,
    }
}

#[test]
fn test_select_algorithms_returns_intersection_in_desired_order() {
    // Desired strong list (subset of a real KexAlgorithms allow-list).
    let desired = [
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512",
        "curve25519-sha256",
        "diffie-hellman-group16-sha512",
    ];
    // Host supports a DIFFERENT order, plus extra/legacy algorithms we must drop.
    let supported = vec![
        "diffie-hellman-group14-sha1".to_string(), // weak — not in desired
        "curve25519-sha256".to_string(),
        "diffie-hellman-group16-sha512".to_string(),
        "mlkem768x25519-sha256".to_string(),
    ];

    let selected = select_algorithms(&desired, &supported);

    // Only the intersection, and in DESIRED order (not host order).
    assert_eq!(
        selected,
        vec![
            "mlkem768x25519-sha256".to_string(),
            "curve25519-sha256".to_string(),
            "diffie-hellman-group16-sha512".to_string(),
        ],
        "must preserve desired order and drop unsupported/weak algorithms"
    );

    // Anti-lockout guarantee: every emitted algorithm is host-supported.
    for algo in &selected {
        assert!(
            supported.contains(algo),
            "emitted algorithm {algo} is not supported by the host"
        );
    }
    // Anti-downgrade guarantee: every emitted algorithm is in the strong list.
    for algo in &selected {
        assert!(
            desired.contains(&algo.as_str()),
            "emitted algorithm {algo} is not in the strong desired list"
        );
    }
    // The weak host algorithm must never appear.
    assert!(
        !selected.iter().any(|a| a == "diffie-hellman-group14-sha1"),
        "weak algorithm leaked into selection"
    );
}

#[test]
fn test_select_algorithms_no_overlap_returns_empty() {
    let desired = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"];
    // Host only offers legacy ciphers we never want.
    let supported = vec!["aes128-cbc".to_string(), "3des-cbc".to_string()];

    let selected = select_algorithms(&desired, &supported);

    assert!(
        selected.is_empty(),
        "no overlap must yield empty so the caller skips the directive (keeps host default)"
    );
}

#[tokio::test]
async fn test_supported_algorithms_parses_ssh_q_output() {
    // `ssh -Q kex` prints one algorithm per line.
    let executor = MockExecutor::new().with_command(
        "ssh",
        &["-Q", "kex"],
        ok_output(
            "curve25519-sha256\nmlkem768x25519-sha256\n\n  diffie-hellman-group16-sha512  \n",
        ),
    );

    let algos = supported_algorithms(&executor, "kex").await;

    assert_eq!(
        algos,
        vec![
            "curve25519-sha256".to_string(),
            "mlkem768x25519-sha256".to_string(),
            "diffie-hellman-group16-sha512".to_string(),
        ],
        "should split lines, trim whitespace and drop blank lines"
    );
}

#[tokio::test]
async fn test_supported_algorithms_unavailable_returns_empty() {
    // `ssh -Q` not registered at all -> executor errors -> treated as "no support".
    let executor = MockExecutor::new();

    let algos = supported_algorithms(&executor, "cipher").await;

    assert!(
        algos.is_empty(),
        "missing ssh binary must yield empty (caller then leaves host default)"
    );
}

/// Reconstructs the deterministic temp path `validate_sshd_config` writes to so
/// the exact `sshd -t -f <path>` invocation can be registered with MockExecutor.
/// Mirrors the implementation: `<temp_dir>/linux-hardener-sshd-validate-<pid>.conf`.
fn sshd_validate_temp_path() -> String {
    std::env::temp_dir()
        .join(format!(
            "linux-hardener-sshd-validate-{}.conf",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string()
}

#[tokio::test]
async fn test_validate_sshd_config_ok_when_sshd_t_succeeds() {
    // `sshd -t -f <temp>` exits 0 -> validation passes.
    let temp = sshd_validate_temp_path();
    let executor = MockExecutor::new().with_command("sshd", &["-t", "-f", &temp], ok_output(""));

    let result = validate_sshd_config(&executor, "PermitRootLogin no\n").await;

    assert!(
        result.is_ok(),
        "validation should succeed when sshd -t exits 0, got: {result:?}"
    );
}

#[tokio::test]
async fn test_validate_sshd_config_err_when_sshd_t_fails() {
    // `sshd -t` exits non-zero (bad config) -> validation must return Err so the
    // caller aborts the apply and never restarts the daemon (no lockout).
    let temp = sshd_validate_temp_path();
    let executor = MockExecutor::new().with_command(
        "sshd",
        &["-t", "-f", &temp],
        CommandOutput {
            stdout: String::new(),
            stderr: "bad configuration line 1".to_string(),
            exit_code: 255,
        },
    );

    let result = validate_sshd_config(&executor, "ThisIsNotAValidDirective\n").await;

    let err = result.expect_err("validation must fail when sshd -t exits non-zero");
    assert!(
        err.to_string().contains("sshd -t rejected"),
        "error should describe the rejection, got: {err}"
    );
}
