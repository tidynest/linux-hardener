//! SSH plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching the real filesystem.

use hardener_common::types::{ComplianceFramework, PluginId, Severity};
use hardener_core::executor::CommandOutput;
use hardener_core::{
    ApplyResult, Context, MockExecutor, PluginConfig, PolicyException, SystemExecutor,
    plugin::HardeningPlugin,
};
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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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
        finding_ids.contains(&"ssh-maxauthtries"),
        "missing MaxAuthTries should be flagged"
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

    let _ = plugin.scan(&ctx, &PluginConfig::default()).await;

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    // PermitRootLogin must now also map to ISO 27001:2022 secure authentication.
    let iso_mapping = root_login
        .finding_compliance
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
        .expect("PermitRootLogin should have an ISO 27001 mapping");
    assert_eq!(iso_mapping.compliance_control_id, "8.5");
    assert_eq!(
        iso_mapping.compliance_control_title,
        "Secure authentication"
    );

    // ...and to a HIPAA technical safeguard (person/entity authentication).
    assert!(
        root_login
            .finding_compliance
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                && m.compliance_control_id == "164.312(d)"),
        "PermitRootLogin should have a HIPAA 164.312(d) mapping, got: {:?}",
        root_login
            .finding_compliance
            .iter()
            .map(|m| (&m.compliance_framework, &m.compliance_control_id))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_ssh_scan_duration_recorded() {
    let executor = secure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();
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
        "diffie-hellman-group14-sha1".to_string(), // weak, not in desired
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

/// Pins the ssh plugin's STIG rows to the real RHEL 8 V2R7 benchmark: the
/// V-230290/291/292 ids shipped previously name unrelated rules (known-hosts
/// auth, Kerberos auth, separate /var). The corrected pairing is DISA's own:
/// RHEL-08-010290 = MACs and RHEL-08-010291 = Ciphers, reversed versus
/// intuition, and the Kex check carries no STIG mapping at all: the RHEL 8
/// KexAlgorithms rule (RHEL-08-040342 / V-255924) was removed in V2R6 and the
/// RHEL 10 STIG never had one.
#[test]
fn ssh_stig_crypto_ids_match_the_rhel8_v2r7_benchmark() {
    let coverage = hardener_plugins::ssh::coverage();
    let stig: Vec<_> = coverage
        .iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::STIG)
        .collect();

    let ciphers = stig
        .iter()
        .find(|m| m.compliance_control_id == "RHEL-08-010291")
        .expect("Ciphers must map to RHEL-08-010291 (V-230252)");
    assert!(
        ciphers
            .compliance_control_title
            .contains("DOD-approved encryption ciphers"),
        "Ciphers row must carry the V2R7 rule title, got: {}",
        ciphers.compliance_control_title
    );

    let macs = stig
        .iter()
        .find(|m| m.compliance_control_id == "RHEL-08-010290")
        .expect("MACs must map to RHEL-08-010290 (V-230251)");
    assert!(
        macs.compliance_control_title
            .contains("Message Authentication Codes (MACs)"),
        "MACs row must carry the V2R7 rule title, got: {}",
        macs.compliance_control_title
    );

    // Exactly the two crypto rules: the Kex STIG mapping is gone, and no
    // mislabelled V-23029x id survives anywhere in the plugin's coverage.
    assert_eq!(
        stig.len(),
        2,
        "ssh coverage must carry exactly the Ciphers and MACs STIG rows"
    );
    assert!(
        coverage
            .iter()
            .all(|m| !m.compliance_control_id.starts_with("V-2302")),
        "no mislabelled V-23029x id may survive"
    );

    // The Kex check keeps its other framework mappings (CIS 5.2.14).
    assert!(
        coverage
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::CIS
                && m.compliance_control_id == "5.2.14"),
        "Kex must keep its CIS mapping"
    );
}

// === Permission-denied honesty (root-only sshd_config) ===

/// A root-only sshd_config (unreadable at the current privilege level) must
/// not be reported as "every directive missing": that would falsely flag a
/// hardened host as insecure. The permission failure surfaces as unchecked
/// entries, one per SSH_DIRECTIVES and SSH_CRYPTO_DIRECTIVES element, instead
/// of findings.
#[tokio::test]
async fn scan_reports_directives_unchecked_when_sshd_config_is_root_only() {
    let mock = MockExecutor::new().with_read_permission_denied("/etc/ssh/sshd_config");
    let ctx = Context::with_executor(Arc::new(mock));
    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(result.scan_success);
    assert!(result.scan_findings.is_empty());
    assert!(
        result
            .scan_unchecked
            .iter()
            .any(|u| u.unchecked_check_id == "ssh-permitrootlogin")
    );

    // Every SSH_DIRECTIVES entry and every crypto directive must appear,
    // matching the finding ids they would otherwise have produced.
    let unchecked_ids: Vec<&str> = result
        .scan_unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    for id in [
        "ssh-permitrootlogin",
        "ssh-passwordauthentication",
        "ssh-permitemptypasswords",
        "ssh-maxauthtries",
        "ssh-x11forwarding",
        "ssh-clientaliveinterval",
        "ssh-clientalivecountmax",
        "ssh-kexalgorithms",
        "ssh-ciphers",
        "ssh-macs",
    ] {
        assert!(
            unchecked_ids.contains(&id),
            "{id} must be unchecked when sshd_config is root-only, got: {unchecked_ids:?}"
        );
    }
    assert_eq!(
        unchecked_ids.len(),
        10,
        "exactly one unchecked entry per directive/crypto table row, got: {unchecked_ids:?}"
    );

    // Crypto directive compliance mappings must still be populated (not the
    // wildcard fallback), proving get_ssh_compliance_mappings resolves crypto
    // names correctly.
    let kex_entry = result
        .scan_unchecked
        .iter()
        .find(|u| u.unchecked_check_id == "ssh-kexalgorithms")
        .expect("KexAlgorithms must be present");
    assert!(
        !kex_entry.unchecked_compliance.is_empty(),
        "crypto directive unchecked entries must carry their real compliance mappings"
    );
}

// === PermitRootLogin remote-root lockout guard ===
//
// Applying `PermitRootLogin no` over the very root SSH session performing the
// apply severs that session's own future access the moment sshd restarts
// (live-reproduced 2026-07-19). On a remote root session the plugin therefore
// downgrades the applied value to `prohibit-password` (key-based root access
// survives, password root login stays blocked) and never loosens an existing
// stricter value. The scan recommendation stays `no`, so the residual gap
// remains visible.

/// Registers everything a full `apply` run needs on the mock: the config
/// file, the timestamped `cp` backup (registered for a small clock window
/// around "now" because the backup suffix is generated inside `apply`), the
/// `sshd -t` validation of the candidate config, and the service restart.
fn apply_ready_executor(config: &str) -> MockExecutor {
    let temp = sshd_validate_temp_path();
    let mut executor = MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", config)
        .with_command("sshd", &["-t", "-f", &temp], ok_output(""))
        .with_command("systemctl", &["restart", "sshd"], ok_output(""));
    let now = chrono::Utc::now();
    for offset in -1..=3i64 {
        let stamp = (now + chrono::Duration::seconds(offset)).format("%Y%m%d_%H%M%S");
        let backup = format!("/etc/ssh/sshd_config.backup.{stamp}");
        executor = executor.with_command(
            "cp",
            &["-p", "/etc/ssh/sshd_config", &backup],
            ok_output(""),
        );
    }
    executor
}

/// Runs a default-config apply against a clone of the mock (clones share
/// state, so the caller can inspect files and logs afterwards).
async fn run_ssh_apply(executor: &MockExecutor) -> ApplyResult {
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    SshHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("ssh apply should not error")
}

/// Returns the sshd_config content the apply left behind in the mock.
fn written_sshd_config(executor: &MockExecutor) -> String {
    executor
        .files()
        .get(&std::path::PathBuf::from("/etc/ssh/sshd_config"))
        .cloned()
        .expect("sshd_config must exist after apply")
}

/// True if the config contains a `PermitRootLogin <value>` line.
fn has_permit_root_login(config: &str, value: &str) -> bool {
    config
        .lines()
        .any(|l| l.trim() == format!("PermitRootLogin {value}"))
}

#[tokio::test]
async fn ssh_remote_root_apply_downgrades_permitrootlogin_to_prohibit_password() {
    let executor = apply_ready_executor("# minimal config\n")
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "prohibit-password"),
        "remote root apply must write prohibit-password, got:\n{written}"
    );
    assert!(
        !has_permit_root_login(&written, "no"),
        "remote root apply must not write the session-severing 'no', got:\n{written}"
    );

    let change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.starts_with("PermitRootLogin:"))
        .expect("a PermitRootLogin change must be recorded");
    assert!(
        change.change_description.contains("downgraded from 'no'"),
        "change must explain the downgrade, got: {}",
        change.change_description
    );
    assert!(
        change.change_description.contains("prohibit-password"),
        "change must name the applied value, got: {}",
        change.change_description
    );
}

#[tokio::test]
async fn ssh_remote_root_apply_leaves_existing_permitrootlogin_no_untouched() {
    let executor = apply_ready_executor("PermitRootLogin no\n")
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "no"),
        "an existing 'no' must never be loosened, got:\n{written}"
    );
    assert!(
        !written.contains("prohibit-password"),
        "an existing 'no' must never be downgraded to prohibit-password, got:\n{written}"
    );
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.starts_with("PermitRootLogin:")),
        "an already-compliant directive must emit no change, got: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn ssh_remote_root_apply_skips_when_already_prohibit_password() {
    let executor = apply_ready_executor("PermitRootLogin prohibit-password\n")
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "prohibit-password"),
        "prohibit-password must be left in place, got:\n{written}"
    );

    let change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.starts_with("PermitRootLogin:"))
        .expect("a PermitRootLogin skip must be recorded");
    assert!(
        change.is_skipped(),
        "already-safe value must be a Skipped change, got: {change:?}"
    );
    assert!(
        change.change_description.contains("console"),
        "skip must point at the manual console step, got: {}",
        change.change_description
    );
}

#[tokio::test]
async fn ssh_local_apply_still_writes_permitrootlogin_no() {
    // Local session (is_remote = false): the guard must stay inactive and the
    // strict baseline apply exactly as before.
    let executor = apply_ready_executor("# minimal config\n");

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "no"),
        "local apply must still write the strict 'no', got:\n{written}"
    );
    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(program, _)| program == "id"),
        "local apply must not probe the session user"
    );
}

#[tokio::test]
async fn ssh_remote_apply_with_failed_uid_probe_applies_strict_no() {
    // `id -u` unregistered on the mock -> the probe errors. Fail-safe: treat
    // as not root, guard inactive, strict value applies (an unprivileged
    // remote session cannot restart sshd anyway).
    let executor = apply_ready_executor("# minimal config\n").remote();

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "no"),
        "a failed uid probe must fall back to the strict 'no', got:\n{written}"
    );
}

#[tokio::test]
async fn ssh_remote_root_apply_leaves_case_variant_no_untouched() {
    // sshd matches directive values case-insensitively (strcasecmp), so
    // `PermitRootLogin No` is an effective `no`: the guard must leave it
    // completely untouched, never downgrade it to prohibit-password.
    let executor = apply_ready_executor("PermitRootLogin No\n")
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "No"),
        "a case-variant 'No' is an effective 'no' and must stay untouched, got:\n{written}"
    );
    assert!(
        !written.contains("prohibit-password"),
        "a case-variant 'No' must never be loosened to prohibit-password, got:\n{written}"
    );
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.starts_with("PermitRootLogin:")),
        "an effectively-compliant directive must emit no change, got: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn ssh_remote_nonroot_apply_applies_strict_no() {
    // Remote session whose `id -u` succeeds but reports a non-root uid: the
    // guard must stay inactive and the strict baseline apply as usual.
    let executor = apply_ready_executor("# minimal config\n")
        .remote()
        .with_command("id", &["-u"], ok_output("1000\n"));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        has_permit_root_login(&written, "no"),
        "a remote non-root session must still write the strict 'no', got:\n{written}"
    );
}

#[tokio::test]
async fn ssh_remote_root_apply_skips_all_safe_or_stricter_values() {
    // `without-password` (legacy spelling of prohibit-password) and
    // `forced-commands-only` (stricter still) must be skipped, not rewritten.
    for value in ["without-password", "forced-commands-only"] {
        let executor = apply_ready_executor(&format!("PermitRootLogin {value}\n"))
            .remote()
            .with_command("id", &["-u"], ok_output("0\n"));

        let result = run_ssh_apply(&executor).await;

        assert!(
            result.apply_success,
            "apply should succeed for {value}: {result:?}"
        );
        let written = written_sshd_config(&executor);
        assert!(
            has_permit_root_login(&written, value),
            "'{value}' must be left in place, got:\n{written}"
        );
        let change = result
            .apply_changes
            .iter()
            .find(|c| c.change_description.starts_with("PermitRootLogin:"))
            .unwrap_or_else(|| panic!("a PermitRootLogin skip must be recorded for {value}"));
        assert!(
            change.is_skipped(),
            "'{value}' must be a Skipped change, got: {change:?}"
        );
    }
}

// === No-op safety: apply must not rewrite sshd_config or restart sshd when
// nothing changed ===
//
// Restarting sshd is the one operation that can drop the admin's own session,
// so doing it for a config that is already compliant is a safety bug (live
// tour: a scan-clean host still got "Updated sshd_config" + "Restarted SSH
// service" + a fresh backup on every apply). When the rendered config is
// byte-identical to what was read, the apply must skip the backup, the write
// and the restart entirely.

/// A fully hardened sshd_config: every plain directive at its secure value and
/// every crypto directive holding exactly the algorithms the strong-crypto
/// executor below reports (so the apply computes no drift for any of them).
const COMPLIANT_SSHD_CONFIG: &str = "\
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
";

/// As [`COMPLIANT_SSHD_CONFIG`] but with `PermitRootLogin` already at the
/// remote-root-safe `prohibit-password`. On a remote root session the lockout
/// guard skips rewriting this without loosening it, so with everything else
/// compliant the apply has no drift at all.
const GUARD_SAFE_COMPLIANT_SSHD_CONFIG: &str = "\
PermitRootLogin prohibit-password
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
";

/// Registers `ssh -Q kex/cipher/mac` so the crypto pass selects exactly the
/// algorithms present in the compliant configs above (intersection preserves
/// desired order), leaving those directives unchanged.
fn with_strong_crypto(executor: MockExecutor) -> MockExecutor {
    executor
        .with_command(
            "ssh",
            &["-Q", "kex"],
            ok_output("curve25519-sha256\ndiffie-hellman-group16-sha512\n"),
        )
        .with_command(
            "ssh",
            &["-Q", "cipher"],
            ok_output("chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\n"),
        )
        .with_command(
            "ssh",
            &["-Q", "mac"],
            ok_output("hmac-sha2-512-etm@openssh.com\nhmac-sha2-256-etm@openssh.com\n"),
        )
}

/// A no-op-scenario executor: the compliant config plus strong-crypto `ssh -Q`
/// responses, but deliberately NO `cp` backup, `sshd -t` or `systemctl restart`
/// registrations. If the apply wrongly reaches any of those the backup command
/// is unregistered and the apply fails loudly, so `apply_success` alone guards
/// the no-op contract.
fn compliant_noop_executor(config: &str) -> MockExecutor {
    with_strong_crypto(MockExecutor::new().with_file("/etc/ssh/sshd_config", config))
}

/// True if the executor's command log contains `systemctl restart sshd`.
fn restarted_sshd(executor: &MockExecutor) -> bool {
    executor
        .log()
        .commands_executed
        .iter()
        .any(|(program, args)| program == "systemctl" && args == &["restart", "sshd"])
}

/// True if the executor backed up sshd_config via `cp`.
fn backed_up_config(executor: &MockExecutor) -> bool {
    executor
        .log()
        .commands_executed
        .iter()
        .any(|(program, _)| program == "cp")
}

/// True if the executor wrote sshd_config.
fn rewrote_config(executor: &MockExecutor) -> bool {
    executor
        .log()
        .files_written
        .iter()
        .any(|(path, _)| path == &std::path::PathBuf::from("/etc/ssh/sshd_config"))
}

#[tokio::test]
async fn ssh_apply_is_full_noop_when_config_already_compliant() {
    let executor = compliant_noop_executor(COMPLIANT_SSHD_CONFIG);
    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "an already-compliant apply must succeed without touching anything: {result:?}"
    );
    assert!(
        !backed_up_config(&executor),
        "no backup on a no-op, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        !rewrote_config(&executor),
        "no config rewrite on a no-op, writes: {:?}",
        executor.log().files_written
    );
    assert!(
        !restarted_sshd(&executor),
        "no sshd restart on a no-op, commands: {:?}",
        executor.log().commands_executed
    );

    // Exactly one change: the already-compliant Skipped indicator.
    assert_eq!(
        result.apply_changes.len(),
        1,
        "an already-compliant apply must emit a single change, got: {:?}",
        result.apply_changes
    );
    let change = &result.apply_changes[0];
    assert!(
        change.is_skipped(),
        "the no-op change must be Skipped, got: {change:?}"
    );
    assert!(
        change.change_description.contains("already compliant"),
        "the change must explain the no-op, got: {}",
        change.change_description
    );
}

#[tokio::test]
async fn ssh_apply_remote_root_guard_skip_with_no_other_drift_is_full_noop() {
    // PermitRootLogin already at the safe prohibit-password; on a remote root
    // session the guard skips it, and with everything else compliant the apply
    // must be a complete no-op (the live tour showed exactly this case doing a
    // pointless sshd restart).
    let executor = compliant_noop_executor(GUARD_SAFE_COMPLIANT_SSHD_CONFIG)
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"));
    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "a guard-skip-only apply must succeed as a no-op: {result:?}"
    );
    assert!(
        !backed_up_config(&executor),
        "no backup on a guard-skip no-op, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        !rewrote_config(&executor),
        "no config rewrite on a guard-skip no-op, writes: {:?}",
        executor.log().files_written
    );
    assert!(
        !restarted_sshd(&executor),
        "no sshd restart on a guard-skip no-op, commands: {:?}",
        executor.log().commands_executed
    );

    // The guard-skip stays visible, alongside the already-compliant indicator.
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.change_description.starts_with("PermitRootLogin:") && c.is_skipped()),
        "the guard-skip must still be surfaced, got: {:?}",
        result.apply_changes
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.is_skipped() && c.change_description.contains("already compliant")),
        "the already-compliant indicator must be present, got: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn ssh_apply_still_writes_and_restarts_when_config_drifts() {
    // Regression guard for the drift path: a config that is not yet compliant
    // must still back up, write and restart exactly as before.
    let executor = apply_ready_executor("# minimal config\n");
    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "a drifting apply must succeed: {result:?}"
    );
    assert!(
        backed_up_config(&executor),
        "a drifting apply must back up the config"
    );
    assert!(
        rewrote_config(&executor),
        "a drifting apply must rewrite the config"
    );
    assert!(
        restarted_sshd(&executor),
        "a drifting apply must restart sshd"
    );
}

#[tokio::test]
async fn scan_honours_directive_override() {
    // Baseline for a directive whose actual value equals the built-in secure
    // value (MaxAuthTries 3), but a stricter directive override makes it
    // non-compliant -> a finding appears even though the host already meets
    // the hardcoded baseline.
    let executor = secure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("MaxAuthTries".to_string(), "2".to_string());

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-maxauthtries")
        .unwrap_or_else(|| {
            panic!(
                "stricter directive should surface a finding, got: {:?}",
                result
                    .scan_findings
                    .iter()
                    .map(|f| &f.finding_id)
                    .collect::<Vec<_>>()
            )
        });

    // Target-dependent field must reflect the override value (2), not the
    // hardcoded baseline (3) - otherwise the finding would self-contradict
    // by recommending the value the host is already at.
    assert_eq!(
        finding.finding_recommended_value, "2",
        "recommended value should reflect the directive override, not the baseline"
    );
}

#[tokio::test]
async fn scan_annotates_valid_exception() {
    // A non-compliant host with valid exceptions on one directive finding
    // (PermitRootLogin) and one crypto finding (KexAlgorithms): exceptions
    // annotate findings, they never drop them, so both stay present and both
    // carry the exception annotation.
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "yes".to_string(),
            allowed: true,
            reason: "Legacy jump host".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    config.exceptions.insert(
        "KexAlgorithms".to_string(),
        PolicyException {
            value: "not set".to_string(),
            allowed: true,
            reason: "Vendor appliance lacks strong KEX support".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let directive_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .expect("non-compliant directive should still produce a finding");
    assert!(
        directive_finding.finding_policy_exception.is_some(),
        "directive finding should be annotated with the valid exception"
    );

    let crypto_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-kexalgorithms")
        .expect("non-compliant crypto directive should still produce a finding");
    assert!(
        crypto_finding.finding_policy_exception.is_some(),
        "crypto finding should be annotated with the valid exception"
    );
}

#[tokio::test]
async fn ssh_exception_and_weak_crypto_skips_are_not_counted_as_applied() {
    // An already-hardened host with a policy exception on one directive and
    // crypto directives the host advertises no strong algorithm for (no
    // `ssh -Q` registered). Every resulting entry is a deliberate no-op: the
    // directive exception, the three "no strong algorithm" crypto skips and
    // the "already compliant" no-op guard. None may be counted as an applied
    // change, or a fully compliant host reads "SSH Hardening - N change(s)
    // applied" describing skips.
    let hardened = "\
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
";
    let executor = apply_ready_executor(hardened);
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PasswordAuthentication".to_string(),
        PolicyException {
            value: "yes".to_string(),
            allowed: true,
            reason: "legacy automation account".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = SshHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("ssh apply should not error");

    assert!(
        result.apply_success,
        "compliant apply should succeed: {result:?}"
    );
    assert_eq!(
        result.applied_change_count(),
        0,
        "a fully compliant host must count zero applied changes, got: {:?}",
        result.apply_changes
    );

    // The directive exception entry is present and is a Skipped no-op.
    let exception = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("skipped (exception"))
        .expect("directive exception skip must be recorded");
    assert!(
        exception.is_skipped(),
        "a policy-exception skip must be a Skipped change, got: {exception:?}"
    );

    // Every "no strong algorithm" crypto entry is a Skipped no-op too.
    let weak_crypto: Vec<_> = result
        .apply_changes
        .iter()
        .filter(|c| c.change_description.contains("no strong algorithm"))
        .collect();
    assert!(
        !weak_crypto.is_empty(),
        "the unmocked host must yield weak-crypto skips, got: {:?}",
        result.apply_changes
    );
    assert!(
        weak_crypto.iter().all(|c| c.is_skipped()),
        "weak-crypto entries must be Skipped changes, got: {weak_crypto:?}"
    );

    // Nothing was written and sshd was never restarted on a compliant host.
    assert!(
        !rewrote_config(&executor),
        "a compliant apply must not rewrite sshd_config"
    );
    assert!(
        !restarted_sshd(&executor),
        "a compliant apply must not restart sshd"
    );
}
