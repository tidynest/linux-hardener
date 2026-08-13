//! SSH plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching the real filesystem.

use hardener_common::types::{ComplianceFramework, PluginId, Severity};
use hardener_core::executor::CommandOutput;
use hardener_core::{
    ApplyResult, Context, ExceptionOutcome, MockExecutor, PluginConfig, PolicyException,
    SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::ssh::{
    SshHardeningPlugin, select_algorithms, sshd_validate_scratch_path, supported_algorithms,
    validate_sshd_config,
};
use hardener_types::{DeclineReason, UncheckedBlocker};
use std::path::Path;
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

/// The path `validate_sshd_config` stages the candidate at, so the exact
/// `sshd -t -f <path>` invocation can be registered with MockExecutor. Asks the
/// implementation rather than reconstructing it: the reconstruction this
/// replaced was a second copy free to drift from the one under test.
fn sshd_validate_temp_path() -> String {
    sshd_validate_scratch_path().to_string_lossy().to_string()
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

/// A MockExecutor that answers every command `validate_sshd_config` issues,
/// so what the test asserts is which commands were run rather than which ones
/// the mock happened to know about.
fn sshd_validate_executor(sshd: CommandOutput) -> MockExecutor {
    let temp = sshd_validate_temp_path();
    MockExecutor::new()
        .with_command("sshd", &["-t", "-f", &temp], sshd)
        .with_command("chmod", &["600", &temp], ok_output(""))
        .with_command("rm", &["-f", &temp], ok_output(""))
}

/// The candidate is staged on whichever host the executor targets, so it has to
/// be removed there too.
///
/// Removing it with a bare `std::fs` call deleted a path on the controller
/// while the file itself sat on the target, so every remote apply left a full
/// copy of the incoming configuration behind on the host it had just hardened,
/// and the controller was asked to delete a path of its own that it never wrote.
#[tokio::test]
async fn test_validate_sshd_config_removes_the_candidate_through_the_executor() {
    let executor = sshd_validate_executor(ok_output(""));

    validate_sshd_config(&executor, "PermitRootLogin no\n")
        .await
        .expect("validation should succeed when sshd -t exits 0");

    let temp = sshd_validate_temp_path();
    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(program, args)| program == "rm" && args.iter().any(|a| a == &temp)),
        "the candidate must be removed on the host it was staged on, got: {:?}",
        executor.log().commands_executed
    );
}

/// The candidate carries the configuration about to be applied and is staged
/// under a predictable name in a world-writable directory, so it states its own
/// mode instead of inheriting whichever default the shared writer currently has.
///
/// It used to inherit 0600 from the temporary file the atomic writer renames
/// into place. Giving a created file 0644 fixed a real defect elsewhere and
/// silently widened this one, which is why a call site that needs something
/// other than the default has to say so.
#[tokio::test]
async fn test_validate_sshd_config_stages_the_candidate_unreadable_by_others() {
    let executor = sshd_validate_executor(ok_output(""));

    validate_sshd_config(&executor, "PermitRootLogin no\n")
        .await
        .expect("validation should succeed when sshd -t exits 0");

    let temp = sshd_validate_temp_path();
    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(program, args)| program == "chmod"
                && args.first().is_some_and(|mode| mode == "600")
                && args.iter().any(|a| a == &temp)),
        "the staged candidate must be restricted to its owner, got: {:?}",
        executor.log().commands_executed
    );
}

/// The candidate is removed even when the daemon rejects it.
///
/// The rejection path is the one that matters: a candidate `sshd -t` refused is
/// exactly the content an operator would least like left readable on the host.
#[tokio::test]
async fn test_validate_sshd_config_removes_the_candidate_after_a_rejection() {
    let executor = sshd_validate_executor(CommandOutput {
        stdout: String::new(),
        stderr: "bad configuration line 1".to_string(),
        exit_code: 255,
    });

    validate_sshd_config(&executor, "ThisIsNotAValidDirective\n")
        .await
        .expect_err("validation must fail when sshd -t exits non-zero");

    let temp = sshd_validate_temp_path();
    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(program, args)| program == "rm" && args.iter().any(|a| a == &temp)),
        "a rejected candidate must not be left behind, got: {:?}",
        executor.log().commands_executed
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
    // The file is registered as well as denied, because that is what a
    // root-only file is: present, and refusing to open. Declaring the denial
    // alone described a path that does not exist, which no executor produces:
    // LocalExecutor::path_exists returns an error for a denied probe and
    // confirms absence only on NotFound. A layered read consults that probe to
    // decide whether to fall through to /usr/etc, so the gentler fixture made
    // this test pass for a reason the real code path does not have.
    let mock = MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n")
        .with_read_permission_denied("/etc/ssh/sshd_config");
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

/// A host with no `sshd_config` in either layer must record the directives as
/// unchecked, not as nothing at all.
///
/// This plugin's `coverage()` declares CIS 5.2.6, 5.2.7, 5.2.10, 5.2.11,
/// 5.2.13, 5.2.14, HIPAA `164.312(d)` and `164.312(a)(1)`, ISO 8.5, 8.20,
/// 8.24, GDPR `TM-AUTH`/`TM-SH` and NIST `SC-13` assessed. The generator
/// passes any control that is assessed, carries no finding, and is recorded
/// unchecked by nothing, and it cannot see `scan_success`. Returning an error
/// with both vectors empty therefore hands every one of those controls a
/// silent Pass on a host with no SSH configuration to have hardened, which is
/// #159 and #166 in a fifth plugin.
///
/// `scan_success` stays false and the error stays: the absence really did stop
/// the scan. What changes is that the absence is now also stated in the one
/// place the compliance generator reads.
#[tokio::test]
async fn scan_reports_directives_unchecked_when_no_sshd_config_exists() {
    let ctx = Context::with_executor(Arc::new(missing_ssh_executor()));
    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !result.scan_success,
        "the scan genuinely could not run; only its silence is the defect"
    );
    assert!(result.scan_findings.is_empty());

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
            "{id} must be unchecked when no sshd_config exists, got: {unchecked_ids:?}"
        );
    }

    assert!(
        result
            .scan_unchecked
            .iter()
            .all(|u| u.unchecked_blocker == UncheckedBlocker::Environment),
        "a file that is not installed stays not installed under sudo, so a \
         privileged re-run is the wrong remedy to offer"
    );
}

/// A read that fails for a reason other than privilege must record the
/// directives unchecked too.
///
/// `read_one` reports `Unreadable` with `permission_denied: false` whenever the
/// read failed and the existence probe could not confirm absence: an I/O error,
/// a path whose parent cannot be traversed, a probe that failed for its own
/// reasons. The plugin returned an error and no unchecked entries there, so
/// every SSH control auto-passed on the same route as the absent case.
///
/// `Unknown` rather than `Environment` as the blocker: the plugin knows only
/// that the read failed and that it was not a refusal, so claiming a privileged
/// re-run would not help is a claim it has not earned. A wrong remedy costs an
/// operator more than a missing one.
#[tokio::test]
async fn scan_reports_directives_unchecked_when_sshd_config_read_fails_indeterminately() {
    // No file registered, so the read fails; the existence probe then fails
    // too, which is what separates this from confirmed absence.
    let mock = MockExecutor::new().with_path_exists_error("/etc/ssh/sshd_config");
    let ctx = Context::with_executor(Arc::new(mock));
    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(result.scan_findings.is_empty());
    let unchecked_ids: Vec<&str> = result
        .scan_unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    assert!(
        unchecked_ids.contains(&"ssh-permitrootlogin"),
        "an indeterminate read must not read as a clean SSH configuration, \
         got: {unchecked_ids:?}"
    );
    assert!(
        result
            .scan_unchecked
            .iter()
            .all(|u| u.unchecked_blocker == UncheckedBlocker::Unknown),
        "the plugin has not established what is missing, so it offers no remedy"
    );
}

/// The remote-access controls must be answerable by the plugin that reads the
/// SSH configuration, not only by a check on the directory's mode.
///
/// `AC-17(a)`, `3.1.12` and ISO 8.2 were mapped in exactly one place in the
/// whole tree: the `/etc/ssh` arm of the permissions plugin, which asks what
/// mode the directory carries. That check answers its own question honestly on
/// a host with no `/etc/ssh` - there is no directory, so there are no wrong
/// permissions on it - and returns `Clear`, which the generator reads as a Pass
/// for all three controls (#167). Nothing had assessed remote access at all.
///
/// SSG maps `AC-17(a)` to the sshd rules themselves as well as to the directory
/// rule: `sshd_disable_root_login` declares `AC-6(2),AC-17(a),IA-2,IA-2(5)`,
/// and `sshd_set_idle_timeout` declares `CM-6(a),AC-17(a),AC-2(5),AC-12,SC-10`.
/// With those carried here, the unchecked entries this plugin already emits
/// reach the three controls, and the generator prefers an unchecked entry over
/// an assessed silence.
#[tokio::test]
async fn remote_access_controls_are_unchecked_when_no_sshd_config_exists() {
    let ctx = Context::with_executor(Arc::new(missing_ssh_executor()));
    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let mapped: Vec<&str> = result
        .scan_unchecked
        .iter()
        .flat_map(|u| &u.unchecked_compliance)
        .map(|m| m.compliance_control_id.as_str())
        .collect();

    for id in ["AC-17(a)", "3.1.12", "8.2"] {
        assert!(
            mapped.contains(&id),
            "{id} was sole-mapped to a directory-mode check, so it passed on a \
             host with no SSH configuration at all"
        );
    }
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
            &["-p", "--no-dereference", "/etc/ssh/sshd_config", &backup],
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

/// An executor whose systemctl refuses, so the `service` fallback is the only
/// route left. `apply_ready_executor` answers systemctl successfully, and the
/// fallback is unreachable until that is overridden.
fn service_fallback_executor(config: &str) -> MockExecutor {
    apply_ready_executor(config)
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"))
        .with_command(
            "systemctl",
            &["restart", "sshd"],
            CommandOutput {
                stdout: String::new(),
                stderr: "System has not been booted with systemd as init system (PID 1)."
                    .to_string(),
                exit_code: 1,
            },
        )
}

/// The `service` fallback has to know the Red Hat family's name for sshd.
///
/// `systemctl restart sshd` is right everywhere, because Debian ships
/// `sshd.service` as an alias, so this fallback is reached only on a host with
/// no working systemd. There the init script is `ssh` on Debian and `sshd` on
/// the Red Hat family, and the fallback asked for Debian's name on every
/// distribution: a non-systemd Rocky or Fedora host was told to restart a
/// service that does not exist there. Only the Red Hat name answers here, so a
/// fallback that asks for `ssh` alone cannot pass this.
#[tokio::test]
async fn ssh_apply_restart_falls_back_to_the_red_hat_service_name() {
    let executor = service_fallback_executor("# minimal config\n").with_command(
        "service",
        &["sshd", "restart"],
        ok_output(""),
    );

    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "the fallback must reach sshd under the Red Hat name: {result:?}"
    );
}

/// And the Debian name has to keep working, because that is the one the
/// fallback used to ask for and the only one it was ever proved against.
#[tokio::test]
async fn ssh_apply_restart_falls_back_to_the_debian_service_name() {
    let executor = service_fallback_executor("# minimal config\n").with_command(
        "service",
        &["ssh", "restart"],
        ok_output(""),
    );

    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "the fallback must reach sshd under the Debian name: {result:?}"
    );
}

/// When no name works the failure must name both attempts. Reporting only the
/// last would send an operator looking for the wrong init script, and reporting
/// only the first would hide that the other was tried at all.
#[tokio::test]
async fn ssh_apply_restart_failure_names_both_service_attempts() {
    let executor = service_fallback_executor("# minimal config\n")
        .with_command(
            "service",
            &["sshd", "restart"],
            CommandOutput {
                stdout: String::new(),
                stderr: "sshd: unrecognized service".to_string(),
                exit_code: 1,
            },
        )
        .with_command(
            "service",
            &["ssh", "restart"],
            CommandOutput {
                stdout: String::new(),
                stderr: "ssh: unrecognized service".to_string(),
                exit_code: 1,
            },
        );

    let result = run_ssh_apply(&executor).await;

    let reported = format!("{:?}", result.apply_changes);
    assert!(
        reported.contains("sshd: unrecognized service") && reported.contains("ssh: unrecognized"),
        "both attempts must appear in the failure, got: {reported}"
    );
}

/// A candidate `sshd -t` rejects must leave nothing counted as applied.
///
/// The gate runs ahead of the first write precisely so a bad candidate touches
/// no bytes, and it fires for real on the debian and ubuntu fixtures, which
/// have no `/run/sshd`. The staged directive edits were still recorded as
/// successes, so `apply` announced "11 of 12 change(s) applied" on a host where
/// it wrote nothing and the scan straight after still raised all ten SSH
/// findings. Skipped is what those edits are: not applied, and not failed
/// either, because they were never attempted against the live file.
#[tokio::test]
async fn ssh_apply_counts_nothing_applied_when_sshd_rejects_the_candidate() {
    let temp = sshd_validate_temp_path();
    let executor = apply_ready_executor("# minimal config\n")
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"))
        .with_command(
            "sshd",
            &["-t", "-f", &temp],
            CommandOutput {
                stdout: String::new(),
                stderr: "Missing privilege separation directory: /run/sshd".to_string(),
                exit_code: 255,
            },
        );

    let result = run_ssh_apply(&executor).await;

    assert!(
        !result.apply_success,
        "a rejected candidate must not report success: {result:?}"
    );
    // Not "nothing counted": the backup file really was written before the
    // gate ran, so it really is a change this apply made. What must not be
    // counted is a hardening directive, none of which reached the live file.
    let counted: Vec<&str> = result
        .apply_changes
        .iter()
        .filter(|c| !c.is_skipped() && !c.is_checkpoint() && c.change_success)
        .map(|c| c.change_description.as_str())
        .collect();
    assert!(
        counted.iter().all(|d| d.starts_with("Created backup:")),
        "only the backup was written, so no directive edit may be counted as applied; got: {counted:#?}"
    );
    // The refusal itself still has to be visible. Reporting nothing applied
    // without saying why would trade an overcount for a silence.
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| !c.change_success && c.change_description.contains("rejected by `sshd -t`")),
        "the refusal must be reported, got: {:#?}",
        result.apply_changes
    );
    // And the edits stay listed, so the operator can still see what would have
    // changed had the candidate been accepted.
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.is_skipped() && c.change_description.starts_with("PermitRootLogin:")),
        "the staged edits must remain visible as skipped, got: {:#?}",
        result.apply_changes
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

/// `sshd_config(5)` accepts `Key=Value`, so an operator may well have written
/// `PermitRootLogin=no`, which is already the strictest value there is. The
/// never-loosen guard can only honour it if the reader sees it: a directive
/// read as "not set" takes the downgrade branch, and the writer does see the
/// `=` shape, so it would rewrite that very line to `prohibit-password`.
#[tokio::test]
async fn ssh_remote_root_apply_leaves_an_equals_separated_no_untouched() {
    let executor = apply_ready_executor("PermitRootLogin=no\n")
        .remote()
        .with_command("id", &["-u"], ok_output("0\n"));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    assert!(
        !written.contains("prohibit-password"),
        "an existing 'no' must never be loosened, whichever separator it uses, got:\n{written}"
    );
    assert!(
        written.lines().any(|l| l.trim() == "PermitRootLogin=no"),
        "the operator's line is already compliant and must stand as written, got:\n{written}"
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

/// The only live `PermitRootLogin` sits inside a `Match` block while the
/// global setting exists as a commented default. Apply must activate the
/// commented global and leave the block alone. Writing the block line instead
/// would harden one subnet, leave root login at sshd's compiled default
/// everywhere else, and then read back as compliant on the next scan.
#[tokio::test]
async fn ssh_apply_never_writes_a_directive_into_a_match_block() {
    const BLOCK: &str = "Match Address 10.0.0.0/8\n    \
                         PermitRootLogin yes\n    \
                         PasswordAuthentication yes";
    let executor = apply_ready_executor(&format!(
        "#PermitRootLogin prohibit-password\n\
         PasswordAuthentication no\n\
         PermitEmptyPasswords no\n\
         MaxAuthTries 3\n\
         X11Forwarding no\n\
         ClientAliveInterval 300\n\
         ClientAliveCountMax 2\n\
         \n\
         {BLOCK}\n"
    ));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    let start = written
        .find("Match Address")
        .unwrap_or_else(|| panic!("the Match block must survive:\n{written}"));

    // Everything from the block header on must be exactly what went in, which
    // rules out both an edit inside the block and an append below it. Trailing
    // whitespace is discounted only because BLOCK is written as a bare literal
    // here; the terminator itself is asserted separately below, and used to be
    // absent.
    assert_eq!(
        written[start..].trim_end(),
        BLOCK,
        "the Match block must survive byte for byte, indentation included:\n{written}",
    );

    // The file this apply writes is a file, and the next thing appended to it
    // must land on its own line. Without this the last directive and whatever
    // an operator adds afterwards become one line, which is how sshd came to
    // refuse a `MACs` value with a `MaxAuthTries` welded onto the end of it.
    assert!(
        written.ends_with('\n'),
        "the written sshd_config must be newline-terminated:\n{written:?}",
    );
    assert!(
        has_permit_root_login(&written[..start], "no"),
        "the commented global default is the line apply must activate:\n{written}",
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.change_description.starts_with("PermitRootLogin:")),
        "a PermitRootLogin change must be recorded, or this test proves nothing: {:?}",
        result.apply_changes
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

/// As [`apply_ready_executor`] but answering any `cp` by program name rather
/// than pinning its arguments.
///
/// The test below is about what those arguments are, so it must not be the
/// thing that decides them: with an exact registration a wrong argv fails as
/// "command not registered", which reads as a broken fixture rather than as the
/// missing flag it is.
fn apply_ready_executor_any_backup(config: &str) -> MockExecutor {
    let temp = sshd_validate_temp_path();
    MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", config)
        .with_command("sshd", &["-t", "-f", &temp], ok_output(""))
        .with_command("systemctl", &["restart", "sshd"], ok_output(""))
        .with_command_program("cp", ok_output(""))
}

/// A backup is only worth taking if it is a copy of the thing about to be
/// replaced, at the mode that thing carries.
///
/// `-p` keeps mode, ownership and timestamps, so an operator who copies the
/// backup back gets sshd_config as it was rather than one wearing whatever the
/// umask handed it. `--no-dereference` copies a symlink as a symlink, which
/// matters here more than anywhere else in the tree: a host whose
/// /etc/ssh/sshd_config is a link into a configuration-management checkout
/// would otherwise be backed up as the managed file, and the object this apply
/// is about to overwrite would have no copy at all.
#[tokio::test]
async fn ssh_backup_copy_keeps_the_mode_and_does_not_follow_a_symlink() {
    let executor = apply_ready_executor_any_backup("# minimal config\n");

    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "a drifting apply must succeed: {result:?}"
    );
    let log = executor.log();
    let (_, args) = log
        .commands_executed
        .iter()
        .find(|(program, _)| program == "cp")
        .expect("a drifting apply must back up the config with cp");
    for flag in ["-p", "--no-dereference"] {
        assert!(
            args.iter().any(|argument| argument == flag),
            "the backup cp must pass {flag}, got: {args:?}"
        );
    }
    // Checked separately from the flags because "the flag is present" and "the
    // flag is a flag" are different claims: an argument added after the source
    // would be read by cp as another file to copy.
    assert_eq!(
        args[args.len() - 2],
        "/etc/ssh/sshd_config",
        "the source must stay the second-to-last argument, got: {args:?}"
    );
    assert!(
        args[args.len() - 1].starts_with("/etc/ssh/sshd_config.backup."),
        "the destination must stay the last argument, got: {args:?}"
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
        directive_finding.is_policy_excepted(),
        "directive finding should be annotated with the valid exception"
    );

    let crypto_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-kexalgorithms")
        .expect("non-compliant crypto directive should still produce a finding");
    assert!(
        crypto_finding.is_policy_excepted(),
        "crypto finding should be annotated with the valid exception"
    );
}

#[tokio::test]
async fn scan_ignores_exception_whose_value_does_not_match() {
    // The exception approves "prohibit-password", but the host actually runs
    // "PermitRootLogin yes". A config file must not be able to pass a control
    // by documenting a deviation the host does not have: the finding stays a
    // live, unannotated violation.
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "prohibit-password".to_string(),
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
            value: "curve25519-sha256".to_string(),
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
        !directive_finding.is_policy_excepted(),
        "an exception for a value the host does not have must not be honoured"
    );

    // The crypto directive is unset on this host, so an exception naming a
    // concrete algorithm list does not describe it either.
    let crypto_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-kexalgorithms")
        .expect("non-compliant crypto directive should still produce a finding");
    assert!(
        !crypto_finding.is_policy_excepted(),
        "an exception for a value the host does not have must not be honoured"
    );
}

/// The host runs "PermitRootLogin yes", the operator's exception documents
/// "prohibit-password". Silently falling back to `NotConfigured` here would
/// look identical to no exception having been written at all, and an operator
/// reading the report would believe their exception was honoured when it was
/// not.
#[tokio::test]
async fn an_ssh_exception_documenting_the_wrong_value_is_reported_as_declined() {
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "prohibit-password".to_string(),
            allowed: true,
            reason: "documented the wrong value".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let ctx = Context::with_executor(Arc::new(insecure_ssh_executor()));
    let plugin = SshHardeningPlugin::new();
    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .expect("the finding is still reported");

    match &finding.finding_exception {
        ExceptionOutcome::Declined(declined) => match &declined.exception_declined_reason {
            DeclineReason::ValueMismatch {
                documented,
                observed,
            } => {
                assert_eq!(documented, "prohibit-password");
                assert_eq!(observed, "yes");
            }
            other => panic!("expected a value mismatch, got {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }
}

#[tokio::test]
async fn ssh_exception_and_weak_crypto_skips_are_not_counted_as_applied() {
    // An otherwise-hardened host with a genuine policy exception on one
    // directive (the exception documents the value the host actually has,
    // "yes", exactly as an operator would write it) and crypto directives
    // the host advertises no strong algorithm for (no `ssh -Q` registered).
    // Every resulting entry is a deliberate no-op: the directive exception,
    // the three "no strong algorithm" crypto skips and the "already
    // compliant" no-op guard. None may be counted as an applied change, or
    // a fully compliant host reads "SSH Hardening - N change(s) applied"
    // describing skips.
    let hardened = "\
PermitRootLogin no
PasswordAuthentication yes
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

#[tokio::test]
async fn apply_ignores_exception_whose_value_does_not_match() {
    // The host has PermitRootLogin yes; the exception documents "no".
    //
    // Uses apply_ready_executor rather than the bare insecure_ssh_executor:
    // without the backup/restart mocks the apply aborts at the `cp` backup
    // step (unregistered command) before the per-directive `changes` are
    // ever merged into the returned ApplyResult, which would make this
    // assertion pass vacuously regardless of the exception-matching logic
    // under test.
    let executor = apply_ready_executor(
        "\
# Default SSH configuration (insecure)
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
",
    );
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "no".to_string(),
            allowed: true,
            reason: "Stale exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("Stale exception")),
        "a non-matching exception must not produce a skipped change"
    );
}

#[tokio::test]
async fn validate_honours_a_directive_override_that_tightens() {
    // The plugin's hardcoded baseline for MaxAuthTries is "3"; the override
    // below picks a distinct value so the assertion can only pass if validate
    // actually consults config.directives rather than the hardcoded baseline.
    // It has to be a distinct *stricter* value: this test used to use "6" and
    // assert the preview said 6, which pinned the rule that an override sets
    // whatever it says, in the one direction that leaves a host less secure
    // than the tool's own baseline.
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("MaxAuthTries".to_string(), "2".to_string());

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("MaxAuthTries") && c.contains('2')),
        "the preview must reflect the directive override, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// The dry run previews the apply it precedes, so it has to read the same
/// configuration that apply reads.
///
/// `validate` parsed the main file alone while scan and apply both resolve the
/// Include first. On the layout RHEL, Fedora and openSUSE ship, a drop-in
/// answers the keyword before the main file, so a main file already holding the
/// target previewed no change at all while the apply went on to write a
/// fragment. That is the preview being short of the run in the direction the
/// operator approves, which is the defect 420a52b and 5aa31cf each fixed
/// elsewhere.
#[tokio::test]
async fn validate_previews_the_change_a_drop_in_forces_even_when_the_main_file_is_compliant() {
    let executor = MockExecutor::new()
        .with_file(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n",
        )
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/50-redhat.conf",
            "X11Forwarding yes\n",
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let report = SshHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("X11Forwarding")),
        "the apply will write a fragment for this directive, so the preview must \
         say so, got: {:?}",
        report.validation_report_estimated_changes
    );
    // The file itself, named once. A preview listing settings while staying
    // silent about a new file appearing in /etc is the defect 5aa31cf fixed in
    // the kernel plugin, and this apply writes exactly such a file.
    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("/etc/ssh/sshd_config.d/00-hardener.conf")),
        "the preview must name the file the apply will create, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// The crypto directives were previewed by nothing at all: `validate` had no
/// loop over them, so an apply that writes three cryptographic lists announced
/// none of them beforehand.
#[tokio::test]
async fn validate_previews_the_crypto_directives_the_apply_would_write() {
    let executor = MockExecutor::new()
        .with_file(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        )
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/50-redhat.conf",
            "Ciphers 3des-cbc\n",
        )
        .with_command(
            "ssh",
            &["-Q", "cipher"],
            ok_output("chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\n3des-cbc\n"),
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let report = SshHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("Ciphers")),
        "the apply writes a strong cipher list over the drop-in's, so the preview \
         must name it, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("3des-cbc") && c.contains("→ 3des-cbc")),
        "the preview must not promise the weak list it is replacing, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// The mirror, and it exists because its absence was measured: removing the
/// already-strong check from the crypto preview left every test green.
///
/// `ssh -Q cipher` is registered deliberately. Without it the intersection is
/// empty and the preview omits the directive for a completely different reason,
/// so the test would pass whether or not the check it guards is there. A test
/// that cannot fail for the reason it exists is not a test.
#[tokio::test]
async fn validate_previews_no_crypto_change_when_the_host_is_already_strong() {
    let executor = MockExecutor::new()
        .with_file(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        )
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/50-redhat.conf",
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n",
        )
        .with_command(
            "ssh",
            &["-Q", "cipher"],
            ok_output(
                "chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\naes128-gcm@openssh.com\n",
            ),
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let report = SshHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("Ciphers")),
        "a host already offering only strong ciphers has nothing to preview, got: {:?}",
        report.validation_report_estimated_changes
    );
}

#[tokio::test]
async fn validate_clamps_a_directive_override_that_would_loosen() {
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("MaxAuthTries".to_string(), "6".to_string());

    let report = plugin.validate(&ctx, &config).await.unwrap();

    let previewed: Vec<_> = report
        .validation_report_estimated_changes
        .iter()
        .filter(|c| c.contains("MaxAuthTries"))
        .collect();
    assert!(
        previewed.iter().any(|c| c.contains('3')) && !previewed.iter().any(|c| c.contains('6')),
        "an override may tighten the baseline and never relax it, so the preview \
         must promise 3 rather than 6, got: {previewed:?}"
    );
}

#[tokio::test]
async fn validate_ignores_exception_whose_value_does_not_match() {
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "no".to_string(),
            allowed: true,
            reason: "Stale exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("PermitRootLogin")),
        "a non-matching exception must leave the change in the preview"
    );
}

#[tokio::test]
async fn validate_honours_an_exception_whose_value_matches() {
    // insecure_ssh_executor's host genuinely runs `PermitRootLogin yes`, which
    // is insecure against the "no" baseline. The exception documents "yes",
    // the value the host actually has, so it must be honoured: the directive
    // is expected to be dropped entirely, not merely annotated.
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

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("PermitRootLogin")),
        "a matching exception must remove the directive from the preview, \
         got: {:?}",
        report.validation_report_estimated_changes
    );
}

#[tokio::test]
async fn ssh_apply_hardens_a_global_directive_a_match_block_appears_to_satisfy() {
    // PermitRootLogin exists only inside the Match block, already at the secure
    // value. A whole-file read returned "no", apply concluded there was nothing
    // to do, wrote nothing and recorded no change at all, and the real global
    // directive stayed at sshd's compiled default (prohibit-password) for every
    // connection outside 10.0.0.0/8. The tool reported the host compliant.
    const BLOCK: &str = "Match Address 10.0.0.0/8\n    PermitRootLogin no";
    let executor = apply_ready_executor(&format!(
        "PasswordAuthentication no\n\
         PermitEmptyPasswords no\n\
         MaxAuthTries 3\n\
         X11Forwarding no\n\
         ClientAliveInterval 300\n\
         ClientAliveCountMax 2\n\
         \n\
         {BLOCK}\n"
    ));

    let result = run_ssh_apply(&executor).await;

    assert!(result.apply_success, "apply should succeed: {result:?}");
    let written = written_sshd_config(&executor);
    let block_start = written
        .find("Match Address")
        .unwrap_or_else(|| panic!("the Match block must survive:\n{written}"));

    assert!(
        written[..block_start].contains("PermitRootLogin no"),
        "the global directive must be written above the Match block:\n{written}"
    );
    assert_eq!(
        written[block_start..].trim_end(),
        BLOCK,
        "the block itself must be untouched:\n{written}"
    );
}

/// The layout every affected distribution ships: an `Include` on line 2, above
/// everything this tool writes.
const SHIPPED_LAYOUT: &str = "\
# Include drop-in configurations
Include /etc/ssh/sshd_config.d/*.conf

PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
";

#[tokio::test]
async fn ssh_scan_reports_the_value_a_drop_in_forces_not_the_one_in_the_main_file() {
    // Verified against sshd itself: with this exact layout, `PermitRootLogin no`
    // in the main file and `yes` in the drop-in, `sshd -T` reports yes, and
    // `sshd -t` accepts the file without complaint. Reading only the main file
    // reported the host compliant while sshd allowed root login.
    let executor = MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", SHIPPED_LAYOUT)
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/99-evil.conf",
            "PermitRootLogin yes\n",
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .expect("the drop-in forces an insecure value, so this must be a finding");
    assert_eq!(
        finding.finding_current_value, "yes",
        "the reported value must be the one sshd uses, not the one in the main file"
    );
    assert!(
        finding
            .finding_explanation
            .contains("/etc/ssh/sshd_config.d/99-evil.conf"),
        "the finding must name the file that actually governs it: {}",
        finding.finding_explanation
    );
}

#[tokio::test]
async fn ssh_scan_accepts_a_drop_in_that_holds_the_secure_value() {
    // The mirror image: a drop-in supplying the target value leaves the host
    // compliant, and must not be reported as a problem just because it is not
    // the main file.
    let executor = MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", SHIPPED_LAYOUT)
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/10-good.conf",
            "PermitRootLogin no\n",
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "ssh-permitrootlogin"),
        "a drop-in already holding the target value is compliant"
    );
}

/// A drop-in supplies the directive and the exception documents the drop-in's
/// value. Scan, the preview and apply must reach the same conclusion about it.
///
/// They did not. Apply read the main file's global scope alone, where this
/// layout has `PermitRootLogin no`, so an exception documenting the `yes` the
/// host actually runs did not match and the apply hardened over it, while scan
/// and the preview compared against the effective `yes` and reported the
/// exception honoured. One run told an operator their documented deviation was
/// respected and removed it. Issue #134.
#[tokio::test]
async fn an_exception_documenting_a_drop_ins_value_binds_scan_preview_and_apply() {
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            // The value the drop-in forces, which is the one sshd obeys, not
            // the one sitting in the main file underneath it.
            value: "yes".to_string(),
            allowed: true,
            reason: "Legacy jump host".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    // Clones share state, so the same host is put to all three questions, and
    // the apply's writes are visible afterwards. The drop-in write commands are
    // registered so the apply can complete the write this asserts it does not
    // make: without them it would abort early and the assertion would hold for
    // a reason that has nothing to do with the exception.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file("/etc/ssh/sshd_config", SHIPPED_LAYOUT)
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/99-legacy.conf",
                "PermitRootLogin yes\n",
            ),
    );
    let plugin = SshHardeningPlugin::new();
    let ctx = Context::with_executor(Arc::new(executor.clone()));

    let finding = plugin
        .scan(&ctx, &config)
        .await
        .unwrap()
        .scan_findings
        .into_iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .expect("the drop-in forces an insecure value, so this must be a finding");
    assert_eq!(
        finding.finding_current_value, "yes",
        "scan reads the value in force"
    );
    assert!(
        finding.is_policy_excepted(),
        "the exception documents the value in force, so scan honours it: {:?}",
        finding.finding_exception
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();
    assert!(
        report
            .validation_report_exceptions
            .iter()
            .any(|e| e.contains("PermitRootLogin")),
        "the preview must honour the exception scan honoured, got: {:?}",
        report.validation_report_exceptions
    );

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let result = plugin.apply(&mut ctx, &config).await.unwrap();
    let change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("PermitRootLogin"))
        .expect("apply must account for PermitRootLogin one way or the other");
    assert!(
        change.is_skipped() && change.change_description.contains("Legacy jump host"),
        "apply must honour the exception scan and the preview honoured, got: {change:?}"
    );
    assert!(
        !dropin_written(&executor)
            .unwrap_or_default()
            .contains("PermitRootLogin"),
        "an excepted directive must not be hardened through this tool's own fragment, \
         which is how the main-file reading overwrote it: {:?}",
        dropin_written(&executor)
    );
}

/// The crypto directives are read from the same resolved configuration as
/// every other directive, because sshd reads them from the same place.
///
/// The layout below is what RHEL, Fedora and openSUSE ship: crypto-policies
/// supplies Ciphers, MACs and KexAlgorithms from a drop-in, and the Include
/// sits above everything this tool writes, so sshd takes the drop-in's value.
/// Reading only the main file reported the strong list this tool put there
/// while sshd negotiated the drop-in's, and because the crypto directives are
/// in `coverage()`, the absence of a finding rendered those controls as Pass.
#[tokio::test]
async fn ssh_scan_reports_the_ciphers_a_drop_in_forces_not_the_main_file_s() {
    let executor = MockExecutor::new()
        .with_file(
            "/etc/ssh/sshd_config",
            &format!("{SHIPPED_LAYOUT}Ciphers chacha20-poly1305@openssh.com\n"),
        )
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/50-redhat.conf",
            "Ciphers 3des-cbc\n",
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-ciphers")
        .expect("the drop-in forces a weak cipher, so this must be a finding");
    assert_eq!(
        finding.finding_current_value, "3des-cbc",
        "the reported value must be the one sshd negotiates, not the one in the main file"
    );
    assert!(
        finding
            .finding_explanation
            .contains("/etc/ssh/sshd_config.d/50-redhat.conf"),
        "the finding must name the file that actually governs it: {}",
        finding.finding_explanation
    );
}

/// The mirror image, and the direction a main-file read gets wrong the other
/// way: a drop-in supplying a strong list leaves the host compliant, and
/// reporting it because the main file is silent would send an operator to edit
/// a file that decides nothing.
#[tokio::test]
async fn ssh_scan_accepts_ciphers_a_drop_in_holds_at_a_strong_value() {
    let executor = MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", SHIPPED_LAYOUT)
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/10-crypto.conf",
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n",
        );
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "ssh-ciphers"),
        "a drop-in already holding a strong cipher list is compliant, findings: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| (&f.finding_id, &f.finding_current_value))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn ssh_apply_beats_a_drop_in_that_would_otherwise_override_the_write() {
    // 23ee0c1 made this case honest: writing sshd_config cannot change a
    // directive a drop-in answers first, so the write was reported as failed
    // rather than applied. Honest, and the host stayed unhardened. The
    // directive now goes to a fragment that sorts before the offending one, so
    // it is genuinely in force and the change is a real success naming where
    // the value came from.
    //
    // The invariant that an inert write is never reported as applied still
    // holds and is covered by apply_reports_failure_when_the_dropin_does_not_win,
    // which is now the only case where a write really is inert.
    let executor = apply_ready_executor(SHIPPED_LAYOUT)
        .with_directory("/etc/ssh/sshd_config.d")
        .with_file(
            "/etc/ssh/sshd_config.d/99-evil.conf",
            "PermitRootLogin yes\n",
        );

    let result = run_ssh_apply(&executor).await;

    let change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("PermitRootLogin"))
        .expect("the shadowed directive must still be reported");
    assert!(
        change.change_success,
        "the directive is now genuinely applied: {}",
        change.change_description
    );
    assert!(
        change
            .change_description
            .contains("/etc/ssh/sshd_config.d/00-hardener.conf"),
        "the operator must be told which file supplies the value: {}",
        change.change_description
    );
    let dropin = dropin_written(&executor).expect("a fragment must beat 99-evil.conf");
    assert!(
        dropin.contains("PermitRootLogin no"),
        "the fragment must carry the directive: {dropin}"
    );
}

#[tokio::test]
async fn validate_reports_a_directive_left_alone_by_a_policy_exception() {
    // The preview dropped an excepted directive entirely: `validate` hit
    // `continue` before it could record anything, so a host with a documented
    // deviation rendered as "0 changes" over an empty panel, with no hint the
    // exception existed. Every other renderer labels a deviation rather than
    // hiding it; this one hid it.
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

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        report
            .validation_report_exceptions
            .iter()
            .any(|e| e.contains("PermitRootLogin") && e.contains("Legacy jump host")),
        "an excepted directive must be reported, naming its reason, got: {:?}",
        report.validation_report_exceptions
    );
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("PermitRootLogin")),
        "an excepted directive is not a pending change and must not inflate the count, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// openSUSE's shape: no `/etc/ssh/sshd_config` at all, the real one under
/// `/usr/etc`, and its Include of the `/etc` drop-in directory six lines above
/// its own.
fn opensuse_ssh_executor() -> MockExecutor {
    MockExecutor::new()
        .with_file(
            "/usr/etc/ssh/sshd_config",
            "# vendor config\n\
             Include /etc/ssh/sshd_config.d/*.conf\n\
             Include /usr/etc/ssh/sshd_config.d/*.conf\n\
             PermitRootLogin yes\n\
             PasswordAuthentication yes\n",
        )
        .with_directory("/etc/ssh/sshd_config.d")
        .with_directory("/usr/etc/ssh/sshd_config.d")
}

#[tokio::test]
async fn scan_reads_the_vendor_config_when_etc_has_none() {
    // Before this change the scan reported "Failed to read
    // /etc/ssh/sshd_config" and assessed nothing, so every SSH control on
    // openSUSE routed to Manual Review and the host was never checked.
    let ctx = Context::with_executor(Arc::new(opensuse_ssh_executor()));
    let plugin = SshHardeningPlugin::new();

    let result = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan must run");

    assert!(
        result.scan_success,
        "the vendor config is readable, so the scan completed: {:?}",
        result.scan_error
    );
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "ssh-permitrootlogin"),
        "PermitRootLogin yes in the vendor file is a real finding, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn an_unreadable_etc_config_is_not_answered_from_the_vendor_copy() {
    // /etc/ssh/sshd_config exists and is what sshd reads, so reporting the
    // vendor file's values because ours could not be read would describe a
    // configuration that is not in force. Asserts the opposite direction: it
    // guards the fix against over-reaching and is not evidence of the defect.
    let ctx = Context::with_executor(Arc::new(
        opensuse_ssh_executor()
            .with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n")
            .with_read_permission_denied("/etc/ssh/sshd_config"),
    ));
    let plugin = SshHardeningPlugin::new();

    let result = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan must run");

    assert!(
        result.scan_findings.is_empty(),
        "an unreadable config must produce unchecked entries, never findings \
         derived from the vendor copy, got: {:?}",
        result.scan_findings
    );
    assert!(
        !result.scan_unchecked.is_empty(),
        "the privilege failure must be reported as unchecked"
    );
}

#[tokio::test]
async fn remediation_never_advises_creating_a_file_that_would_mask_the_vendor_config() {
    // Making the scan work on openSUSE is what first renders these findings
    // there, and every one of them carried "Edit /etc/ssh/sshd_config". On a
    // host whose sshd_config lives under /usr/etc, creating that file makes
    // sshd stop reading the vendor one, discarding both its Include lines. The
    // advice would have instructed the operator to cause the masking defect
    // this workstream exists to remove.
    let ctx = Context::with_executor(Arc::new(opensuse_ssh_executor()));
    let plugin = SshHardeningPlugin::new();

    let result = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan must run");

    let steps: Vec<&str> = result
        .scan_findings
        .iter()
        .flat_map(|f| f.finding_remediation_steps.iter().map(|s| s.as_str()))
        .collect();
    assert!(!steps.is_empty(), "the scan must have produced findings");
    assert!(
        !steps
            .iter()
            .any(|s| s.contains("Edit /etc/ssh/sshd_config")
                && !s.contains("/etc/ssh/sshd_config.d")),
        "advising the operator to create /etc/ssh/sshd_config masks the vendor \
         file wholesale, got: {steps:?}"
    );
    assert!(
        steps.iter().any(|s| s.contains("/etc/ssh/sshd_config.d")),
        "the drop-in directory is where openSUSE's own vendor config directs \
         administrators, got: {steps:?}"
    );
}

// === Writing where the setting is actually read from ===
//
// sshd uses the first value it obtains for a keyword and reads
// /etc/ssh/sshd_config.d/*.conf before the main file, so a fragment there
// outranks anything this tool writes to sshd_config. On Fedora and RHEL
// 50-redhat.conf does exactly that; on openSUSE there is no main file under
// /etc at all and the vendor one must never be masked.

/// Registers the commands a full apply run needs, without pinning the
/// timestamped backup name: `cp` is registered by program because the suffix
/// is generated inside `apply`.
fn dropin_apply_commands(executor: MockExecutor) -> MockExecutor {
    executor
        .with_command_program("cp", ok_output(""))
        .with_command_program("sshd", ok_output(""))
        .with_command("systemctl", &["restart", "sshd"], ok_output(""))
}

fn dropin_written(executor: &MockExecutor) -> Option<String> {
    executor
        .files()
        .get(&std::path::PathBuf::from(
            "/etc/ssh/sshd_config.d/00-hardener.conf",
        ))
        .cloned()
}

#[tokio::test]
async fn apply_writes_a_winning_dropin_when_one_overrides_the_main_file() {
    // Fedora and RHEL: 50-redhat.conf sets X11Forwarding yes and sshd reads it
    // first, so everything written to sshd_config for that directive is inert.
    // 23ee0c1 made the tool honest about that; this makes it effective.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/50-redhat.conf",
                "X11Forwarding yes\n",
            ),
    );

    let result = run_ssh_apply(&executor).await;

    let dropin = dropin_written(&executor).unwrap_or_else(|| {
        panic!(
            "a drop-in must be written to beat 50-redhat.conf, wrote: {:?}",
            executor.log().files_written
        )
    });
    assert!(
        dropin.contains("X11Forwarding no"),
        "the drop-in must carry the overridden directive, got: {dropin}"
    );
    assert!(
        result.apply_success,
        "the directive is now genuinely applied, so apply succeeds: {:?}",
        result.apply_changes
    );
}

/// A crypto directive a drop-in overrides is routed to the fragment that beats
/// it, exactly as every other overridden directive already is.
///
/// This is the half the scan fix deliberately left open. RHEL, Fedora and
/// openSUSE let crypto-policies supply Ciphers, MACs and KexAlgorithms from
/// /etc/ssh/sshd_config.d, which sshd reads before the main file, so writing
/// the strong list into sshd_config reported a change sshd never obeyed. The
/// maintainer's decision is that this tool overrides that fragment rather than
/// deferring to it.
///
/// `ssh -Q cipher` is registered because the target is the intersection of this
/// tool's allow-list with what the host supports: without it the intersection is
/// empty and the whole directive is skipped, which would make this test pass by
/// asserting nothing.
#[tokio::test]
async fn apply_writes_a_winning_dropin_for_a_crypto_directive_a_dropin_overrides() {
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nCiphers aes256-gcm@openssh.com\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file("/etc/ssh/sshd_config.d/50-redhat.conf", "Ciphers 3des-cbc\n"),
    )
    .with_command(
        "ssh",
        &["-Q", "cipher"],
        ok_output("chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\naes128-gcm@openssh.com\n3des-cbc\n"),
    );

    let result = run_ssh_apply(&executor).await;

    let dropin = dropin_written(&executor).unwrap_or_else(|| {
        panic!(
            "a drop-in must be written to beat 50-redhat.conf's cipher list, wrote: {:?}",
            executor.log().files_written
        )
    });
    assert!(
        dropin.contains("Ciphers "),
        "the drop-in must carry the overridden crypto directive, got: {dropin}"
    );
    assert!(
        !dropin.contains("3des-cbc"),
        "the drop-in must not carry the weak algorithm it exists to beat, got: {dropin}"
    );
    assert!(
        result.apply_success,
        "the directive is genuinely applied, so apply succeeds: {:?}",
        result.apply_changes
    );
}

/// The mirror: a drop-in already holding a strong list needs no fragment, and
/// writing one anyway would restate a value the host already obeys.
#[tokio::test]
async fn apply_writes_no_crypto_dropin_when_the_overriding_file_is_already_strong() {
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/50-redhat.conf",
                "Ciphers chacha20-poly1305@openssh.com\n",
            ),
    )
    .with_command(
        "ssh",
        &["-Q", "cipher"],
        ok_output(
            "chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\naes128-gcm@openssh.com\n",
        ),
    );

    let _ = run_ssh_apply(&executor).await;

    let dropin = dropin_written(&executor).unwrap_or_default();
    assert!(
        !dropin.contains("Ciphers"),
        "a file underneath already holding a strong list needs no fragment, got: {dropin}"
    );
}

#[tokio::test]
async fn apply_writes_no_dropin_when_nothing_overrides_the_main_file() {
    // Arch and Debian pass today. The drop-in is written only where needed, so
    // a host with no conflicting fragment must be untouched by this feature.
    // Asserts the opposite direction: it guards against over-correction and is
    // not evidence that the defect is fixed.
    let executor = dropin_apply_commands(
        MockExecutor::new().with_file("/etc/ssh/sshd_config", "X11Forwarding yes\n"),
    );

    run_ssh_apply(&executor).await;

    assert!(
        dropin_written(&executor).is_none(),
        "no drop-in overrides this host, so none should be created"
    );
    assert!(
        written_sshd_config(&executor).contains("X11Forwarding no"),
        "the main file is still the write target here"
    );
}

#[tokio::test]
async fn apply_reports_failure_when_the_dropin_does_not_win() {
    // The one assumption under this design is that 00- sorts first. A host
    // shipping something earlier must produce a failed change naming it, never
    // a success.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/00-aaa-wins.conf",
                "X11Forwarding yes\n",
            ),
    );

    let result = run_ssh_apply(&executor).await;

    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| !c.change_success && c.change_description.contains("00-aaa-wins.conf")),
        "a drop-in that still loses must be reported, naming the winner, got: {:?}",
        result.apply_changes
    );
    assert!(
        !result.apply_success,
        "a directive that is still overridden has not been applied"
    );
}

#[tokio::test]
async fn apply_writes_only_the_dropin_on_a_vendor_only_host() {
    // openSUSE: the apply failure there is the advisory lock, which opens
    // /etc/ssh/sshd_config directly with std::fs and dies on a path that does
    // not exist. Fixing the lock alone would be worse than leaving it: apply
    // would go on to create /etc/ssh/sshd_config, and because the override is
    // whole-file sshd would stop reading the vendor config, discarding both
    // its Include lines and the crypto policy fragment.
    let executor = dropin_apply_commands(opensuse_ssh_executor());

    let result = SshHardeningPlugin::new()
        .apply(
            &mut Context::with_executor(Arc::new(executor.clone())),
            &PluginConfig::default(),
        )
        .await
        .expect("apply must not abort on a host whose sshd_config is under /usr/etc");

    let dropin = dropin_written(&executor).unwrap_or_else(|| {
        panic!(
            "with no /etc/ssh/sshd_config, every managed directive goes to the drop-in, wrote: {:?}",
            executor.log().files_written
        )
    });
    assert!(
        dropin.contains("PermitRootLogin no"),
        "the drop-in must carry the managed directives, got: {dropin}"
    );
    assert!(
        !executor
            .log()
            .files_written
            .iter()
            .any(|(p, _)| p.to_str().is_some_and(|s| s.starts_with("/usr/etc/"))),
        "the vendor file must never be written, wrote: {:?}",
        executor.log().files_written
    );
    assert!(
        !executor
            .log()
            .files_written
            .iter()
            .any(|(p, _)| p.to_str() == Some("/etc/ssh/sshd_config")),
        "creating the admin file masks the vendor config wholesale, wrote: {:?}",
        executor.log().files_written
    );
    assert!(
        result.apply_success,
        "the host is hardened through the drop-in, so apply succeeds: {:?}",
        result.apply_changes
    );
}

#[tokio::test]
async fn apply_prunes_a_fragment_nothing_needs_any_more() {
    // The fragment exists only to beat something. An operator who removes the
    // drop-in that made it necessary would otherwise be left with a file
    // shadowing sshd_config indefinitely, which is the same class of surprise
    // as the fragments this feature exists to defeat.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/00-hardener.conf",
                "# Managed by linux-hardener.\nX11Forwarding no\n",
            )
            .with_command_program("rm", ok_output("")),
    );

    run_ssh_apply(&executor).await;

    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "rm"
                && args.contains(&"/etc/ssh/sshd_config.d/00-hardener.conf".to_string())),
        "the fragment must be removed once nothing overrides the main file, commands: {:?}",
        executor.log().commands_executed
    );
}

#[tokio::test]
async fn applying_twice_keeps_the_fragment_that_beats_a_vendor_drop_in() {
    // Fedora and RHEL. The first apply routes X11Forwarding to the fragment
    // because 50-redhat.conf outranks sshd_config. On the second apply the
    // effective value comes from the fragment this tool wrote, and unless the
    // plugin can tell "the winner is us" apart from "nothing overrides the main
    // file" it writes the directive where 50-redhat.conf still beats it and
    // prunes the fragment holding the host, leaving it less hardened after two
    // runs than after one. The scheduler applies on a cadence, so that is a
    // fleet host silently unhardening itself and reporting success.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/50-redhat.conf",
                "X11Forwarding yes\n",
            )
            .with_command_program("rm", ok_output("")),
    );

    run_ssh_apply(&executor).await;
    assert!(
        dropin_written(&executor).is_some_and(|dropin| dropin.contains("X11Forwarding no")),
        "positive control: the first apply must write the fragment, wrote: {:?}",
        executor.log().files_written
    );
    executor.clear_log();

    let second = run_ssh_apply(&executor).await;

    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "rm"
                && args.contains(&"/etc/ssh/sshd_config.d/00-hardener.conf".to_string())),
        "the second apply removed the fragment that is still the only thing beating \
         50-redhat.conf, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        !written_sshd_config(&executor).contains("X11Forwarding"),
        "50-redhat.conf is read before sshd_config, so writing the directive there is \
         inert, got:\n{}",
        written_sshd_config(&executor)
    );
    assert!(
        second
            .apply_changes
            .iter()
            .any(|change| change.change_description.contains("already compliant")),
        "a host the previous run hardened has nothing left to change, got: {:?}",
        second.apply_changes
    );
}

#[tokio::test]
async fn a_fragment_is_still_pruned_once_the_file_underneath_holds_the_target() {
    // The mirror of keeping a value the fragment alone holds: where the drop-in
    // that made the fragment necessary now sets the target itself, the fragment
    // has nothing left to do and must go, exactly as it does when the main file
    // is the only other source. Guards the keep-it-alive rule against becoming
    // "never prune".
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/00-hardener.conf",
                "# Managed by linux-hardener.\nX11Forwarding no\n",
            )
            .with_file(
                "/etc/ssh/sshd_config.d/50-redhat.conf",
                "X11Forwarding no\n",
            )
            .with_command_program("rm", ok_output("")),
    );

    run_ssh_apply(&executor).await;

    assert!(
        executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "rm"
                && args.contains(&"/etc/ssh/sshd_config.d/00-hardener.conf".to_string())),
        "50-redhat.conf now holds the target itself, so the fragment is redundant and must \
         be removed, commands: {:?}",
        executor.log().commands_executed
    );
}

// === Keeping a value the fragment is the only source of ===
//
// The remote-root lockout guard asks whether the value in force is already at
// least as strict as the one it may safely write, and treats "yes" as a reason
// to write nothing. Once this tool's own fragment supplies that value, writing
// nothing means rewriting the fragment without the directive, so the answer
// "it is already safe" is what takes the safety away.

#[tokio::test]
async fn a_second_apply_over_a_root_session_keeps_the_value_only_the_fragment_holds() {
    // openSUSE reached over a root SSH session. The vendor sshd_config says
    // PermitRootLogin yes and is never edited, so the first apply puts the
    // downgraded prohibit-password in the fragment. On the second apply the
    // fragment is what makes the host safe, the guard reads it as "already safe
    // enough", skips, and the fragment is rewritten without the directive.
    let executor = dropin_apply_commands(
        opensuse_ssh_executor()
            .remote()
            .with_command("id", &["-u"], ok_output("0\n"))
            .with_command_program("rm", ok_output("")),
    );

    run_ssh_apply(&executor).await;
    let after_first =
        dropin_written(&executor).expect("positive control: the first apply writes the fragment");
    assert!(
        after_first.contains("PermitRootLogin prohibit-password"),
        "positive control: the downgraded value must reach the fragment, got: {after_first}"
    );

    run_ssh_apply(&executor).await;

    assert_eq!(
        dropin_written(&executor).as_deref(),
        Some(after_first.as_str()),
        "the second apply dropped a directive the fragment was the only source of, so the \
         host is back on the vendor's value"
    );
}

#[tokio::test]
async fn a_second_apply_over_a_root_session_keeps_a_value_a_drop_in_still_contests() {
    // The same conflation on a host whose sshd_config is the administrator's:
    // 50-redhat.conf holds PermitRootLogin yes, so the first apply routes the
    // downgraded value to the fragment. On the second apply the guard sees the
    // fragment's own prohibit-password, calls the host already safe enough and
    // skips, which empties the fragment and hands the directive back to
    // 50-redhat.conf.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\n",
            )
            .with_directory("/etc/ssh/sshd_config.d")
            .with_file(
                "/etc/ssh/sshd_config.d/50-redhat.conf",
                "PermitRootLogin yes\n",
            )
            .with_command_program("rm", ok_output(""))
            .remote()
            .with_command("id", &["-u"], ok_output("0\n")),
    );

    run_ssh_apply(&executor).await;
    assert!(
        dropin_written(&executor)
            .is_some_and(|dropin| dropin.contains("PermitRootLogin prohibit-password")),
        "positive control: the first apply must route the downgraded value to the fragment, \
         wrote: {:?}",
        executor.log().files_written
    );
    executor.clear_log();

    let second = run_ssh_apply(&executor).await;

    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(command, args)| command == "rm"
                && args.contains(&"/etc/ssh/sshd_config.d/00-hardener.conf".to_string())),
        "the second apply removed the fragment that is still the only thing beating \
         50-redhat.conf, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        second
            .apply_changes
            .iter()
            .any(|change| change.change_description.contains("already compliant")),
        "a host the previous run hardened has nothing left to change, got: {:?}",
        second.apply_changes
    );
}

/// A host stricter than this tool's baseline on every directive whose value
/// has a direction: two authentication attempts rather than three, a sixty
/// second idle probe rather than five minutes, one missed probe rather than
/// two. Crypto lines are the ones `secure_ssh_executor` uses, so the crypto
/// pass contributes nothing either way.
const STRICTER_THAN_BASELINE: &str = r#"
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 2
X11Forwarding no
ClientAliveInterval 60
ClientAliveCountMax 1
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
"#;

#[tokio::test]
async fn ssh_scan_does_not_report_a_stricter_host_as_violating() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_file("/etc/ssh/sshd_config", STRICTER_THAN_BASELINE),
    ));

    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("ssh scan should not error");

    assert!(
        result.scan_findings.is_empty(),
        "a host stricter than the baseline is compliant, but these were flagged: {:?}",
        result
            .scan_findings
            .iter()
            .map(|finding| (
                finding.finding_id.as_str(),
                finding.finding_current_value.as_str()
            ))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn ssh_apply_never_loosens_a_stricter_host() {
    let executor = apply_ready_executor(STRICTER_THAN_BASELINE);

    run_ssh_apply(&executor).await;

    let written = written_sshd_config(&executor);
    for (directive, kept) in [
        ("MaxAuthTries", "2"),
        ("ClientAliveInterval", "60"),
        ("ClientAliveCountMax", "1"),
    ] {
        assert!(
            written
                .lines()
                .any(|line| line.trim() == format!("{directive} {kept}")),
            "apply loosened {directive}: the host had {kept} and the file now reads:\n{written}"
        );
    }
}

#[tokio::test]
async fn ssh_scan_flags_an_idle_probe_that_is_switched_off() {
    // ClientAliveInterval 0 stops sshd probing an idle client at all, so zero
    // is the loosest value the setting has while being the smallest number it
    // can hold. Judged purely on "smaller is stricter" it would score best.
    let disabled =
        STRICTER_THAN_BASELINE.replace("ClientAliveInterval 60", "ClientAliveInterval 0");
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new().with_file("/etc/ssh/sshd_config", &disabled),
    ));

    let result = SshHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("ssh scan should not error");

    assert!(
        result
            .scan_findings
            .iter()
            .any(|finding| finding.finding_id == "ssh-clientaliveinterval"),
        "an idle probe switched off is not a stricter idle probe, findings: {:?}",
        result
            .scan_findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn ssh_apply_clamps_an_operator_override_that_would_loosen() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("MaxAuthTries".to_string(), "6".to_string());
    config
        .directives
        .insert("X11Forwarding".to_string(), "yes".to_string());

    let executor = apply_ready_executor("# minimal config\n");
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    SshHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("ssh apply should not error");

    let written = written_sshd_config(&executor);
    assert!(
        written.lines().any(|line| line.trim() == "MaxAuthTries 3"),
        "an override may tighten the baseline and never relax it, file reads:\n{written}"
    );
    assert!(
        written
            .lines()
            .any(|line| line.trim() == "X11Forwarding no"),
        "an override may tighten the baseline and never relax it, file reads:\n{written}"
    );
}

#[tokio::test]
async fn apply_does_not_loosen_a_vendor_host_through_its_own_fragment() {
    // On a host whose sshd_config lives under /usr/etc, the vendor file is
    // never edited and every managed directive goes to the fragment instead.
    // The fragment sorts first, so writing the plain baseline into it
    // overrides the vendor file's stricter value: this host allows two
    // authentication attempts and one missed keepalive probe, and the
    // fragment would hand it back three and two.
    let executor = dropin_apply_commands(
        MockExecutor::new()
            .with_file(
                "/usr/etc/ssh/sshd_config",
                "# vendor config\n\
                 Include /etc/ssh/sshd_config.d/*.conf\n\
                 MaxAuthTries 2\n\
                 ClientAliveCountMax 1\n",
            )
            .with_directory("/etc/ssh/sshd_config.d"),
    );

    SshHardeningPlugin::new()
        .apply(
            &mut Context::with_executor(Arc::new(executor.clone())),
            &PluginConfig::default(),
        )
        .await
        .expect("apply must not abort on a vendor-only host");

    let dropin = dropin_written(&executor).expect("the fragment carries the managed directives");
    assert!(
        dropin.contains("MaxAuthTries 2"),
        "the fragment loosened MaxAuthTries from the vendor file's 2, got:\n{dropin}"
    );
    assert!(
        dropin.contains("ClientAliveCountMax 1"),
        "the fragment loosened ClientAliveCountMax from the vendor file's 1, got:\n{dropin}"
    );
}

// =============================================================================
// The directory the fragment lives in
// =============================================================================
//
// `write_file` cannot create a missing parent: it lands its content through a
// temporary file in the target directory. The creation is shared with the
// kernel, pam and audit plugins, and these tests are what proves this plugin
// routes through that one implementation rather than a copy of its own.

const DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

/// A vendor-only host that never gained the `/etc` drop-in directory.
///
/// Everything managed goes to the fragment on such a host, because the vendor
/// file is never edited, so the write this guard protects is always reached.
/// The directory is registered nowhere, which is what absence looks like to the
/// mock: `path_exists` answers false from the metadata registry and `read_dir`
/// returns nothing, exactly as an absent directory would.
fn vendor_host_without_the_dropin_directory() -> MockExecutor {
    dropin_apply_commands(MockExecutor::new().with_file(
        "/usr/etc/ssh/sshd_config",
        "# vendor config\n\
         Include /etc/ssh/sshd_config.d/*.conf\n\
         PermitRootLogin yes\n\
         PasswordAuthentication yes\n",
    ))
}

/// How many times the apply asked for the drop-in directory to exist.
fn dropin_mkdir_count(executor: &MockExecutor) -> usize {
    executor
        .log()
        .commands_executed
        .iter()
        .filter(|(program, args)| {
            program == "mkdir"
                && args.contains(&"-p".to_string())
                && args.contains(&DROPIN_DIR.to_string())
        })
        .count()
}

#[tokio::test]
async fn apply_creates_the_dropin_directory_when_it_is_absent() {
    let executor = vendor_host_without_the_dropin_directory().with_command(
        "mkdir",
        &["-p", DROPIN_DIR],
        ok_output(""),
    );

    let result = run_ssh_apply(&executor).await;

    assert_eq!(
        dropin_mkdir_count(&executor),
        1,
        "an absent parent must be created, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        dropin_written(&executor).is_some(),
        "the fragment must still be written, writes: {:?}",
        executor.log().files_written
    );
    assert!(
        result.apply_success,
        "an apply that created the directory it needed succeeded, changes: {:?}",
        result.apply_changes
    );
}

/// A probe that cannot answer is not an answer. `path_exists` returns an error
/// for a directory it could not determine, and reading that as "it is there"
/// would skip the creation on exactly the host that needs it. `mkdir -p` on an
/// existing directory does nothing, so attempting it costs nothing.
#[tokio::test]
async fn apply_creates_the_dropin_directory_when_the_probe_cannot_answer() {
    let executor = vendor_host_without_the_dropin_directory()
        .with_path_exists_error(DROPIN_DIR)
        .with_command("mkdir", &["-p", DROPIN_DIR], ok_output(""));

    run_ssh_apply(&executor).await;

    assert_eq!(
        dropin_mkdir_count(&executor),
        1,
        "a probe that failed must be treated as may-be-missing, commands: {:?}",
        executor.log().commands_executed
    );
}

/// `execute_command` returns Ok for a command that ran and failed, so an
/// unchecked exit code would let a failed mkdir be followed by a write that
/// cannot land. The failure must reach the operator as a failed change carrying
/// the reason, and the reason names the exit code as well as the stderr,
/// because a mkdir that fails silently prints nothing.
#[tokio::test]
async fn apply_reports_why_the_dropin_directory_could_not_be_created() {
    let executor = vendor_host_without_the_dropin_directory().with_command(
        "mkdir",
        &["-p", DROPIN_DIR],
        CommandOutput {
            stdout: String::new(),
            stderr: "mkdir: cannot create directory '/etc/ssh/sshd_config.d': \
                     Read-only file system\n"
                .to_string(),
            exit_code: 1,
        },
    );

    let result = run_ssh_apply(&executor).await;

    let failed = result
        .apply_changes
        .iter()
        .find(|change| !change.change_success)
        .expect("a failed mkdir must produce a failed change, not a silent success");
    let reason = failed
        .change_error
        .as_deref()
        .expect("a failed change must carry the reason");
    assert!(
        reason.contains("Read-only file system"),
        "the operator must be told why the directory could not be created, got: {reason}"
    );
    assert!(
        reason.contains("mkdir exited 1"),
        "the exit code belongs in the reason, because a silent mkdir leaves \
         nothing else to report, got: {reason}"
    );
    assert!(
        dropin_written(&executor).is_none(),
        "a write into a directory that could not be created must not be attempted, \
         writes: {:?}",
        executor.log().files_written
    );
    assert!(
        !result.apply_success,
        "an apply that could not write the fragment has not succeeded"
    );
}

/// Names only ssh's own paths, so a failure here cannot come from another
/// plugin's entry in a shared list.
#[test]
fn ssh_reloads_for_its_own_paths_and_no_others() {
    let plugin = SshHardeningPlugin::new();
    assert!(plugin.reloads_for_path(Path::new("/etc/ssh/sshd_config")));
    assert!(plugin.reloads_for_path(Path::new("/etc/ssh/sshd_config.d/00-hardener.conf")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/sysctl.conf")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/audit/auditd.conf")));
}

// The agreement test that used to live here (asserting the predicate covers
// the two literal paths `apply` checkpoints) moved to
// `crates/hardener-plugins/src/ssh/tests.rs`, where `SSHD_ADMIN_CONFIG_PATH`
// and `dropin::DROPIN_PATH` are visible by name. This file compiles as a
// separate crate and can only see literals, which stayed green through a
// change to either constant's value - the drift the test exists to catch.

/// Asserts that the finding named by `finding_id` advertises `key`, and that
/// an exception written under that key silences it on a rescan of the same
/// host.
///
/// This plugin reaches exceptions through `matching_exception`, which requires
/// the documented value to equal the live one, so the exception is built out
/// of the finding itself. That makes this prove the second half too: the value
/// a consumer would copy from a finding is the value the wrapper accepts.
async fn assert_key_silences(finding_id: &str, key: &str) {
    let scan = async |config: &PluginConfig| {
        SshHardeningPlugin::new()
            .scan(
                &Context::with_executor(Arc::new(insecure_ssh_executor())),
                config,
            )
            .await
            .expect("ssh scan should not error")
    };

    let result = scan(&PluginConfig::default()).await;
    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .unwrap_or_else(|| panic!("the insecure fixture must report {finding_id}"));

    assert_eq!(
        finding.finding_exception_key.as_deref(),
        Some(key),
        "{finding_id} must name the sshd directive, not its own id",
    );

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        key.to_string(),
        PolicyException {
            value: finding.finding_current_value.clone(),
            allowed: true,
            reason: "legacy jump host".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let excepted = scan(&config).await;
    let annotated = excepted
        .scan_findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .unwrap_or_else(|| panic!("an excepted {finding_id} is still reported, annotated"));

    assert!(
        annotated.is_policy_excepted(),
        "an exception written under {key} must annotate {finding_id}",
    );
}

/// An sshd directive is spelled in camel case and its finding id is lowercased,
/// so `PermitRootLogin` and `ssh-permitrootlogin` differ by a transform that
/// cannot be inverted: nothing in the id says where the capitals were.
// assertions-in-helper: both sites assert the same two things, so the pair
// lives in assert_key_silences rather than being written out twice.
#[tokio::test]
async fn an_ssh_directive_finding_names_the_exception_key_that_silences_it() {
    assert_key_silences("ssh-permitrootlogin", "PermitRootLogin").await;
}

/// The crypto directives are a second, separately built finding site in this
/// plugin, and they take their key from a different table, so covering the
/// directive site above says nothing about them.
// assertions-in-helper: both sites assert the same two things, so the pair
// lives in assert_key_silences rather than being written out twice.
#[tokio::test]
async fn an_ssh_crypto_finding_names_the_exception_key_that_silences_it() {
    assert_key_silences("ssh-ciphers", "Ciphers").await;
}

/// The apply leaves a timestamped copy of `sshd_config` beside it and nothing
/// removed one: 17 had accumulated in `/etc/ssh` on the development host by
/// 2026-08-11, two naming shapes deep, and the checkpoint captures the
/// directory so each is restored by every rollback (#154, found in
/// `audit-hardening` and the same defect here).
///
/// Asserted on which paths `rm` was given rather than on how many, because "the
/// surplus was removed" is equally true of a prune that removed the newest.
#[tokio::test]
async fn ssh_apply_prunes_the_backups_that_came_before_it() {
    let doomed = ["1763680168", "20251209_012340"];
    let kept = ["20260718_112302", "20260810_120000", "20260810_120001"];

    let mut executor = apply_ready_executor_any_backup("# minimal config\n")
        .with_command_program("rm", ok_output(""));
    for stamp in kept.iter().chain(doomed.iter()) {
        executor = executor.with_file(&format!("/etc/ssh/sshd_config.backup.{stamp}"), "Port 22\n");
    }

    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "a drifting apply must succeed: {result:?}"
    );
    // Every `rm` the apply ran, not the first one: it removes its own sshd -t
    // temporary file too, and a lookup taking the first match would assert
    // against that one and never see the prune.
    let log = executor.log();
    let removed: Vec<&String> = log
        .commands_executed
        .iter()
        .filter(|(program, _)| program == "rm")
        .flat_map(|(_, args)| args.iter())
        .collect();
    for stamp in doomed {
        let backup = format!("/etc/ssh/sshd_config.backup.{stamp}");
        assert!(
            removed.iter().any(|argument| **argument == backup),
            "the older backup {backup} must be removed, rm was given: {removed:?}"
        );
    }
    for stamp in kept {
        let backup = format!("/etc/ssh/sshd_config.backup.{stamp}");
        assert!(
            !removed.iter().any(|argument| **argument == backup),
            "the newest backups must be kept, but {backup} was removed: {removed:?}"
        );
    }
}

/// The prune has to run on an apply that rewrites nothing, which for this
/// plugin is the only kind a compliant host ever performs.
///
/// ssh differs from audit and pam in what it does on a no-op: it returns before
/// creating any checkpoint, so nothing captures its backups and there is no
/// checkpoint bloat to undo. What is left is the pile itself. `/etc/ssh` held
/// 17 on the development host on 2026-08-11 and `apply --dry-run` reported "0
/// change(s) to apply", so the copy-side prune was never going to reach them:
/// on a host that stays compliant, the next rewrite that would trigger it may
/// never come.
///
/// The no-op contract the fixture beside this one pins is untouched. This
/// asserts the same three things it does, that nothing was copied, rewritten or
/// restarted, so a prune that started rewriting the config to reach its own
/// call site would fail here rather than pass quietly.
#[tokio::test]
async fn ssh_apply_prunes_even_when_it_changes_nothing() {
    let doomed = ["1763680168", "20251209_012340"];
    let kept = ["20260718_112302", "20260810_120000", "20260810_120001"];

    let mut executor =
        compliant_noop_executor(COMPLIANT_SSHD_CONFIG).with_command_program("rm", ok_output(""));
    for stamp in kept.iter().chain(doomed.iter()) {
        executor = executor.with_file(&format!("/etc/ssh/sshd_config.backup.{stamp}"), "Port 22\n");
    }

    let result = run_ssh_apply(&executor).await;

    assert!(
        result.apply_success,
        "an already-compliant apply must succeed: {result:?}"
    );
    assert!(
        !backed_up_config(&executor),
        "the prune must not turn a no-op into a run that copies, commands: {:?}",
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

    let log = executor.log();
    let removed: Vec<&String> = log
        .commands_executed
        .iter()
        .filter(|(program, _)| program == "rm")
        .flat_map(|(_, args)| args.iter())
        .collect();
    for stamp in doomed {
        let backup = format!("/etc/ssh/sshd_config.backup.{stamp}");
        assert!(
            removed.iter().any(|argument| **argument == backup),
            "a no-op apply must still prune {backup}, rm was given: {removed:?}"
        );
    }
    for stamp in kept {
        let backup = format!("/etc/ssh/sshd_config.backup.{stamp}");
        assert!(
            !removed.iter().any(|argument| **argument == backup),
            "the newest backups must survive, but {backup} was removed: {removed:?}"
        );
    }
}
