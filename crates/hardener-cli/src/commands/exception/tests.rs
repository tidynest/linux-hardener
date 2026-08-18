use super::*;
use hardener_core::MockExecutor;
use hardener_types::{ExceptionOutcome, FindingCategory, Severity};

fn finding(key: Option<&str>, current: &str) -> Finding {
    Finding {
        finding_category: FindingCategory::Services,
        finding_current_value: current.to_string(),
        finding_description: String::new(),
        finding_explanation: String::new(),
        finding_id: "service_bluetooth".to_string(),
        finding_impact: String::new(),
        finding_recommended_value: "disabled".to_string(),
        finding_remediation_steps: vec![],
        finding_severity: Severity::Medium,
        finding_title: "Bluetooth service is enabled".to_string(),
        finding_compliance: vec![],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: key.map(str::to_string),
    }
}

/// The value written is the one this scan just read, not one carried in from a
/// row that may be days old. A stale pin makes an exception that never applies.
#[test]
fn the_pinned_value_comes_from_the_matching_finding() {
    let findings = vec![
        finding(Some("cups"), "enabled"),
        finding(Some("bluetooth"), "active"),
    ];

    let pinned = pin_from_findings(&findings, "bluetooth").expect("the key is present");

    assert_eq!(pinned.finding_current_value, "active");
}

/// A key the host's own scan did not produce is refused. That refusal is also
/// the input validation for the desktop: a crafted key cannot reach the
/// document, because it never matches a live finding.
#[test]
fn an_unknown_key_is_refused_by_name() {
    let findings = vec![finding(Some("cups"), "enabled")];

    let err = pin_from_findings(&findings, "bluetooth").expect_err("an absent key must refuse");

    assert!(
        err.to_string().contains("bluetooth"),
        "the refusal names the key: {err}"
    );
}

/// A finding with no key cannot be excepted at all, and must not be matched by
/// a caller passing an empty key.
#[test]
fn a_keyless_finding_never_matches() {
    let findings = vec![finding(None, "enabled")];

    assert!(pin_from_findings(&findings, "").is_err());
}

/// `%Y-%m-%d` is the only format `PolicyException::is_expired` parses; anything
/// else must be refused before it is ever written, not silently kept forever.
#[test]
fn a_valid_expiry_date_is_accepted() {
    assert!(parse_expiry("2027-01-31").is_ok());
}

/// A date in the wrong order parses as neither format nor value here, and must
/// not be written: `is_expired` would read it back as "never expires".
#[test]
fn a_malformed_expiry_date_is_refused() {
    let err = parse_expiry("31/01/2027").expect_err("day/month/year must be refused");
    assert!(
        err.to_string().contains("YYYY-MM-DD"),
        "the refusal names the expected format: {err}"
    );
}

/// A value that merely looks date-shaped but names no real date must also be
/// refused, not accepted and left for the host to disagree with later.
#[test]
fn an_invalid_calendar_date_is_refused() {
    assert!(parse_expiry("2027-02-30").is_err());
}

/// A rename over an existing file otherwise carries the temporary file's own
/// mode (root's umask default), silently discarding whatever mode the
/// operator set on the target.
#[test]
fn write_atomically_preserves_the_target_mode() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "existing = true\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

    write_atomically(&path, "existing = true\nnew = 1\n").unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
}

/// A target that does not exist yet has no mode to preserve, so the write
/// still succeeds and the file lands with the temporary file's default mode.
#[test]
fn write_atomically_succeeds_for_a_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    write_atomically(&path, "new = 1\n").unwrap();

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new = 1\n");
}

/// Re-scans `plugin_id` against the config `add` just wrote, using the same
/// executor `add` scanned with, and returns the finding keyed `key`.
///
/// Writing the exception and reading the file back, which both composition
/// tests below also do, proves only that some bytes landed in the right
/// table. It does not prove that the plugin's own comparison then treats what
/// was written as an applied exception. This is the step that closes that
/// loop: loading the config exactly as `add` loaded it, scanning exactly as
/// `add` scanned, and reading the outcome back off the live finding.
async fn rescan_finding(
    config_path: &PathBuf,
    plugin_id: &str,
    key: &str,
    executor: Arc<dyn hardener_core::executor::SystemExecutor>,
) -> Finding {
    let config = crate::commands::config_loader(Some(config_path))
        .load()
        .expect("the config add just wrote loads cleanly");
    let registry = hardener_plugins::create_plugin_registry();
    let plugin = registry
        .get(&PluginId::new(plugin_id))
        .expect("a known plugin id resolves")
        .expect("the plugin is registered");
    let ctx = Context::with_executor(executor);
    let scan = plugin
        .scan(&ctx, config.get_plugin_config(plugin_id))
        .await
        .expect("the rescan succeeds against the same mock executor");
    scan.scan_findings
        .into_iter()
        .find(|f| f.finding_exception_key.as_deref() == Some(key))
        .unwrap_or_else(|| panic!("the rescan still reports a finding keyed '{key}'"))
}

/// `add` then `remove`, driven end to end through a temporary config and a
/// [`MockExecutor`] scan, for a value-comparing plugin.
///
/// Everything above this test proves one function of the composition:
/// `pin_from_findings` matches a key, `upsert_exception`/`remove_exception`
/// edit a document, `write_atomically` preserves a mode. None of that proves
/// the composition itself, that `add` loads the named config, scans the named
/// plugin, finds the finding the scan produced, pins the value the scan read,
/// and writes it to the path it was given, all correctly wired together. SSH
/// is the value-comparing plugin here: `PasswordAuthentication` is refused
/// unless the exception's documented value equals the value SSH's own scan
/// reads.
///
/// `PasswordAuthentication` is deliberate, not `PermitRootLogin`
/// (`SSH_DIRECTIVES[0]`, `crates/hardener-plugins/src/ssh/mod.rs:86`): the
/// mock's `sshd_config` sets only `PermitRootLogin`, which is enough on its
/// own to make it the first finding the scan pushes, so a build that ignored
/// `key` entirely and pinned `findings[0]` would still pass a test that used
/// it. `PasswordAuthentication` is absent from the mock config, which is its
/// own kind of insecure (`crates/hardener-plugins/src/ssh/mod.rs` treats a
/// missing directive as violating every direction), and is pushed second, so
/// only a build that actually matches on `key` finds it.
#[tokio::test]
async fn add_then_remove_pins_the_scanned_value_for_a_value_comparing_plugin() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "").expect("an empty starting config");

    let executor: Arc<dyn hardener_core::executor::SystemExecutor> =
        Arc::new(MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin yes\n"));

    add(AddOptions {
        plugin_id: "ssh-hardening",
        key: "PasswordAuthentication",
        reason: "break-glass access from the bastion",
        approved_by: None,
        ticket: None,
        expires: None,
        config_path: Some(&config_path),
        format: OutputFormat::Json,
        quiet: true,
        executor: executor.clone(),
    })
    .await
    .expect("add must succeed against a temporary config and a mock scan");

    let written = std::fs::read_to_string(&config_path).expect("the write landed");
    assert!(
        written.contains("[ssh.exceptions.PasswordAuthentication]"),
        "the exception table is written under the plugin's config section: {written}"
    );
    assert!(
        written.contains("value = \"not set\""),
        "the value pinned is the one the scan read, not a placeholder or the \
         recommended value: {written}"
    );

    let rescanned = rescan_finding(
        &config_path,
        "ssh-hardening",
        "PasswordAuthentication",
        executor,
    )
    .await;
    assert!(
        matches!(rescanned.finding_exception, ExceptionOutcome::Applied(_)),
        "the value add pinned must be the one the plugin's own comparison then \
         accepts as an applied exception, not merely a string sitting in the \
         file: {:?}",
        rescanned.finding_exception
    );

    remove(RemoveOptions {
        plugin_id: "ssh-hardening",
        key: "PasswordAuthentication",
        config_path: Some(&config_path),
        format: OutputFormat::Json,
        quiet: true,
    })
    .await
    .expect("remove must succeed against the same config");

    let restored = std::fs::read_to_string(&config_path).expect("the file is still there");
    assert!(
        !restored.contains("PasswordAuthentication"),
        "remove takes the written exception back out: {restored}"
    );
}

/// The same composition, for a presence plugin, so the advisory-value path is
/// exercised rather than reasoned about.
///
/// auditd not installed is a presence finding: apply refuses nothing on a
/// value comparison for it, so this is what would have stayed unverified had
/// only SSH been covered. `MockExecutor::with_command_exists("auditd", false)`
/// is enough on its own; the audit plugin returns its finding before reading
/// or executing anything else once `auditd` is confirmed absent. The rescan
/// below is what actually reaches
/// [`hardener_plugins::audit::exception_outcome_for_presence`] (called from
/// `crates/hardener-plugins/src/audit/mod.rs:1119`, with
/// `AUDITD_PRESENT_EXCEPTION`, which is the `"auditd-present"` key this test
/// passes): without it, this test
/// asserted nothing the value-comparing test above did not already cover.
#[tokio::test]
async fn add_then_remove_pins_the_scanned_value_for_a_presence_plugin() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "").expect("an empty starting config");

    let executor: Arc<dyn hardener_core::executor::SystemExecutor> =
        Arc::new(MockExecutor::new().with_command_exists("auditd", false));

    add(AddOptions {
        plugin_id: "audit-hardening",
        key: "auditd-present",
        reason: "audited by the host's own syslog pipeline instead",
        approved_by: None,
        ticket: None,
        expires: None,
        config_path: Some(&config_path),
        format: OutputFormat::Json,
        quiet: true,
        executor: executor.clone(),
    })
    .await
    .expect("add must succeed for a presence plugin too");

    let written = std::fs::read_to_string(&config_path).expect("the write landed");
    assert!(
        written.contains("[audit.exceptions.auditd-present]"),
        "the exception table is written under the plugin's config section: {written}"
    );
    assert!(
        written.contains("value = \"not installed\""),
        "the pinned value is what the scan observed, not a placeholder: {written}"
    );

    let rescanned =
        rescan_finding(&config_path, "audit-hardening", "auditd-present", executor).await;
    assert!(
        matches!(rescanned.finding_exception, ExceptionOutcome::Applied(_)),
        "the presence plugin's own lookup must accept what add pinned: {:?}",
        rescanned.finding_exception
    );

    remove(RemoveOptions {
        plugin_id: "audit-hardening",
        key: "auditd-present",
        config_path: Some(&config_path),
        format: OutputFormat::Json,
        quiet: true,
    })
    .await
    .expect("remove must succeed against the same config");

    let restored = std::fs::read_to_string(&config_path).expect("the file is still there");
    assert!(
        !restored.contains("auditd-present"),
        "remove takes the written exception back out: {restored}"
    );
}

/// `add` refuses a malformed `--expires` before it ever scans a plugin or
/// writes anything, which is not proved by the direct `parse_expiry` tests
/// above: all three call the function directly, and both composition tests
/// above pass `expires: None`, so deleting the check at the top of `add`
/// (`crates/hardener-cli/src/commands/exception.rs:79-81`) would leave the
/// whole suite green while silently restoring a fail-open in the one field
/// whose purpose is to bound a deviation in time.
#[tokio::test]
async fn add_refuses_a_malformed_expiry_before_writing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "").expect("an empty starting config");

    let executor: Arc<dyn hardener_core::executor::SystemExecutor> =
        Arc::new(MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin yes\n"));

    let err = add(AddOptions {
        plugin_id: "ssh-hardening",
        key: "PermitRootLogin",
        reason: "break-glass access from the bastion",
        approved_by: None,
        ticket: None,
        expires: Some("31/01/2027"),
        config_path: Some(&config_path),
        format: OutputFormat::Json,
        quiet: true,
        executor,
    })
    .await
    .expect_err("a day/month/year expiry must be refused");

    assert!(
        err.to_string().contains("YYYY-MM-DD"),
        "the refusal names the expected format: {err}"
    );
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("the file is still there"),
        "",
        "a refused expiry must be caught before any scan or write happens, not \
         merely refused after the fact"
    );
}
