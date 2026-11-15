//! Password hashing (#191) through the whole PAM plugin, with MockExecutor.
//!
//! The unit tests beside `pam/hashing.rs` pin the readings and the plan; these
//! pin what an operator sees: the findings scan reports, the file apply
//! writes, what apply leaves as a manual step, and what the dry run previews.
//! Each host is shaped on files its distribution ships, read from the
//! packages on 2026-11-15, and the host probe's answer is the one that host
//! gives (Ubuntu 24.04's was taken from this machine).
//!
//! Kept in its own file so the hashing work and the rest of the PAM suite can
//! change without touching each other.

use hardener_common::types::Severity;
use hardener_core::{
    CommandOutput, Context, ExceptionOutcome, MockExecutor, PluginConfig, PolicyException,
    UncheckedBlocker, plugin::HardeningPlugin,
};
use hardener_plugins::PamHardeningPlugin;
use std::sync::Arc;

const SECURE_AGEING: &str = "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n";

/// Ubuntu 24.04: yescrypt everywhere, and a PAM 1.5.3 that ignores the cost
/// factor. Two accounts, one still on SHA-512.
const UBUNTU_2404_PROBE: &str = "pam_unix_yescrypt=yes\npam_unix_cost_factor=no\n\
     libcrypt_yescrypt=yes\nshadow_yescrypt=yes\nfips=no\nshadow=read\n\
     scheme=yescrypt\nscheme=sha512\nend=1\n";

/// A host with yescrypt everywhere and Linux-PAM 1.6.0 or later.
const MODERN_PROBE: &str = "pam_unix_yescrypt=yes\npam_unix_cost_factor=yes\n\
     libcrypt_yescrypt=yes\nshadow_yescrypt=yes\nfips=no\nshadow=read\nend=1\n";

/// RHEL 9: shadow 4.9 built without yescrypt. pam_unix links libcrypt.so.2,
/// libxcrypt 4.4.18 built with every hash (c9s libxcrypt.spec), so the probe
/// finds `$y$` there; RHEL 9 is held to SHA-512 by shadow alone.
const RHEL9_PROBE: &str = "pam_unix_yescrypt=yes\npam_unix_cost_factor=no\n\
     libcrypt_yescrypt=yes\nshadow_yescrypt=no\nfips=no\nshadow=read\nend=1\n";

const UBUNTU_2404_COMMON_PASSWORD: &str =
    "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n";

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: 0,
    }
}

/// A host compliant in everything but hashing, so every assertion below is
/// about hashing alone. The modules the other directives need are loaded from
/// `password-auth`; the `pam_unix` password line goes where each test says.
fn host(login_defs: &str, stack_file: &str, stack: &str, probe: Option<&str>) -> MockExecutor {
    let mut executor = MockExecutor::new()
        .with_directory("/etc")
        .with_directory("/etc/security")
        .with_file(
            "/etc/security/pwquality.conf",
            "minlen = 14\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\nmaxrepeat = 3\n",
        )
        .with_file("/etc/security/faillock.conf", "deny = 3\n")
        .with_file("/etc/security/pwhistory.conf", "remember = 10\n")
        .with_file(
            "/etc/pam.d/password-auth",
            "auth     required pam_faillock.so preauth silent\n\
             password required pam_pwquality.so retry=3\n\
             password required pam_pwhistory.so\n",
        )
        .with_file("/etc/login.defs", login_defs)
        .with_file(stack_file, stack)
        .with_command_program("cp", ok(""))
        .with_command_program("chmod", ok(""));
    if let Some(probe) = probe {
        executor = executor.with_command_program("sh", ok(probe));
    }
    executor
}

fn with_memory(executor: MockExecutor, kib: u64) -> MockExecutor {
    executor.with_file("/proc/meminfo", &format!("MemTotal:       {kib} kB\n"))
}

fn config_with(key: &str, value: &str) -> PluginConfig {
    let mut config = PluginConfig::default();
    config.directives.insert(key.to_string(), value.to_string());
    config
}

fn hashing_ids(findings: &[hardener_core::plugin::Finding]) -> Vec<&str> {
    findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .filter(|id| {
            matches!(
                *id,
                "pam-ENCRYPT_METHOD"
                    | "pam-YESCRYPT_COST_FACTOR"
                    | "pam-SHA_CRYPT_MIN_ROUNDS"
                    | "pam-stored-password-hashes"
                    | "pam-yescrypt-cost-memory"
            )
        })
        .collect()
}

fn written(executor: &MockExecutor, path: &str) -> Option<String> {
    executor
        .log()
        .files_written
        .iter()
        .rev()
        .find(|(p, _)| p.to_str() == Some(path))
        .map(|(_, content)| content.clone())
}

#[tokio::test]
async fn ubuntu_2404_is_moved_to_yescrypt_in_login_defs_and_nothing_else() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD SHA512\n#YESCRYPT_COST_FACTOR 5\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/common-password",
        UBUNTU_2404_COMMON_PASSWORD,
        Some(UBUNTU_2404_PROBE),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = PluginConfig::default();

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    assert_eq!(
        hashing_ids(&scan.scan_findings),
        vec!["pam-ENCRYPT_METHOD", "pam-stored-password-hashes"],
        "group passwords and chpasswd -c still use SHA-512 here, and one account \
         is stored with it"
    );
    let method = &scan.scan_findings[0];
    assert_eq!(method.finding_current_value, "SHA512");
    assert_eq!(method.finding_recommended_value, "YESCRYPT");
    assert_eq!(method.finding_severity, Severity::Low);
    assert!(
        method.finding_compliance.is_empty(),
        "a compliance control fails on any live mapped finding, and salted \
         SHA-512 is what DISA requires, so this preference must fail none: {:?}",
        method.finding_compliance
    );
    assert!(
        method
            .finding_description
            .contains("passwords set through pam_unix, as passwd sets them, already get yescrypt"),
        "the operator must not read this as passwd making SHA-512 hashes: {}",
        method.finding_description
    );
    let stored = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-stored-password-hashes")
        .expect("stored hashes counted");
    assert_eq!(stored.finding_current_value, "1 sha512");

    let preview = plugin.validate(&ctx, &config).await.expect("validate runs");
    assert!(
        preview
            .validation_report_estimated_changes
            .contains(&"ENCRYPT_METHOD will change: SHA512 -> YESCRYPT".to_string()),
        "{:?}",
        preview.validation_report_estimated_changes
    );
    assert!(
        !preview.has_blocking_issue(),
        "{:?}",
        preview.validation_report_issues
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    let file = written(&executor, "/etc/login.defs").expect("login.defs written");
    assert!(file.contains("ENCRYPT_METHOD YESCRYPT"), "{file}");
    assert!(file.contains("PASS_MAX_DAYS 90"), "{file}");
    assert!(
        !executor
            .log()
            .files_written
            .iter()
            .any(|(p, _)| p.starts_with("/etc/pam.d")),
        "the PAM stack is never written"
    );

    // The next scan agrees with what apply did.
    let after = Arc::new(host(
        &file,
        "/etc/pam.d/common-password",
        UBUNTU_2404_COMMON_PASSWORD,
        Some(UBUNTU_2404_PROBE),
    ));
    let rescan = plugin
        .scan(&Context::with_executor(after), &config)
        .await
        .expect("scan runs");
    assert_eq!(
        hashing_ids(&rescan.scan_findings),
        vec!["pam-stored-password-hashes"],
        "only the stored hash remains, and only a password change moves it"
    );
}

#[tokio::test]
async fn rhel9_is_held_to_sha512_and_left_alone() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD SHA512\nSHA_CRYPT_MAX_ROUNDS 100000\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/system-auth",
        "password    sufficient    pam_unix.so sha512 shadow nullok use_authtok\n",
        Some(RHEL9_PROBE),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = PluginConfig::default();

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    assert!(
        hashing_ids(&scan.scan_findings).is_empty(),
        "shadow 4.9 has no yescrypt, so SHA-512 at 100000 rounds is the target and \
         is met: {:?}",
        scan.scan_findings
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    assert!(
        written(&executor, "/etc/login.defs").is_none(),
        "writing YESCRYPT there would make shadow 4.9 fall back to DES"
    );
}

#[tokio::test]
async fn a_stack_line_naming_sha512_is_reported_and_left_to_the_operator() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/system-auth",
        "password    sufficient    pam_unix.so sha512 shadow nullok use_authtok\n",
        Some(MODERN_PROBE),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = PluginConfig::default();

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-ENCRYPT_METHOD")
        .expect("the stack's sha512 is what passwd uses");
    assert_eq!(finding.finding_current_value, "SHA512");
    assert!(
        finding
            .finding_remediation_steps
            .iter()
            .any(|s| s.contains("/etc/pam.d/system-auth") && s.contains("yescrypt")),
        "{:?}",
        finding.finding_remediation_steps
    );

    let preview = plugin.validate(&ctx, &config).await.expect("validate runs");
    assert!(
        preview.has_blocking_issue(),
        "apply leaves a manual step and fails, so the dry run fails too: {:?}",
        preview.validation_report_issues
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(!result.apply_success);
    assert!(
        result.apply_changes.iter().any(|c| !c.change_success
            && c.change_error.as_deref() == Some(hardener_types::PAM_INLINE_OVERRIDE_MARKER)
            && c.change_description.contains("/etc/pam.d/system-auth")),
        "the stack edit is reported as a manual step: {:?}",
        result.apply_changes
    );
    assert!(
        executor.log().files_written.is_empty(),
        "login.defs is already right and the stack is never written: {:?}",
        executor.log().files_written
    );
}

/// shadow built with PAM sets newusers' passwords through a PAM service of
/// that name, and Arch's shadow 4.13 packaging shipped one that named sha512
/// on its own pam_unix line.
#[tokio::test]
async fn a_newusers_service_naming_sha512_is_a_manual_step() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/newusers",
        "auth\t\trequired\tpam_unix.so\npassword \trequired \tpam_unix.so sha512 shadow\n",
        Some(MODERN_PROBE),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = PluginConfig::default();

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-ENCRYPT_METHOD")
        .expect("newusers hashes with sha512 here");
    assert_eq!(finding.finding_current_value, "SHA512");
    assert!(
        finding
            .finding_remediation_steps
            .iter()
            .any(|s| s.contains("/etc/pam.d/newusers") && s.contains("change it to yescrypt")),
        "{:?}",
        finding.finding_remediation_steps
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(!result.apply_success);
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("/etc/pam.d/newusers")),
        "{:?}",
        result.apply_changes
    );
}

/// openSUSE installs `common-password` in `/usr/lib/pam.d`, which Linux-PAM
/// searches when `/etc/pam.d` has no such file. A line there is read, and the
/// manual step names the file the host actually has.
#[tokio::test]
async fn a_stack_line_in_usr_lib_pam_d_is_read_and_named_as_it_is() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(host(
        &login_defs,
        "/usr/lib/pam.d/common-password",
        "password\trequired\tpam_unix.so\tsha512 nullok\n",
        Some(MODERN_PROBE),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = PluginConfig::default();

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-ENCRYPT_METHOD")
        .expect("the vendor stack's sha512 is what passwd uses");
    assert!(
        finding
            .finding_remediation_steps
            .iter()
            .any(|s| s.contains("/usr/lib/pam.d/common-password")),
        "{:?}",
        finding.finding_remediation_steps
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(!result.apply_success);
    assert!(
        !executor
            .log()
            .files_written
            .iter()
            .any(|(p, _)| p.starts_with("/usr/lib/pam.d") || p.starts_with("/etc/pam.d")),
        "no stack file is ever written"
    );
}

#[tokio::test]
async fn a_fips_host_on_yescrypt_is_not_moved_down() {
    let probe = MODERN_PROBE.replace("fips=no", "fips=yes");
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/system-auth",
        "password sufficient pam_unix.so yescrypt shadow\n",
        Some(&probe),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let scan = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");
    assert!(
        hashing_ids(&scan.scan_findings).is_empty(),
        "{:?}",
        scan.scan_findings
    );
    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply runs");
    assert!(result.apply_success);
    assert!(written(&executor, "/etc/login.defs").is_none());
}

#[tokio::test]
async fn a_fips_host_on_md5_is_moved_to_sha512_not_yescrypt() {
    let probe = MODERN_PROBE.replace("fips=no", "fips=yes");
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD MD5\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/system-auth",
        "password sufficient pam_unix.so shadow\n",
        Some(&probe),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();

    let scan = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-ENCRYPT_METHOD")
        .expect("MD5 is reported");
    assert_eq!(finding.finding_severity, Severity::High);
    assert_eq!(finding.finding_recommended_value, "SHA512");
    assert!(
        finding
            .finding_compliance
            .iter()
            .any(|m| m.compliance_control_id == "8.3.2"),
        "MD5 is a storage weakness and fails the mapped controls: {:?}",
        finding.finding_compliance
    );

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    let file = written(&executor, "/etc/login.defs").expect("written");
    assert!(file.contains("ENCRYPT_METHOD SHA512"), "{file}");
    assert!(file.contains("SHA_CRYPT_MIN_ROUNDS 100000"), "{file}");
    assert!(file.contains("SHA_CRYPT_MAX_ROUNDS 100000"), "{file}");
}

#[tokio::test]
async fn a_raised_cost_is_refused_on_a_host_too_small_to_check_it() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(with_memory(
        host(
            &login_defs,
            "/etc/pam.d/system-auth",
            "password sufficient pam_unix.so yescrypt shadow\n",
            Some(MODERN_PROBE),
        ),
        1024 * 1024,
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = config_with("YESCRYPT_COST_FACTOR", "9");

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-YESCRYPT_COST_FACTOR")
        .expect("the cost is below what the operator asked for");
    assert_eq!(finding.finding_current_value, "5");
    assert_eq!(finding.finding_recommended_value, "9");
    assert_eq!(
        finding.finding_severity,
        Severity::Low,
        "5 is still the default"
    );

    let preview = plugin.validate(&ctx, &config).await.expect("validate runs");
    assert!(
        preview.validation_report_issues.iter().any(|i| i
            .validation_issue_message
            .contains("will not be set to 9")
            && i.validation_issue_severity == Severity::High),
        "{:?}",
        preview.validation_report_issues
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(!result.apply_success);
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| !c.change_success && c.change_description.contains("Refused to set")),
        "{:?}",
        result.apply_changes
    );
    let file = written(&executor, "/etc/login.defs").expect("the affordable cost is written");
    assert!(
        file.contains("YESCRYPT_COST_FACTOR 6") && !file.contains("YESCRYPT_COST_FACTOR 9"),
        "a cost of 9 needs 256 MiB per check and ten of them do not fit in half \
         of 1 GiB, so the plan falls back to 6, the most that host carries: {file}"
    );
}

#[tokio::test]
async fn a_raised_cost_is_written_where_the_host_can_afford_it() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(with_memory(
        host(
            &login_defs,
            "/etc/pam.d/system-auth",
            "password sufficient pam_unix.so yescrypt shadow\n",
            Some(MODERN_PROBE),
        ),
        16 * 1024 * 1024,
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let config = config_with("YESCRYPT_COST_FACTOR", "9");

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    let file = written(&executor, "/etc/login.defs").expect("written");
    assert!(file.contains("YESCRYPT_COST_FACTOR 9"), "{file}");
}

#[tokio::test]
async fn on_pam_1_5_a_raised_cost_also_needs_rounds_on_the_stack_line() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(with_memory(
        host(
            &login_defs,
            "/etc/pam.d/common-password",
            UBUNTU_2404_COMMON_PASSWORD,
            Some(UBUNTU_2404_PROBE),
        ),
        16 * 1024 * 1024,
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let config = config_with("YESCRYPT_COST_FACTOR", "7");

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("apply runs");
    let file = written(&executor, "/etc/login.defs").expect("written");
    assert!(
        file.contains("YESCRYPT_COST_FACTOR 7"),
        "shadow's own tools read it: {file}"
    );
    assert!(!result.apply_success);
    assert!(
        result
            .apply_changes
            .iter()
            .any(
                |c| c.change_error.as_deref() == Some(hardener_types::PAM_INLINE_OVERRIDE_MARKER)
                    && c.change_description.contains("rounds=7")
            ),
        "pam_unix 1.5 never reads the factor, so the line needs rounds=7: {:?}",
        result.apply_changes
    );
}

/// The memory guard is part of the plan scan, apply and validate share. On a
/// Linux-PAM older than 1.6.0, `rounds=` on the stack line is the only setting
/// that raises the cost of a user's password, so naming the refused cost
/// there would hand the operator the lockout the refusal prevents. The plan
/// falls back to the largest cost the host can carry instead, and names that
/// one everywhere, so a refused override never leaves the host weaker than no
/// override would. This host starts below the default, at rounds=3.
#[tokio::test]
async fn on_pam_1_5_an_unaffordable_cost_is_refused_once_and_never_advised_as_rounds() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\nYESCRYPT_COST_FACTOR 3\n");
    let executor = Arc::new(with_memory(
        host(
            &login_defs,
            "/etc/pam.d/common-password",
            "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt rounds=3\n",
            Some(UBUNTU_2404_PROBE),
        ),
        1024 * 1024,
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = config_with("YESCRYPT_COST_FACTOR", "9");

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-YESCRYPT_COST_FACTOR")
        .expect("the cost is below what the operator asked for");
    let steps = &finding.finding_remediation_steps;
    assert!(
        !steps
            .iter()
            .any(|s| s.contains("rounds=9") || s.contains("COST_FACTOR 9 in")),
        "the scan must not promise a write apply refuses: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.contains("apply will not raise") && s.contains("6 or less")),
        "{steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.contains("Set YESCRYPT_COST_FACTOR 6 in /etc/login.defs (apply does this)")),
        "{steps:?}"
    );
    assert!(
        steps.iter().any(|s| s.contains("set rounds=6 there")),
        "{steps:?}"
    );

    let preview = plugin.validate(&ctx, &config).await.expect("validate runs");
    let messages: Vec<&str> = preview
        .validation_report_issues
        .iter()
        .map(|i| i.validation_issue_message.as_str())
        .collect();
    assert!(
        !messages.iter().any(|m| m.contains("rounds=9")),
        "{messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("set rounds=6 there")),
        "{messages:?}"
    );
    assert_eq!(
        messages
            .iter()
            .filter(|m| m.contains("will not be set to 9"))
            .count(),
        1,
        "{messages:?}"
    );
    assert!(
        preview
            .validation_report_estimated_changes
            .contains(&"YESCRYPT_COST_FACTOR will change: 3 -> 6".to_string()),
        "{:?}",
        preview.validation_report_estimated_changes
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(!result.apply_success);
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("rounds=9")),
        "no change may advise a rounds= the host cannot afford: {:?}",
        result.apply_changes
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(
                |c| c.change_error.as_deref() == Some(hardener_types::PAM_INLINE_OVERRIDE_MARKER)
                    && c.change_description.contains("set rounds=6 there")
            ),
        "{:?}",
        result.apply_changes
    );
    assert_eq!(
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success && c.change_description.contains("Refused to set"))
            .count(),
        1,
        "{:?}",
        result.apply_changes
    );
    let file = written(&executor, "/etc/login.defs").expect("the affordable cost is written");
    assert!(file.contains("YESCRYPT_COST_FACTOR 6"), "{file}");
    assert!(!file.contains("YESCRYPT_COST_FACTOR 9"), "{file}");
}

/// The issue's 1 GiB, set by hand on a small VM: the cost check is
/// tighten-only and passes it, so the memory advisory is what reports it.
#[tokio::test]
async fn a_hand_set_cost_of_11_on_a_2_gib_host_is_reported_and_left_alone() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\nYESCRYPT_COST_FACTOR 11\n");
    let executor = Arc::new(with_memory(
        host(
            &login_defs,
            "/etc/pam.d/system-auth",
            "password sufficient pam_unix.so yescrypt shadow\n",
            Some(MODERN_PROBE),
        ),
        2 * 1024 * 1024,
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let config = PluginConfig::default();

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    assert_eq!(
        hashing_ids(&scan.scan_findings),
        vec!["pam-yescrypt-cost-memory"],
        "{:?}",
        scan.scan_findings
    );
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-yescrypt-cost-memory")
        .expect("reported");
    assert_eq!(finding.finding_current_value, "11");
    assert_eq!(finding.finding_recommended_value, "7 or less");

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    assert!(
        written(&executor, "/etc/login.defs").is_none(),
        "apply never lowers a cost"
    );
}

#[tokio::test]
async fn an_exception_for_sha512_is_honoured_by_scan_apply_and_dry_run() {
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD SHA512\nSHA_CRYPT_MAX_ROUNDS 100000\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/common-password",
        "password required pam_unix.so sha512 shadow\n",
        Some(MODERN_PROBE),
    ));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = PamHardeningPlugin::new();
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "ENCRYPT_METHOD".to_string(),
        PolicyException {
            value: "SHA512".to_string(),
            allowed: true,
            reason: "shared with a RHEL 8 host that cannot verify yescrypt".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let scan = plugin.scan(&ctx, &config).await.expect("scan runs");
    let finding = scan
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "pam-ENCRYPT_METHOD")
        .expect("still listed, as a documented deviation");
    assert!(matches!(
        finding.finding_exception,
        ExceptionOutcome::Applied(_)
    ));
    assert!(
        !scan
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "pam-YESCRYPT_COST_FACTOR"),
        "the cost judged is SHA-512's, the algorithm the exception keeps"
    );

    let preview = plugin.validate(&ctx, &config).await.expect("validate runs");
    assert!(
        preview
            .validation_report_exceptions
            .iter()
            .any(|line| line.contains("ENCRYPT_METHOD")),
        "{:?}",
        preview.validation_report_exceptions
    );
    assert!(
        !preview.has_blocking_issue(),
        "{:?}",
        preview.validation_report_issues
    );

    let result = plugin.apply(&mut ctx, &config).await.expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    assert!(written(&executor, "/etc/login.defs").is_none());
}

#[tokio::test]
async fn opensuse_vendor_login_defs_is_carried_over_and_moved_to_yescrypt() {
    let vendor = "UMASK 022\nHOME_MODE 0700\nENCRYPT_METHOD SHA512\nPASS_MAX_DAYS 99999\n\
                  PASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n";
    let executor = Arc::new(
        host(
            "",
            "/etc/pam.d/common-password",
            "password\trequired\tpam_unix.so\tnullok\n",
            Some(MODERN_PROBE),
        )
        .without_file("/etc/login.defs")
        .with_file("/usr/etc/login.defs", vendor),
    );
    let mut ctx = Context::with_executor(executor.clone());

    let result = PamHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply runs");
    assert!(result.apply_success, "{:?}", result.apply_changes);
    let file = written(&executor, "/etc/login.defs").expect("the /etc copy is created");
    for kept in ["UMASK 022", "HOME_MODE 0700", "PASS_MAX_DAYS 90"] {
        assert!(file.contains(kept), "{kept} missing from {file}");
    }
    assert!(file.contains("ENCRYPT_METHOD YESCRYPT"), "{file}");
    assert!(
        written(&executor, "/usr/etc/login.defs").is_none(),
        "the vendor file is never written"
    );
}

#[tokio::test]
async fn a_probe_that_cannot_run_holds_the_host_to_sha512_and_counts_nothing() {
    let login_defs = format!(
        "{SECURE_AGEING}ENCRYPT_METHOD SHA512\nSHA_CRYPT_MIN_ROUNDS 100000\nSHA_CRYPT_MAX_ROUNDS 100000\n"
    );
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/common-password",
        "password required pam_unix.so sha512 shadow\n",
        None,
    ));
    let ctx = Context::with_executor(executor);

    let scan = PamHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan runs");
    assert!(
        hashing_ids(&scan.scan_findings).is_empty(),
        "{:?}",
        scan.scan_findings
    );
    let unchecked = scan
        .scan_unchecked
        .iter()
        .find(|u| u.unchecked_check_id == "pam-stored-password-hashes")
        .expect("stored hashes are reported unchecked, not as clean");
    assert_eq!(unchecked.unchecked_blocker, UncheckedBlocker::Environment);
    assert!(unchecked.unchecked_compliance.is_empty());
}

#[tokio::test]
async fn an_unprivileged_scan_reports_the_stored_hashes_unchecked() {
    let probe = MODERN_PROBE.replace("shadow=read", "shadow=denied");
    let login_defs = format!("{SECURE_AGEING}ENCRYPT_METHOD YESCRYPT\n");
    let executor = Arc::new(host(
        &login_defs,
        "/etc/pam.d/system-auth",
        "password sufficient pam_unix.so yescrypt shadow\n",
        Some(&probe),
    ));

    let scan = PamHardeningPlugin::new()
        .scan(&Context::with_executor(executor), &PluginConfig::default())
        .await
        .expect("scan runs");
    let unchecked = scan
        .scan_unchecked
        .iter()
        .find(|u| u.unchecked_check_id == "pam-stored-password-hashes")
        .expect("reported unchecked");
    assert_eq!(unchecked.unchecked_blocker, UncheckedBlocker::Privilege);
}

#[tokio::test]
async fn an_unreadable_login_defs_leaves_every_hashing_check_unchecked() {
    let executor = Arc::new(
        host(
            SECURE_AGEING,
            "/etc/pam.d/system-auth",
            "password sufficient pam_unix.so yescrypt shadow\n",
            Some(MODERN_PROBE),
        )
        .with_read_permission_denied("/etc/login.defs"),
    );

    let scan = PamHardeningPlugin::new()
        .scan(&Context::with_executor(executor), &PluginConfig::default())
        .await
        .expect("scan runs");
    assert!(
        hashing_ids(&scan.scan_findings).is_empty(),
        "{:?}",
        scan.scan_findings
    );
    for id in [
        "pam-ENCRYPT_METHOD",
        "pam-YESCRYPT_COST_FACTOR",
        "pam-SHA_CRYPT_MIN_ROUNDS",
    ] {
        let entry = scan
            .scan_unchecked
            .iter()
            .find(|u| u.unchecked_check_id == id)
            .unwrap_or_else(|| panic!("{id} must be unchecked: {:?}", scan.scan_unchecked));
        assert_eq!(entry.unchecked_blocker, UncheckedBlocker::Privilege);
        assert!(!entry.unchecked_compliance.is_empty());
    }
}
