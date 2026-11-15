#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading.

//! Unit tests for [`hashing`](super).
//!
//! Every fixture below is shaped on a file a distribution ships, read from its
//! package on 2026-11-15: Ubuntu 24.04 (this machine), Ubuntu 26.04
//! (`login.defs` 1:4.17.4-2ubuntu3, `libpam-runtime` 1.7.0-5ubuntu3.2),
//! CentOS Stream 9 and 10 (`shadow-utils.login.defs`, `authselect`), and
//! openSUSE Factory (`shadow-login_defs-suse.patch`, `common-password.pamd`).

use super::*;
use hardener_core::PolicyException;

const UBUNTU_2404_LOGIN_DEFS: &str =
    "PASS_MAX_DAYS 99999\nENCRYPT_METHOD SHA512\n#YESCRYPT_COST_FACTOR 5\n";
const UBUNTU_2404_COMMON_PASSWORD: &str = "\
# here are the per-package modules (the \"Primary\" block)
password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt
# here's the fallback if no module succeeds
password\trequisite\t\t\tpam_deny.so
password\trequired\t\t\tpam_permit.so
";
const RHEL9_LOGIN_DEFS: &str = "ENCRYPT_METHOD SHA512\nSHA_CRYPT_MAX_ROUNDS 100000\n";
const RHEL9_SYSTEM_AUTH: &str = "\
auth        sufficient    pam_unix.so yescrypt nullok
password    requisite     pam_pwquality.so local_users_only
password    sufficient    pam_unix.so sha512 shadow nullok use_authtok
password    required      pam_deny.so
";
const RHEL10_LOGIN_DEFS: &str = "ENCRYPT_METHOD YESCRYPT\n#YESCRYPT_COST_FACTOR 5\n";
const RHEL10_SYSTEM_AUTH: &str =
    "password    sufficient    pam_unix.so yescrypt shadow nullok use_authtok\n";
const OPENSUSE_LOGIN_DEFS: &str = "UMASK 022\nENCRYPT_METHOD SHA512\n";
const OPENSUSE_COMMON_PASSWORD: &str = "password\trequired\tpam_unix.so\tnullok\n";

/// A probe from a host that can do everything: yescrypt in all three, a
/// Linux-PAM that reads the cost factor, no FIPS, and no stored hashes.
fn capable() -> HostProbe {
    HostProbe {
        pam_unix_yescrypt: Tri::Yes,
        libcrypt_yescrypt: Tri::Yes,
        shadow_yescrypt: Tri::Yes,
        pam_reads_cost_factor: Tri::Yes,
        fips: Tri::No,
        stored: StoredHashes::Schemes(vec![]),
    }
}

/// Ubuntu 24.04: everything but the cost factor, which PAM 1.5.3 ignores.
fn ubuntu_2404() -> HostProbe {
    HostProbe {
        pam_reads_cost_factor: Tri::No,
        ..capable()
    }
}

/// RHEL 9: pam_unix and libcrypt have yescrypt, shadow 4.9 was built without.
fn rhel9() -> HostProbe {
    HostProbe {
        shadow_yescrypt: Tri::No,
        pam_reads_cost_factor: Tri::No,
        ..capable()
    }
}

fn lines(file: &'static str, content: &str) -> Vec<PamUnixLine> {
    pam_unix_password_lines(file, content)
}

fn config_with(directives: &[(&str, &str)]) -> PluginConfig {
    let mut config = PluginConfig::default();
    for (key, value) in directives {
        config
            .directives
            .insert((*key).to_string(), (*value).to_string());
    }
    config
}

fn exception(value: &str) -> PolicyException {
    PolicyException {
        value: value.to_string(),
        allowed: true,
        reason: "accepted by the security team".to_string(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: None,
    }
}

// --- the stack parser -------------------------------------------------------

#[test]
fn a_bracketed_control_field_with_spaces_does_not_hide_the_module() {
    let found = lines("/etc/pam.d/common-password", UBUNTU_2404_COMMON_PASSWORD);
    assert_eq!(
        found,
        vec![PamUnixLine {
            file: "/etc/pam.d/common-password",
            method: Some(HashMethod::Yescrypt),
            rounds: None,
        }]
    );
}

#[test]
fn only_password_lines_count_and_auth_lines_are_ignored() {
    let found = lines("/etc/pam.d/system-auth", RHEL9_SYSTEM_AUTH);
    assert_eq!(found.len(), 1, "the auth line hashes nothing: {found:?}");
    assert_eq!(found[0].method, Some(HashMethod::Sha512));
}

#[test]
fn a_comment_ends_the_line_wherever_it_starts() {
    let found = lines(
        "/etc/pam.d/passwd",
        "password required pam_unix.so shadow # sha512 was here\n",
    );
    assert_eq!(
        found[0].method, None,
        "a commented argument is not an argument"
    );
    assert!(lines("/etc/pam.d/passwd", "# password required pam_unix.so md5\n").is_empty());
}

#[test]
fn a_continued_line_is_one_line_and_the_last_algorithm_wins() {
    let found = lines(
        "/etc/pam.d/passwd",
        "-Password required /usr/lib64/security/pam_unix.so md5 \\\n    yescrypt rounds=4 rounds=7\n",
    );
    assert_eq!(
        found,
        vec![PamUnixLine {
            file: "/etc/pam.d/passwd",
            method: Some(HashMethod::Yescrypt),
            rounds: Some("7".to_string()),
        }]
    );
}

#[test]
fn another_module_naming_an_algorithm_is_not_pam_unix() {
    assert!(
        lines(
            "/etc/pam.d/passwd",
            "password required pam_unix2.so sha512\n"
        )
        .is_empty()
    );
    assert!(lines("/etc/pam.d/passwd", "password include system-auth\n").is_empty());
}

// --- how each reader takes ENCRYPT_METHOD -----------------------------------

#[test]
fn shadow_takes_the_spelling_exactly_and_pam_unix_takes_it_loosely() {
    assert_eq!(
        HashMethod::from_login_defs("YESCRYPT"),
        Some(HashMethod::Yescrypt)
    );
    assert_eq!(HashMethod::from_login_defs("yescrypt"), None);
    assert_eq!(
        pam_login_defs_method("yescrypt"),
        Some(HashMethod::Yescrypt)
    );
    assert_eq!(pam_login_defs_method("SHA512"), Some(HashMethod::Sha512));
    assert_eq!(
        pam_login_defs_method("DES"),
        None,
        "pam_unix has no DES token"
    );
    assert_eq!(
        pam_login_defs_method("BCRYPT"),
        None,
        "pam_unix calls it blowfish"
    );
}

#[test]
fn the_ranking_runs_weakest_first() {
    assert!(HashMethod::Des < HashMethod::Md5);
    assert!(HashMethod::Bcrypt < HashMethod::Sha512);
    assert!(HashMethod::Sha512 < HashMethod::Yescrypt);
}

// --- the probe ---------------------------------------------------------------

#[test]
fn a_complete_probe_is_read_line_by_line() {
    let probe = parse_host_probe(
        "pam_unix_yescrypt=yes\npam_unix_cost_factor=no\nlibcrypt_yescrypt=yes\n\
         shadow_yescrypt=yes\nfips=no\nshadow=read\nscheme=yescrypt\nscheme=sha512\nend=1\n",
    );
    assert_eq!(probe.yescrypt(), Tri::Yes);
    assert_eq!(probe.pam_reads_cost_factor, Tri::No);
    assert_eq!(probe.fips, Tri::No);
    assert_eq!(
        probe.stored,
        StoredHashes::Schemes(vec!["yescrypt".to_string(), "sha512".to_string()])
    );
}

#[test]
fn a_probe_that_did_not_finish_counts_nothing() {
    let probe = parse_host_probe("pam_unix_yescrypt=yes\nshadow=read\nscheme=md5\n");
    assert!(matches!(probe.stored, StoredHashes::Unknown(_)));
    assert_eq!(probe.yescrypt(), Tri::Unknown);
}

#[test]
fn one_component_without_yescrypt_is_enough_to_say_no() {
    assert_eq!(rhel9().yescrypt(), Tri::No);
    let partial = HostProbe {
        libcrypt_yescrypt: Tri::Unknown,
        ..capable()
    };
    assert_eq!(partial.yescrypt(), Tri::Unknown);
}

#[test]
fn the_real_probe_script_reports_schemes_and_never_a_hash() {
    let dir = std::env::temp_dir().join(format!("hardener-191-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let shadow = dir.join("shadow");
    std::fs::write(
        &shadow,
        "root:$y$j9T$SALTSALTSALTSALT$HASHHASHHASHHASH:20000:0:99999:7:::\n\
         alice:$6$rounds=5000$SALTSALT$HASHHASH:20000:0:99999:7:::\n\
         bob:$1$SALTSALT$HASHHASH:20000:0:99999:7:::\n\
         carol:abCDefGHijKLm:20000:0:99999:7:::\n\
         locked:!$6$SALTSALT$HASHHASH:20000:0:99999:7:::\n\
         daemon:*:20000:0:99999:7:::\n\
         empty::20000:0:99999:7:::\n\
         last:$2b$12$SALTSALTSALTSALTSALTSOHASHHASHHASHHASHHASHHASHHAS:20000:0:99999:7:::",
    )
    .expect("fixture");
    let output = std::process::Command::new("sh")
        .args(["-c", HOST_PROBE_SCRIPT, "sh"])
        .arg(&shadow)
        .output()
        .expect("sh runs");
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);

    for leak in ["SALT", "HASH", "abCD", "root", "alice", "$", ":"] {
        assert!(
            !stdout.contains(leak),
            "the probe printed {leak:?}, which only a hash or a user name holds: {stdout}"
        );
    }
    let probe = parse_host_probe(&stdout);
    assert_eq!(
        probe.stored,
        StoredHashes::Schemes(
            ["yescrypt", "sha512", "md5", "des", "bcrypt"]
                .map(str::to_string)
                .to_vec()
        ),
        "locked, disabled and empty fields are not hashes, and a last line with no \
         newline still counts: {stdout}"
    );
}

#[test]
fn the_real_probe_script_says_absent_for_a_missing_shadow() {
    let output = std::process::Command::new("sh")
        .args([
            "-c",
            HOST_PROBE_SCRIPT,
            "sh",
            "/nonexistent/hardener-191/shadow",
        ])
        .output()
        .expect("sh runs");
    let probe = parse_host_probe(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(probe.stored, StoredHashes::Absent);
}

// --- the target ---------------------------------------------------------------

#[test]
fn a_capable_host_outside_fips_is_held_to_yescrypt() {
    let (target, why) = method_target(&PluginConfig::default(), &capable());
    assert_eq!(target, HashMethod::Yescrypt);
    assert!(why.is_empty());
}

#[test]
fn fips_mode_holds_the_host_to_sha512_unless_the_operator_chooses_yescrypt() {
    let fips = HostProbe {
        fips: Tri::Yes,
        ..capable()
    };
    assert_eq!(
        method_target(&PluginConfig::default(), &fips).0,
        HashMethod::Sha512
    );
    let chosen = config_with(&[("ENCRYPT_METHOD", "yescrypt")]);
    assert_eq!(method_target(&chosen, &fips).0, HashMethod::Yescrypt);
}

#[test]
fn no_override_can_raise_a_host_that_lacks_yescrypt_to_it() {
    let chosen = config_with(&[("ENCRYPT_METHOD", "YESCRYPT")]);
    assert_eq!(method_target(&chosen, &rhel9()).0, HashMethod::Sha512);
    assert_eq!(
        method_target(&chosen, &HostProbe::unknown(String::new())).0,
        HashMethod::Sha512
    );
}

#[test]
fn an_override_cannot_loosen_the_algorithm() {
    let looser = config_with(&[("ENCRYPT_METHOD", "MD5")]);
    assert_eq!(method_target(&looser, &capable()).0, HashMethod::Yescrypt);
}

// --- the algorithm reading ----------------------------------------------------

#[test]
fn ubuntu_2404_hashes_user_passwords_with_yescrypt_and_group_passwords_with_sha512() {
    let stack = lines("/etc/pam.d/common-password", UBUNTU_2404_COMMON_PASSWORD);
    let reading = read_method(UBUNTU_2404_LOGIN_DEFS, &stack, &ubuntu_2404());
    assert_eq!(reading.weakest, Some(HashMethod::Sha512));
    assert_eq!(reading.display, "SHA512");
}

#[test]
fn rhel10_is_yescrypt_on_every_path() {
    let stack = lines("/etc/pam.d/system-auth", RHEL10_SYSTEM_AUTH);
    let reading = read_method(RHEL10_LOGIN_DEFS, &stack, &capable());
    assert_eq!(reading.weakest, Some(HashMethod::Yescrypt));
    assert!(reading.notes.is_empty(), "{:?}", reading.notes);
}

#[test]
fn a_lowercase_value_is_not_one_shadow_accepts() {
    let reading = read_method("ENCRYPT_METHOD yescrypt\n", &[], &capable());
    assert_eq!(reading.weakest, None);
    assert_eq!(reading.display, "yescrypt");
}

#[test]
fn yescrypt_where_shadow_lacks_it_is_no_algorithm_at_all() {
    let reading = read_method("ENCRYPT_METHOD YESCRYPT\n", &[], &rhel9());
    assert_eq!(reading.weakest, None, "shadow 4.9 falls back to DES here");
}

#[test]
fn a_line_with_no_algorithm_and_no_login_defs_value_is_unknown() {
    let stack = lines("/etc/pam.d/common-password", OPENSUSE_COMMON_PASSWORD);
    let reading = read_method("", &stack, &capable());
    assert_eq!(reading.weakest, None);
    assert_eq!(reading.display, "not set");
}

// --- the cost readings --------------------------------------------------------

#[test]
fn pam_1_5_resets_an_out_of_range_rounds_to_5_and_pam_1_6_clamps_it() {
    let stack = lines(
        "/etc/pam.d/common-password",
        "password required pam_unix.so yescrypt rounds=1\n",
    );
    let new = read_yescrypt_cost("", &stack, &capable(), 5);
    let old = read_yescrypt_cost("", &stack, &ubuntu_2404(), 5);
    assert_eq!(new.lowest, Some(3));
    assert_eq!(old.lowest, Some(5));
    let unknown = HostProbe {
        pam_reads_cost_factor: Tri::Unknown,
        ..capable()
    };
    assert_eq!(
        read_yescrypt_cost("", &stack, &unknown, 5).lowest,
        Some(3),
        "where the release is unknown the lower answer is reported"
    );
}

#[test]
fn pam_1_5_never_reads_the_cost_factor_so_only_rounds_reaches_it() {
    let stack = lines("/etc/pam.d/common-password", UBUNTU_2404_COMMON_PASSWORD);
    let login_defs = "ENCRYPT_METHOD YESCRYPT\nYESCRYPT_COST_FACTOR 8\n";
    let old = read_yescrypt_cost(login_defs, &stack, &ubuntu_2404(), 8);
    assert_eq!(old.lowest, Some(5));
    assert_eq!(old.stack_shortfalls.len(), 1, "{:?}", old.stack_shortfalls);
    let new = read_yescrypt_cost(login_defs, &stack, &capable(), 8);
    assert_eq!(new.lowest, Some(8));
    assert!(new.stack_shortfalls.is_empty());
}

#[test]
fn rhel9_sha512_rounds_come_from_the_maximum() {
    let stack = lines("/etc/pam.d/system-auth", RHEL9_SYSTEM_AUTH);
    let reading = read_sha_rounds(RHEL9_LOGIN_DEFS, &stack, &rhel9(), 100_000);
    assert_eq!(reading.lowest, Some(100_000));
}

#[test]
fn sha_rounds_below_1000_on_the_line_fall_back_to_5000() {
    let stack = lines(
        "/etc/pam.d/system-auth",
        "password sufficient pam_unix.so sha512 rounds=500\n",
    );
    let reading = read_sha_rounds(RHEL9_LOGIN_DEFS, &stack, &rhel9(), 100_000);
    assert_eq!(reading.lowest, Some(5000));
    assert_eq!(reading.stack_shortfalls.len(), 1);
}

#[test]
fn shadow_takes_the_minimum_when_both_bounds_are_set() {
    let reading = read_sha_rounds(
        "SHA_CRYPT_MIN_ROUNDS 5000\nSHA_CRYPT_MAX_ROUNDS 100000\n",
        &[],
        &capable(),
        100_000,
    );
    assert_eq!(reading.lowest, Some(5000));
}

// --- the plan -----------------------------------------------------------------

fn hashing(login_defs: &str, stack: Vec<PamUnixLine>, probe: HostProbe) -> Hashing {
    Hashing::new(
        &PluginConfig::default(),
        login_defs.to_string(),
        stack,
        probe,
    )
}

#[test]
fn ubuntu_2404_gets_yescrypt_written_and_nothing_else() {
    let h = hashing(
        UBUNTU_2404_LOGIN_DEFS,
        lines("/etc/pam.d/common-password", UBUNTU_2404_COMMON_PASSWORD),
        ubuntu_2404(),
    );
    let config = PluginConfig::default();
    assert_eq!(
        h.plan_writes(&config),
        vec![("ENCRYPT_METHOD", "YESCRYPT".to_string())]
    );
    assert!(
        h.manual_steps(&config, &h.projected(&h.plan_writes(&config)))
            .is_empty()
    );
}

#[test]
fn rhel9_already_meets_its_sha512_target_and_nothing_is_written() {
    let h = hashing(
        RHEL9_LOGIN_DEFS,
        lines("/etc/pam.d/system-auth", RHEL9_SYSTEM_AUTH),
        rhel9(),
    );
    assert_eq!(h.target, HashMethod::Sha512);
    assert!(!h.method_violated());
    assert!(h.plan_writes(&PluginConfig::default()).is_empty());
}

#[test]
fn opensuse_moves_to_yescrypt_where_it_can() {
    let h = hashing(
        OPENSUSE_LOGIN_DEFS,
        lines("/etc/pam.d/common-password", OPENSUSE_COMMON_PASSWORD),
        capable(),
    );
    let config = PluginConfig::default();
    let writes = h.plan_writes(&config);
    assert_eq!(writes, vec![("ENCRYPT_METHOD", "YESCRYPT".to_string())]);
    let projected = h.projected(&writes);
    assert!(projected.contains("UMASK 022"), "{projected}");
    assert!(h.manual_steps(&config, &projected).is_empty());
}

#[test]
fn opensuse_that_cannot_confirm_yescrypt_gets_sha512_rounds_instead() {
    let h = hashing(
        OPENSUSE_LOGIN_DEFS,
        lines("/etc/pam.d/common-password", OPENSUSE_COMMON_PASSWORD),
        HostProbe::unknown(String::new()),
    );
    let config = PluginConfig::default();
    assert_eq!(
        h.plan_writes(&config),
        vec![
            ("SHA_CRYPT_MIN_ROUNDS", "100000".to_string()),
            ("SHA_CRYPT_MAX_ROUNDS", "100000".to_string()),
        ]
    );
}

#[test]
fn only_the_maximum_is_written_where_the_minimum_already_suffices() {
    let h = hashing(
        "ENCRYPT_METHOD SHA512\nSHA_CRYPT_MIN_ROUNDS 200000\n",
        lines("/etc/pam.d/system-auth", RHEL9_SYSTEM_AUTH),
        rhel9(),
    );
    assert_eq!(
        h.plan_writes(&PluginConfig::default()),
        vec![("SHA_CRYPT_MAX_ROUNDS", "100000".to_string())],
        "pam_unix reads only the maximum"
    );
}

#[test]
fn a_fips_host_on_yescrypt_is_never_moved_down_to_sha512() {
    let fips = HostProbe {
        fips: Tri::Yes,
        ..capable()
    };
    let h = hashing(
        RHEL10_LOGIN_DEFS,
        lines("/etc/pam.d/system-auth", RHEL10_SYSTEM_AUTH),
        fips,
    );
    assert_eq!(h.target, HashMethod::Sha512);
    assert!(!h.method_violated());
    assert!(h.plan_writes(&PluginConfig::default()).is_empty());
    assert_eq!(h.cost_method, HashMethod::Yescrypt);
}

#[test]
fn a_lowercase_yescrypt_is_respelled_not_replaced() {
    let h = hashing(
        "ENCRYPT_METHOD yescrypt\n",
        vec![],
        HostProbe::unknown(String::new()),
    );
    assert_eq!(
        h.plan_writes(&PluginConfig::default()),
        vec![("ENCRYPT_METHOD", "YESCRYPT".to_string())]
    );
    let h = hashing("ENCRYPT_METHOD yescrypt\n", vec![], rhel9());
    assert_eq!(
        h.plan_writes(&PluginConfig::default())[0],
        ("ENCRYPT_METHOD", "SHA512".to_string()),
        "a shadow without yescrypt was already failing on it"
    );
}

#[test]
fn a_stack_line_naming_sha512_is_left_as_a_manual_step() {
    let h = hashing(
        RHEL10_LOGIN_DEFS,
        lines(
            "/etc/pam.d/system-auth",
            "password sufficient pam_unix.so sha512 shadow\n",
        ),
        capable(),
    );
    let config = PluginConfig::default();
    assert!(h.method_violated());
    assert!(
        h.plan_writes(&config).is_empty(),
        "login.defs is already right"
    );
    let steps = h.manual_steps(&config, &h.login_defs);
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].0, "ENCRYPT_METHOD");
    assert!(
        steps[0].1.contains("change it to yescrypt"),
        "{}",
        steps[0].1
    );
}

#[test]
fn a_raised_cost_on_pam_1_5_needs_rounds_on_the_line() {
    let config = config_with(&[("YESCRYPT_COST_FACTOR", "7")]);
    let h = Hashing::new(
        &config,
        RHEL10_LOGIN_DEFS.to_string(),
        lines("/etc/pam.d/common-password", UBUNTU_2404_COMMON_PASSWORD),
        ubuntu_2404(),
    );
    let writes = h.plan_writes(&config);
    assert!(writes.contains(&("YESCRYPT_COST_FACTOR", "7".to_string())));
    let steps = h.manual_steps(&config, &h.projected(&writes));
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert!(steps[0].1.contains("rounds=7"), "{}", steps[0].1);
}

#[test]
fn the_same_raised_cost_needs_nothing_on_the_stack_where_pam_reads_the_factor() {
    let config = config_with(&[("YESCRYPT_COST_FACTOR", "7")]);
    let h = Hashing::new(
        &config,
        RHEL10_LOGIN_DEFS.to_string(),
        lines("/etc/pam.d/system-auth", RHEL10_SYSTEM_AUTH),
        capable(),
    );
    let writes = h.plan_writes(&config);
    assert_eq!(writes, vec![("YESCRYPT_COST_FACTOR", "7".to_string())]);
    assert!(h.manual_steps(&config, &h.projected(&writes)).is_empty());
}

#[test]
fn a_cost_override_above_11_is_capped_where_every_tool_stops() {
    let config = config_with(&[("YESCRYPT_COST_FACTOR", "15")]);
    assert_eq!(
        cost_target(&config, YESCRYPT_COST_FACTOR, YESCRYPT_COST_MAX),
        11
    );
    let lower = config_with(&[("YESCRYPT_COST_FACTOR", "3")]);
    assert_eq!(
        cost_target(&lower, YESCRYPT_COST_FACTOR, YESCRYPT_COST_MAX),
        5,
        "an override only tightens"
    );
}

#[test]
fn an_exception_for_the_algorithm_stops_the_write_and_moves_the_cost_check() {
    let mut config = PluginConfig::default();
    config
        .exceptions
        .insert("ENCRYPT_METHOD".to_string(), exception("SHA512"));
    let h = Hashing::new(
        &config,
        OPENSUSE_LOGIN_DEFS.to_string(),
        lines("/etc/pam.d/common-password", OPENSUSE_COMMON_PASSWORD),
        capable(),
    );
    assert!(h.method_excepted);
    assert_eq!(h.cost_method, HashMethod::Sha512);
    let writes = h.plan_writes(&config);
    assert!(
        !writes.iter().any(|(key, _)| *key == "ENCRYPT_METHOD"),
        "{writes:?}"
    );
}

// --- the findings ---------------------------------------------------------------

#[test]
fn the_scan_names_the_algorithm_and_the_stored_hashes_but_no_hash() {
    let probe = HostProbe {
        stored: StoredHashes::Schemes(vec![
            "yescrypt".to_string(),
            "sha512".to_string(),
            "sha512".to_string(),
            "md5".to_string(),
        ]),
        ..ubuntu_2404()
    };
    let h = hashing(
        UBUNTU_2404_LOGIN_DEFS,
        lines("/etc/pam.d/common-password", UBUNTU_2404_COMMON_PASSWORD),
        probe,
    );
    let scan = scan_findings(&PluginConfig::default(), &h);
    let ids: Vec<&str> = scan
        .findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    assert_eq!(ids, vec!["pam-ENCRYPT_METHOD", STORED_HASHES_ID]);

    let method = &scan.findings[0];
    assert_eq!(method.finding_current_value, "SHA512");
    assert_eq!(method.finding_recommended_value, "YESCRYPT");
    assert_eq!(method.finding_severity, Severity::Low);
    assert_eq!(
        method.finding_exception_key.as_deref(),
        Some("ENCRYPT_METHOD")
    );
    assert!(
        method
            .finding_compliance
            .iter()
            .any(|m| m.compliance_control_id == "IA-5(1)(c)"),
        "{:?}",
        method.finding_compliance
    );

    let stored = &scan.findings[1];
    assert_eq!(stored.finding_current_value, "1 md5, 2 sha512");
    assert_eq!(
        stored.finding_severity,
        Severity::High,
        "MD5 is the worst present"
    );
    assert!(stored.finding_compliance.is_empty());
    assert_eq!(stored.finding_exception_key, None);
}

#[test]
fn a_compliant_host_has_no_hashing_finding() {
    let h = hashing(
        RHEL10_LOGIN_DEFS,
        lines("/etc/pam.d/system-auth", RHEL10_SYSTEM_AUTH),
        capable(),
    );
    let scan = scan_findings(&PluginConfig::default(), &h);
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(scan.unchecked.is_empty());
}

#[test]
fn stored_hashes_at_the_reference_are_not_weaker() {
    let stored = StoredHashes::Schemes(vec!["sha512".to_string(), "yescrypt".to_string()]);
    assert!(matches!(
        stored_hashes_finding(&stored, HashMethod::Sha512),
        StoredOutcome::Nothing
    ));
}

#[test]
fn an_unreadable_shadow_is_unchecked_and_says_root_would_help() {
    match stored_hashes_finding(&StoredHashes::Denied, HashMethod::Yescrypt) {
        StoredOutcome::Unchecked(check) => {
            assert_eq!(check.unchecked_check_id, STORED_HASHES_ID);
            assert_eq!(check.unchecked_blocker, UncheckedBlocker::Privilege);
            assert!(check.unchecked_compliance.is_empty());
        }
        _ => panic!("a denied read must be reported unchecked"),
    }
    assert!(matches!(
        stored_hashes_finding(&StoredHashes::Absent, HashMethod::Yescrypt),
        StoredOutcome::Nothing
    ));
}

// --- the memory guard -----------------------------------------------------------

#[test]
fn ten_checks_must_fit_in_half_the_memory() {
    let gib = 1024 * 1024;
    assert_eq!(max_affordable_cost(gib / 4), 4);
    assert_eq!(max_affordable_cost(gib / 2), 5);
    assert_eq!(max_affordable_cost(gib), 6);
    assert_eq!(max_affordable_cost(4 * gib), 8);
    assert_eq!(max_affordable_cost(16 * gib), 10);
    assert_eq!(
        max_affordable_cost(20 * gib),
        11,
        "1 GiB per check needs 20 GiB"
    );
    assert_eq!(
        max_affordable_cost(512 * gib),
        11,
        "never above what the tools accept"
    );
}

#[test]
fn mem_total_is_read_in_kib() {
    assert_eq!(
        parse_mem_total_kib("MemTotal:       16384000 kB\nMemFree: 1 kB\n"),
        Some(16_384_000)
    );
    assert_eq!(parse_mem_total_kib("MemFree: 1 kB\n"), None);
}

// --- the table ------------------------------------------------------------------

#[test]
fn every_hashing_directive_has_its_own_mappings_not_the_catch_all() {
    assert_eq!(
        HASHING_DIRECTIVES.len(),
        3,
        "the loop below must have something to check"
    );
    for d in HASHING_DIRECTIVES {
        let mappings = super::super::get_pam_compliance_mappings(d.pam_directive_name);
        assert!(
            !mappings.iter().any(|m| m.compliance_control_id == "5.3.1"),
            "{} fell through to the catch-all: {mappings:?}",
            d.pam_directive_name
        );
        assert!(
            !mappings.iter().any(
                |m| m.compliance_framework == hardener_common::types::ComplianceFramework::STIG
            ),
            "{} must not claim a STIG rule that demands SHA-512",
            d.pam_directive_name
        );
    }
}

#[test]
fn coverage_carries_the_hashing_controls() {
    assert!(
        super::super::coverage()
            .iter()
            .any(|m| m.compliance_control_id == "8.3.2")
    );
}
