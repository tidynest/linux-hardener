#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`config_validation`](super).
//!
//! Split out of `config_validation.rs`. This file sits in the
//! `config_validation/` directory beside it, which the 2018 path rules allow
//! with no `mod.rs` and no `#[path]`, so `super` still resolves to
//! `crate::config_validation` and every import carried across unchanged,
//! private items included.

use super::*;

/// Every section, not the five `validate_config` happened to name. The
/// audit, mac and services sections were exempt by omission: the only loop
/// that mentioned them read the `custom_directives` table, never their
/// `directives` map, so removing that dead table made the omission plain.
///
/// The five listed sections are the positive control here. They passed
/// this before the fix and still do, which is what says the test is
/// exercising validation rather than passing by matching nothing.
#[test]
fn every_plugin_section_rejects_a_shell_metacharacter() {
    for section in [
        "kernel",
        "ssh",
        "firewall",
        "pam",
        "permissions",
        "audit",
        "mac",
        "services",
    ] {
        let config: HardenerConfig =
            toml::from_str(&format!("[{section}.directives]\nSomeKey = \"a;b\"\n"))
                .expect("the section parses");

        let error = validate_config(&config).expect_err(&format!(
            "[{section}.directives] accepts a shell metacharacter, so nothing checks it"
        ));

        assert!(
            error.to_string().contains(section),
            "the error must name the section it came from: {error}"
        );
    }
}

#[test]
fn test_universal_rejects_shell_metacharacters() {
    assert!(check_universal("safe_value").is_ok());
    assert!(check_universal("1024").is_ok());
    assert!(check_universal("has;semicolon").is_err());
    assert!(check_universal("$(command)").is_err());
    assert!(check_universal("line\nbreak").is_err());
    assert!(check_universal("back`tick").is_err());
    assert!(check_universal("pipe|chain").is_err());
}

#[test]
fn test_kernel_value_validation() {
    assert!(validate_kernel_value("net.ipv4.tcp_syncookies", "1").is_ok());
    assert!(validate_kernel_value("vm.swappiness", "60").is_ok());
    assert!(validate_kernel_value("net.ipv4.tcp_rmem", "4096 87380 6291456").is_ok());
    assert!(validate_kernel_value("key", "not_a_number").is_err());
    assert!(validate_kernel_value("key", "").is_err());
}

#[test]
fn test_ssh_value_validation() {
    assert!(validate_ssh_value("MaxAuthTries", "3").is_ok());
    assert!(validate_ssh_value("PermitRootLogin", "no").is_ok());
    assert!(validate_ssh_value("key", "").is_err());
    assert!(validate_ssh_value("key", &"x".repeat(300)).is_err());
}

#[test]
fn test_firewall_value_validation() {
    assert!(validate_firewall_value("ssh.port", "22").is_ok());
    assert!(validate_firewall_value("ssh.port", "1024-65535").is_ok());
    assert!(validate_firewall_value("ssh.port", "not_a_port").is_err());
    assert!(validate_firewall_value("ssh.protocol", "tcp").is_ok());
    assert!(validate_firewall_value("ssh.protocol", "garbage").is_err());
    assert!(validate_firewall_value("ssh.action", "drop").is_ok());
    assert!(validate_firewall_value("ssh.action", "allow").is_err());
    assert!(validate_firewall_value("ssh.source", "10.0.0.0/8").is_ok());
    assert!(validate_firewall_value("ssh.source", "evil.com").is_err());
}

#[test]
fn test_pam_value_validation() {
    assert!(validate_pam_value("minlen", "16").is_ok());
    assert!(validate_pam_value("PASS_MAX_DAYS", "90").is_ok());
    assert!(validate_pam_value("hash", "sha512").is_ok());
    assert!(validate_pam_value("key", "has space").is_err());
    assert!(validate_pam_value("key", "").is_err());
}

#[test]
fn test_permissions_value_validation() {
    assert!(validate_permissions_value("/root", "700").is_ok());
    assert!(validate_permissions_value("/boot", "0755").is_ok());
    assert!(validate_permissions_value("/etc/ssh", "0600").is_ok());
    assert!(validate_permissions_value("/tmp", "644").is_ok());
    assert!(validate_permissions_value("/etc", "rwx").is_err());
    assert!(validate_permissions_value("/etc", "888").is_err());
    assert!(validate_permissions_value("/etc", "77").is_err());
    assert!(validate_permissions_value("/etc", "12345").is_err());
}

#[test]
fn test_permissions_rejects_suid() {
    assert!(validate_permissions_value("key", "4755").is_err());
}

#[test]
fn test_permissions_rejects_sgid() {
    assert!(validate_permissions_value("key", "2755").is_err());
}

#[test]
fn test_permissions_rejects_world_writable() {
    assert!(validate_permissions_value("key", "777").is_err());
    assert!(validate_permissions_value("key", "0777").is_err());
}

#[test]
fn test_permissions_rejects_no_access() {
    assert!(validate_permissions_value("key", "000").is_err());
    assert!(validate_permissions_value("key", "0000").is_err());
}

#[test]
fn test_validate_config_rejects_bad_directives() {
    let mut config = HardenerConfig::default();
    config.kernel.directives.insert(
        "kernel.randomize_va_space".to_string(),
        "not_numeric".to_string(),
    );
    config
        .ssh
        .directives
        .insert("PermitRootLogin".to_string(), "no; rm -rf /".to_string());

    let result = validate_config(&config);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    // Both errors should be reported, not just the first
    assert!(error_message.contains("kernel"));
    assert!(error_message.contains("ssh") || error_message.contains("forbidden character"));
}

#[test]
fn test_validate_config_accepts_valid_config() {
    let mut config = HardenerConfig::default();
    config
        .kernel
        .directives
        .insert("kernel.randomize_va_space".to_string(), "2".to_string());
    config
        .ssh
        .directives
        .insert("PermitRootLogin".to_string(), "no".to_string());
    config
        .permissions
        .directives
        .insert("/root".to_string(), "700".to_string());

    assert!(validate_config(&config).is_ok());
}

#[test]
fn test_kernel_key_rejects_path_traversal() {
    assert!(validate_directive_key("kernel", "kernel/../../../etc/passwd").is_err());
    assert!(validate_directive_key("kernel", "net.ipv4.../../secret").is_err());
}

#[test]
fn test_kernel_key_rejects_shell_metacharacters() {
    assert!(validate_directive_key("kernel", "net.ipv4; rm -rf /").is_err());
    assert!(validate_directive_key("kernel", "key\nnewline").is_err());
}

#[test]
fn test_kernel_key_accepts_valid_sysctl_names() {
    assert!(validate_directive_key("kernel", "net.ipv4.tcp_syncookies").is_ok());
    assert!(validate_directive_key("kernel", "kernel.randomize_va_space").is_ok());
    assert!(validate_directive_key("kernel", "fs.protected_hardlinks").is_ok());
}

/// The directive-key guard refuses on either clause, and its length ceiling is
/// a ceiling.
///
/// The two clauses are joined by `||`, so as `&&` an empty key is admitted:
/// nothing refuses it and the kernel plugin's `key.replace('.', "/")` then
/// builds a sysctl path from nothing. The length comparison is the same
/// boundary shape as everywhere else, and a test feeding a wildly oversized key
/// cannot fail under `==` or `>=`, since all three refuse it.
#[test]
fn a_directive_key_is_refused_when_empty_and_only_past_its_ceiling() {
    assert!(
        validate_directive_key("kernel-hardening", "").is_err(),
        "an empty key must be refused on its own clause"
    );

    let at_ceiling = "k".repeat(128);
    assert!(
        validate_directive_key("kernel-hardening", &at_ceiling).is_ok(),
        "exactly 128 characters is within the limit, not past it"
    );

    let past_ceiling = "k".repeat(129);
    assert!(
        validate_directive_key("kernel-hardening", &past_ceiling).is_err(),
        "and one character more is refused"
    );
}

/// The ssh value ceiling is a ceiling too.
#[test]
fn an_ssh_value_is_accepted_at_its_ceiling_and_refused_past_it() {
    assert!(
        validate_ssh_value("Banner", &"b".repeat(256)).is_ok(),
        "exactly 256 characters is within the limit"
    );
    assert!(
        validate_ssh_value("Banner", &"b".repeat(257)).is_err(),
        "and one character more is refused"
    );
    assert!(
        validate_ssh_value("Banner", "").is_err(),
        "the control: an empty value is refused for being empty"
    );
}

/// Each character class a pam token may use is allowed on its own.
///
/// The three are joined by `||`, so as `&&` a pair becomes a conjunction and no
/// single character can satisfy it: every token carrying the affected character
/// is refused, and an operator's valid `pam_unix` setting stops loading. One
/// token per class is what separates them, since a token mixing all three
/// satisfies any of the mutants.
#[test]
fn each_character_class_a_pam_token_may_use_is_allowed_alone() {
    for value in ["sha512", "sha_512", "pam-unix", "600"] {
        assert!(
            validate_pam_value("pam_key", value).is_ok(),
            "`{value}` is a valid pam value and must load"
        );
    }
    assert!(
        validate_pam_value("pam_key", "sha512; rm -rf /").is_err(),
        "the control: a token carrying anything else is refused"
    );
}

/// A permissions mode is refused on either side of its length window, **for
/// its width**.
///
/// The clauses are joined by `||`, so as `&&` the condition is unsatisfiable
/// and no length is refused at all. The first version of this test asked only
/// whether a refusal came back and did not fail the mutant: `"77"` fell through
/// to the world-writable check and `"07555"` to the special-bits check, so both
/// were still refused, for the wrong reason. The widths here are otherwise
/// **valid** modes, so nothing downstream refuses them, and the message is read
/// for what it names.
#[test]
fn a_permissions_mode_is_refused_on_either_side_of_its_width() {
    for value in ["75", "00755"] {
        let refusal = validate_permissions_value("/etc/shadow", value)
            .expect_err("`{value}` is not a 3 or 4 digit octal mode and must be refused");
        assert!(
            refusal.contains("3-4 digit"),
            "`{value}` must be refused for its width and not for something \
             downstream, which would leave the width check unpinned: {refusal}"
        );
    }
    for value in ["755", "0640"] {
        assert!(
            validate_permissions_value("/etc/shadow", value).is_ok(),
            "the control: `{value}` is a valid mode and must be accepted"
        );
    }
}
