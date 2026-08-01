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
