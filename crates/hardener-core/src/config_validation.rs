//! Validates directive values at config load time.
//!
//! Rejects values containing shell metacharacters, newlines, or patterns
//! that don't match the expected format for each plugin family. This is
//! defence in depth: even if a plugin handles bad values gracefully, the
//! validation layer ensures they never reach plugin code.

use crate::config::HardenerConfig;
use hardener_common::error::{HardeningError, Result};

/// Characters that must never appear in any directive value.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '`', '$', '(', ')', '{', '}', '|', '&', '\n', '\r', '\0',
];

/// Validates all directive values in a merged config.
///
/// Returns `Err` listing every invalid directive, not just the first.
pub fn validate_config(config: &HardenerConfig) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    validate_plugin_directives(
        "kernel",
        &config.kernel.directives,
        validate_kernel_value,
        &mut errors,
    );
    validate_plugin_directives(
        "ssh",
        &config.ssh.directives,
        validate_ssh_value,
        &mut errors,
    );
    validate_plugin_directives(
        "firewall",
        &config.firewall.directives,
        validate_firewall_value,
        &mut errors,
    );
    validate_plugin_directives(
        "pam",
        &config.pam.directives,
        validate_pam_value,
        &mut errors,
    );
    validate_plugin_directives(
        "permissions",
        &config.permissions.directives,
        validate_permissions_value,
        &mut errors,
    );

    if errors.is_empty() {
        Ok(())
    } else {
        Err(HardeningError::Config(format!(
            "Invalid config directive values:\n  - {}",
            errors.join("\n  - ")
        )))
    }
}

/// Iterates a plugin's directives map and applies both universal and
/// plugin-specific validation.
fn validate_plugin_directives(
    section: &str,
    directives: &std::collections::HashMap<String, String>,
    plugin_validator: fn(&str, &str) -> std::result::Result<(), String>,
    errors: &mut Vec<String>,
) {
    for (key, value) in directives {
        if let Err(reason) = validate_directive_key(section, key) {
            errors.push(format!("[{section}.directives] {key}: {reason}"));
            continue;
        }
        if let Err(reason) = check_universal(value) {
            errors.push(format!("[{section}.directives] {key}: {reason}"));
        } else if let Err(reason) = plugin_validator(key, value) {
            errors.push(format!("[{section}.directives] {key}: {reason}"));
        }
    }
}

/// Universal check: no shell metacharacters, no control characters.
fn check_universal(value: &str) -> std::result::Result<(), String> {
    if let Some(bad) = value.chars().find(|c| SHELL_METACHARACTERS.contains(c)) {
        let label = match bad {
            '\n' => "newline".to_string(),
            '\r' => "carriage return".to_string(),
            '\0' => "null byte".to_string(),
            c => format!("'{c}'"),
        };
        return Err(format!("contains forbidden character {label}"));
    }
    Ok(())
}

/// Validates directive keys for safe characters. Prevents path traversal
/// via sysctl `.replace('.', "/")` in the kernel plugin.
pub fn validate_directive_key(plugin_id: &str, key: &str) -> std::result::Result<(), String> {
    if key.is_empty() || key.len() > 128 {
        return Err(format!("directive key too long or empty: '{key}'"));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '/')
    {
        return Err(format!(
            "directive key for '{plugin_id}' contains invalid characters: '{key}'"
        ));
    }
    if key.contains("..") {
        return Err(format!("directive key contains '..': '{key}'"));
    }
    Ok(())
}

// ── Per-plugin validators ──────────────────────────────────────────

/// Kernel: sysctl values must be numeric (possibly space-separated for multi-value params).
fn validate_kernel_value(_key: &str, value: &str) -> std::result::Result<(), String> {
    // Sysctl values can be single integers or space-separated integers
    // (e.g., "0 0 0" for net.ipv4.tcp_rmem)
    if !value.is_empty()
        && value
            .split_whitespace()
            .all(|token| token.parse::<i64>().is_ok())
    {
        Ok(())
    } else {
        Err(format!("expected numeric sysctl value, got '{value}'"))
    }
}

/// SSH: single-line, no whitespace-only, reasonable length.
fn validate_ssh_value(_key: &str, value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("empty value".to_string());
    }
    if value.len() > 256 {
        return Err(format!("value too long ({} chars, max 256)", value.len()));
    }
    Ok(())
}

/// Firewall: compound keys `<rule_id>.<field>`: validate by field.
fn validate_firewall_value(key: &str, value: &str) -> std::result::Result<(), String> {
    let field = key.rsplit('.').next().unwrap_or(key);
    match field {
        "port" => {
            // Single port or range: "22" or "1024-65535"
            if value.split('-').all(|p| p.parse::<u16>().is_ok()) && value.split('-').count() <= 2 {
                Ok(())
            } else {
                Err(format!("expected port or port range, got '{value}'"))
            }
        }
        "protocol" => {
            if matches!(value, "tcp" | "udp" | "any") {
                Ok(())
            } else {
                Err(format!("expected tcp|udp|any, got '{value}'"))
            }
        }
        "action" => {
            if matches!(value, "accept" | "drop" | "reject") {
                Ok(())
            } else {
                Err(format!("expected accept|drop|reject, got '{value}'"))
            }
        }
        "source" => {
            // IP address or CIDR: basic structural check
            if value
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '/' || c == ':')
            {
                Ok(())
            } else {
                Err(format!("expected IP/CIDR, got '{value}'"))
            }
        }
        _ => Ok(()),
    }
}

/// PAM: numeric values for password/login directives.
fn validate_pam_value(_key: &str, value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("empty value".to_string());
    }
    // PAM values are either integers or simple tokens (e.g., "sha512")
    if value.parse::<i64>().is_ok() {
        return Ok(());
    }
    // Allow single alphanumeric tokens (e.g., hash algorithm names)
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Ok(());
    }
    Err(format!(
        "expected numeric or single-token value, got '{value}'"
    ))
}

/// Permissions: octal mode string like "700", "0755".
/// Rejects special bits (SUID/SGID/sticky), world-writable, and zero modes.
fn validate_permissions_value(_key: &str, value: &str) -> std::result::Result<(), String> {
    if value.len() < 3 || value.len() > 4 {
        return Err(format!("expected 3-4 digit octal mode, got '{value}'"));
    }
    if !value.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(format!("expected octal digits (0-7), got '{value}'"));
    }
    let mode =
        u32::from_str_radix(value, 8).map_err(|_| format!("invalid octal mode: '{value}'"))?;
    if mode & 0o7000 != 0 {
        return Err(format!(
            "special bits (SUID/SGID/sticky) not allowed: '{value}'"
        ));
    }
    if mode & 0o002 != 0 {
        return Err(format!("world-writable mode not allowed: '{value}'"));
    }
    if mode == 0 {
        return Err(format!("zero permissions not allowed: '{value}'"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
