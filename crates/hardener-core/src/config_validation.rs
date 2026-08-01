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

/// A plugin's own value check, run after the universal one has passed.
type ValueValidator = fn(&str, &str) -> std::result::Result<(), String>;

/// Validates all directive values in a merged config.
///
/// Returns `Err` listing every invalid directive, not just the first.
///
/// Every section appears in the table below. Listing them as separate calls
/// let three of them be forgotten, and a section absent from the list is not
/// validated leniently, it is not validated at all.
pub fn validate_config(config: &HardenerConfig) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    for (section, directives, plugin_validator) in [
        (
            "kernel",
            &config.kernel.directives,
            validate_kernel_value as ValueValidator,
        ),
        ("ssh", &config.ssh.directives, validate_ssh_value),
        (
            "firewall",
            &config.firewall.directives,
            validate_firewall_value,
        ),
        ("pam", &config.pam.directives, validate_pam_value),
        (
            "permissions",
            &config.permissions.directives,
            validate_permissions_value,
        ),
        ("audit", &config.audit.directives, accept_any_value),
        ("mac", &config.mac.directives, accept_any_value),
        ("services", &config.services.directives, accept_any_value),
    ] {
        validate_plugin_directives(section, directives, plugin_validator, &mut errors);
    }

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
    plugin_validator: ValueValidator,
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

/// The audit, mac and services plugins declare no directive value format of
/// their own, so the universal checks are the whole of their validation. This
/// says that deliberately, where their omission from the table said nothing.
fn accept_any_value(_key: &str, _value: &str) -> std::result::Result<(), String> {
    Ok(())
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
mod tests;
