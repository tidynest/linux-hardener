const MAX_IPC_STRING_LEN: usize = 4096;

/// Rejects control characters (except space) and strings exceeding MAX_IPC_STRING_LEN bytes.
pub fn validate_ipc_string(s: &str, field_name: &str) -> Result<(), String> {
    if s.len() > MAX_IPC_STRING_LEN {
        return Err(format!(
            "{field_name} exceeds maximum length ({} > {MAX_IPC_STRING_LEN})",
            s.len()
        ));
    }
    if let Some(pos) = s.bytes().position(|b| b < b' ' && b != b'\t') {
        return Err(format!(
            "{field_name} contains invalid control character at byte {pos}"
        ));
    }
    Ok(())
}

const KNOWN_PLUGIN_IDS: &[&str] = &[
    "audit-hardening",
    "firewall-hardening",
    "kernel-hardening",
    "mac-hardening",
    "pam-hardening",
    "permissions-hardening",
    "services-hardening",
    "ssh-hardening",
];

/// Short prefixes the frontend sends (mapped to full IDs via starts_with).
const KNOWN_PLUGIN_PREFIXES: &[&str] = &[
    "audit",
    "firewall",
    "kernel",
    "mac",
    "pam",
    "permissions",
    "services",
    "ssh",
];

/// Validates plugin IDs against the known plugin registry.
///
/// Accepts both full IDs (`"kernel-hardening"`) and short prefixes (`"kernel"`).
pub fn validate_plugin_ids(ids: &[String]) -> Result<(), String> {
    for id in ids {
        validate_ipc_string(id, "plugin_id")?;
        let is_known =
            KNOWN_PLUGIN_IDS.contains(&id.as_str()) || KNOWN_PLUGIN_PREFIXES.contains(&id.as_str());
        if !is_known {
            return Err(format!("Unknown plugin ID: '{id}'"));
        }
    }
    Ok(())
}

const MAX_CHECKPOINT_NAME_LEN: usize = 255;

/// Validates checkpoint ID matches the format `cp_<digits>_<8 hex chars>`.
pub fn validate_checkpoint_id(id: &str) -> Result<(), String> {
    validate_ipc_string(id, "checkpoint_id")?;

    let parts: Vec<&str> = id.splitn(3, '_').collect();
    let valid = parts.len() == 3
        && parts[0] == "cp"
        && !parts[1].is_empty()
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2].len() == 8
        && parts[2].bytes().all(|b| b.is_ascii_hexdigit());

    if !valid {
        return Err(format!(
            "Invalid checkpoint ID format: '{id}' (expected cp_<timestamp>_<hex>)"
        ));
    }
    Ok(())
}

/// Validates checkpoint name: 1-255 chars, alphanumeric + spaces/hyphens/underscores.
pub fn validate_checkpoint_name(name: &str) -> Result<(), String> {
    validate_ipc_string(name, "checkpoint_name")?;

    if name.is_empty() {
        return Err("Checkpoint name cannot be empty".to_string());
    }
    if name.len() > MAX_CHECKPOINT_NAME_LEN {
        return Err(format!(
            "Checkpoint name too long ({} > {MAX_CHECKPOINT_NAME_LEN})",
            name.len()
        ));
    }
    if let Some(ch) = name
        .chars()
        .find(|c| !c.is_alphanumeric() && *c != ' ' && *c != '-' && *c != '_')
    {
        return Err(format!(
            "Checkpoint name contains invalid character: '{ch}'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_string_accepts_normal_text() {
        assert!(validate_ipc_string("Hello World 123", "test").is_ok());
    }

    #[test]
    fn ipc_string_accepts_empty() {
        assert!(validate_ipc_string("", "test").is_ok());
    }

    #[test]
    fn ipc_string_accepts_tab() {
        assert!(validate_ipc_string("line\ttab", "test").is_ok());
    }

    #[test]
    fn ipc_string_rejects_null_byte() {
        assert!(validate_ipc_string("hello\x00world", "test").is_err());
    }

    #[test]
    fn ipc_string_rejects_newline() {
        assert!(validate_ipc_string("line\nbreak", "test").is_err());
    }

    #[test]
    fn ipc_string_rejects_oversize() {
        let big = "a".repeat(MAX_IPC_STRING_LEN + 1);
        assert!(validate_ipc_string(&big, "test").is_err());
    }

    #[test]
    fn ipc_string_accepts_max_size() {
        let exact = "a".repeat(MAX_IPC_STRING_LEN);
        assert!(validate_ipc_string(&exact, "test").is_ok());
    }

    #[test]
    fn plugin_ids_accepts_full_id() {
        assert!(validate_plugin_ids(&["kernel-hardening".into()]).is_ok());
    }

    #[test]
    fn plugin_ids_accepts_short_prefix() {
        assert!(validate_plugin_ids(&["ssh".into(), "firewall".into()]).is_ok());
    }

    #[test]
    fn plugin_ids_rejects_unknown() {
        assert!(validate_plugin_ids(&["nonexistent".into()]).is_err());
    }

    #[test]
    fn plugin_ids_rejects_argument_injection() {
        assert!(validate_plugin_ids(&["--config".into()]).is_err());
    }

    #[test]
    fn plugin_ids_accepts_empty_list() {
        assert!(validate_plugin_ids(&[]).is_ok());
    }

    #[test]
    fn checkpoint_id_accepts_valid() {
        assert!(validate_checkpoint_id("cp_1740000000000_abcdef01").is_ok());
    }

    #[test]
    fn checkpoint_id_rejects_path_traversal() {
        assert!(validate_checkpoint_id("../../../etc/shadow").is_err());
    }

    #[test]
    fn checkpoint_id_rejects_flag_injection() {
        assert!(validate_checkpoint_id("--format").is_err());
    }

    #[test]
    fn checkpoint_id_rejects_empty() {
        assert!(validate_checkpoint_id("").is_err());
    }

    #[test]
    fn checkpoint_id_rejects_wrong_prefix() {
        assert!(validate_checkpoint_id("xx_123_abcdef01").is_err());
    }

    #[test]
    fn checkpoint_name_accepts_valid() {
        assert!(validate_checkpoint_name("My Backup 2026-02").is_ok());
    }

    #[test]
    fn checkpoint_name_accepts_underscores() {
        assert!(validate_checkpoint_name("pre_update_snapshot").is_ok());
    }

    #[test]
    fn checkpoint_name_rejects_empty() {
        assert!(validate_checkpoint_name("").is_err());
    }

    #[test]
    fn checkpoint_name_rejects_oversize() {
        let long = "a".repeat(256);
        assert!(validate_checkpoint_name(&long).is_err());
    }

    #[test]
    fn checkpoint_name_rejects_shell_metachar() {
        assert!(validate_checkpoint_name("$(rm -rf /)").is_err());
    }

    #[test]
    fn checkpoint_name_rejects_backtick() {
        assert!(validate_checkpoint_name("`whoami`").is_err());
    }
}
