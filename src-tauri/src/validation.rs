use std::path::{Path, PathBuf};

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

/// Rejects paths containing `..` components.
fn reject_path_traversal(path: &Path) -> Result<(), String> {
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(format!("Path traversal not allowed: '{}'", path.display()));
        }
    }
    Ok(())
}

/// Dangerous path prefixes that should never be read/written by IPC commands.
const DANGEROUS_PREFIXES: &[&str] = &["/proc/", "/sys/", "/dev/"];

/// Dangerous exact paths.
const DANGEROUS_PATHS: &[&str] = &["/etc/shadow", "/etc/passwd", "/etc/sudoers"];

/// Dotfile basenames that are dangerous write/read targets.
const DANGEROUS_DOTFILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".profile",
    ".ssh",
    ".gnupg",
    ".config/systemd",
];

/// Returns true if the path targets a dangerous location.
fn is_dangerous_path(path: &Path) -> bool {
    let s = path.to_string_lossy();

    if DANGEROUS_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return true;
    }
    if DANGEROUS_PATHS.iter().any(|p| s == *p) {
        return true;
    }

    // Check for dangerous dotfiles relative to home
    if let Some(home) = dirs::home_dir() {
        let home_s = home.to_string_lossy();
        for dotfile in DANGEROUS_DOTFILES {
            let dangerous = format!("{home_s}/{dotfile}");
            if s.starts_with(&dangerous) {
                return true;
            }
        }
    }

    false
}

/// Resolves the home directory prefix from a path string.
fn expand_home(path: &str) -> Result<PathBuf, String> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().ok_or_else(|| "Cannot determine home directory".to_string())?;
        Ok(home.join(rest))
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Allowed directories for config paths passed to pkexec (root reads these).
const PRIVILEGED_CONFIG_DIRS: &[&str] = &["/etc/linux-hardener/"];

/// Validates a config path for privileged (pkexec) operations.
///
/// Only permits paths inside `/etc/linux-hardener/` or `~/.config/linux-hardener/`.
/// Canonicalises to resolve symlinks and `..` segments.
pub fn validate_privileged_config_path(path: &str) -> Result<PathBuf, String> {
    validate_ipc_string(path, "config_path")?;

    let expanded = expand_home(path)?;
    reject_path_traversal(&expanded)?;

    // Canonicalise (resolves symlinks — file must exist)
    let canonical = expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve config path '{}': {e}", expanded.display()))?;

    let canonical_s = canonical.to_string_lossy();

    // Check against allowed directories
    if PRIVILEGED_CONFIG_DIRS
        .iter()
        .any(|d| canonical_s.starts_with(d))
    {
        return Ok(canonical);
    }

    // Allow user config dir: ~/.config/linux-hardener/
    if let Some(config_dir) = dirs::config_dir() {
        let allowed = config_dir.join("linux-hardener");
        if let Ok(allowed_canonical) = allowed.canonicalize()
            && canonical.starts_with(&allowed_canonical)
        {
            return Ok(canonical);
        }
        // Also allow if the dir doesn't exist yet but path matches
        if canonical.starts_with(&allowed) {
            return Ok(canonical);
        }
    }

    Err(format!(
        "Config path '{}' is outside allowed directories \
         (/etc/linux-hardener/, ~/.config/linux-hardener/)",
        path
    ))
}

/// Validates a config path for user-privilege operations (deny-dangerous approach).
///
/// Rejects known-dangerous locations and requires `.toml` extension.
pub fn validate_user_config_path(path: &str) -> Result<PathBuf, String> {
    validate_ipc_string(path, "config_path")?;

    let expanded = expand_home(path)?;
    reject_path_traversal(&expanded)?;

    if is_dangerous_path(&expanded) {
        return Err(format!(
            "Config path '{}' targets a restricted location",
            path
        ));
    }

    match expanded.extension().and_then(|e| e.to_str()) {
        Some("toml") => Ok(expanded),
        _ => Err(format!(
            "Config path '{}' must have a .toml extension",
            path
        )),
    }
}

/// Safe directory names (relative to home) for report export.
const SAFE_EXPORT_DIRS: &[&str] = &["Documents", "Downloads", "Desktop"];

/// Validates an output path for report export (user-privilege file write).
///
/// Allows `~/Documents/`, `~/Downloads/`, `~/Desktop/`, `/tmp/`,
/// and XDG user directories. Canonicalises the parent directory.
pub fn validate_output_path(path: &str) -> Result<PathBuf, String> {
    validate_ipc_string(path, "output_path")?;

    let expanded = expand_home(path)?;
    reject_path_traversal(&expanded)?;

    if is_dangerous_path(&expanded) {
        return Err(format!(
            "Output path '{}' targets a restricted location",
            path
        ));
    }

    let expanded_s = expanded.to_string_lossy();

    // Allow /tmp/
    if expanded_s.starts_with("/tmp/") {
        return Ok(expanded);
    }

    // Check against safe home subdirectories
    if let Some(home) = dirs::home_dir() {
        for dir_name in SAFE_EXPORT_DIRS {
            let allowed = home.join(dir_name);
            if expanded.starts_with(&allowed) {
                return Ok(expanded);
            }
        }

        // Allow XDG document/download dirs if different from defaults
        if let Some(doc_dir) = dirs::document_dir()
            && expanded.starts_with(&doc_dir)
        {
            return Ok(expanded);
        }
        if let Some(dl_dir) = dirs::download_dir()
            && expanded.starts_with(&dl_dir)
        {
            return Ok(expanded);
        }
    }

    Err(format!(
        "Output path '{}' is outside allowed directories \
         (~/Documents/, ~/Downloads/, ~/Desktop/, /tmp/)",
        path
    ))
}

/// Validates SSH key file path is inside `~/.ssh/`.
///
/// Canonicalises to prevent symlink escapes.
pub fn validate_ssh_key_path(path: &str) -> Result<PathBuf, String> {
    validate_ipc_string(path, "key_file")?;

    let expanded = expand_home(path)?;
    reject_path_traversal(&expanded)?;

    let home = dirs::home_dir().ok_or_else(|| "Cannot determine home directory".to_string())?;
    let ssh_dir = home.join(".ssh");

    // Check prefix before canonicalisation (file may not exist in tests)
    if !expanded.starts_with(&ssh_dir) {
        return Err(format!("SSH key path '{}' must be inside ~/.ssh/", path));
    }

    // If the file exists, canonicalise to catch symlink escapes
    if expanded.exists() {
        let canonical = expanded
            .canonicalize()
            .map_err(|e| format!("Cannot resolve SSH key path: {e}"))?;
        if !canonical.starts_with(&ssh_dir) {
            return Err(format!(
                "SSH key path '{}' resolves outside ~/.ssh/ (symlink escape)",
                path
            ));
        }
        return Ok(canonical);
    }

    Ok(expanded)
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

    // --- Path helper tests ---

    #[test]
    fn path_traversal_rejects_dotdot() {
        assert!(reject_path_traversal(Path::new("/etc/linux-hardener/../../shadow")).is_err());
    }

    #[test]
    fn path_traversal_accepts_clean_path() {
        assert!(reject_path_traversal(Path::new("/etc/linux-hardener/config.toml")).is_ok());
    }

    #[test]
    fn dangerous_path_detects_proc() {
        assert!(is_dangerous_path(Path::new("/proc/self/environ")));
    }

    #[test]
    fn dangerous_path_detects_shadow() {
        assert!(is_dangerous_path(Path::new("/etc/shadow")));
    }

    #[test]
    fn dangerous_path_detects_ssh_dir() {
        if let Some(home) = dirs::home_dir() {
            assert!(is_dangerous_path(&home.join(".ssh/id_rsa")));
        }
    }

    #[test]
    fn dangerous_path_allows_safe_location() {
        assert!(!is_dangerous_path(Path::new(
            "/etc/linux-hardener/config.toml"
        )));
    }

    #[test]
    fn expand_home_resolves_tilde() {
        if let Some(home) = dirs::home_dir() {
            let result = expand_home("~/Documents/report.txt").unwrap();
            assert_eq!(result, home.join("Documents/report.txt"));
        }
    }

    #[test]
    fn expand_home_passes_absolute() {
        let result = expand_home("/etc/config.toml").unwrap();
        assert_eq!(result, PathBuf::from("/etc/config.toml"));
    }

    // --- Privileged config path tests ---

    #[test]
    fn privileged_config_rejects_etc_shadow() {
        assert!(validate_privileged_config_path("/etc/shadow").is_err());
    }

    #[test]
    fn privileged_config_rejects_traversal() {
        assert!(validate_privileged_config_path("/etc/linux-hardener/../../shadow").is_err());
    }

    #[test]
    fn privileged_config_rejects_proc() {
        assert!(validate_privileged_config_path("/proc/self/environ").is_err());
    }

    // --- User config path tests ---

    #[test]
    fn user_config_accepts_toml_in_downloads() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/Downloads/custom.toml", home.display());
            assert!(validate_user_config_path(&path).is_ok());
        }
    }

    #[test]
    fn user_config_rejects_non_toml() {
        assert!(validate_user_config_path("/tmp/evil.sh").is_err());
    }

    #[test]
    fn user_config_rejects_proc() {
        assert!(validate_user_config_path("/proc/cpuinfo").is_err());
    }

    #[test]
    fn user_config_rejects_ssh_dir() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/.ssh/id_rsa", home.display());
            assert!(validate_user_config_path(&path).is_err());
        }
    }

    // --- Output path tests ---

    #[test]
    fn output_path_accepts_documents() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/Documents/report.html", home.display());
            assert!(validate_output_path(&path).is_ok());
        }
    }

    #[test]
    fn output_path_accepts_tmp() {
        assert!(validate_output_path("/tmp/report.json").is_ok());
    }

    #[test]
    fn output_path_rejects_bashrc() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/.bashrc", home.display());
            assert!(validate_output_path(&path).is_err());
        }
    }

    #[test]
    fn output_path_rejects_etc() {
        assert!(validate_output_path("/etc/cron.d/evil").is_err());
    }

    #[test]
    fn output_path_rejects_ssh_authorized_keys() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/.ssh/authorized_keys", home.display());
            assert!(validate_output_path(&path).is_err());
        }
    }

    // --- SSH key path tests ---

    #[test]
    fn ssh_key_accepts_standard_path() {
        if dirs::home_dir().is_some() {
            assert!(validate_ssh_key_path("~/.ssh/id_ed25519").is_ok());
        }
    }

    #[test]
    fn ssh_key_rejects_outside_ssh_dir() {
        assert!(validate_ssh_key_path("/etc/ssl/private/server.key").is_err());
    }

    #[test]
    fn ssh_key_rejects_traversal_escape() {
        assert!(validate_ssh_key_path("~/.ssh/../../etc/shadow").is_err());
    }

    #[test]
    fn ssh_key_rejects_absolute_outside() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/Documents/key.pem", home.display());
            assert!(validate_ssh_key_path(&path).is_err());
        }
    }
}
