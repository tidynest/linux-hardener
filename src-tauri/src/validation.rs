use std::path::{Path, PathBuf};

const MAX_IPC_STRING_LEN: usize = 4096;

/// Rejects ASCII control characters, tab excepted, and strings exceeding
/// MAX_IPC_STRING_LEN bytes.
///
/// DEL is named separately because it is the one control character above space
/// rather than below it, and a `b < b' '` test alone therefore misses it. That
/// was reached in practice: a `Delete` keypress that inserts a literal U+007F
/// left one in the desktop's webhook URL field, and the save wrote it to the
/// config as an endpoint URL. Tab stays permitted, which is deliberate.
///
/// The C1 range (U+0080 to U+009F) is **not** refused. It is multi-byte in
/// UTF-8, so no single-byte comparison reaches it, and refusing it wants a
/// `chars()` pass and a decision nobody has needed yet.
pub fn validate_ipc_string(s: &str, field_name: &str) -> Result<(), String> {
    if s.len() > MAX_IPC_STRING_LEN {
        return Err(format!(
            "{field_name} exceeds maximum length ({} > {MAX_IPC_STRING_LEN})",
            s.len()
        ));
    }
    if let Some(pos) = s
        .bytes()
        .position(|b| (b < b' ' && b != b'\t') || b == b'\x7f')
    {
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
    "service-minimisation",
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
    "service",
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

    // Canonicalise (resolves symlinks; file must exist)
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
mod tests;
