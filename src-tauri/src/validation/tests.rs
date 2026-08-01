#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`validation`](super).
//!
//! Split out of `validation.rs`. This file sits in the `validation/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::validation` and every
//! import carried across unchanged, private items included.

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
