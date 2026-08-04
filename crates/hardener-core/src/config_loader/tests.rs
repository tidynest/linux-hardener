#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`config_loader`](super).
//!
//! Split out of `config_loader.rs`. This file sits in the `config_loader/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::config_loader` and
//! every import carried across unchanged, private items included.

use super::*;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_default_config() {
    let loader = ConfigLoader::new().skip_defaults();
    let config = loader.load().unwrap();
    assert!(config.global.enabled_plugins.is_empty());
    assert!(config.ssh.is_enabled());
}

/// `custom_directives` was accepted and validated for several releases
/// while no plugin ever read it, and it has now been removed rather than
/// implemented. An operator's file still carries the table, so the loader
/// has to keep ignoring it: nothing here sets `deny_unknown_fields`, and
/// this is what says so out loud, because adding that attribute would turn
/// every such file into a hard load failure.
#[test]
fn a_config_still_naming_the_removed_custom_directives_loads() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
  [ssh]
  enabled = true

  [ssh.directives]
  PermitRootLogin = "no"

  [ssh.custom_directives]
  SomeSettingNoPluginEverRead = "yes"
  "#
    )
    .unwrap();

    let config = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file.path().to_path_buf())
        .load()
        .expect("a file naming the removed table must still load");

    assert!(config.ssh.is_enabled());
    assert_eq!(
        config
            .ssh
            .directives
            .get("PermitRootLogin")
            .map(String::as_str),
        Some("no"),
        "the surviving directives must be read, not discarded with the removed table"
    );
}

#[test]
fn test_load_from_file() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
  [global]
  disabled_plugins = ["mac-hardening"]

  [ssh]
  enabled = true
  "#
    )
    .unwrap();

    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file.path().to_path_buf());

    let config = loader.load().unwrap();
    assert_eq!(
        config.global.disabled_plugins,
        vec!["mac-hardening".to_string()]
    );
    assert!(config.ssh.is_enabled());
}

#[test]
fn test_missing_cli_config_error() {
    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(PathBuf::from("/nonexistent/config.toml"));

    let result = loader.load();
    assert!(result.is_err());
}

#[test]
fn test_merge_configs() {
    let base = HardenerConfig::default();
    let mut overlay = HardenerConfig::default();
    overlay.global.disabled_plugins = vec!["ssh-hardening".to_string()];
    overlay.ssh.enabled = Some(false);

    let merged = ConfigLoader::merge_configs(base, overlay).unwrap();
    assert_eq!(
        merged.global.disabled_plugins,
        vec!["ssh-hardening".to_string()]
    );
    assert!(!merged.ssh.is_enabled());
}

#[test]
fn test_merge_directives() {
    let mut base = HardenerConfig::default();
    base.ssh
        .directives
        .insert("MaxAuthTries".to_string(), "3".to_string());

    let mut overlay = HardenerConfig::default();
    overlay
        .ssh
        .directives
        .insert("PermitRootLogin".to_string(), "no".to_string());

    let merged = ConfigLoader::merge_configs(base, overlay).unwrap();
    assert_eq!(merged.ssh.directives.get("MaxAuthTries").unwrap(), "3");
    assert_eq!(merged.ssh.directives.get("PermitRootLogin").unwrap(), "no");
}

#[test]
fn test_user_config_path() {
    let path = ConfigLoader::user_config_path();
    assert!(path.is_some());
    let path = path.unwrap();
    assert!(path.to_string_lossy().contains("linux-hardener"));
}

#[test]
fn test_system_config_path() {
    let path = ConfigLoader::system_config_path();
    assert!(path.is_some());
    assert_eq!(
        path.unwrap(),
        PathBuf::from("/etc/linux-hardener/config.toml")
    );
}

#[test]
fn test_config_routing_end_to_end() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[services.exceptions.cups]
value = "running"
allowed = true
reason = "Print server required"
"#
    )
    .unwrap();

    let config = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file.path().to_path_buf())
        .load()
        .unwrap();

    let plugin = config.get_plugin_config("service-minimisation");
    assert!(
        plugin.has_valid_exception("cups").is_some(),
        "Exception added under [services] must be reachable via service-minimisation ID"
    );
}

/// A later source that merely mentions a section must not re-enable a plugin an
/// earlier source disabled.
///
/// `enabled` defaulted to `true`, so a file that named `[mac]` for any reason,
/// a single directive included, supplied `enabled = true` for it. That was
/// indistinguishable from a file that asked for it. Site policy disabling
/// `mac-hardening` was therefore undone by any partial `--config`, and since
/// `apply` began honouring that flag the verb that writes was exposed to it: a
/// plugin the site had turned off would be applied.
#[test]
fn a_section_mentioned_without_enabled_does_not_revive_a_disabled_plugin() {
    let mut base = HardenerConfig::default();
    base.mac.enabled = Some(false);

    let mut overlay = HardenerConfig::default();
    overlay
        .mac
        .directives
        .insert("selinux_mode".to_string(), "enforcing".to_string());

    let merged = ConfigLoader::merge_configs(base, overlay).expect("the sources merge");

    assert!(
        !merged.is_plugin_enabled("mac-hardening"),
        "a section mentioned for its directives says nothing about whether the \
         plugin runs, so the earlier decision stands"
    );
    assert_eq!(
        merged
            .mac
            .directives
            .get("selinux_mode")
            .map(String::as_str),
        Some("enforcing"),
        "while the directive it did carry is still merged, or the fix would have \
         cost the file its actual purpose"
    );
}

/// The control, in both directions: a later source that *says* so still decides.
#[test]
fn a_section_that_states_enabled_still_decides_it() {
    let mut base = HardenerConfig::default();
    base.mac.enabled = Some(false);
    let mut overlay = HardenerConfig::default();
    overlay.mac.enabled = Some(true);

    let revived = ConfigLoader::merge_configs(base, overlay).expect("the sources merge");
    assert!(
        revived.is_plugin_enabled("mac-hardening"),
        "an explicit `enabled = true` is a decision and must be honoured"
    );

    let mut base = HardenerConfig::default();
    let mut overlay = HardenerConfig::default();
    overlay.mac.enabled = Some(false);
    let disabled = ConfigLoader::merge_configs(base.clone(), overlay).expect("the sources merge");
    assert!(
        !disabled.is_plugin_enabled("mac-hardening"),
        "and an explicit `enabled = false` still turns a plugin off"
    );
    base.mac.enabled = None;
    assert!(
        HardenerConfig::default().is_plugin_enabled("mac-hardening"),
        "with nothing said anywhere, a plugin runs, which is the shipped default"
    );
}
