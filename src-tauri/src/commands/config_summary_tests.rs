#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! What the config picker card reports about a file it just loaded.
//!
//! The card shows one number an operator uses to confirm they chose the file
//! they meant: "N plugins". Until 2026-08-25 that number came from each
//! section's own `enabled` flag alone, so a config narrowing the set through
//! `[global]` still reported all eight.

use super::*;
use hardener_core::HardenerConfig;

fn summary_of(config: &HardenerConfig) -> Vec<String> {
    summarise_config("/tmp/whatever.toml".to_string(), config).config_enabled_plugins
}

/// A stock config runs every plugin, which is the baseline the rest move from.
#[test]
fn a_config_with_no_opinion_enables_every_plugin() {
    let enabled = summary_of(&HardenerConfig::default());

    assert_eq!(enabled.len(), 8, "got {enabled:?}");
    assert!(enabled.contains(&"mac-hardening".to_string()));
}

/// `disabled_plugins` is one of the two global lists the card could not see.
///
/// This is the case that matters most: `disabled_plugins = ["mac-hardening"]`
/// is the documented way to decline the MAC plugin, whose live behaviour no
/// reading has ever confirmed. The card said eight plugins for a file that
/// runs seven.
#[test]
fn a_globally_disabled_plugin_is_not_reported_as_enabled() {
    let mut config = HardenerConfig::default();
    config.global.disabled_plugins = vec!["mac-hardening".to_string()];

    let enabled = summary_of(&config);

    assert_eq!(enabled.len(), 7, "got {enabled:?}");
    assert!(
        !enabled.contains(&"mac-hardening".to_string()),
        "the plugin the config declines must not be counted: {enabled:?}"
    );
}

/// The allow list is the other, and it is the wider error: a config naming one
/// plugin reported all eight.
#[test]
fn an_allow_list_narrows_the_reported_set_to_itself() {
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["ssh-hardening".to_string()];

    assert_eq!(summary_of(&config), vec!["ssh-hardening".to_string()]);
}

/// The flag the card always honoured still works, so the fix widened the gate
/// rather than replacing it.
#[test]
fn a_section_disabled_by_its_own_flag_is_still_excluded() {
    let mut config = HardenerConfig::default();
    config.kernel.enabled = Some(false);

    let enabled = summary_of(&config);

    assert_eq!(enabled.len(), 7, "got {enabled:?}");
    assert!(!enabled.contains(&"kernel-hardening".to_string()));
}

/// Every id in `plugin_sections` reaches its own section, and nothing else.
///
/// `get_plugin_config` matches on the full plugin id and falls through to a
/// shared empty default for anything it does not recognise, and that default
/// reports enabled. So an id that drifts out of step, or a section listed
/// under a short name the way these were before, silently reports its plugin
/// as enabled no matter what the file says. Writing a directive into each
/// section and reading it back through the id is what proves the two agree.
#[test]
fn every_section_id_resolves_to_its_own_section() {
    // Named unconditionally, so an empty sweep below cannot pass in silence.
    let stock = HardenerConfig::default();
    assert_eq!(plugin_sections(&stock).len(), 8);

    for index in 0..8 {
        let mut config = HardenerConfig::default();
        let id = plugin_sections(&config)[index].0.to_string();

        // `plugin_sections` borrows, so pick the field by the id under test.
        let section = match id.as_str() {
            "kernel-hardening" => &mut config.kernel,
            "ssh-hardening" => &mut config.ssh,
            "firewall-hardening" => &mut config.firewall,
            "pam-hardening" => &mut config.pam,
            "service-minimisation" => &mut config.services,
            "audit-hardening" => &mut config.audit,
            "permissions-hardening" => &mut config.permissions,
            "mac-hardening" => &mut config.mac,
            other => panic!("unknown section id {other}"),
        };
        section.enabled = Some(false);

        let enabled = summary_of(&config);
        assert!(
            !enabled.contains(&id),
            "{id} was disabled in its own section and still reported enabled, \
             which is what happens when the id does not reach `get_plugin_config`"
        );
        assert_eq!(enabled.len(), 7, "only {id} should have left: {enabled:?}");
    }
}

/// The counts describe what the file declares, not what will run.
///
/// A disabled section's directives still appear in the total, because the
/// card labels them "directives" rather than "directives that will apply".
/// Pinned so the distinction is a decision rather than an accident.
#[test]
fn the_counts_describe_the_file_rather_than_the_run() {
    let mut config = HardenerConfig::default();
    config
        .kernel
        .directives
        .insert("kernel.kptr_restrict".to_string(), "2".to_string());
    config.kernel.enabled = Some(false);

    let summary = summarise_config("/tmp/whatever.toml".to_string(), &config);

    assert_eq!(summary.config_directive_count, 1);
    assert!(
        !summary
            .config_enabled_plugins
            .contains(&"kernel-hardening".to_string())
    );
}
