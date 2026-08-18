use hardener_core::{HardenerConfig, PluginConfig, PolicyException};

#[test]
fn test_default_config() {
    let config = HardenerConfig::default();
    assert!(config.global.enabled_plugins.is_empty());
    assert!(config.global.disabled_plugins.is_empty());
    assert!(config.ssh.is_enabled());
}

#[test]
fn test_plugin_enabled_default() {
    let config = HardenerConfig::default();
    assert!(config.is_plugin_enabled("ssh-hardening"));
    assert!(config.is_plugin_enabled("kernel-hardening"));
}

#[test]
fn test_plugin_disabled() {
    let mut config = HardenerConfig::default();
    config.global.disabled_plugins = vec!["ssh-hardening".to_string()];
    assert!(!config.is_plugin_enabled("ssh-hardening"));
    assert!(config.is_plugin_enabled("kernel-hardening"));
}

#[test]
fn test_plugin_enabled_list() {
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["ssh-hardening".to_string()];
    assert!(config.is_plugin_enabled("ssh-hardening"));
    assert!(!config.is_plugin_enabled("kernel-hardening"));
}

#[test]
fn test_disabled_takes_precedence() {
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["ssh-hardening".to_string()];
    config.global.disabled_plugins = vec!["ssh-hardening".to_string()];
    assert!(!config.is_plugin_enabled("ssh-hardening"));
}

#[test]
fn section_enabled_false_disables_the_plugin() {
    // `[ssh] enabled = false` is the obvious way to turn a plugin off, and it
    // is the one an operator reaches for first. Reading only the [global]
    // lists left such a host scanned and hardened anyway, with nothing said.
    let mut config = HardenerConfig::default();
    config.ssh.enabled = Some(false);
    assert!(!config.is_plugin_enabled("ssh-hardening"));
    assert!(config.is_plugin_enabled("kernel-hardening"));
}

#[test]
fn section_enabled_true_cannot_re_enable_a_globally_disabled_plugin() {
    // Disabled anywhere is final. `enabled = true` is the default value of the
    // key, so treating it as an override would let a config that never
    // mentions the plugin silently defeat [global] disabled_plugins.
    let mut config = HardenerConfig::default();
    config.global.disabled_plugins = vec!["ssh-hardening".to_string()];
    config.ssh.enabled = Some(true);
    assert!(!config.is_plugin_enabled("ssh-hardening"));
}

#[test]
fn section_enabled_false_beats_a_global_enabled_list() {
    // The other direction of the same rule: naming a plugin in
    // [global] enabled_plugins does not outrank its own section turning it off.
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["ssh-hardening".to_string()];
    config.ssh.enabled = Some(false);
    assert!(!config.is_plugin_enabled("ssh-hardening"));
}

#[test]
fn resolve_str_prefers_a_directive_override() {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("MaxAuthTries".to_string(), "3".to_string());

    assert_eq!(config.resolve_str("MaxAuthTries", "6"), "3");
}

#[test]
fn resolve_str_falls_back_to_the_plugin_baseline() {
    // The direction matters: falling back the other way would make every
    // unset directive resolve to whatever the operator last configured
    // elsewhere, or to nothing at all.
    let config = PluginConfig::default();

    assert_eq!(config.resolve_str("MaxAuthTries", "6"), "6");
}

#[test]
fn test_policy_exception_valid() {
    let exception = PolicyException {
        value: "yes".to_string(),
        allowed: true,
        reason: "Test reason".to_string(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: None,
    };
    assert!(exception.is_valid());
}

#[test]
fn test_policy_exception_not_allowed() {
    let exception = PolicyException {
        value: "yes".to_string(),
        allowed: false,
        reason: "Test reason".to_string(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: None,
    };
    assert!(!exception.is_valid());
}

#[test]
fn test_policy_exception_expired() {
    let exception = PolicyException {
        value: "yes".to_string(),
        allowed: true,
        reason: "Test reason".to_string(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: Some("2020-01-01".to_string()),
    };
    assert!(exception.is_expired());
    assert!(!exception.is_valid());
}

/// Every field of a `HardenerConfig` must survive TOML, not only the one field
/// somebody wrote an assertion for.
///
/// This asserted `config.ssh.enabled == parsed.ssh.enabled` over a
/// `default()` config, and so could not fail for any of the other eight
/// sections, nor for `[global]`, nor for directives or exceptions in the
/// section it did name. Both halves were weak: a per-field assertion reaches
/// only the field it was written for, and an all-default fixture serialises
/// most keys to nothing, so a field dropped on the way through compares equal
/// to a field that was never there.
///
/// Re-serialising the parsed config and comparing the TOML text needs no
/// per-field assertion and no `PartialEq`: a section lost on parse changes the
/// text. Every value below is a distinct marker for the same reason
/// `scan_manager_tests.rs` uses them, so a field rebuilt as a default cannot
/// match the fixture by coincidence.
#[test]
fn test_config_serialization() {
    let marked = |enabled: bool, directive: &str, exception_key: &str| {
        let mut plugin = PluginConfig {
            enabled: Some(enabled),
            ..Default::default()
        };
        plugin.directives.insert(
            format!("directive-{directive}"),
            format!("value-{directive}"),
        );
        plugin.exceptions.insert(
            exception_key.to_string(),
            PolicyException {
                value: format!("value-{exception_key}"),
                allowed: true,
                reason: format!("reason-{exception_key}"),
                approved_by: Some(format!("approver-{exception_key}")),
                approved_date: Some("2026-08-18".to_string()),
                ticket: Some(format!("ticket-{exception_key}")),
                expires: Some("2027-08-18".to_string()),
            },
        );
        plugin
    };

    let config = HardenerConfig {
        global: hardener_core::GlobalConfig {
            enabled_plugins: vec!["ssh-hardening".to_string()],
            disabled_plugins: vec!["mac-hardening".to_string()],
        },
        ssh: marked(true, "ssh", "PermitRootLogin"),
        kernel: marked(false, "kernel", "net.ipv4.ip_forward"),
        firewall: marked(true, "firewall", "default-policy"),
        pam: marked(false, "pam", "minlen"),
        audit: marked(true, "audit", "rules-file"),
        mac: marked(false, "mac", "enforcing"),
        permissions: marked(true, "permissions", "/etc/shadow"),
        services: marked(false, "services", "cups"),
        compliance: Default::default(),
    };

    let toml_str = toml::to_string(&config).unwrap();
    let parsed: HardenerConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(
        toml_str,
        toml::to_string(&parsed).unwrap(),
        "a config must come back exactly as it went in: a section, directive or \
         exception field lost on the way through shows up here as a difference"
    );
}

#[test]
fn test_has_valid_exception_found() {
    let mut plugin = PluginConfig::default();
    plugin.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "yes".to_string(),
            allowed: true,
            reason: "Legacy server".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    assert!(plugin.has_valid_exception("PermitRootLogin").is_some());
    assert!(plugin.has_valid_exception("X11Forwarding").is_none());
}

#[test]
fn test_has_valid_exception_expired() {
    let mut plugin = PluginConfig::default();
    plugin.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "yes".to_string(),
            allowed: true,
            reason: "Temporary".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: Some("2020-01-01".to_string()),
        },
    );
    assert!(plugin.has_valid_exception("PermitRootLogin").is_none());
}

#[test]
fn test_get_plugin_config_all_ids() {
    let mut config = HardenerConfig::default();
    // Disable each plugin uniquely so we can verify routing
    config.ssh.enabled = Some(false);
    config.kernel.enabled = Some(true);
    config.firewall.enabled = Some(false);
    config.pam.enabled = Some(true);
    config.audit.enabled = Some(false);
    config.mac.enabled = Some(true);
    config.permissions.enabled = Some(false);
    config.services.enabled = Some(true);

    assert!(!config.get_plugin_config("ssh-hardening").is_enabled());
    assert!(config.get_plugin_config("kernel-hardening").is_enabled());
    assert!(!config.get_plugin_config("firewall-hardening").is_enabled());
    assert!(config.get_plugin_config("pam-hardening").is_enabled());
    assert!(!config.get_plugin_config("audit-hardening").is_enabled());
    assert!(config.get_plugin_config("mac-hardening").is_enabled());
    assert!(
        !config
            .get_plugin_config("permissions-hardening")
            .is_enabled()
    );
    assert!(
        config
            .get_plugin_config("service-minimisation")
            .is_enabled()
    );
}

#[test]
fn test_get_plugin_config_unknown_returns_default() {
    let config = HardenerConfig::default();
    let plugin = config.get_plugin_config("nonexistent-plugin");
    assert!(plugin.is_enabled());
    assert!(plugin.directives.is_empty());
    assert!(plugin.exceptions.is_empty());
}

#[test]
fn test_get_plugin_config_service_minimisation() {
    let mut config = HardenerConfig::default();
    config.services.enabled = Some(false);
    config
        .services
        .directives
        .insert("key".into(), "val".into());

    let plugin = config.get_plugin_config("service-minimisation");
    assert!(!plugin.is_enabled());
    assert_eq!(plugin.directives.get("key").unwrap(), "val");
}

#[test]
fn test_get_plugin_config_isolation() {
    let mut config = HardenerConfig::default();
    config
        .ssh
        .directives
        .insert("PermitRootLogin".into(), "no".into());

    // SSH has the directive, kernel does not
    assert!(
        config
            .get_plugin_config("ssh-hardening")
            .directives
            .contains_key("PermitRootLogin")
    );
    assert!(
        !config
            .get_plugin_config("kernel-hardening")
            .directives
            .contains_key("PermitRootLogin")
    );
}

#[test]
fn test_get_plugin_config_exceptions_routed() {
    let mut config = HardenerConfig::default();
    config.services.exceptions.insert(
        "cups".to_string(),
        PolicyException {
            value: "running".to_string(),
            allowed: true,
            reason: "Print server needed".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let plugin = config.get_plugin_config("service-minimisation");
    assert!(plugin.has_valid_exception("cups").is_some());
    assert!(plugin.has_valid_exception("avahi").is_none());
}
