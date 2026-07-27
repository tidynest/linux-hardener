use hardener_core::{HardenerConfig, PluginConfig, PolicyException};

#[test]
fn test_default_config() {
    let config = HardenerConfig::default();
    assert!(config.global.enabled_plugins.is_empty());
    assert!(config.global.disabled_plugins.is_empty());
    assert!(config.ssh.enabled);
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
    config.ssh.enabled = false;
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
    config.ssh.enabled = true;
    assert!(!config.is_plugin_enabled("ssh-hardening"));
}

#[test]
fn section_enabled_false_beats_a_global_enabled_list() {
    // The other direction of the same rule: naming a plugin in
    // [global] enabled_plugins does not outrank its own section turning it off.
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["ssh-hardening".to_string()];
    config.ssh.enabled = false;
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

#[test]
fn test_config_serialization() {
    let config = HardenerConfig::default();
    let toml_str = toml::to_string(&config).unwrap();
    let parsed: HardenerConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(config.ssh.enabled, parsed.ssh.enabled);
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
    config.ssh.enabled = false;
    config.kernel.enabled = true;
    config.firewall.enabled = false;
    config.pam.enabled = true;
    config.audit.enabled = false;
    config.mac.enabled = true;
    config.permissions.enabled = false;
    config.services.enabled = true;

    assert!(!config.get_plugin_config("ssh-hardening").enabled);
    assert!(config.get_plugin_config("kernel-hardening").enabled);
    assert!(!config.get_plugin_config("firewall-hardening").enabled);
    assert!(config.get_plugin_config("pam-hardening").enabled);
    assert!(!config.get_plugin_config("audit-hardening").enabled);
    assert!(config.get_plugin_config("mac-hardening").enabled);
    assert!(!config.get_plugin_config("permissions-hardening").enabled);
    assert!(config.get_plugin_config("service-minimisation").enabled);
}

#[test]
fn test_get_plugin_config_unknown_returns_default() {
    let config = HardenerConfig::default();
    let plugin = config.get_plugin_config("nonexistent-plugin");
    assert!(plugin.enabled);
    assert!(plugin.directives.is_empty());
    assert!(plugin.exceptions.is_empty());
}

#[test]
fn test_get_plugin_config_service_minimisation() {
    let mut config = HardenerConfig::default();
    config.services.enabled = false;
    config
        .services
        .directives
        .insert("key".into(), "val".into());

    let plugin = config.get_plugin_config("service-minimisation");
    assert!(!plugin.enabled);
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
