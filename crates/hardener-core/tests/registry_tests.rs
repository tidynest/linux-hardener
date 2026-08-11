use hardener_common::types::PluginId;
use hardener_core::PluginRegistry;
use hardener_core::testing::MockPlugin;

#[test]
fn test_register_plugin() {
    let registry = PluginRegistry::new();
    let plugin = Box::new(MockPlugin::new("test_plugin").name("Test Plugin"));
    let result = registry.register(plugin);
    assert!(result.is_ok());

    // Verify it was registered
    assert_eq!(registry.count().unwrap(), 1);
}

#[test]
fn test_register_duplicate_plugin_fails() {
    let registry = PluginRegistry::new();
    let plugin1 = Box::new(MockPlugin::new("test_plugin").name("Test Plugin"));
    let plugin2 = Box::new(MockPlugin::new("test_plugin").name("Test Plugin"));
    registry.register(plugin1).unwrap();

    let result = registry.register(plugin2);
    assert!(result.is_err());
}

#[test]
fn test_get_plugin() {
    let registry = PluginRegistry::new();
    let plugin = Box::new(MockPlugin::new("test_plugin").name("Test Plugin"));
    registry.register(plugin).unwrap();

    let retrieved = registry.get(&PluginId::new("test_plugin")).unwrap();
    assert!(retrieved.is_some());

    let metadata = retrieved.unwrap().metadata();
    assert_eq!(metadata.plugin_id, PluginId::new("test_plugin"));
    assert_eq!(metadata.plugin_name, "Test Plugin");
}

#[test]
fn test_get_nonexistent_plugin() {
    let registry = PluginRegistry::new();
    let retrieved = registry.get(&PluginId::new("nonexistent")).unwrap();
    assert!(retrieved.is_none());
}

#[test]
fn test_list_plugins() {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(MockPlugin::new("plugin_b").name("Plugin B")))
        .unwrap();
    registry
        .register(Box::new(MockPlugin::new("plugin_a").name("Plugin A")))
        .unwrap();
    registry
        .register(Box::new(MockPlugin::new("plugin_c").name("Plugin C")))
        .unwrap();

    let list = registry.list().unwrap();
    assert_eq!(list.len(), 3);
    // Verify alphabetical ordering by ID
    assert_eq!(list[0].plugin_id, PluginId::new("plugin_a"));
    assert_eq!(list[1].plugin_id, PluginId::new("plugin_b"));
    assert_eq!(list[2].plugin_id, PluginId::new("plugin_c"));
}

#[test]
fn test_contains() {
    let registry = PluginRegistry::new();
    let plugin = Box::new(MockPlugin::new("test_plugin").name("Test Plugin"));
    registry.register(plugin).unwrap();
    assert!(registry.contains(&PluginId::new("test_plugin")).unwrap());
    assert!(!registry.contains(&PluginId::new("nonexistent")).unwrap());
}

/// The count is the number registered, at every number.
///
/// `test_register_plugin` asserts it equals 1 after registering one, which a
/// body returning a constant `1` satisfies exactly: an empty registry would
/// report a plugin, and a full one would report a single plugin however many
/// were loaded. `count` is what the CLI and the desktop both show as "plugins
/// loaded", so the wrong number there is the first thing an operator sees.
#[test]
fn the_plugin_count_is_the_number_registered_at_every_number() {
    let registry = PluginRegistry::new();
    assert_eq!(
        registry.count().unwrap(),
        0,
        "an empty registry has no plugins, which a constant answer cannot say"
    );

    for (registered, id) in ["first-hardening", "second-hardening", "third-hardening"]
        .into_iter()
        .enumerate()
    {
        registry
            .register(Box::new(MockPlugin::new(id)))
            .expect("a distinct id registers");
        assert_eq!(
            registry.count().unwrap(),
            registered + 1,
            "the count must follow every registration, not only the first"
        );
    }
}
