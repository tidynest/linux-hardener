//! Plugin registry for managing hardening plugins.
//!
//! Provides centralised registration and retrieval of security hardening plugins.

use hardener_common::{error::Result, types::PluginId};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::plugin::{HardeningPlugin, PluginMetadata};

/// Type alias for a thread-safe collection of registered plugins.
type PluginMap = Arc<RwLock<HashMap<PluginId, Arc<Box<dyn HardeningPlugin>>>>>;

/// Registry for managing hardening plugins.
///
/// The PluginRegistry maintains a collection of registered plugins and provides
/// thread-safe access to them.
pub struct PluginRegistry {
    plugins: PluginMap,
}

impl PluginRegistry {
    /// Creates a new empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a new plugin in the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if a plugin with the same ID already exists.
    pub fn register(&self, plugin: Box<dyn HardeningPlugin>) -> Result<()> {
        let plugin_id = plugin.metadata().plugin_id;

        let mut plugins = self.plugins.write().map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to acquire write lock: {}",
                e
            ))
        })?;
        if plugins.contains_key(&plugin_id) {
            return Err(hardener_common::error::HardeningError::Plugin(format!(
                "Plugin '{}' is already registered",
                plugin_id
            )));
        }

        plugins.insert(plugin_id, Arc::new(plugin));
        Ok(())
    }

    /// Retrieves a plugin by its ID
    ///
    /// Returns `None` if no plugin with the given ID exists.
    pub fn get(&self, id: &PluginId) -> Result<Option<Arc<Box<dyn HardeningPlugin>>>> {
        let plugins = self.plugins.read().map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to acquire read lock: {}",
                e
            ))
        })?;

        Ok(plugins.get(id).cloned())
    }

    /// Lists all registered plugins' metadata.
    ///
    /// Returns a vector sorted by plugin ID.
    pub fn list(&self) -> Result<Vec<PluginMetadata>> {
        let plugins = self.plugins.read().map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to acquire read lock: {}",
                e
            ))
        })?;

        let mut metadata_list: Vec<PluginMetadata> =
            plugins.values().map(|plugin| plugin.metadata()).collect();

        // Sort by plugin ID for consistent ordering.
        metadata_list.sort_by(|a, b| a.plugin_id.as_str().cmp(b.plugin_id.as_str()));

        Ok(metadata_list)
    }

    /// Returns the number of registered plugins.
    pub fn count(&self) -> Result<usize> {
        let plugins = self.plugins.read().map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to acquire read lock: {}",
                e
            ))
        })?;

        Ok(plugins.len())
    }

    /// Checks if a plugin with the given ID is registered.
    pub fn contains(&self, id: &PluginId) -> Result<bool> {
        let plugins = self.plugins.read().map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to acquire read lock: {}",
                e
            ))
        })?;

        Ok(plugins.contains_key(id))
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockPlugin;

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
}
