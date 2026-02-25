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
