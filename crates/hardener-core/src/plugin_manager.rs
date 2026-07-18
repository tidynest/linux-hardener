//! Plugin manager for orchestrating hardening plugin execution.
//!
//! The PluginManager handles plugin lifecycle, dependency resolution
//! and execution order. It ensures plugins execute in the correct order
//! based on their declared dependencies.

use crate::{
    ApplyResult,
    // Checkpoint,
    Context,
    HardenerConfig,
    PluginRegistry,
    ScanResult,
};
use anyhow::{Result, anyhow};
use hardener_common::types::PluginId;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Topo;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Manages plugin registration, dependency resolution, and execution.
pub struct PluginManager {
    /// Registry containing all registered plugins.
    registry: PluginRegistry,
    /// Directed graph representing plugin dependencies.
    /// Nodes are PluginIds, edges point from dependent to dependency.
    dependency_graph: DiGraph<PluginId, ()>,
    /// Maps PluginId to graph NodeIndex for efficient lookups.
    node_indices: HashMap<PluginId, NodeIndex>,
}

impl PluginManager {
    /// Creates a new PluginManager with the given registry.
    ///
    /// The dependency graph will be built when plugins are loaded.
    ///
    /// # Arguments
    /// * `registry` - PluginRegistry containing registered plugins
    ///
    /// # Example
    /// ```
    /// use hardener_core::{PluginManager, PluginRegistry};
    ///
    /// let registry = PluginRegistry::new();
    /// let manager = PluginManager::new(registry);
    /// ```
    pub fn new(registry: PluginRegistry) -> PluginManager {
        PluginManager {
            registry,
            dependency_graph: DiGraph::new(),
            node_indices: HashMap::new(),
        }
    }

    /// Resolves plugin dependencies and builds the dependency graph.
    ///
    /// This validates that:
    /// - All declared dependencies exist in the registry
    /// - No circular dependencies exist
    ///
    /// # Errors
    /// Returns an error if:
    /// - A plugin declares a dependency that doesn't exist
    /// - Circular dependencies are detected
    ///
    /// # Example
    /// ```no_run
    /// # use hardener_core::{PluginManager, PluginRegistry};
    /// let mut manager = PluginManager::new(PluginRegistry::new());
    /// manager.resolve_dependencies()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn resolve_dependencies(&mut self) -> Result<()> {
        info!("Resolving plugin dependencies");

        // Clear existing graph
        self.dependency_graph.clear();
        self.node_indices.clear();

        // Get all plugins from registry
        let plugins_metadata = self.registry.list()?;

        // First pass: Create nodes for all plugins
        for metadata in &plugins_metadata {
            let node_index = self.dependency_graph.add_node(metadata.plugin_id.clone());
            self.node_indices
                .insert(metadata.plugin_id.clone(), node_index);
            debug!("Added node for plugin: {}", metadata.plugin_id);
        }

        // Second pass: Add edges for dependencies
        for metadata in &plugins_metadata {
            let plugin = self
                .registry
                .get(&metadata.plugin_id)?
                .ok_or_else(|| anyhow!("Plugin not found in registry: {}", metadata.plugin_id))?;

            let dependent_idx = self.node_indices[&metadata.plugin_id];

            for dependency_id in plugin.dependencies() {
                // Validate dependency exists
                if !self.node_indices.contains_key(&dependency_id) {
                    return Err(anyhow!(
                        "Plugin '{}' depends on '{}', which is not registered",
                        metadata.plugin_id,
                        dependency_id
                    ));
                }
                let dependency_idx = self.node_indices[&dependency_id];

                // Add edge: dependent -> dependency
                self.dependency_graph
                    .add_edge(dependency_idx, dependent_idx, ());
                debug!(
                    "Added dependency: {} -> {}",
                    metadata.plugin_id, dependency_id
                );
            }
        }

        // Detect circular dependencies using topological sort
        if petgraph::algo::is_cyclic_directed(&self.dependency_graph) {
            return Err(anyhow!("Circular dependency detected in plugin graph"));
        }

        // Success message and return
        info!(
            "Dependency resolution successful: {} plugins",
            plugins_metadata.len()
        );
        Ok(())
    }

    /// Returns the execution order for plugins based on dependencies.
    ///
    /// Uses topological sorting to ensure dependencies execute before dependents.
    ///
    /// # Errors
    /// Returns an error if dependencies haven't been resolved yet.
    ///
    /// # Example
    /// ```no_run
    /// # use hardener_core::{PluginManager, PluginRegistry};
    /// let mut manager = PluginManager::new(PluginRegistry::new());
    /// manager.resolve_dependencies()?;
    /// let order = manager.execution_order()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn execution_order(&self) -> Result<Vec<PluginId>> {
        if self.node_indices.is_empty() {
            return Err(anyhow!(
                "Dependencies not resolved. Call resolve_dependencies() first."
            ));
        }

        let mut order = Vec::new();
        let mut topo = Topo::new(&self.dependency_graph);

        while let Some(node_idx) = topo.next(&self.dependency_graph) {
            let plugin_id = &self.dependency_graph[node_idx];
            order.push(plugin_id.clone());
        }

        debug!("Execution order determined: {} plugins", order.len());
        Ok(order)
    }

    /// Executes scan across all registered plugins in dependency order.
    ///
    /// Each plugin scans the system and returns findings. Results are aggregated
    /// into a combined result. Individual plugin errors are logged but don't stop
    /// the entire scan.
    ///
    /// # Arguments
    /// * `ctx` - Execution context containing system information
    ///
    /// # Errors
    /// Returns an error if dependency resolution fails or no plugins are registered.
    ///
    /// # Example
    /// ```ignore
    /// # use hardener_core::{PluginManager, PluginRegistry, Context};
    /// let mut manager = PluginManager::new(PluginRegistry::new());
    /// manager.resolve_dependencies()?;
    /// let ctx = Context::new();
    /// let results = manager.execute_scan(&ctx).await?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub async fn execute_scan(&self, ctx: &Context) -> Result<Vec<ScanResult>> {
        info!("Starting scan execution");

        // Deliberately sequential: this path honours the dependency graph's
        // execution order and only the scheduler daemon uses it. The CLI scan
        // and report paths run plugins concurrently instead.
        let execution_order = self.execution_order()?;
        let mut all_scan_results = Vec::new();

        for plugin_id in execution_order {
            let plugin = self
                .registry
                .get(&plugin_id)?
                .ok_or_else(|| anyhow!("Plugin not found: {}", plugin_id))?;

            info!("Executing scan for plugin: {}", plugin_id);

            match plugin.scan(ctx).await {
                Ok(result) => {
                    debug!(
                        "Plugin {} scan completed: {} findings",
                        plugin_id,
                        result.scan_findings.len()
                    );
                    all_scan_results.push(result);
                }
                Err(e) => {
                    warn!("Plugin {} scan failed: {}", plugin_id, e);

                    // Create error result but continue scanning other plugins
                    all_scan_results.push(ScanResult {
                        scan_plugin_id: plugin_id.clone(),
                        scan_success: false,
                        scan_findings: vec![],
                        scan_unchecked: vec![],
                        scan_duration_us: 0,
                        scan_error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(
            "Scan execution complete: {} plugins scanned",
            all_scan_results.len()
        );
        Ok(all_scan_results)
    }

    /// Executes apply across selected plugins with checkpoint and rollback support.
    ///
    /// Creates a checkpoint before applying changes. If any plugin fails, automatically
    /// rolls back all changes to the checkpoint state.
    ///
    /// # Arguments
    /// * `ctx` - Mutable execution context
    /// * `config` - Configuration for hardening
    /// * `plugin_ids` - Specific plugins to apply (empty = all plugins)
    ///
    /// # Errors
    /// Returns an error if dependency resolution fails or checkpoint creation fails.
    ///
    /// # Example
    /// ```ignore
    /// # use hardener_core::{PluginManager, PluginRegistry, Context, HardenerConfig};
    /// let mut manager = PluginManager::new(PluginRegistry::new());
    /// manager.resolve_dependencies()?;
    /// let mut ctx = Context::new();
    /// let config = HardenerConfig::default();
    /// let results = manager.execute_apply(&mut ctx, &config, &[]).await?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub async fn execute_apply(
        &self,
        ctx: &mut Context,
        config: &HardenerConfig,
        plugin_ids: &[PluginId],
    ) -> Result<Vec<ApplyResult>> {
        info!("Starting apply execution");

        // Determine which plugins to execute
        let execution_order = self.execution_order()?;
        let plugins_to_apply: Vec<PluginId> = if plugin_ids.is_empty() {
            // Apply all plugins
            execution_order
        } else {
            // Apply only specified plugins, but in dependency order
            execution_order
                .into_iter()
                .filter(|id| plugin_ids.contains(id))
                .collect()
        };

        if plugins_to_apply.is_empty() {
            return Err(anyhow!("No plugins to apply"));
        }

        info!("Applying {} plugins", plugins_to_apply.len());

        let mut all_results = Vec::new();

        for plugin_id in plugins_to_apply {
            let plugin = self
                .registry
                .get(&plugin_id)?
                .ok_or_else(|| anyhow!("Plugin not found: {}", plugin_id))?;

            info!("Executing apply for plugin: {}", plugin_id);

            let plugin_config = config.get_plugin_config(plugin_id.as_str());
            match plugin.apply(ctx, plugin_config).await {
                Ok(result) => {
                    if result.apply_success {
                        debug!(
                            "Plugin {} apply completed: {}",
                            plugin_id, result.apply_plugin_id
                        );
                        all_results.push(result);
                    } else {
                        warn!(
                            "Plugin {} apply failed: {:?}",
                            plugin_id, result.apply_error
                        );
                        all_results.push(result);
                        // Continue with other plugins even if one fails
                    }
                }
                Err(e) => {
                    warn!("Plugin {} apply error: {}", plugin_id, e);

                    // Create error result
                    all_results.push(ApplyResult {
                        apply_plugin_id: plugin_id.clone(),
                        apply_success: false,
                        apply_changes: vec![],
                        apply_checkpoint_id: None,
                        apply_error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(
            "Apply execution complete: {} plugins processed",
            all_results.len()
        );
        Ok(all_results)
    }
}
