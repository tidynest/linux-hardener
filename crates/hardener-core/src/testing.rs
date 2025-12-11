//! Test utilities for hardener-core.
//!
//! Provides MockPlugin for testing plugin-related functionality.

use crate::{
    ApplyResult, Checkpoint, Config, Context, HardeningPlugin, PluginMetadata, ScanResult,
    ValidationReport,
};
use async_trait::async_trait;
use hardener_common::{
    error::Result,
    types::{FindingCategory, PluginId},
};

/// A configurable mock plugin for testing.
///
/// # Examples
///
/// ```ignore
/// // Simple plugin with no dependencies
/// let plugin = MockPlugin::new("test-plugin");
///
/// // Plugin with dependencies
/// let plugin = MockPlugin::new("dependent").depends_on(&["base-plugin"]);
///
/// // Plugin that fails on scan
/// let plugin = MockPlugin::new("failing").fail_scan();
/// ```
pub struct MockPlugin {
    plugin_id: String,
    plugin_name: String,
    plugin_description: String,
    plugin_category: FindingCategory,
    plugin_dependencies: Vec<PluginId>,
    plugin_fail_scan: bool,
    plugin_fail_apply: bool,
}

impl MockPlugin {
    /// Creates a new mock plugin with the given ID.
    pub fn new(plugin_id: &str) -> MockPlugin {
        MockPlugin {
            plugin_id: plugin_id.to_string(),
            plugin_name: format!("Mock {}", plugin_id),
            plugin_description: format!("Mock plugin: {}", plugin_id),
            plugin_category: FindingCategory::Kernel,
            plugin_dependencies: vec![],
            plugin_fail_scan: false,
            plugin_fail_apply: false,
        }
    }

    /// Sets a custom name for the plugin.
    pub fn name(mut self, name: &str) -> MockPlugin {
        self.plugin_name = name.to_string();
        self
    }

    /// Sets a custom description for the plugin.
    pub fn description(mut self, desc: &str) -> MockPlugin {
        self.plugin_description = desc.to_string();
        self
    }

    /// Sets the plugin category.
    pub fn category(mut self, category: FindingCategory) -> MockPlugin {
        self.plugin_category = category;
        self
    }

    /// Adds dependencies to the mock plugin.
    pub fn depends_on(mut self, deps: &[&str]) -> MockPlugin {
        self.plugin_dependencies = deps.iter().map(|d| PluginId::new(*d)).collect();
        self
    }

    /// Configures the mock to fail on scan.
    pub fn fail_scan(mut self) -> MockPlugin {
        self.plugin_fail_scan = true;
        self
    }

    /// Configures the mock to fail on apply.
    pub fn fail_apply(mut self) -> MockPlugin {
        self.plugin_fail_apply = true;
        self
    }
}

#[async_trait]
impl HardeningPlugin for MockPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_id: PluginId::new(&self.plugin_id),
            plugin_name: self.plugin_name.clone(),
            plugin_version: "1.0.0".to_string(),
            plugin_description: self.plugin_description.clone(),
            plugin_category: self.plugin_category,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        self.plugin_dependencies.clone()
    }

    async fn scan(&self, _ctx: &Context) -> Result<ScanResult> {
        if self.plugin_fail_scan {
            return Err(hardener_common::error::HardeningError::Plugin(
                "Mock scan failure".to_string(),
            ));
        }
        Ok(ScanResult {
            scan_plugin_id: PluginId::new(&self.plugin_id),
            scan_success: true,
            scan_findings: vec![],
            scan_duration_us: 10,
            scan_error: None,
        })
    }

    async fn apply(&self, _ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        if self.plugin_fail_apply {
            return Err(hardener_common::error::HardeningError::Plugin(
                "Mock apply failure".to_string(),
            ));
        }
        Ok(ApplyResult {
            apply_plugin_id: PluginId::new(&self.plugin_id),
            apply_success: true,
            apply_changes: vec![],
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    async fn rollback(&self, _ctx: &mut Context, _checkpoint: &Checkpoint) -> Result<()> {
        Ok(())
    }

    async fn validate(&self, _ctx: &Context, _config: &Config) -> Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: PluginId::new(&self.plugin_id),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}
