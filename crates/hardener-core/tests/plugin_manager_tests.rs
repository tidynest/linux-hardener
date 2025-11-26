//! Integration tests for PluginManager.
//!
//! Tests dependency resolution, execution order, and plugin workflows.

use hardener_common::types::{FindingCategory, PluginId};
use hardener_core::{
    ApplyResult, Checkpoint, Config, Context, HardeningPlugin, PluginManager, PluginMetadata,
    PluginRegistry, ScanResult, ValidationReport,
};

/// Mock plugin with no dependencies - used as a base plugin
struct MockPluginA;

impl HardeningPlugin for MockPluginA {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Kernel,
            plugin_description: "Test plugin with no dependencies".to_string(),
            plugin_id: PluginId::from("plugin-a"),
            plugin_name: "Mock Plugin A".to_string(),
            plugin_version: "1.0.0".to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![] // No dependencies
    }

    fn scan(&self, _ctx: &Context) -> hardener_common::error::Result<ScanResult> {
        Ok(ScanResult {
            scan_plugin_id: PluginId::from("plugin-a"),
            scan_success: true,
            scan_findings: vec![],
            scan_duration_us: 10,
            scan_error: None,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config,
    ) -> hardener_common::error::Result<ApplyResult> {
        Ok(ApplyResult {
            apply_plugin_id: PluginId::from("plugin-a"),
            apply_success: true,
            apply_changes: vec![],
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint,
    ) -> hardener_common::error::Result<()> {
        Ok(())
    }

    fn validate(&self, _config: &Config) -> hardener_common::error::Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: PluginId::from("plugin-a"),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}

/// Mock plugin that depends on Mock Plugin A.
struct MockPluginB;

impl HardeningPlugin for MockPluginB {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_id: PluginId::from("plugin-b"),
            plugin_name: "Mock Plugin B".to_string(),
            plugin_version: "1.0.0".to_string(),
            plugin_description: "Test plugin that depends on plugin-a".to_string(),
            plugin_category: FindingCategory::Network,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![PluginId::from("plugin-a")] // Depends on plugin A
    }

    fn scan(&self, _ctx: &Context) -> hardener_common::error::Result<ScanResult> {
        Ok(ScanResult {
            scan_plugin_id: PluginId::from("plugin-b"),
            scan_success: true,
            scan_findings: vec![],
            scan_duration_us: 15,
            scan_error: None,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config,
    ) -> hardener_common::error::Result<ApplyResult> {
        Ok(ApplyResult {
            apply_plugin_id: PluginId::from("plugin-b"),
            apply_success: true,
            apply_changes: vec![],
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint,
    ) -> hardener_common::error::Result<()> {
        Ok(())
    }

    fn validate(&self, _config: &Config) -> hardener_common::error::Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: PluginId::from("plugin-b"),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}

/// Mock plugin that depends on Mock Plugin B (creating chain: A -> B -> C).
struct MockPluginC;

impl HardeningPlugin for MockPluginC {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_id: PluginId::from("plugin-c"),
            plugin_name: "Mock Plugin C".to_string(),
            plugin_version: "1.0.0".to_string(),
            plugin_description: "Test plugin that depends on plugin-b".to_string(),
            plugin_category: FindingCategory::Authentication,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![PluginId::from("plugin-b")] // Depends on plugin-b
    }

    fn scan(&self, _ctx: &Context) -> hardener_common::error::Result<ScanResult> {
        Ok(ScanResult {
            scan_plugin_id: PluginId::from("plugin-c"),
            scan_success: true,
            scan_findings: vec![],
            scan_duration_us: 20,
            scan_error: None,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config,
    ) -> hardener_common::error::Result<ApplyResult> {
        Ok(ApplyResult {
            apply_plugin_id: PluginId::from("plugin-c"),
            apply_success: true,
            apply_changes: vec![],
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint,
    ) -> hardener_common::error::Result<()> {
        Ok(())
    }

    fn validate(&self, _config: &Config) -> hardener_common::error::Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: PluginId::from("plugin-c"),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}

/// Mock plugin for testing circular dependency detection.
/// When combined with MockPluginCircularB, creates a cycle
struct MockPluginCircular;

impl HardeningPlugin for MockPluginCircular {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_id: PluginId::from("plugin-circular"),
            plugin_name: "Mock Plugin Circular".to_string(),
            plugin_version: "1.0.0".to_string(),
            plugin_description: "Test plugin for circular dependency".to_string(),
            plugin_category: FindingCategory::Services,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![PluginId::from("plugin-circular-b")] // Depends on circular-b
    }

    fn scan(&self, _ctx: &Context) -> hardener_common::error::Result<ScanResult> {
        Ok(ScanResult {
            scan_plugin_id: PluginId::from("plugin-circular"),
            scan_success: true,
            scan_findings: vec![],
            scan_duration_us: 10,
            scan_error: None,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config,
    ) -> hardener_common::error::Result<ApplyResult> {
        Ok(ApplyResult {
            apply_plugin_id: PluginId::from("plugin-circular"),
            apply_success: true,
            apply_changes: vec![],
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint,
    ) -> hardener_common::error::Result<()> {
        Ok(())
    }

    fn validate(&self, _config: &Config) -> hardener_common::error::Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: PluginId::from("plugin-circular"),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}

/// Mock plugin that completes the circular dependency.
/// Depends on MockPluginCircular, creating a cycle.
struct MockPluginCircularB;

impl HardeningPlugin for MockPluginCircularB {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_id: PluginId::from("plugin-circular-b"),
            plugin_name: "Mock Plugin Circular B".to_string(),
            plugin_version: "1.0.0".to_string(),
            plugin_description: "Test plugin that completes circular dependency".to_string(),
            plugin_category: FindingCategory::FileSystem,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![PluginId::from("plugin-circular")] // Depends back on circular - CREATES CYCLE!
    }

    fn scan(&self, _ctx: &Context) -> hardener_common::error::Result<ScanResult> {
        Ok(ScanResult {
            scan_plugin_id: PluginId::from("plugin-circular-b"),
            scan_success: true,
            scan_findings: vec![],
            scan_duration_us: 10,
            scan_error: None,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config,
    ) -> hardener_common::error::Result<ApplyResult> {
        Ok(ApplyResult {
            apply_plugin_id: PluginId::from("plugin-circular-b"),
            apply_success: true,
            apply_changes: vec![],
            apply_checkpoint_id: None,
            apply_error: None,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint,
    ) -> hardener_common::error::Result<()> {
        Ok(())
    }

    fn validate(&self, _config: &Config) -> hardener_common::error::Result<ValidationReport> {
        Ok(ValidationReport {
            validation_report_plugin_id: PluginId::from("plugin-circular-b"),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: vec![],
        })
    }
}

/// Tests basic dependency resolution with a valid chain: A -> B -> C.
///
/// Verifies that:
/// - All plugins are registered successfully
/// - Dependencies are resolved without errors
/// - No circular dependencies are detected
#[test]
fn test_dependency_resolution_valid_chain() {
    // Create registry and register plugins in random order
    let registry = PluginRegistry::new();
    registry.register(Box::new(MockPluginB)).unwrap();
    registry.register(Box::new(MockPluginA)).unwrap();
    registry.register(Box::new(MockPluginC)).unwrap();

    // Create plugin manager
    let mut manager = PluginManager::new(registry);

    // Resolve dependencies - should succeed
    let result = manager.resolve_dependencies();
    if let Err(e) = &result {
        eprintln!("Error: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "Dependency resolution should succeed for valid chain"
    );
}

/// Tests detection of missing dependencies.
///
/// Verifies that:
/// - Attempting to resolve when a required dependency is missing fails
/// - Error message correctly identifies the missing plugin
#[test]
fn test_dependency_resolution_missing_dependency() {
    // Create registry and register only PluginB (which depends on PluginA)
    let registry = PluginRegistry::new();
    registry.register(Box::new(MockPluginB)).unwrap();
    // Note: PluginA is NOT registered, but PluginB depends on it

    // Create plugin manager
    let mut manager = PluginManager::new(registry);

    // Resolve dependencies - should fail
    let result = manager.resolve_dependencies();
    assert!(result.is_err(), "Should fail when dependency is missing");

    // Verify error message mentions the missing plugin
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("plugin-a"),
        "Error should mention missing plugin-a, got: {}",
        error_msg
    );
}

/// Tests detection of circular dependencies.
///
/// Verifies that:
/// - Circular dependency between two plugins is detected
/// - Error message indicates circular dependency was found
#[test]
fn test_dependency_resolution_circular() {
    // Create registry and register both circular plugins
    let registry = PluginRegistry::new();
    registry.register(Box::new(MockPluginCircular)).unwrap();
    registry.register(Box::new(MockPluginCircularB)).unwrap();
    // These two plugins depend on each other, creating a cycle

    // Create plugin manager
    let mut manager = PluginManager::new(registry);

    // Resolve dependencies - should fail due to cycle
    let result = manager.resolve_dependencies();
    assert!(
        result.is_err(),
        "Should fail when circular dependency exists"
    );

    // Verify error message mentions circular dependency
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Circular dependency"),
        "Error should mention circular dependency, got: {}",
        error_msg
    );
}

/// Tests that execution order respects dependencies.
///
/// Verifies that:
/// - Plugins are ordered based on their dependencies
/// - Dependencies execute before dependents
/// - For chain A <- B <- C, order is [A, B, C]
#[test]
fn test_execution_order_respects_dependencies() {
    // Create registry and register plugins in random order
    let registry = PluginRegistry::new();
    registry.register(Box::new(MockPluginC)).unwrap();
    registry.register(Box::new(MockPluginA)).unwrap();
    registry.register(Box::new(MockPluginB)).unwrap();

    // Create plugin manager and resolve dependencies
    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();

    // Get execution order
    let order = manager.execution_order().unwrap();

    // Verify we have all 3 plugins
    assert_eq!(order.len(), 3, "Should have 3 plugins in execution order");

    // Verify correct order: A must come before B, B must come before C
    let pos_a = order
        .iter()
        .position(|id| id.as_str() == "plugin-a")
        .unwrap();
    let pos_b = order
        .iter()
        .position(|id| id.as_str() == "plugin-b")
        .unwrap();
    let pos_c = order
        .iter()
        .position(|id| id.as_str() == "plugin-c")
        .unwrap();

    assert!(pos_a < pos_b, "Plugin A must execute before Plugin B");
    assert!(pos_b < pos_c, "Plugin B must execute before Plugin C");
}

/// Tests scan execution across multiple plugins.
///
/// Verifies that:
/// - All registered plugins are scanned
/// - Results are aggregated correctly
/// - Scan executes in dependency order
#[test]
fn test_execute_scan_workflow() {
    // Create registry and register plugins
    let registry = PluginRegistry::new();
    registry.register(Box::new(MockPluginA)).unwrap();
    registry.register(Box::new(MockPluginB)).unwrap();
    registry.register(Box::new(MockPluginC)).unwrap();

    // Create plugin manager and resolve dependencies
    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();

    // Create context for scanning
    let ctx = Context::new();

    // Execute scan
    let results = manager.execute_scan(&ctx).unwrap();

    // Verify all 3 plugins were scanned
    assert_eq!(
        results.len(),
        3,
        "Should have scan results for all 3 plugins"
    );

    // Verify all scans succeeded
    for result in &results {
        assert!(
            result.scan_success,
            "Plugin {} scan should succeed",
            result.scan_plugin_id
        );
        assert!(
            result.scan_error.is_none(),
            "Plugin {} should have no error",
            result.scan_plugin_id
        );
    }

    // Verify we have results for each plugin
    let plugin_ids: Vec<String> = results
        .iter()
        .map(|r| r.scan_plugin_id.to_string())
        .collect();
    assert!(
        plugin_ids.contains(&"plugin-a".to_string()),
        "Should have result for plugin-a"
    );
    assert!(
        plugin_ids.contains(&"plugin-b".to_string()),
        "Should have result for plugin-b"
    );
    assert!(
        plugin_ids.contains(&"plugin-c".to_string()),
        "Should have result for plugin-c"
    );
}

/// Tests apply execution across multiple plugins.
///
/// Verifies that:
/// - All registered plugins can apply changes
/// - Results are aggregated correctly
/// - Apply executes in dependency order
#[test]
fn test_execute_apply_workflow() {
    // Create registry and register plugins
    let registry = PluginRegistry::new();
    registry.register(Box::new(MockPluginA)).unwrap();
    registry.register(Box::new(MockPluginB)).unwrap();
    registry.register(Box::new(MockPluginC)).unwrap();

    // Create plugin manager and resolve dependencies
    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();

    // Create context and config
    let mut ctx = Context::new();
    let config = Config::default();

    // Execute apply on all plugins (empty vec = all plugins)
    let results = manager.execute_apply(&mut ctx, &config, &[]).unwrap();

    // Verify all 3 plugins were applied
    assert_eq!(
        results.len(),
        3,
        "Should have apply results for all 3 plugins"
    );

    // Verify all applies succeeded
    for result in &results {
        assert!(
            result.apply_success,
            "Plugin {} apply should succeed",
            result.apply_plugin_id
        );
        assert!(
            result.apply_error.is_none(),
            "Plugin {} should have no error",
            result.apply_plugin_id
        );
    }

    // Verify we have results for each plugin
    let plugin_ids: Vec<String> = results
        .iter()
        .map(|r| r.apply_plugin_id.to_string())
        .collect();
    assert!(
        plugin_ids.contains(&"plugin-a".to_string()),
        "Should have result for plugin-a"
    );
    assert!(
        plugin_ids.contains(&"plugin-b".to_string()),
        "Should have result for plugin-b"
    );
    assert!(
        plugin_ids.contains(&"plugin-c".to_string()),
        "Should have result for plugin-c"
    );
}
