//! Integration tests for PluginManager.
//!
//! Tests dependency resolution, execution order, and plugin workflows.

use hardener_core::testing::MockPlugin;
use hardener_core::{Context, HardenerConfig, PluginManager, PluginRegistry};

/// Tests basic dependency resolution with a valid chain: A → B → C.
///
/// Verifies that:
/// - All plugins are registered successfully
/// - Dependencies are resolved without errors
/// - No circular dependencies are detected
#[test]
fn test_dependency_resolution_valid_chain() {
    // Create registry and register plugins in random order
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-b").depends_on(&["plugin-a"]),
        ))
        .unwrap();
    registry
        .register(Box::new(MockPlugin::new("plugin-a")))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-c").depends_on(&["plugin-b"]),
        ))
        .unwrap();

    // Create plugin manager
    let mut manager = PluginManager::new(registry);

    // Resolve dependencies - should succeed
    let result = manager.resolve_dependencies();
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
    registry
        .register(Box::new(
            MockPlugin::new("plugin-b").depends_on(&["plugin-a"]),
        ))
        .unwrap();

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
    registry
        .register(Box::new(
            MockPlugin::new("plugin-circular").depends_on(&["plugin-circular-b"]),
        ))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-circular-b").depends_on(&["plugin-circular"]),
        ))
        .unwrap();
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
/// - For chain A ← B ← C, order is [A, B, C]
#[test]
fn test_execution_order_respects_dependencies() {
    // Create registry and register plugins in random order
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-c").depends_on(&["plugin-b"]),
        ))
        .unwrap();
    registry
        .register(Box::new(MockPlugin::new("plugin-a")))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-b").depends_on(&["plugin-a"]),
        ))
        .unwrap();

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
#[tokio::test]
async fn test_execute_scan_workflow() {
    // Create registry and register plugins
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(MockPlugin::new("plugin-a")))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-b").depends_on(&["plugin-a"]),
        ))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-c").depends_on(&["plugin-b"]),
        ))
        .unwrap();

    // Create plugin manager and resolve dependencies
    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();

    // Create context and config for scanning
    let ctx = Context::new();
    let config = HardenerConfig::default();

    // Execute scan
    let results = manager.execute_scan(&ctx, &config).await.unwrap();

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

/// Tests that `execute_scan` threads the `HardenerConfig` it is given down
/// to each plugin's own `scan()`, rather than only using it to resolve
/// dependency order.
///
/// This is the manager-level counterpart to the per-plugin config tests:
/// those prove each plugin's `scan()` honours its `PluginConfig` when called
/// directly; this proves `PluginManager::execute_scan` (the entry point the
/// scheduler daemon runs scans through, and the shape the CLI and desktop
/// scan paths mirror) is the thing actually resolving and passing that
/// `PluginConfig` in the first place. The mock is registered under the real
/// `kernel-hardening` ID specifically so `HardenerConfig::get_plugin_config`
/// routes it to `config.kernel` exactly as it would the real plugin.
#[tokio::test]
async fn test_execute_scan_honours_directive_override() {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(
            MockPlugin::new("kernel-hardening").directive_sensitive("mock-directive"),
        ))
        .unwrap();

    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();
    let ctx = Context::new();

    // Default config carries no directives, so the plugin's (mock)
    // baseline-compliant value has nothing stricter to fail against.
    let baseline = manager
        .execute_scan(&ctx, &HardenerConfig::default())
        .await
        .unwrap();
    assert_eq!(baseline.len(), 1, "the one registered plugin should scan");
    assert!(
        baseline[0].scan_findings.is_empty(),
        "default config has no directive override; execute_scan should report no finding"
    );

    // The same key, set as a stricter directive under [kernel], must reach
    // the plugin via execute_scan and flip the finding on.
    let mut strict_config = HardenerConfig::default();
    strict_config
        .kernel
        .directives
        .insert("mock-directive".to_string(), "strict-value".to_string());

    let strict = manager.execute_scan(&ctx, &strict_config).await.unwrap();
    assert_eq!(strict.len(), 1, "the one registered plugin should scan");
    assert_eq!(
        strict[0].scan_findings.len(),
        1,
        "a [kernel] directive override must reach the plugin's scan via execute_scan"
    );
    assert_eq!(
        strict[0].scan_findings[0].finding_recommended_value, "strict-value",
        "the finding should carry the directive's value through from the config"
    );
}

/// Tests apply execution across multiple plugins.
///
/// Verifies that:
/// - All registered plugins can apply changes
/// - Results are aggregated correctly
/// - Apply executes in dependency order
#[tokio::test]
async fn test_execute_apply_workflow() {
    // Create registry and register plugins
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(MockPlugin::new("plugin-a")))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-b").depends_on(&["plugin-a"]),
        ))
        .unwrap();
    registry
        .register(Box::new(
            MockPlugin::new("plugin-c").depends_on(&["plugin-b"]),
        ))
        .unwrap();

    // Create plugin manager and resolve dependencies
    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();

    // Create context and config
    let mut ctx = Context::new();
    let config = HardenerConfig::default();

    // Execute apply on all plugins (empty vec = all plugins)
    let results = manager.execute_apply(&mut ctx, &config, &[]).await.unwrap();

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

/// `execute_scan` is the entry point the scheduler daemon runs scans through,
/// and it resolved each plugin's `PluginConfig` without ever asking whether the
/// config enables that plugin at all. A scheduled scan therefore ran plugins
/// the operator had turned off, and every host in the fleet kept reporting
/// findings for them.
///
/// Registered under real plugin IDs so `is_plugin_enabled` and
/// `get_plugin_config` route to `config.kernel` and `config.ssh` exactly as
/// they would for the real plugins.
#[tokio::test]
async fn execute_scan_skips_a_plugin_the_config_disables() {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(MockPlugin::new("kernel-hardening")))
        .unwrap();
    registry
        .register(Box::new(MockPlugin::new("ssh-hardening")))
        .unwrap();

    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();
    let ctx = Context::new();

    let mut config = HardenerConfig::default();
    config.kernel.enabled = Some(false);

    let results = manager.execute_scan(&ctx, &config).await.unwrap();

    let scanned: Vec<String> = results
        .iter()
        .map(|r| r.scan_plugin_id.to_string())
        .collect();
    assert!(
        !scanned.contains(&"kernel-hardening".to_string()),
        "a disabled plugin must not be scanned: {scanned:?}"
    );
    assert!(
        scanned.contains(&"ssh-hardening".to_string()),
        "an enabled plugin must still be scanned: {scanned:?}"
    );
}
