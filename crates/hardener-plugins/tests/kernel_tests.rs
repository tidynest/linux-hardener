use hardener_common::types::FindingCategory;
use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::KernelHardeningPlugin;

#[test]
fn test_kernel_plugin_metadata() {
    let plugin = KernelHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.as_str(), "kernel-hardening");
    assert_eq!(metadata.plugin_name, "Kernel Hardening");
    assert_eq!(metadata.plugin_category, FindingCategory::Kernel);
    assert!(metadata.plugin_description.contains("sysctl"));
    assert!(!metadata.plugin_version.is_empty());
}

#[test]
fn test_kernel_plugin_has_no_dependencies() {
    let plugin = KernelHardeningPlugin::new();
    let deps = plugin.dependencies();

    assert_eq!(deps.len(), 0, "Kernel plugin should have no dependencies");
}

/// Declared environment smoke test. `Context::new()` hands the plugin a
/// `LocalExecutor`, so this runs against whatever host executes it, and it may
/// therefore assert only what is true on every host: the call completed, it
/// answered for this plugin, and it recorded how long it took. The
/// deterministic coverage of what the scan actually finds lives in
/// `kernel_mock_tests.rs`, where the sysctl values are fixture-supplied and so
/// the expected findings are known.
///
/// It used to check the shape of `scan_findings.first()` inside an
/// `if let Some(..)`, which asserted nothing at all on a host that happens to
/// be compliant, and the standing rule here is that doing nothing must never
/// exit 0. `kernel_mock_tests.rs:251` covers that shape against a known value.
/// It also asserted `scan_success`, which the scan sets to the literal `true`
/// at its only return site, so that assertion could not have failed either.
#[tokio::test]
async fn kernel_scan_host_smoke_test() {
    let plugin = KernelHardeningPlugin::new();
    let ctx = Context::new();

    let scan_result = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("the kernel scan reports a parameter it could not read through scan_unchecked, never as Err");

    assert_eq!(scan_result.scan_plugin_id.as_str(), "kernel-hardening");
    assert!(
        scan_result.scan_duration_us > 0,
        "Should record scan duration in microseconds"
    );
}

/// Declared environment smoke test, under the same `LocalExecutor` caveat as
/// the scan above: it runs against the executing host, so it may assert only
/// host-invariants. What validate previews for a given host state is covered
/// deterministically in `kernel_mock_tests.rs` (compliant, drifted, read-only
/// and absent parameters each have their own fixture).
#[tokio::test]
async fn kernel_validate_host_smoke_test() {
    let plugin = KernelHardeningPlugin::new();
    let ctx = Context::new();
    let config = PluginConfig::default();

    let validation = plugin
        .validate(&ctx, &config)
        .await
        .expect("kernel validate reports an undeterminable parameter as an issue, never as Err");

    assert_eq!(
        validation.validation_report_plugin_id.as_str(),
        "kernel-hardening"
    );

    // Validate examines every kernel parameter and files each into exactly one
    // of pending / already-compliant / issues, so their total is non-zero on
    // any host. (It is not "estimated_changes must be non-empty": a fully
    // compliant host legitimately has zero pending changes, with every
    // parameter counted in validation_report_compliant_count instead.)
    //
    // The one arm that files a parameter into none of the three is the
    // excepted one, which `continue`s into validation_report_exceptions
    // instead. It cannot be reached from here: `PluginConfig::default()`
    // carries an empty exception map. So this stays a host-invariant rather
    // than a measurement of the machine, which is why it survived the sweep
    // that removed this file's host-dependent assertions.
    let examined = validation.validation_report_estimated_changes.len()
        + validation.validation_report_compliant_count
        + validation.validation_report_issues.len();
    assert!(
        examined > 0,
        "validate should examine the kernel parameters"
    );
}

#[tokio::test]
#[ignore] // Run manually with: sudo cargo test kernel_apply -- --ignored --nocapture
async fn test_kernel_apply_requires_root() {
    let plugin = KernelHardeningPlugin::new();
    let mut ctx = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.as_str(), "kernel-hardening");
            assert!(
                apply_result.apply_success,
                "Apply should succeed with root privileges"
            );
        }
        // The arm used to be empty, excused as "expected if not running as
        // root". Nothing runs this test except someone who deliberately asked
        // for it with `--ignored`, and the invocation above it says to ask as
        // root, so an `Err` here is a real failure and not an absent
        // privilege. Swallowing it let the one test covering apply exit 0
        // having asserted nothing at all.
        Err(e) => panic!("kernel apply failed: {e}"),
    }
}
