#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`checkpoint`](super).
//!
//! Split out of `commands/checkpoint.rs`. This file sits in the `checkpoint/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::commands::checkpoint`
//! and every import carried across unchanged, private items included.

use super::*;
use hardener_types::{DivergenceState, ReloadResult, RollbackDivergence};

mod fleet_partial_restore {
    //! Regression for issue #67 surviving on the fleet path (`batch.rs`):
    //! `rollback_one` used to dispatch the reload only inside
    //! `Ok(mut r) if r.rollback_success`, so a checkpoint where some files
    //! came back and others did not (`rollback_success == false`) got no
    //! reload at all for the files that genuinely were restored. The fix
    //! made `reload_restored_paths` (called from both the local and the
    //! fleet path) the one place this decision is made, and it looks only at
    //! each file's own `restore_success`, never at the checkpoint's overall
    //! one.
    //!
    //! `rollback_one` itself cannot be driven from a unit test: it opens a
    //! real SSH connection via `SshExecutor::connect` before it ever reaches
    //! this logic, and there is no seam to inject a mock there. What *can*
    //! be exercised directly, with no network and no privilege, is
    //! `reload_restored_paths`, the exact function both call sites now share
    //! (Finding 5) and the only place the success/failure decision is made
    //! (Finding 1). This module builds the same `RollbackResult` shape a
    //! partial restore produces (three files back, one not, so
    //! `rollback_success == false`) and proves the three that came back are
    //! still offered to their plugin.
    //!
    //! A stub plugin, module-scoped so it cannot leak into the rest of this
    //! file's tests, stands in for a real one so the assertion is not at the
    //! mercy of any real plugin's `systemctl`/`sshd -t` behaviour.
    use super::*;
    use hardener_common::executor::MockExecutor;
    use hardener_common::types::{FindingCategory, PluginId};
    use hardener_core::plugin::{
        ApplyResult, HardeningPlugin, PluginMetadata, ScanResult, ValidationReport,
    };
    use hardener_core::{PluginConfig, PluginRegistry};
    use hardener_types::{FileRestoreAction, FileRestoreResult};
    use std::path::Path;

    /// Claims every `/etc/stub/*` path and reports a successful reload.
    #[derive(Default)]
    struct StubPlugin;

    #[async_trait::async_trait]
    impl HardeningPlugin for StubPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                plugin_category: FindingCategory::Network,
                plugin_description: "Stub plugin for the fleet reload-dispatch test.".to_string(),
                plugin_id: PluginId::from("stub"),
                plugin_name: "stub".to_string(),
                plugin_version: "0.1.0".to_string(),
            }
        }

        fn dependencies(&self) -> Vec<PluginId> {
            Vec::new()
        }

        async fn scan(
            &self,
            _ctx: &Context,
            _config: &PluginConfig,
        ) -> hardener_common::error::Result<ScanResult> {
            unimplemented!("not exercised by this test")
        }

        async fn apply(
            &self,
            _ctx: &mut Context,
            _config: &PluginConfig,
        ) -> hardener_common::error::Result<ApplyResult> {
            unimplemented!("not exercised by this test")
        }

        async fn validate(
            &self,
            _ctx: &Context,
            _config: &PluginConfig,
        ) -> hardener_common::error::Result<ValidationReport> {
            unimplemented!("not exercised by this test")
        }

        fn reloads_for_path(&self, path: &Path) -> bool {
            path.starts_with("/etc/stub")
        }

        async fn reload_after_rollback(
            &self,
            _ctx: &Context,
        ) -> hardener_common::error::Result<Option<String>> {
            Ok(Some("stub reloaded".to_string()))
        }

        async fn divergences_after_rollback(
            &self,
            _ctx: &Context,
            _restored: &[std::path::PathBuf],
        ) -> Vec<RollbackDivergence> {
            // Test stub: models nothing about a real subsystem.
            Vec::new()
        }
    }

    fn restored(path: &str) -> FileRestoreResult {
        FileRestoreResult {
            restore_path: path.to_string(),
            restore_action: FileRestoreAction::Restored,
            restore_success: true,
            restore_error: None,
        }
    }

    fn failed_restore(path: &str) -> FileRestoreResult {
        FileRestoreResult {
            restore_path: path.to_string(),
            restore_action: FileRestoreAction::Restored,
            restore_success: false,
            restore_error: Some("permission denied".to_string()),
        }
    }

    #[tokio::test]
    async fn a_partially_restored_checkpoint_still_reloads_what_came_back() {
        let mut result = RollbackResult {
            rollback_checkpoint_id: "cp_1".to_string(),
            rollback_checkpoint_name: "before-upgrade".to_string(),
            // False because /etc/stub/four did not come back; this is the
            // exact condition the old fleet-path guard tested for and
            // skipped the reload dispatch entirely on.
            rollback_success: false,
            rollback_files: vec![
                restored("/etc/stub/one"),
                restored("/etc/stub/two"),
                restored("/etc/stub/three"),
                failed_restore("/etc/stub/four"),
            ],
            rollback_reloads: Vec::new(),
            rollback_divergences: Vec::new(),
        };

        let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
        let registry = PluginRegistry::new();
        registry
            .register(Box::new(StubPlugin))
            .expect("stub registers cleanly into an empty registry");

        reload_restored_paths(&ctx, &registry, &mut result).await;

        assert_eq!(
            result.rollback_reloads.len(),
            1,
            "the plugin owning the three restored /etc/stub/* paths must still be \
             asked to reload even though the checkpoint as a whole did not fully \
             restore: {:?}",
            result.rollback_reloads
        );
        assert!(
            result.rollback_reloads[0].reload_success,
            "the stub plugin reports success for what it was actually asked to \
             reload: {:?}",
            result.rollback_reloads[0]
        );
    }
}

mod nothing_restored_never_lists_the_registry {
    //! `plugins_or_reload_failure` (in `hardener-plugins`) turns a registry
    //! that cannot be listed into a `plugin-registry` `ReloadResult` row, so
    //! a checkpoint that restored nothing at all must never reach that call
    //! in the first place: otherwise a transient registry lock issue makes a
    //! clean no-op rollback report a reload failure it never actually
    //! attempted. `reload_restored_paths`'s early return on an empty
    //! restored-paths list is what prevents this.
    //!
    //! Proven with a tripwire plugin whose `metadata()` panics on its second
    //! call: the first call is `PluginRegistry::register`'s own lookup of
    //! the plugin id, which must succeed; any further call could only come
    //! from `PluginRegistry::list`, which only the reload dispatch would
    //! trigger. A passing test means that dispatch never ran.
    use super::*;
    use hardener_common::executor::MockExecutor;
    use hardener_common::types::{FindingCategory, PluginId};
    use hardener_core::plugin::{
        ApplyResult, HardeningPlugin, PluginMetadata, ScanResult, ValidationReport,
    };
    use hardener_core::{PluginConfig, PluginRegistry};
    use hardener_types::{FileRestoreAction, FileRestoreResult};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct TripwirePlugin {
        metadata_already_read: AtomicBool,
    }

    #[async_trait::async_trait]
    impl HardeningPlugin for TripwirePlugin {
        fn metadata(&self) -> PluginMetadata {
            if self.metadata_already_read.swap(true, Ordering::SeqCst) {
                panic!(
                    "the reload dispatch listed the registry even though \
                     nothing was restored"
                );
            }
            PluginMetadata {
                plugin_category: FindingCategory::Network,
                plugin_description: "Tripwire plugin for the empty-guard test.".to_string(),
                plugin_id: PluginId::from("tripwire"),
                plugin_name: "tripwire".to_string(),
                plugin_version: "0.1.0".to_string(),
            }
        }

        fn dependencies(&self) -> Vec<PluginId> {
            Vec::new()
        }

        async fn scan(
            &self,
            _ctx: &Context,
            _config: &PluginConfig,
        ) -> hardener_common::error::Result<ScanResult> {
            unimplemented!("not exercised by this test")
        }

        async fn apply(
            &self,
            _ctx: &mut Context,
            _config: &PluginConfig,
        ) -> hardener_common::error::Result<ApplyResult> {
            unimplemented!("not exercised by this test")
        }

        async fn validate(
            &self,
            _ctx: &Context,
            _config: &PluginConfig,
        ) -> hardener_common::error::Result<ValidationReport> {
            unimplemented!("not exercised by this test")
        }

        async fn divergences_after_rollback(
            &self,
            _ctx: &Context,
            _restored: &[std::path::PathBuf],
        ) -> Vec<RollbackDivergence> {
            // Test stub: models nothing about a real subsystem.
            Vec::new()
        }
    }

    #[tokio::test]
    async fn a_checkpoint_that_restored_nothing_is_never_handed_to_the_dispatch() {
        let mut result = RollbackResult {
            rollback_checkpoint_id: "cp_1".to_string(),
            rollback_checkpoint_name: "before-upgrade".to_string(),
            rollback_success: false,
            rollback_files: vec![FileRestoreResult {
                restore_path: "/etc/stub/one".to_string(),
                restore_action: FileRestoreAction::Restored,
                restore_success: false,
                restore_error: Some("permission denied".to_string()),
            }],
            rollback_reloads: Vec::new(),
            rollback_divergences: Vec::new(),
        };

        let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
        let registry = PluginRegistry::new();
        registry
            .register(Box::new(TripwirePlugin::default()))
            .expect("tripwire registers cleanly (its first metadata() call)");

        // No panic here means `PluginRegistry::list` was never called, which
        // means the reload dispatch never ran.
        reload_restored_paths(&ctx, &registry, &mut result).await;

        assert!(
            result.rollback_reloads.is_empty(),
            "a checkpoint that restored nothing must come back with no reload \
             rows at all, not an empty-but-touched Vec: {:?}",
            result.rollback_reloads
        );
    }
}

#[test]
fn a_rollback_whose_reload_failed_does_not_report_success() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: vec![ReloadResult {
            reload_plugin_id: "ssh-hardening".to_string(),
            reload_action: "reload failed".to_string(),
            reload_success: false,
            reload_error: Some("sshd -t refused the restored config".to_string()),
        }],
        rollback_divergences: Vec::new(),
    };
    assert_eq!(
        rollback_failure_reason(&result),
        Some(FailureReason::Reload)
    );
}

#[test]
fn a_rollback_whose_files_failed_says_so_rather_than_blaming_the_reload() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: false,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
        rollback_divergences: Vec::new(),
    };
    assert_eq!(rollback_failure_reason(&result), Some(FailureReason::Files));
}

#[test]
fn a_clean_rollback_has_no_failure_reason() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
        rollback_divergences: Vec::new(),
    };
    assert_eq!(rollback_failure_reason(&result), None);
}

/// Finding 6 (final review): the fleet path has
/// `a_hosts_divergences_reach_the_fleet_summary` (`commands/batch/tests.rs`)
/// proving a divergence does not turn a host into a failure. This is its
/// local-path equivalent, on the function an operator running `hardener
/// rollback` directly actually hits: reporting is reporting, and a `Diverged`
/// or `Unverifiable` row must never make `rollback_failure_reason` return
/// `Some`, or a rollback an operator ran clean would exit non-zero over
/// something that is not a failure.
#[test]
fn a_clean_rollback_carrying_divergences_still_has_no_failure_reason() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
        rollback_divergences: vec![
            RollbackDivergence {
                divergence_plugin_id: "kernel-hardening".to_string(),
                divergence_subject: "kernel.kptr_restrict".to_string(),
                divergence_state: DivergenceState::Diverged,
                divergence_detail: "no configuration file names it".to_string(),
                divergence_expected: None,
            },
            RollbackDivergence {
                divergence_plugin_id: "firewall-hardening".to_string(),
                divergence_subject: "ufw".to_string(),
                divergence_state: DivergenceState::Unverifiable,
                divergence_detail: "ufw status could not be run".to_string(),
                divergence_expected: None,
            },
        ],
    };
    assert_eq!(rollback_failure_reason(&result), None);
}
