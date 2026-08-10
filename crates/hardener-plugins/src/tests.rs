#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for the crate root.
//!
//! Split out of `lib.rs`. Unlike a root module that leans on `use super::*`,
//! this block already reached the crate through `crate::` and an absolute path,
//! so every import carried across unchanged.

use hardener_core::plugin::HardeningPlugin;

use crate::define_plugin;

// Use the macro to define a test plugin
define_plugin! {
    TestPlugin {
        id: "test-plugin",
        name: "Test Plugin",
        version: "0.1.0",
        description: "A test plugin for macro validation",
        category: Kernel,
        dependencies: [],
    }
}

#[test]
fn test_macro_generates_plugin() {
    // Create an instance
    let plugin = TestPlugin;

    // Test metadata
    let meta = plugin.metadata();
    assert_eq!(meta.plugin_id.to_string(), "test-plugin");
    assert_eq!(meta.plugin_name, "Test Plugin");
    assert_eq!(meta.plugin_version, "0.1.0");
    assert_eq!(
        meta.plugin_description,
        "A test plugin for macro validation"
    );

    // Test dependencies
    let deps = plugin.dependencies();
    assert_eq!(deps.len(), 0);
}

/// `coverage_for` returning `None` for a real plugin would silently strip
/// that plugin's controls from the failure path, handing them back the Pass
/// this table exists to prevent. A new plugin must therefore appear here,
/// and this test is what says so.
#[test]
fn every_registered_plugin_declares_its_coverage() {
    let registry = crate::create_plugin_registry();
    let registered = registry.list().expect("the registry lists its plugins");
    // A registry that listed nothing would satisfy "every registered plugin
    // declares its coverage" by having none, which is the reassuring answer a
    // check that cannot reach the question always gives.
    assert!(
        registered.len() >= 8,
        "the registry listed fewer than the 8 plugins this workspace registers, so the loop below covers less than it was written to; an emptiness guard would pass on a registry down to one"
    );
    for metadata in registered {
        assert!(
            crate::coverage_for(metadata.plugin_id.as_str()).is_some(),
            "plugin '{}' is registered but absent from coverage_table",
            metadata.plugin_id.as_str()
        );
    }
}

/// A plugin the registry lists but `get_plugin_config` does not name falls
/// through to one shared empty default whose `enabled` is `true`. The
/// operator's `enabled = false`, directive overrides and policy exceptions
/// for that plugin are then read as absent rather than as unroutable, so
/// the plugin runs unconfigured, applies baseline values the operator
/// overrode, and reports the deviations its exceptions document as
/// violations.
///
/// The routing is a hand-written match over eight literals because
/// `HardenerConfig` names its sections as struct fields, leaving nothing to
/// derive it from; the registry is the only thing that can say the match is
/// complete. `hardener-core` cannot see the registry, which is why this
/// guard lives here rather than beside the code it guards.
#[test]
fn every_registered_plugin_routes_to_its_own_config_section() {
    let config = hardener_core::HardenerConfig::default();
    // Every unroutable id gets the one shared static, so identity with it
    // is precisely the fell-through state and nothing else.
    let fallback = config.get_plugin_config("no-plugin-answers-to-this-id");

    let registered = crate::create_plugin_registry()
        .list()
        .expect("the registry lists its plugins");
    assert!(
        registered.len() >= 8,
        "the registry listed fewer than the 8 plugins this workspace registers, so the loop below covers less than it was written to; an emptiness guard would pass on a registry down to one"
    );
    for metadata in registered {
        let id = metadata.plugin_id.as_str();
        assert!(
            !std::ptr::eq(config.get_plugin_config(id), fallback),
            "plugin '{id}' is registered but HardenerConfig::get_plugin_config \
             does not route it, so its configuration is silently ignored"
        );
    }
}

#[test]
fn compliance_coverage_spans_multiple_frameworks() {
    use std::collections::HashSet;
    let coverage = crate::compliance_coverage();
    assert!(!coverage.is_empty(), "plugins must declare coverage");

    // Entries are deduplicated by (framework, control_id).
    let unique: HashSet<_> = coverage
        .iter()
        .map(|m| (m.compliance_framework, m.compliance_control_id.as_str()))
        .collect();
    assert_eq!(
        unique.len(),
        coverage.len(),
        "coverage must be deduplicated"
    );

    // CIS is fully wired; at least one non-CIS framework must also be covered
    // or the multi-framework reports would all collapse to manual review.
    let frameworks: HashSet<_> = coverage.iter().map(|m| m.compliance_framework).collect();
    assert!(
        frameworks.len() >= 2,
        "coverage must span multiple frameworks"
    );
}

/// The 11 curated CIS controls wired off ManualReview in the
/// 2026-06-29 CIS-coverage work must all reach `compliance_coverage()`.
/// Each is a catalogued control, so its presence here flips it to Pass/Fail.
#[test]
fn newly_wired_cis_controls_are_all_covered() {
    use hardener_common::types::ComplianceFramework;
    let required = [
        "6.1.2", "6.1.3", "6.1.4", "6.1.5", // permissions
        "3.2.2", "3.2.3", "3.2.4",   // kernel
        "2.1.1",   // services (xinetd)
        "3.4.1.1", // firewall
        "5.3.2", "5.3.3", // pam
    ];
    let covered: Vec<String> = crate::compliance_coverage()
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::CIS)
        .map(|m| m.compliance_control_id)
        .collect();
    for id in required {
        assert!(
            covered.contains(&id.to_string()),
            "CIS {id} missing from coverage"
        );
    }
}

mod backup_pruning {
    use std::sync::Arc;

    use hardener_common::executor::SystemExecutor;
    use hardener_core::{CommandOutput, Context, MockExecutor};

    use crate::{BACKUPS_KEPT, prune_timestamped_backups};

    fn succeeding() -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    /// The oldest go and the newest stay, and the sort that decides which is
    /// which is a text sort over the whole name.
    ///
    /// Asserted on which paths `rm` was given rather than on how many, because
    /// "the surplus was removed" is equally true of a prune that removed the
    /// newest ones.
    ///
    /// The two shapes in the fixture are both real. `/etc/ssh` on the
    /// development host holds `sshd_config.backup.1763680168` beside
    /// `sshd_config.backup.20251209_012340`: the plugin wrote unix seconds
    /// before it wrote a formatted stamp, and both are still there. A text sort
    /// orders those correctly for as long as unix seconds are ten digits
    /// beginning with a 1 and formatted stamps begin with a 2, which is until
    /// the year 2033. Neither shape is generated any more; both are still on
    /// disk to be removed.
    #[tokio::test]
    async fn the_newest_backups_are_kept_and_the_rest_removed() {
        let prefix = "/etc/ssh/sshd_config.backup.";
        let doomed = ["1763680168", "20251209_012340"];
        let kept = ["20260718_112302", "20260810_120000", "20260810_120001"];

        let mut executor = MockExecutor::new().with_command_program("rm", succeeding());
        for stamp in kept.iter().chain(doomed.iter()) {
            executor = executor.with_file(&format!("{prefix}{stamp}"), "Port 22\n");
        }
        let executor = Arc::new(executor);
        let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

        prune_timestamped_backups(&ctx, prefix, BACKUPS_KEPT).await;

        let log = executor.log();
        let (_, args) = log
            .commands_executed
            .iter()
            .find(|(program, _)| program == "rm")
            .expect("a directory over the retention limit must be pruned");
        for stamp in doomed {
            let path = format!("{prefix}{stamp}");
            assert!(
                args.contains(&path),
                "the older backup {path} must be removed, got: {args:?}"
            );
        }
        for stamp in kept {
            let path = format!("{prefix}{stamp}");
            assert!(
                !args.contains(&path),
                "the newest {BACKUPS_KEPT} backups must be kept, but {path} was removed: {args:?}"
            );
        }
    }

    /// The file being backed up, and anything else sharing the directory, is
    /// not a backup. The prefix is the whole of what makes a path a candidate.
    ///
    /// The same fixture proves the count guard: five files sit in the
    /// directory and two of them are backups, so a prune counting entries
    /// rather than backups would be over its limit and delete something.
    #[tokio::test]
    async fn only_paths_carrying_the_prefix_are_candidates() {
        let executor = Arc::new(
            MockExecutor::new()
                .with_command_program("rm", succeeding())
                .with_file("/etc/ssh/sshd_config.backup.20260718_112302", "Port 22\n")
                .with_file("/etc/ssh/sshd_config.backup.20260810_120000", "Port 22\n")
                .with_file("/etc/ssh/sshd_config", "Port 22\n")
                .with_file("/etc/ssh/ssh_config", "Host *\n")
                .with_file("/etc/ssh/sshd_config.d/10-hardening.conf", "Port 22\n"),
        );
        let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

        prune_timestamped_backups(&ctx, "/etc/ssh/sshd_config.backup.", BACKUPS_KEPT).await;

        let log = executor.log();
        assert!(
            !log.commands_executed
                .iter()
                .any(|(program, _)| program == "rm"),
            "a directory holding fewer backups than the retention limit must not be \
             pruned at all, but rm ran: {:?}",
            log.commands_executed
        );
    }
}
