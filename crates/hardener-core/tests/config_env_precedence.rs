//! `ConfigLoader::load()` against `HARDENER_DISABLED_PLUGINS`.
//!
//! # Why this is an integration test rather than a unit test
//!
//! `HARDENER_DISABLED_PLUGINS` is process-wide, and `apply_env_overrides`
//! reads it with `std::env::var`, so setting it is visible to every test
//! running in the same process regardless of which thread set it. This is not
//! hypothetical: `crates/hardener-core/src/config_loader/tests.rs` carries
//! `a_root_session_skips_the_user_config_an_unprivileged_one_reads`, which
//! asserts `as_root.global.disabled_plugins.is_empty()`. That assertion goes
//! red whenever this variable is set, because a root load still runs
//! `apply_env_overrides` after skipping the user config, so the leaked value
//! lands in `disabled_plugins` regardless of which config source produced it.
//! Measured on 2026-08-20 at 223 of 250 paired runs failing when the two
//! tests shared a process; the full suite survived only because libtest sorts
//! by name and the writer happened to sort after the victim, which is an
//! accident of naming rather than a guarantee `cargo test`'s thread-per-test
//! model makes for anyone.
//!
//! The hazard is the *readers*, not a second writer: the original version of
//! this test set the variable, loaded, and removed it, with a comment
//! promising to stay the only test in its file that touched the environment.
//! That promise cannot be kept from inside a single file, because nothing
//! stops a sibling file in the same test binary from reading the same
//! process-wide state while the variable is set. Moving the write into its
//! own binary is what actually keeps that promise: this is the only test in
//! this process, so nothing sharing this process reads
//! `HARDENER_DISABLED_PLUGINS` while it is set, the same shape of fix
//! `tests/inventory_shared_path.rs` took for `XDG_CONFIG_HOME`.
//!
//! Restore happens through a drop guard rather than a bare `remove_var`, so a
//! pre-existing value in the developer's own environment is put back, and so
//! the restore still runs if `load()` panics.
//!
//! Ceiling: this pins what one test observes about one variable in one
//! process. It says nothing about `HARDENER_ENABLED_PLUGINS`, which no test
//! anywhere sets and then loads.

use hardener_core::ConfigLoader;
use std::ffi::OsString;

const ENV_DISABLED_PLUGINS: &str = "HARDENER_DISABLED_PLUGINS";

/// Sets an environment variable for the life of the guard, restoring
/// whatever the variable held before, including on an unwind.
struct RestoreEnvVar {
    name: &'static str,
    previous: Option<OsString>,
}

impl RestoreEnvVar {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(name);
        // SAFETY: this binary contains the only test that touches the
        // process environment, so nothing else in this process can be
        // reading it concurrently.
        unsafe { std::env::set_var(name, value) };
        Self { name, previous }
    }
}

impl Drop for RestoreEnvVar {
    fn drop(&mut self) {
        // SAFETY: see `set`. This runs on a panic unwind as well as on the
        // ordinary path, which is the point of the guard: `load()` panicking
        // must not leave the variable set for the rest of the process.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }
}

/// Environment overrides are applied after every file source, including a
/// named `--config`, which is the order all four documents promise and which
/// nothing drove through `load()` before 2026-08-20.
///
/// Red-first control: swapping the CLI merge and the env override in `load()`
/// compiles cleanly and silently lets a file beat the environment.
///
/// The named file also states a directive no other source names, and that
/// directive is asserted to survive. Without it, this test still passes if
/// the CLI merge is deleted from `load()` entirely, since the only assertions
/// left would be about the environment layer alone; the directive is what
/// proves the named file was actually read rather than skipped.
#[test]
fn the_environment_outranks_a_named_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let named = dir.path().join("named.toml");
    std::fs::write(
        &named,
        "[global]\ndisabled_plugins = [\"ssh-hardening\"]\n\
         [kernel.directives]\nfrom_named = \"1\"\n",
    )
    .expect("write named");

    let _guard = RestoreEnvVar::set(ENV_DISABLED_PLUGINS, "mac-hardening");

    let config = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(named)
        .load()
        .expect("load");

    assert!(
        !config.is_plugin_enabled("mac-hardening"),
        "the environment names mac-hardening and is applied last"
    );
    assert!(
        config.is_plugin_enabled("ssh-hardening"),
        "the named file's list is REPLACED by the environment rather than \
         merged with it, so the plugin only the file named is enabled again"
    );
    assert_eq!(
        config
            .get_plugin_config("kernel-hardening")
            .directives
            .get("from_named")
            .map(String::as_str),
        Some("1"),
        "the named file must actually have been read, not merely present: a \
         directive only it states must survive to here"
    );
}
