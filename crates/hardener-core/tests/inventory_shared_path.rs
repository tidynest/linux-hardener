//! `load` and `save` against the shared inventory path.
//!
//! These pin the two wrappers the front ends actually call. `save_to` and
//! `load_from` beside them are already covered by unit tests, but a wrapper is
//! not its inner function: a mutation pass on 2026-08-12 found
//! `save -> Ok(())` and `load -> Ok(Default::default())` both surviving 453
//! tests, because nothing exercised the wrappers themselves.
//!
//! # Why this is an integration test rather than a unit test
//!
//! Reaching the wrappers means moving the config directory, and
//! `dirs::config_dir()` reads `XDG_CONFIG_HOME` from the process environment.
//! Writing an environment variable while another thread reads one is the race
//! Rust 2024 made `set_var` `unsafe` for, and it is not hypothetical here:
//! putting these tests in `inventory/tests.rs` made the pre-existing
//! `save_then_load_round_trips` fail, because it calls `std::env::temp_dir()`,
//! which reads `TMPDIR`, while these tests were writing `XDG_CONFIG_HOME`.
//! Under `cargo nextest` it passed regardless, since nextest gives every test
//! its own process; `cargo test` runs them as threads and the gate runs both.
//!
//! An integration test is its own binary. The only tests in this process are
//! the ones below, and the lock serialises those, so nothing reads the
//! environment while it is being written.
//!
//! Ceiling: this pins where the wrappers read and write, not what any caller
//! does with the result. It also cannot pin the real `~/.config` location,
//! which is the point of moving it.

use hardener_core::inventory::{default_path, load, save};
use hardener_types::remote::{HostsConfig, RemoteHostProfile};
use std::sync::Mutex;

/// Serialises every test in this file that redirects the config directory.
static CONFIG_DIR_LOCK: Mutex<()> = Mutex::new(());

fn sample() -> HostsConfig {
    HostsConfig {
        hosts: vec![RemoteHostProfile {
            name: "web-01".into(),
            hostname: "web-01.example.com".into(),
            user: Some("admin".into()),
            port: 22,
            key_file: None,
            host_key_checking: true,
        }],
    }
}

/// Points the config directory at a fresh temporary root for one closure.
///
/// The environment read inside `body`, and by `tempfile` on the way in, both
/// happen under the lock, so no thread reads the environment while it is being
/// written.
fn with_config_root<T>(body: impl FnOnce() -> T) -> T {
    let _guard = CONFIG_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = tempfile::tempdir().expect("a temporary config root");
    let previous = std::env::var_os("XDG_CONFIG_HOME");

    // SAFETY: the lock above serialises every reader and writer of the
    // environment in this binary, and the previous value is restored before
    // the lock is released.
    unsafe { std::env::set_var("XDG_CONFIG_HOME", root.path()) };
    let result = body();
    unsafe {
        match previous {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
    result
}

/// `save` writes the inventory, rather than reporting success and doing nothing.
///
/// The mutant `save -> Ok(())` leaves the file absent while every caller is
/// told the write succeeded. A host added through the CLI's `batch` or the
/// desktop fleet view would vanish at the next read.
///
/// Asserted on the file rather than through `load`, so this fails for one
/// reason only. A test that saved and then loaded would also go red when
/// `load` broke, and neither failure would say which.
#[test]
fn save_writes_the_inventory_to_the_shared_path() {
    with_config_root(|| {
        save(&sample()).expect("save to the default path");

        let path = default_path().expect("the config directory resolves");
        let written = std::fs::read_to_string(&path)
            .expect("save() reported success, so the shared file must exist");

        assert!(
            written.contains("web-01"),
            "the saved host must reach the file both front ends read: {written}"
        );
    });
}

/// `load` reads the inventory, rather than returning an empty one.
///
/// The mutant `load -> Ok(Default::default())` reports an empty inventory
/// whatever is on disk. A fleet run would then find no hosts and report
/// nothing to do, which reads as a clean result rather than as a failure.
///
/// Seeded by writing the file directly rather than through `save`, so this
/// fails for one reason only, mirroring the test above.
#[test]
fn load_reads_the_inventory_from_the_shared_path() {
    with_config_root(|| {
        let path = default_path().expect("the config directory resolves");
        let seed = toml::to_string_pretty(&sample()).expect("serialise the seed inventory");
        std::fs::write(&path, seed).expect("seed the shared file directly");

        let loaded = load().expect("load from the default path");

        assert_eq!(
            loaded.hosts.len(),
            1,
            "load() must read the shared file, not report an empty inventory"
        );
        assert_eq!(loaded.hosts[0].name, "web-01");
    });
}
