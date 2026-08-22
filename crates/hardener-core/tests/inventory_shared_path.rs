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

use hardener_core::config_write::{WriteAudit, logger_at};
use hardener_core::inventory::{default_path, load, save_audited};
use hardener_state::audit::{ActionType, AuditLogger, QueryFilter};
use hardener_types::remote::{HostsConfig, RemoteHostProfile};
use std::collections::HashMap;
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

/// Runs `body` on a runtime of its own.
///
/// `with_config_root` holds a `std::sync::Mutex` across its closure, so the
/// closure cannot be `async` without holding a non-`Send` guard across an
/// await. The runtime goes inside the closure instead.
fn block_on<T>(body: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(body)
}

/// `save_audited` writes the inventory, rather than reporting success and doing
/// nothing.
///
/// The mutant `save_audited -> Ok(())` leaves the file absent while every
/// caller is told the write succeeded. A host added through the CLI's `batch`
/// or the desktop fleet view would vanish at the next read.
///
/// Asserted on the file rather than through `load`, so this fails for one
/// reason only. A test that saved and then loaded would also go red when
/// `load` broke, and neither failure would say which.
#[test]
fn save_writes_the_inventory_to_the_shared_path() {
    with_config_root(|| {
        block_on(async { save_audited(&sample(), unaudited()).await })
            .expect("save to the default path");

        let path = default_path().expect("the config directory resolves");
        let written = std::fs::read_to_string(&path)
            .expect("save_audited() reported success, so the shared file must exist");

        assert!(
            written.contains("web-01"),
            "the saved host must reach the file both front ends read: {written}"
        );
    });
}

/// A descriptor with no logger, for the tests that are about the file rather
/// than the entry.
///
/// The `None` is the state a host with an unwritable log directory is in, not
/// an opt-out: the inventory still has to be writable there.
fn unaudited() -> WriteAudit<'static> {
    WriteAudit {
        logger: None,
        action: ActionType::ConfigChange,
        target: "host:web-01".to_string(),
        details: HashMap::new(),
    }
}

/// A host joining or leaving the inventory is recorded.
///
/// This is the whole reason `save` became `save_audited`. A host leaving the
/// file stops being scanned, and nothing else in the tool reports that: the
/// fleet simply has one fewer row the next time somebody looks.
#[test]
fn save_files_an_entry_naming_the_host() {
    with_config_root(|| {
        let log = default_path()
            .expect("the config directory resolves")
            .with_file_name("audit.log");
        let log_path = log.to_str().expect("utf-8 path").to_string();

        block_on(async {
            let logger = logger_at(&log_path).await.expect("a logger opens");
            save_audited(
                &sample(),
                WriteAudit {
                    logger: Some(&logger),
                    action: ActionType::ConfigChange,
                    target: "host:web-01".to_string(),
                    details: HashMap::from([("operation".to_string(), "save".to_string())]),
                },
            )
            .await
            .expect("save to the default path");

            let entries = AuditLogger::query(&log_path, QueryFilter::new())
                .await
                .expect("query");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].entry_target, "host:web-01");
            assert_eq!(entries[0].entry_details["operation"], "save");
        });
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
