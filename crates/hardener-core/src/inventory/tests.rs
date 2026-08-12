#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`inventory`](super).
//!
//! Split out of `inventory.rs`. This file sits in the `inventory/` directory
//! beside it, which the 2018 path rules allow with no `mod.rs` and no
//! `#[path]`, so `super` still resolves to `crate::inventory` and every
//! import carried across unchanged, private items included.

use super::*;
use hardener_types::remote::RemoteHostProfile;

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

#[test]
fn missing_file_is_empty_inventory() {
    let path = std::env::temp_dir().join("hardener-test-missing-hosts.toml");
    let _ = std::fs::remove_file(&path);
    let config = load_from(&path).expect("load missing");
    assert!(config.hosts.is_empty());
}

#[test]
fn save_then_load_round_trips() {
    let path = std::env::temp_dir().join("hardener-test-roundtrip-hosts.toml");
    save_to(&path, &sample()).expect("save");
    let loaded = load_from(&path).expect("load");
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.hosts.len(), 1);
    assert_eq!(loaded.hosts[0].name, "web-01");
    assert_eq!(loaded.hosts[0].user.as_deref(), Some("admin"));
}

/// The inventory path is the shared one, named rather than defaulted.
///
/// Both the CLI's `batch` and the desktop read the host list through this
/// function, and it exists so the two cannot disagree about where the file is.
/// Replaced by `Ok(PathBuf::new())` every caller reads and writes the empty
/// path, so a saved host would vanish and a fleet run would find no inventory,
/// and nothing else in the tree notices.
///
/// The assertion is on the shape rather than the whole string, because the
/// prefix is the operator's own config directory and naming it here would pin
/// this machine instead of the contract.
///
/// This comment used to add that `dirs::config_dir()` reading the environment
/// meant the wrappers could not be asked of an injected root without changing
/// the signature, and that `load` and `save` therefore stayed unpinned. Reading
/// the environment is what makes them pinnable: `XDG_CONFIG_HOME` moves the
/// directory, measured 2026-08-12 after a mutation pass found both wrappers
/// surviving. They are pinned in `tests/inventory_shared_path.rs`, which is a
/// separate binary because writing that variable races every other thread in
/// this one that reads any variable at all.
#[test]
fn the_inventory_path_names_the_shared_file() {
    let path = default_path().expect("the config directory resolves on any host");

    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("hosts.toml"),
        "the file both front ends read must be the one this names: {}",
        path.display()
    );
    assert_eq!(
        path.parent().and_then(|dir| dir.file_name()?.to_str()),
        Some("linux-hardener"),
        "and it sits in this tool's own config directory: {}",
        path.display()
    );
    assert!(
        path.is_absolute(),
        "an inventory path resolved relative to the working directory would \
         find a different file per caller: {}",
        path.display()
    );
}
