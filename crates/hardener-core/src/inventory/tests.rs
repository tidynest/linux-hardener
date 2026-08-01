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
