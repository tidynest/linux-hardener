#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`adapter`](super).
//!
//! Split out of `adapter.rs`. This file sits in the `adapter/` directory
//! beside it, which the 2018 path rules allow with no `mod.rs` and no
//! `#[path]`, so `super` still resolves to `crate::adapter` and every import
//! carried across unchanged.

use super::*;

/// Mock adapter for testing.
struct MockAdapter {
    distro: Distribution,
}

impl DistributionAdapter for MockAdapter {
    fn distribution(&self) -> &Distribution {
        &self.distro
    }
}

#[test]
fn test_adapter_distribution() {
    let adapter = MockAdapter {
        distro: Distribution {
            distro_name: "TestOS".to_string(),
            distro_version: "1.0".to_string(),
            distro_family: DistroFamily::Debian,
            distro_codename: None,
        },
    };

    assert_eq!(adapter.distribution().distro_name, "TestOS");
    assert_eq!(adapter.distribution().distro_version, "1.0");
}

#[test]
fn test_adapter_family() {
    let adapter = MockAdapter {
        distro: Distribution {
            distro_name: "TestOS".to_string(),
            distro_version: "1.0".to_string(),
            distro_family: DistroFamily::RedHat,
            distro_codename: None,
        },
    };

    assert_eq!(adapter.family(), DistroFamily::RedHat);
}

#[test]
fn test_adapter_family_debian() {
    let adapter = MockAdapter {
        distro: Distribution {
            distro_name: "Ubuntu".to_string(),
            distro_version: "22.04".to_string(),
            distro_family: DistroFamily::Debian,
            distro_codename: Some("jammy".to_string()),
        },
    };

    assert_eq!(adapter.family(), DistroFamily::Debian);
}

#[test]
fn test_adapter_family_arch() {
    let adapter = MockAdapter {
        distro: Distribution {
            distro_name: "Arch".to_string(),
            distro_version: "rolling".to_string(),
            distro_family: DistroFamily::Arch,
            distro_codename: None,
        },
    };

    assert_eq!(adapter.family(), DistroFamily::Arch);
}

#[test]
fn test_adapter_family_suse() {
    let adapter = MockAdapter {
        distro: Distribution {
            distro_name: "openSUSE".to_string(),
            distro_version: "15.4".to_string(),
            distro_family: DistroFamily::Suse,
            distro_codename: None,
        },
    };

    assert_eq!(adapter.family(), DistroFamily::Suse);
}
