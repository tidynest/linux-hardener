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
//! Split out of `lib.rs`. A crate root cannot become a directory, so these go
//! to `src/tests.rs` rather than beside the file they came from, and `super`
//! there means this file instead of the root. The block's `use super::*`
//! became `use crate::*`, which still reaches private items because the module
//! is still a descendant of the root.

use crate::*;

#[test]
fn test_distribution_detection() {
    let result = Distribution::detect();
    assert!(result.is_ok());

    let distro = result.unwrap();
    assert!(!distro.distro_name.is_empty());
    assert!(!distro.distro_version.is_empty());
}

#[test]
fn test_family_mapping() {
    // Debian family
    assert_eq!(
        Distribution::map_to_family("ubuntu").unwrap(),
        DistroFamily::Debian
    );
    assert_eq!(
        Distribution::map_to_family("debian").unwrap(),
        DistroFamily::Debian
    );

    // Red Hat family
    assert_eq!(
        Distribution::map_to_family("fedora").unwrap(),
        DistroFamily::RedHat
    );
    assert_eq!(
        Distribution::map_to_family("rhel").unwrap(),
        DistroFamily::RedHat
    );

    // Arch family
    assert_eq!(
        Distribution::map_to_family("arch").unwrap(),
        DistroFamily::Arch
    );

    // SUSE family
    assert_eq!(
        Distribution::map_to_family("opensuse").unwrap(),
        DistroFamily::Suse
    );

    // Unknown should error
    assert!(Distribution::map_to_family("unknown").is_err());
}

#[test]
fn test_version_major() {
    let distro = |version: &str| Distribution {
        distro_family: DistroFamily::RedHat,
        distro_name: "rhel".to_string(),
        distro_version: version.to_string(),
        distro_codename: None,
    };

    assert_eq!(distro("10").version_major(), Some(10));
    assert_eq!(distro("10.0").version_major(), Some(10));
    assert_eq!(distro("22.04").version_major(), Some(22));
    assert_eq!(distro("rolling").version_major(), None);
    assert_eq!(distro("").version_major(), None);
}

#[test]
fn test_from_os_release_rocky_10() {
    let content = r#"NAME="Rocky Linux"
VERSION="10.0 (Red Quartz)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.0"
PLATFORM_ID="platform:el10"
PRETTY_NAME="Rocky Linux 10.0 (Red Quartz)"
CPE_NAME="cpe:/o:rocky:rocky:10::baseos"
"#;

    let distro = Distribution::from_os_release(content).unwrap();
    assert_eq!(distro.distro_family, DistroFamily::RedHat);
    assert_eq!(distro.distro_name, "rocky");
    assert_eq!(distro.distro_version, "10.0");
}

#[test]
fn test_from_os_release_garbage() {
    assert!(Distribution::from_os_release("not an os-release file").is_err());
}
