#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`package`](super).
//!
//! Split out of `package/mod.rs`. That file *is* the module `package`, so its
//! tests go to `package/tests.rs` in the directory it already owns; a
//! `package/mod/` would resolve to no module at all. `super` is unchanged.

use super::*;

#[test]
fn test_validate_debian_package_name_valid() {
    assert!(validate_package_name("nginx", PackageNameRules::Debian).is_ok());
    assert!(validate_package_name("lib-ssl1.1", PackageNameRules::Debian).is_ok());
    assert!(validate_package_name("python3+extra", PackageNameRules::Debian).is_ok());
}

#[test]
fn test_validate_debian_package_name_invalid() {
    assert!(validate_package_name("a", PackageNameRules::Debian).is_err());
    assert!(validate_package_name("package;rm", PackageNameRules::Debian).is_err());
    assert!(validate_package_name("pkg_name", PackageNameRules::Debian).is_err());
}

#[test]
fn test_validate_rpm_package_name_valid() {
    assert!(validate_package_name("kernel", PackageNameRules::Rpm).is_ok());
    assert!(validate_package_name("glibc-2.34", PackageNameRules::Rpm).is_ok());
    assert!(validate_package_name("lib_ssl+extra", PackageNameRules::Rpm).is_ok());
}

#[test]
fn test_validate_rpm_package_name_invalid() {
    assert!(validate_package_name("x", PackageNameRules::Rpm).is_err());
    assert!(validate_package_name("package;evil", PackageNameRules::Rpm).is_err());
}

#[test]
fn test_validate_arch_package_name_valid() {
    assert!(validate_package_name("linux", PackageNameRules::Arch).is_ok());
    assert!(validate_package_name("lib32-gcc-libs", PackageNameRules::Arch).is_ok());
    assert!(validate_package_name("python@3.11", PackageNameRules::Arch).is_ok());
}

#[test]
fn test_validate_arch_package_name_invalid() {
    assert!(validate_package_name("p", PackageNameRules::Arch).is_err());
    assert!(validate_package_name("package|whoami", PackageNameRules::Arch).is_err());
}
