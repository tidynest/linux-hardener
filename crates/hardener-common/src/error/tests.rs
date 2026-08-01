#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`error`](super).
//!
//! Split out of `error.rs`. This file sits in the `error/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`, so
//! `super` still resolves to `crate::error` and every import carried across
//! unchanged, private items included.

#[allow(unused_imports)]
use anyhow::Context;

use super::*;

#[test]
fn detects_io_permission_denied_through_anyhow_chain() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err = anyhow::Error::new(io).context("Failed to read file /etc/security/pwquality.conf");
    assert!(is_permission_denied(&err));
}

#[test]
fn detects_permission_strings() {
    assert!(message_indicates_permission_denied(
        "nft: Permission denied"
    ));
    assert!(message_indicates_permission_denied(
        "Operation not permitted"
    ));
    assert!(message_indicates_permission_denied(
        "You must be root to run this"
    ));
    assert!(!message_indicates_permission_denied(
        "No such file or directory"
    ));
}

#[test]
fn not_found_is_not_permission_denied() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
    let err = anyhow::Error::new(io).context("Failed to read file /etc/nothing");
    assert!(!is_permission_denied(&err));
}

#[test]
fn detects_ssh_auth_failure_signatures() {
    // The strings ssh prints to stderr when a key/agent is the problem.
    assert!(message_indicates_ssh_auth_failure(
        "root@host: Permission denied (publickey)."
    ));
    assert!(message_indicates_ssh_auth_failure(
        "Permission denied (publickey,password)"
    ));
    assert!(message_indicates_ssh_auth_failure(
        "Could not open a connection to your authentication agent."
    ));
    assert!(message_indicates_ssh_auth_failure(
        "Load key \"/x\": no such identity"
    ));
    // Case-insensitive.
    assert!(message_indicates_ssh_auth_failure(
        "PERMISSION DENIED (PUBLICKEY)"
    ));
}

#[test]
fn network_failures_are_not_ssh_auth_failures() {
    // A genuine network fault must never be mislabelled as an auth problem.
    assert!(!message_indicates_ssh_auth_failure(
        "connect to host 10.0.0.5 port 22: Connection refused"
    ));
    assert!(!message_indicates_ssh_auth_failure(
        "connect to host 10.0.0.5 port 22: Connection timed out"
    ));
    assert!(!message_indicates_ssh_auth_failure(
        "connect to host 10.0.0.5 port 22: No route to host"
    ));
    assert!(!message_indicates_ssh_auth_failure(
        "ssh: Could not resolve hostname bogus: Name or service not known"
    ));
}
