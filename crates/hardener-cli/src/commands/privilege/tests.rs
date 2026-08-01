#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`privilege`](super).
//!
//! Split out of `commands/privilege.rs`. This file sits in the `privilege/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::privilege` and every import carried
//! across unchanged, private items included.

use super::*;
use hardener_common::executor::{CommandOutput, MockExecutor};

#[tokio::test]
async fn is_privileged_via_uid_and_sudo() {
    let ok = |stdout: &str| CommandOutput {
        stdout: stdout.into(),
        stderr: String::new(),
        exit_code: 0,
    };
    let fail = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 1,
    };

    // uid 0 -> privileged; sudo is not even consulted
    let root = MockExecutor::new().with_command("id", &["-u"], ok("0\n"));
    assert!(is_privileged(&root).await);

    // non-root but passwordless sudo -> privileged
    let sudoer = MockExecutor::new()
        .with_command("id", &["-u"], ok("1000\n"))
        .with_command("sudo", &["-n", "true"], ok(""));
    assert!(is_privileged(&sudoer).await);

    // non-root, sudo denied -> not privileged
    let nope = MockExecutor::new()
        .with_command("id", &["-u"], ok("1000\n"))
        .with_command("sudo", &["-n", "true"], fail);
    assert!(!is_privileged(&nope).await);

    // id -u errors (transport/IO) and sudo also unavailable -> fail closed
    let broken = MockExecutor::new();
    assert!(
        !is_privileged(&broken).await,
        "errors from both probes must fail closed"
    );
}
