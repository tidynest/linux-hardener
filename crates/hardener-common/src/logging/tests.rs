#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`logging`](super).
//!
//! Split out of `logging.rs`. This file sits in the `logging/` directory
//! beside it, which the 2018 path rules allow with no `mod.rs` and no
//! `#[path]`, so `super` still resolves to `crate::logging` and every import
//! carried across unchanged, private items included.

use super::*;

#[test]
fn test_logger_initialisation() {
    // This test verifies that init_logger() doesn't panic
    // Note: Can only be called once per test process
    init_logger();
    tracing::info!("Test log message");
}
