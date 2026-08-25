//! Shared foundation crate for the Linux system hardener.
//!
//! Provides error types, file utilities, logging, common type re-exports, and
//! the [`executor::SystemExecutor`] trait used by all other crates in the
//! workspace.
//!
//! **The executor trait is defined here, not in `hardener-core`.** This crate
//! owns the abstraction and the mock; `hardener-core` owns the two real
//! implementations, `LocalExecutor` and `SshExecutor`, and re-exports the trait
//! alongside them. That direction is what lets `hardener-state` depend on this
//! crate rather than on core. The header omitted the executor entirely, which
//! left the crate's most load-bearing export undocumented at its own root.

pub mod binary_utils;
pub mod error;
pub mod executor;
pub mod file_utils;
pub mod logging;
pub mod text;
pub mod types;
pub mod vendor_config;
