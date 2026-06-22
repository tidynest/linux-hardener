//! Shared foundation crate for the Linux system hardener.
//!
//! Provides error types, file utilities, logging, and common type re-exports
//! used by all other crates in the workspace.

pub mod binary_utils;
pub mod error;
pub mod executor;
pub mod file_utils;
pub mod logging;
pub mod types;
