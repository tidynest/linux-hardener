//! System executor abstraction for local and remote operations.

pub mod local;
#[cfg(feature = "system")]
pub mod ssh;

pub use hardener_common::executor::{CommandOutput, FileMetadata, MockExecutor, SystemExecutor};
