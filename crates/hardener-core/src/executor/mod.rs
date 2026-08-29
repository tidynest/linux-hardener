//! System executor abstraction for local and remote operations.

pub mod local;
#[cfg(feature = "system")]
pub mod ssh;

pub use hardener_common::executor::{
    CommandOutput, FileMetadata, SystemExecutor, host_key_for, host_keys_for, hostname_file_name,
    session_host_key, session_is_root,
};
// The mock exists only for tests, so its re-export carries the same gate the
// definition does. A release build of anything depending on this crate gets
// no mock and no reference to one.
#[cfg(feature = "test-support")]
pub use hardener_common::executor::MockExecutor;
