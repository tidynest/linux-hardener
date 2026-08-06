//! System executor abstraction for local and remote operations.

pub mod local;
#[cfg(feature = "system")]
pub mod ssh;

pub use hardener_common::executor::{
    CommandOutput, FileMetadata, MockExecutor, SystemExecutor, host_key_for, host_keys_for,
    hostname_file_name, session_host_key, session_is_root,
};
