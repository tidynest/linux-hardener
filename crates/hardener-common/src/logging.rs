//! Logging infrastructure for the Linux hardening tool.
//!
//! Provides initialisation and configuration for the tracing-based
//! logging system used throughout the application

use tracing_subscriber::{EnvFilter, fmt};

/// Initialises the logging system with sensible defaults.
///
/// This function sets up structured logging using the `tracing` crate.
/// Log levels can be controlled via the `RUST_LOG` environment variable.
///
/// # Default Log Level
/// If `RUST_LOG` is not set, defaults to info level.
///
/// # Examples
/// ```no_run
/// use hardener_common::logging::init_logger;
///
/// init_logger();
/// tracing::info!("Logging initialised");
/// ```
///
/// # Panics
/// Panics if the global default subscriber cannot be set (only if called multiple times).
pub fn init_logger() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(true)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_initialisation() {
        // This test verifies that init_logger() doesn't panic
        // Note: Can only be called once per test process
        init_logger();
        tracing::info!("Test log message");
    }
}
