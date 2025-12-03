//! SSH Executor integration tests.
//!
//! These tests verify the SshExecutor implementation.
//!
//! # Test Categories
//!
//! 1. **Unit tests** - Test SshConfig defaults and validation (always run)
//! 2. **Integration tests** - Require actual SSH connection (marked `#[ignore]`)
//!
//! # Running Integration Tests
//!
//! Integration tests require a Docker container or accessible SSH host.
//!
//! ## Option 1: Docker (recommended for CI)
//! ```bash
//! # Start test container
//! docker run -d --name ssh-test -p 2222:22 \
//!     -e SSH_ENABLE_ROOT=true \
//!     -e SSH_ENABLE_ROOT_PASSWORD_AUTH=true \
//!     panubo/sshd:latest
//!
//! # Wait for SSH to be ready
//! sleep 3
//!
//! # Run integration tests
//! SSH_TEST_HOST=localhost SSH_TEST_PORT=2222 SSH_TEST_USER=root SSH_TEST_PASSWORD=root \
//!     cargo test -p hardener-core --test ssh_executor_tests -- --ignored
//!
//! # Cleanup
//! docker stop ssh-test && docker rm ssh-test
//! ```
//!
//! ## Option 2: Local SSH (for development)
//! ```bash
//! # Use passwordless SSH to localhost
//! SSH_TEST_HOST=localhost SSH_TEST_USER=$USER \
//!     cargo test -p hardener-core --test ssh_executor_tests -- --ignored
//! ```

use hardener_core::executor::ssh::{SshConfig, SshExecutor};
use hardener_core::SystemExecutor;
use openssh::KnownHosts;
use std::env;
use std::path::Path;
use std::time::Duration;

// =============================================================================
// UNIT TESTS - Always run, no SSH connection required
// =============================================================================

#[test]
fn test_ssh_config_default() {
    let config = SshConfig::default();

    assert_eq!(config.host, "");
    assert_eq!(config.port, 22);
    assert!(config.user.is_none());
    assert!(config.identity_file.is_none());
    assert_eq!(config.connect_timeout, Duration::from_secs(30));
    // Default should be Strict for security
    assert!(matches!(config.known_hosts, KnownHosts::Strict));
}

#[test]
fn test_ssh_config_custom() {
    let config = SshConfig {
        host: "example.com".to_string(),
        port: 2222,
        user: Some("admin".to_string()),
        identity_file: Some("/home/user/.ssh/id_ed25519".to_string()),
        known_hosts: KnownHosts::Accept,
        connect_timeout: Duration::from_secs(60),
    };

    assert_eq!(config.host, "example.com");
    assert_eq!(config.port, 2222);
    assert_eq!(config.user, Some("admin".to_string()));
    assert_eq!(config.identity_file, Some("/home/user/.ssh/id_ed25519".to_string()));
    assert_eq!(config.connect_timeout, Duration::from_secs(60));
}

// =============================================================================
// INTEGRATION TESTS - Require actual SSH connection
// =============================================================================

/// Helper to get test configuration from environment variables.
fn get_test_config() -> Option<SshConfig> {
    let host = env::var("SSH_TEST_HOST").ok()?;

    Some(SshConfig {
        host,
        port: env::var("SSH_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(22),
        user: env::var("SSH_TEST_USER").ok(),
        identity_file: env::var("SSH_TEST_KEY").ok(),
        known_hosts: KnownHosts::Accept, // Accept for testing
        connect_timeout: Duration::from_secs(10),
    })
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_connect() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");

    let executor = SshExecutor::connect(config).await;
    assert!(executor.is_ok(), "Should connect successfully: {:?}", executor.err());

    let executor = executor.unwrap();
    assert!(executor.is_remote());
    assert!(executor.description().starts_with("ssh://"));
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_read_file() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // /etc/hostname should exist on any Linux system
    let content = executor.read_file(Path::new("/etc/hostname")).await;
    assert!(content.is_ok(), "Should read /etc/hostname: {:?}", content.err());
    assert!(!content.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_read_file_not_found() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    let result = executor.read_file(Path::new("/nonexistent/file/path")).await;
    assert!(result.is_err());
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_read_file_optional() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Existing file
    let result = executor.read_file_optional(Path::new("/etc/hostname")).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());

    // Non-existing file
    let result = executor.read_file_optional(Path::new("/nonexistent/path")).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_path_exists() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Should exist
    assert!(executor.path_exists(Path::new("/etc")).await.unwrap());
    assert!(executor.path_exists(Path::new("/etc/passwd")).await.unwrap());

    // Should not exist
    assert!(!executor.path_exists(Path::new("/nonexistent")).await.unwrap());
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_file_metadata() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Directory
    let meta = executor.file_metadata(Path::new("/etc")).await.unwrap();
    assert!(meta.exists);
    assert!(meta.is_dir);
    assert!(!meta.is_file);
    assert!(meta.mode > 0);

    // File
    let meta = executor.file_metadata(Path::new("/etc/passwd")).await.unwrap();
    assert!(meta.exists);
    assert!(meta.is_file);
    assert!(!meta.is_dir);
    assert!(meta.size > 0);

    // Non-existent
    let meta = executor.file_metadata(Path::new("/nonexistent")).await.unwrap();
    assert!(!meta.exists);
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_execute_command() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Simple command
    let output = executor.execute_command("echo", &["hello", "world"]).await.unwrap();
    assert!(output.success());
    assert_eq!(output.stdout.trim(), "hello world");
    assert_eq!(output.exit_code, 0);

    // Command with failure
    let output = executor.execute_command("false", &[]).await.unwrap();
    assert!(!output.success());
    assert_ne!(output.exit_code, 0);
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_command_exists() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Should exist on any Linux system
    assert!(executor.command_exists("cat").await.unwrap());
    assert!(executor.command_exists("ls").await.unwrap());

    // Should not exist
    assert!(!executor.command_exists("definitely_not_a_real_command_xyz").await.unwrap());
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable and write permissions"]
async fn test_ssh_executor_write_file() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Write to temp file
    let test_path = Path::new("/tmp/hardener_ssh_test");
    let test_content = "Hello from SSH executor test!\n";

    let result = executor.write_file(test_path, test_content).await;
    assert!(result.is_ok(), "Should write file: {:?}", result.err());

    // Read it back
    let content = executor.read_file(test_path).await.unwrap();
    assert_eq!(content, test_content);

    // Cleanup
    let _ = executor.execute_command("rm", &["-f", "/tmp/hardener_ssh_test"]).await;
}

#[test]
fn test_ssh_executor_description_format() {
    // Verify we understand the description format without needing a connection
    let expected_format = "ssh://testuser@example.com:2222";

    assert!(expected_format.starts_with("ssh://"));
    assert!(expected_format.contains("@"));
    assert!(expected_format.contains(":"));

    // Test default user case
    let default_user_format = "ssh://root@localhost:22";
    assert!(default_user_format.contains("root@"));
}

// =============================================================================
// PLUGIN INTEGRATION TESTS - Test plugins over SSH
// =============================================================================

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_kernel_param_read() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Read a kernel parameter that should exist
    let result = executor.read_file_optional(
        Path::new("/proc/sys/kernel/hostname")
    ).await;

    assert!(result.is_ok());
    let content = result.unwrap();
    assert!(content.is_some(), "Should be able to read kernel hostname");
}

#[tokio::test]
#[ignore = "Requires SSH_TEST_HOST environment variable"]
async fn test_ssh_executor_systemctl_command() {
    let config = get_test_config().expect("SSH_TEST_HOST not set");
    let executor = SshExecutor::connect(config).await.expect("Failed to connect");

    // Check if systemctl exists
    if executor.command_exists("systemctl").await.unwrap() {
        // List unit files (should work without root)
        let output = executor.execute_command(
            "systemctl",
            &["list-unit-files", "--no-pager", "--no-legend"]
        ).await.unwrap();

        // Even if it fails, we should get a response
        assert!(!output.stdout.is_empty() || !output.stderr.is_empty());
    }
}
