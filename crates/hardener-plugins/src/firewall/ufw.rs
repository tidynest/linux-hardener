//! UFW (Uncomplicated Firewall) backend implementation.
//!
//! This backend manages firewall rules on Ubuntu/Debian systems using ufw.

use crate::firewall::{
    FirewallBackend,
    Rule,
};
use hardener_common::error::{
    HardeningError,
    Result,
};
use hardener_core::{
    Change,
    ChangeType,
};
use std::process::Command;

/// UFW firewall backend for Ubuntu/Debian systems.
pub struct UfwBackend;

impl UfwBackend {
    /// Creates a new UFW backend instance.
    pub fn new() -> UfwBackend {
        UfwBackend
    }

    /// Executes a ufw command and returns the output.
    ///
    /// # Arguments
    /// * `args` - Command arguments to pass to ufw
    ///
    /// # Returns
    /// The command output as a string, or an error if execution fails.
    fn execute_ufw(
        &self,
        args: &[&str],
    ) -> Result<String> {
        let output = Command::new("ufw")
            .args(args)
            .output()
            .map_err(|e| {
                HardeningError::Plugin(format!(
                    "Failed to execute ufw command: {}", e
                ))
            })?;

        if !output.status.success() {
            return Err(HardeningError::Plugin(format!(
                "ufw command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl FirewallBackend for UfwBackend {
    fn backend_name(&self) -> &str {
        "ufw"
    }

    fn detect(&self) -> Result<bool> {
        // Check if ufw command exists by trying to run it.
        match Command::new("which").arg("ufw").output() {
            Ok(output) => Ok(output.status.success()),
            Err(_)     => Ok(false),
        }
    }

    fn is_enabled(&self) -> Result<()> {
        // Run 'ufw status' and check if it says "Status: active".
        let output = self.execute_ufw(&["status"])?;

        Ok(output.contains("Status: active"))
    }

    fn enable(&self) -> Result<()> {
        // Enable UFW firewall
        tracing::info!("Enabling UFW firewall");

        let output = self.execute_ufw(&["--force", "enable"])?;

        if output.contains("Firewall is active") || output.contains("enabled") {
            tracing::info!("UFW firewall enabled successfully");
            Ok(())
        } else {
            Err(HardeningError::Plugin(
                "Failed to enable UFW firewall".to_string(),
            ))
        }
    }
}
