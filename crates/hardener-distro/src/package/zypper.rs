//! Zypper package manager implementation for SUSE systems.

use super::{Package, PackageManager};
use hardener_common::error::{HardeningError, Result};
use std::process::Command;

/// Zypper package manager implementation.
pub struct ZypperPackageManager;

impl Default for ZypperPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ZypperPackageManager {
    /// Creates a new Zypper package manager instance.
    pub fn new() -> ZypperPackageManager {
        Self
    }

    /// Executes a zypper command and returns the output.
    ///
    /// # Arguments
    /// * `args` - Command-line arguments to pass to zypper
    ///
    /// # Security
    /// This method runs zypper with elevated privileges. Ensures arguments
    /// are validated before passing them to this function.
    fn execute_zypper(&self, args: &[&str]) -> Result<String> {
        super::execute_command("zypper", args)
    }
}

impl PackageManager for ZypperPackageManager {
    fn update(&self) -> Result<()> {
        self.execute_zypper(&["--non-interactive", "refresh"])?;
        Ok(())
    }

    fn install(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Validate all package names before executing command
        super::validate_package_names(packages, super::PackageNameRules::Rpm)?;

        let mut args = vec!["--non-interactive", "install"];
        args.extend(packages);

        self.execute_zypper(&args)?;
        Ok(())
    }

    fn remove(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Validate all package names before executing command
        super::validate_package_names(packages, super::PackageNameRules::Rpm)?;

        let mut args = vec!["--non-interactive", "remove"];
        args.extend(packages);

        self.execute_zypper(&args)?;
        Ok(())
    }

    fn list_installed(&self) -> Result<Vec<Package>> {
        let output = super::execute_command("rpm", &[
            "-qa",
            "--queryformat",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
        ])?;
        Ok(super::parse_rpm_package_list(&output))
    }

    fn is_installed(&self, package: &str) -> Result<bool> {
        let result = Command::new("rpm")
            .args(["-q", package])
            .output()
            .map_err(|e| {
                HardeningError::PackageManager(format!("Failed to query package {}", e))
            })?;

        Ok(result.status.success())
    }

    fn security_updates(&self) -> Result<Vec<Package>> {
        // Zypper uses "patches" for security updates, not individual packages
        let output = self.execute_zypper(&[
            "--non-interactive",
            "list-patches",
            "--category",
            "security",
        ])?;

        let mut packages = Vec::new();

        for line in output.lines() {
            // Skip header lines and separators
            if line.starts_with("Repository") || line.starts_with("---") || line.is_empty() {
                continue;
            }

            // Parse zypper output: "Repository | Name | Category |
            // Severity | Interactive | Status | Summary"
            let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            if parts.len() >= 7 {
                let patch_name = parts[1].to_string();
                let status = parts[5];

                // Only include patches that are "needed" or "not installed"
                if status.contains("needed") || status.contains("Needed") {
                    packages.push(Package {
                        package_name: patch_name,
                        package_version: "security-patch".to_string(),
                        package_architecture: "noarch".to_string(),
                        package_is_security_update: true,
                    });
                }
            }
        }

        Ok(packages)
    }
}
