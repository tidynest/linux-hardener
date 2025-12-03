//! Pacman package manager implementation for Arch Linux systems.

use super::{Package, PackageManager};
use hardener_common::error::{HardeningError, Result};
use std::process::Command;

/// Pacman package manager implementation.
pub struct PacmanPackageManager;

impl Default for PacmanPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PacmanPackageManager {
    /// Creates a new Pacman package manager instance.
    pub fn new() -> PacmanPackageManager {
        Self
    }

    /// Executes a pacman command and returns the output.
    ///
    /// # Arguments
    /// * `args` - Command-line arguments to pass to pacman
    ///
    /// # Security
    /// This method runs pacman with elevated privileges. Ensures arguments
    /// are validated before passing them to this function.
    fn execute_pacman(&self, args: &[&str]) -> Result<String> {
        super::execute_command("pacman", args)
    }
}

impl PackageManager for PacmanPackageManager {
    fn update(&self) -> Result<()> {
        self.execute_pacman(&["-Sy"])?;
        Ok(())
    }

    fn install(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Validate all package names before executing command
        super::validate_package_names(packages, super::PackageNameRules::Arch)?;

        let mut args = vec!["-S", "--noconfirm"];
        args.extend(packages);

        self.execute_pacman(&args)?;
        Ok(())
    }

    fn remove(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Validate all package names before executing command
        super::validate_package_names(packages, super::PackageNameRules::Arch)?;

        let mut args = vec!["-R", "--noconfirm"];
        args.extend(packages);

        self.execute_pacman(&args)?;
        Ok(())
    }

    fn list_installed(&self) -> Result<Vec<Package>> {
        let output = self.execute_pacman(&["-Q"])?;

        let packages = output
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    Some(Package {
                        package_name: parts[0].to_string(),
                        package_version: parts[1].to_string(),
                        package_architecture: std::env::consts::ARCH.to_string(),
                        package_is_security_update: false,
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(packages)
    }

    fn is_installed(&self, package: &str) -> Result<bool> {
        let result = Command::new("pacman")
            .args(["-Q", package])
            .output()
            .map_err(|e| {
                HardeningError::PackageManager(format!("Failed to query package: {}", e))
            })?;

        Ok(result.status.success())
    }

    fn security_updates(&self) -> Result<Vec<Package>> {
        // Arch Linux is a rolling release distribution.
        // There is no distinction between security updates and regular updates.
        // All update are applied together via `pacman -Syu`.
        // Therefore, we return an empty list as security-specific updates don't exist.
        Ok(Vec::new())
    }
}
