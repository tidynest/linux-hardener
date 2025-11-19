//! Pacman package manager implementation for Arch Linux systems.

use super::{
    Package,
    PackageManager
};
use hardener_common::error::{
    HardeningError,
    Result,
};
use std::process::Command;

/// Pacman package manager implementation.
pub struct PacmanPackageManager;

impl PacmanPackageManager {
    /// Creates a new Pacman package manager instance.
    pub fn new() -> PacmanPackageManager {
        Self
    }

    /// Validates a package name to prevent command injection.
    ///
    /// Arch Linux package names can contain:
    /// - Letters, digits
    /// - @, dot, underscore, plus, minus
    /// - Must be at least 2 characters
    ///
    /// # Security
    /// This prevents command injection attacks via malicious package names.
    fn validate_package_name(package_name: &str) -> Result<()> {
        if package_name.len() < 2 {
            return Err(HardeningError::Validation(
                "Package name too short".to_string(),
            ));
        }

        // Arch package naming rules: alphanumeric, @, ., _, +, -
        let valid = package_name.chars().all(|c| {
            c.is_ascii_alphanumeric()
            || c == '@' || c == '.' || c == '_' || c == '+' || c == '-'
        });

            if !valid {
            return Err(HardeningError::Validation(format!(
            "Invalid package name '{}': contains forbidden characters",
            package_name
            )));
        }

        Ok(())
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
        let output = Command::new("pacman")
            .args(args)
            .output()
            .map_err(|e| HardeningError::PackageManager(format!(
                "Failed to execute pacman: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "Pacman command failed: {}", stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
        for package_name in packages {
            Self::validate_package_name(package_name)?;
        }

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
        for package_name in packages {
            Self::validate_package_name(package_name)?;
        }

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
                        package_name:               parts[0].to_string(),
                        package_version:            parts[1].to_string(),
                        package_architecture:       std::env::consts::ARCH.to_string(),
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
            .args(&["-Q", package])
            .output()
            .map_err(|e| HardeningError::PackageManager(format!(
                    "Failed to query package: {}", e
                )))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_package_name_valid() {
        // Valid Arch package names
        assert!(PacmanPackageManager::validate_package_name("linux").is_ok());
        assert!(PacmanPackageManager::validate_package_name("lib32-gcc-libs").is_ok());
        assert!(PacmanPackageManager::validate_package_name("python@3.11").is_ok());
        assert!(PacmanPackageManager::validate_package_name("package_name+extra").is_ok());
    }

    #[test]
    fn test_validate_package_name_invalid() {
        // Too short
        assert!(PacmanPackageManager::validate_package_name("p").is_err());

        // Invalid characters (shell metacharacters)
        assert!(PacmanPackageManager::validate_package_name("package;rm-rf").is_err());
        assert!(PacmanPackageManager::validate_package_name("package&&evil").is_err());
        assert!(PacmanPackageManager::validate_package_name("package|whoami").is_err());
    }
}
