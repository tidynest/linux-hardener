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

    /// Validates a package name to prevent command injection.
    ///
    /// RPM package names must follow specific rules:
    /// - Must start with alphanumeric
    /// - Can contain: letters, digits, plus, minus, dot, underscore
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

        // RPM package naming rules: alphanumeric, +, -, ., _
        let valid = package_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.' || c == '_');

        if !valid {
            return Err(HardeningError::Validation(format!(
                "Invalid package name '{}': contains forbidden characters",
                package_name
            )));
        }

        Ok(())
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
        let output = Command::new("zypper").args(args).output().map_err(|e| {
            HardeningError::PackageManager(format!("Failed to execute zypper: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "Zypper command failed: {}",
                stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
        for package_name in packages {
            Self::validate_package_name(package_name)?;
        }

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
        for package_name in packages {
            Self::validate_package_name(package_name)?;
        }

        let mut args = vec!["--non-interactive", "remove"];
        args.extend(packages);

        self.execute_zypper(&args)?;
        Ok(())
    }

    fn list_installed(&self) -> Result<Vec<Package>> {
        let output = Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
            ])
            .output()
            .map_err(|e| HardeningError::PackageManager(format!("Failed to execute rpm: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "rpm command failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let packages = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 3 {
                    Some(Package {
                        package_name: parts[0].to_string(),
                        package_version: parts[1].to_string(),
                        package_architecture: parts[2].to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_package_name_valid() {
        // Valid RPM package names (same rules as DNF)
        assert!(ZypperPackageManager::validate_package_name("zypper").is_ok());
        assert!(ZypperPackageManager::validate_package_name("kernel-default").is_ok());
        assert!(ZypperPackageManager::validate_package_name("lib_ssl+devel").is_ok());
    }

    #[test]
    fn test_validate_package_name_invalid() {
        // Too short
        assert!(ZypperPackageManager::validate_package_name("z").is_err());

        // Invalid characters (shell metacharacters)
        assert!(ZypperPackageManager::validate_package_name("package;evil").is_err());
        assert!(ZypperPackageManager::validate_package_name("package&&bad").is_err());
        assert!(ZypperPackageManager::validate_package_name("package|cmd").is_err());
    }
}
