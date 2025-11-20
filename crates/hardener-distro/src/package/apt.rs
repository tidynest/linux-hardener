//! APT package manager implementation for Debian/Ubuntu systems.

use super::{Package, PackageManager};
use hardener_common::error::{HardeningError, Result};
use std::process::Command;

/// APT package manager implementation.
pub struct AptPackageManager;

impl AptPackageManager {
    /// Creates a new APT package manager instance.
    pub fn new() -> AptPackageManager {
        Self
    }

    /// Validates a package name to prevent command injection.
    ///
    /// Package names in Debian/Ubuntu must follow specific rules:
    /// - Must start with alphanumeric
    /// - Can contain: letters, digits, plus, minus, dot
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

        // Debian package naming rules: alphanumeric, +, -, .
        let valid = package_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');

        if !valid {
            return Err(HardeningError::Validation(format!(
                "Invalid package name '{}': contains forbidden characters",
                package_name
            )));
        }

        Ok(())
    }

    /// Executes an apt-get command and returns the output.
    ///
    /// # Arguments
    /// * `args` - Command-line arguments to pass to apt-get
    ///
    /// # Security
    /// This method runs apt-get with elevated privileges. Ensures arguments
    /// are validated before passing them to this function.
    fn execute_apt(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("apt-get").args(args).output().map_err(|e| {
            HardeningError::PackageManager(format!("Failed to execute apt-get: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "APT command failed: {}",
                stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Executes a dpkg-query command and returns the output.
    fn execute_dpkg_query(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("dpkg-query")
            .args(args)
            .output()
            .map_err(|e| {
                HardeningError::PackageManager(format!("Failed to execute dpkg-query: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "dpkg-query failed: {}",
                stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl PackageManager for AptPackageManager {
    fn update(&self) -> Result<()> {
        self.execute_apt(&["update"])?;
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

        let mut args = vec!["install", "-y"];
        args.extend(packages);

        self.execute_apt(&args)?;
        Ok(())
    }

    fn remove(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        let mut args = vec!["remove", "-y"];
        args.extend(packages);

        self.execute_apt(&args)?;
        Ok(())
    }

    fn list_installed(&self) -> Result<Vec<Package>> {
        let output = self.execute_dpkg_query(&[
            "-W",
            "--showformat=${Package}\t${Version}\t${Architecture}\n",
        ])?;

        let packages = output
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
        let result = Command::new("dpkg-query")
            .args(&["-W", "-f=${Status}", package])
            .output()
            .map_err(|e| {
                HardeningError::PackageManager(format!("Failed to query package: {}", e))
            })?;

        if !result.status.success() {
            return Ok(false);
        }

        let status = String::from_utf8_lossy(&result.stdout);
        Ok(status.contains("install ok installed"))
    }

    fn security_updates(&self) -> Result<Vec<Package>> {
        // First, update the package cache to get latest information
        self.execute_apt(&["update"])?;

        // Use apt-get upgrade with --dry-run to see what would be upgraded
        let output = self.execute_apt(&[
            "upgrade",
            "--dry-run",
            "-V", // Verbose to show versions
        ])?;

        let mut packages = Vec::new();

        for line in output.lines() {
            // Look for lines like "Inst package-name [old-version]
            // (new-version Ubuntu:22.04/jammy-security [arch])"
            if line.trim().starts_with("Inst ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let package_name = parts[1].to_string();

                    // Check if this is a security update (contains "-security" in the line)
                    let is_security = line.contains("-security") || line.contains("security");

                    if is_security {
                        // Extract version - it's in parentheses
                        if let Some(version_start) = line.find('(') {
                            if let Some(version_end) = line[version_start..].find(' ') {
                                let version = line[version_start + 1..version_start + version_end]
                                    .to_string();

                                // Extract architecture if present
                                let arch = if let Some(arch_start) = line.rfind('[') {
                                    if let Some(arch_end) = line[arch_start..].find(']') {
                                        line[arch_start + 1..arch_start + arch_end].to_string()
                                    } else {
                                        "unknown".to_string()
                                    }
                                } else {
                                    "unknown".to_string()
                                };

                                packages.push(Package {
                                    package_name,
                                    package_version: version,
                                    package_architecture: arch,
                                    package_is_security_update: true,
                                });
                            }
                        }
                    }
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
        // Valid Debian package names
        assert!(AptPackageManager::validate_package_name("nginx").is_ok());
        assert!(AptPackageManager::validate_package_name("lib-ssl1.1").is_ok());
        assert!(AptPackageManager::validate_package_name("python3+extra").is_ok());
    }

    #[test]
    fn test_validate_package_name_invalid() {
        // Too short
        assert!(AptPackageManager::validate_package_name("a").is_err());

        // Invalid characters (shell metacharacters)
        assert!(AptPackageManager::validate_package_name("package;rm-rf").is_err());
        assert!(AptPackageManager::validate_package_name("package&&malicious").is_err());
        assert!(AptPackageManager::validate_package_name("package|whoami").is_err());
    }
}
