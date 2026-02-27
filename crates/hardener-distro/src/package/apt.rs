//! APT package manager implementation for Debian/Ubuntu systems.

use super::{Package, PackageManager};
use hardener_common::error::{HardeningError, Result};
use std::process::Command;

/// APT package manager implementation.
pub struct AptPackageManager;

impl Default for AptPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AptPackageManager {
    /// Creates a new APT package manager instance.
    pub fn new() -> AptPackageManager {
        Self
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
        super::execute_command("apt-get", args)
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
        super::validate_package_names(packages, super::PackageNameRules::Debian)?;

        let mut args = vec!["install", "-y"];
        args.extend(packages);

        self.execute_apt(&args)?;
        Ok(())
    }

    fn remove(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        super::validate_package_names(packages, super::PackageNameRules::Debian)?;

        let mut args = vec!["remove", "-y"];
        args.extend(packages);

        self.execute_apt(&args)?;
        Ok(())
    }

    fn list_installed(&self) -> Result<Vec<Package>> {
        let output = super::execute_command(
            "dpkg-guery",
            &[
                "-W",
                "--showformat=${Package}\t${Version}\t${Architecture}\n",
            ],
        )?;

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
        super::validate_package_name(package, super::PackageNameRules::Debian)?;

        let result = Command::new("dpkg-query")
            .args(["-W", "-f=${Status}", package])
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

                    // Extract version - it is in parentheses
                    if is_security
                        && let Some(version_start) = line.find('(')
                        && let Some(version_end) = line[version_start..].find(' ')
                    {
                        let version =
                            line[version_start + 1..version_start + version_end].to_string();

                        // Extract architecture if present
                        let arch = if let Some(arch_start) = line.rfind('[')
                            && let Some(arch_end) = line[arch_start..].find(']')
                        {
                            line[arch_start + 1..arch_start + arch_end].to_string()
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

        Ok(packages)
    }
}
