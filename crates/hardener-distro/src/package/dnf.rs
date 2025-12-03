//! DNF package manager implementation for Fedora/RHEL systems.

use super::{Package, PackageManager};
use hardener_common::error::{HardeningError, Result};
use std::process::Command;

/// DNF package manager implementation.
pub struct DnfPackageManager;

impl Default for DnfPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DnfPackageManager {
    /// Creates a new DNF package manager instance.
    pub fn new() -> DnfPackageManager {
        Self
    }

    fn execute_dnf(&self, args: &[&str]) -> Result<String> {
        super::execute_command("dnf", args)
    }
}

impl PackageManager for DnfPackageManager {
    fn update(&self) -> Result<()> {
        // DNF's check-update returns exit code 100 if updates are available
        // We ignore the exit code and just refresh the metadata
        let _ = Command::new("dnf")
            .args(["-y", "check-update"])
            .output()
            .map_err(|e| HardeningError::PackageManager(format!("Failed to execute dnf: {}", e)))?;

        Ok(())
    }

    fn install(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Validate all package names before executing command
        super::validate_package_names(packages, super::PackageNameRules::Rpm)?;

        let mut args = vec!["-y", "install"];
        args.extend(packages);

        self.execute_dnf(&args)?;
        Ok(())
    }

    fn remove(&self, packages: &[&str]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        // Validate all package names before executing command
        super::validate_package_names(packages, super::PackageNameRules::Rpm)?;

        let mut args = vec!["-y", "remove"];
        args.extend(packages);

        self.execute_dnf(&args)?;
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
                HardeningError::PackageManager(format!("Failed to query package: {}", e))
            })?;

        Ok(result.status.success())
    }

    fn security_updates(&self) -> Result<Vec<Package>> {
        // Use dnf updateinfo to list security updates
        let output = self.execute_dnf(&["updateinfo", "list", "security"])?;

        let mut packages = Vec::new();

        for line in output.lines() {
            // Skip empty lines and header lines
            if line.trim().is_empty()
                || line.starts_with("Last metadata")
                || line.starts_with("Updates Information")
            {
                continue;
            }

            // Parse DNF updateinfo output format:
            // "FEDORA-2023-abc123def456 security kernel-5.15.0-1.fc37.x86_64"
            // or "RHSA-2023:1234 Important/Sec. package-name-version.arch"
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 3 {
                // The last part is usually package-name-version.arch
                let package_full = parts[parts.len() - 1];

                // Try to split package name from version.arch
                if let Some(last_dash) = package_full.rfind('-') {
                    if let Some(second_last_dash) = package_full[..last_dash].rfind('-') {
                        let package_name = package_full[..second_last_dash].to_string();
                        let version_arch = &package_full[second_last_dash + 1..];

                        // Split version from architecture
                        let (version, arch) = if let Some(dot_pos) = version_arch.rfind('.') {
                            let arch_part = &version_arch[dot_pos + 1..];
                            let version_part = &version_arch[..dot_pos];
                            (version_part.to_string(), arch_part.to_string())
                        } else {
                            (version_arch.to_string(), "unknown".to_string())
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
