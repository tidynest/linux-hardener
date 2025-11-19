//! DNF package manager implementation for Fedora/RHEL systems.

use hardener_common::error::{
    HardeningError,
    Result,
};
use std::process::Command;
use super::{
    Package,
    PackageManager
};

/// DNF package manager implementation.
pub struct DnfPackageManager;

impl DnfPackageManager {
    /// Creates a new DNF package manager instance.
    pub fn new() -> DnfPackageManager {
        Self
    }

    /// Executes a dnf command and returns the output.
    ///
    /// # Arguments
    /// * `args` - Command-line arguments to pass to dnf
    ///
    /// # Security
    /// This method runs dnf with elevated privileges. Ensures arguments
    /// are validated before passing them to this function.
    fn execute_dnf(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("dnf")
            .args(args)
            .output()
            .map_err(|e| HardeningError::PackageManager(format!(
                "Failed to execute dnf: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "DNF command failed: {}", stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Validates a package name to prevent command injection.
    ///
    /// RPM package names must follow specific rules:
    /// - Must start with alphanumeric
    /// - Can contain: letters, digits, plus, minus, dot, underscore
    /// - Must be at least 2 characters
    ///
    /// # Security
    /// This precents command injection attacks via malicious package names.
    fn validate_package_name(package_name: &str) -> Result<()> {
        if package_name.len() < 2 {
            return Err(HardeningError::Validation(
                "Package name too short".to_string(),
            ));
        }

        // RPM package naming rules: alphanumeric, +, -, ., _
        let valid = package_name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == '+' || c == '-' || c == '.' || c == '_'
        });

        if !valid {
            return Err(HardeningError::Validation(format!(
                "Invalid package name '{}': contains forbidden characters",
                package_name
            )));
        }

        Ok(())
    }
}

impl PackageManager for DnfPackageManager {
    fn update(&self) -> Result<()> {
        // DNF's check-update returns exit code 100 if updates are available
        // We ignore the exit code and just refresh the metadata
        let _ = Command::new("dnf")
            .args(&["-y", "check-update"])
            .output()
            .map_err(|e| HardeningError::PackageManager(format!(
                "Failed to execute dnf: {}", e
            )))?;

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
        for package_name in packages {
            Self::validate_package_name(package_name)?;
        }

        let mut args = vec!["-y", "remove"];
        args.extend(packages);

        self.execute_dnf(&args)?;
        Ok(())
    }

    fn list_installed(&self) -> Result<Vec<Package>> {
        let output = Command::new("rpm").args(&[
            "-qa", 
            "--queryformat", 
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"
        ])
            .output()
            .map_err(|e| HardeningError::PackageManager(format!(
                "Failed to execute rpm: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HardeningError::PackageManager(format!(
                "rpm command failed: {}", stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let packages = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >=3 {
                    Some(Package {
                        package_name:           parts[0].to_string(),
                        package_version:        parts[1].to_string(),
                        package_architecture:   parts[2].to_string(),
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
            .args(&["-q", package])
            .output()
            .map_err(|e| HardeningError::PackageManager(format!(
                "Failed to query package: {}", e
            )))?;

        Ok(result.status.success())
    }

    fn security_updates(&self) -> Result<Vec<Package>> {
        // Use dnf updateinfo to list security updates
        let output = self.execute_dnf(&["updateinfo", "list", "security"])?;

        let mut packages = Vec::new();

        for line in output.lines() {
            // Skip empty lines and header lines
            if line.trim().is_empty() || 
                line.starts_with("Last metadata") || 
                line.starts_with("Updates Information") {
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
                            package_version:        version,
                            package_architecture:   arch,
                            package_is_security_update: true,
                        });
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
        // Valid RPM package names
        assert!(DnfPackageManager::validate_package_name("kernel").is_ok());
        assert!(DnfPackageManager::validate_package_name("glibc-2.34").is_ok());
        assert!(DnfPackageManager::validate_package_name("lib_ssl+extra").is_ok());
    }

    #[test]
    fn test_validate_package_name_invalid() {
        // Too short
        assert!(DnfPackageManager::validate_package_name("x").is_err());

        // Invalid characters (shell metacharacters)
        assert!(DnfPackageManager::validate_package_name("package;malicious").is_err());
        assert!(DnfPackageManager::validate_package_name("package&&cmd").is_err());
        assert!(DnfPackageManager::validate_package_name("package|cat").is_err());
    }
}
