//! Package manager abstraction layer.
//!
//! This module provides a unified interface for interacting with different
//! package managers across Linux distributions (APT, DNF, Pacman, Zypper).

use hardener_common::error::{HardeningError, Result};
use serde::{Deserialize, Serialize};

/// Represents a software package in the system.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Package {
    pub package_name: String,
    pub package_version: String,
    pub package_architecture: String,
    pub package_is_security_update: bool,
}

/// Allowed characters for package manager name validation ordered after distribution family.
#[derive(Clone, Copy, Debug)]
pub enum PackageNameRules {
    /// Debian/Ubuntu: alphanumeric, +, -, .
    Debian,
    /// RPM-based (Fedora, RHEL, SUSE): alphanumeric, +, -, ., _
    Rpm,
    /// Arch Linux: alphanumeric, @, ., _, +, -
    Arch,
}

/// Validates a package against distribution-specific rules.
///
/// # Security
/// Prevents command injection attacks via malicious package names.
pub fn validate_package_name(package_name: &str, rules: PackageNameRules) -> Result<()> {
    if package_name.len() < 2 {
        return Err(HardeningError::Validation(
            "Package name too short".to_string(),
        ));
    }

    let valid = match rules {
        PackageNameRules::Debian => package_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'),
        PackageNameRules::Rpm => package_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.' || c == '_'),
        PackageNameRules::Arch => package_name.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '@' || c == '.' || c == '_' || c == '+' || c == '-'
        }),
    };

    if !valid {
        return Err(HardeningError::Validation(format!(
            "Invalid package name '{}': contains forbidden characters",
            package_name
        )));
    }

    Ok(())
}

/// Validates a slice of package names.
pub fn validate_package_names(packages: &[&str], rules: PackageNameRules) -> Result<()> {
    for package_name in packages {
        validate_package_name(package_name, rules)?;
    }
    Ok(())
}

/// Executes a command and returns stdout, with standardised error handling.
///
/// Resolves bare command names to absolute paths via a trusted search list,
/// preventing PATH-based binary substitution attacks.
pub fn execute_command(command: &str, args: &[&str]) -> Result<String> {
    let resolved = hardener_common::binary_utils::resolve_binary(command);
    let output = std::process::Command::new(&resolved)
        .args(args)
        .output()
        .map_err(|e| {
            HardeningError::PackageManager(format!("Failed to execute {}: {}", resolved, e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HardeningError::PackageManager(format!(
            "{} command failed: {}",
            command, stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parses RPM query output into Package list.
/// Used by both DNF and Zypper which share RPM backend.
pub fn parse_rpm_package_list(output: &str) -> Vec<Package> {
    output
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
        .collect()
}

/// Trait for package manager operations across different distributions.
///
/// This trait provides a common interface for package management operations
/// regardless of the underlying package manager (APT, DNF, Pacman, Zypper).
///
/// All implementations must be thread-safe (`Send + Sync`).
pub trait PackageManager: Send + Sync {
    /// Updates the package manager's cache/metadata.
    ///
    /// # Examples
    /// - APT: `apt-get update`
    /// - DNF: `dnf check-update`
    /// - Pacman: `pacman -Sy`
    /// - Zypper: `zypper refresh`
    fn update(&self) -> Result<()>;

    /// Installs the specified packages.
    ///
    /// # Arguments
    /// * `packages` - Slice of package names to install
    fn install(&self, packages: &[&str]) -> Result<()>;

    /// Removes the specified packages.
    ///
    /// # Arguments
    /// * `packages` - Slice of package names to remove
    fn remove(&self, package_name: &[&str]) -> Result<()>;

    /// Lists all installed packages on the system.
    fn list_installed(&self) -> Result<Vec<Package>>;

    /// Checks if a specific package is installed.
    ///
    /// # Arguments
    /// * `package` - Package name to check
    fn is_installed(&self, package: &str) -> Result<bool>;

    /// Lists available security updates.
    fn security_updates(&self) -> Result<Vec<Package>>;
}

// Package manager implementations
mod apt;
mod dnf;
mod pacman;
mod zypper;

// Re-export implementations
pub use apt::AptPackageManager;
pub use dnf::DnfPackageManager;
pub use pacman::PacmanPackageManager;
pub use zypper::ZypperPackageManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_debian_package_name_valid() {
        assert!(validate_package_name("nginx", PackageNameRules::Debian).is_ok());
        assert!(validate_package_name("lib-ssl1.1", PackageNameRules::Debian).is_ok());
        assert!(validate_package_name("python3+extra", PackageNameRules::Debian).is_ok());
    }

    #[test]
    fn test_validate_debian_package_name_invalid() {
        assert!(validate_package_name("a", PackageNameRules::Debian).is_err());
        assert!(validate_package_name("package;rm", PackageNameRules::Debian).is_err());
        assert!(validate_package_name("pkg_name", PackageNameRules::Debian).is_err());
    }

    #[test]
    fn test_validate_rpm_package_name_valid() {
        assert!(validate_package_name("kernel", PackageNameRules::Rpm).is_ok());
        assert!(validate_package_name("glibc-2.34", PackageNameRules::Rpm).is_ok());
        assert!(validate_package_name("lib_ssl+extra", PackageNameRules::Rpm).is_ok());
    }

    #[test]
    fn test_validate_rpm_package_name_invalid() {
        assert!(validate_package_name("x", PackageNameRules::Rpm).is_err());
        assert!(validate_package_name("package;evil", PackageNameRules::Rpm).is_err());
    }

    #[test]
    fn test_validate_arch_package_name_valid() {
        assert!(validate_package_name("linux", PackageNameRules::Arch).is_ok());
        assert!(validate_package_name("lib32-gcc-libs", PackageNameRules::Arch).is_ok());
        assert!(validate_package_name("python@3.11", PackageNameRules::Arch).is_ok());
    }

    #[test]
    fn test_validate_arch_package_name_invalid() {
        assert!(validate_package_name("p", PackageNameRules::Arch).is_err());
        assert!(validate_package_name("package|whoami", PackageNameRules::Arch).is_err());
    }
}
