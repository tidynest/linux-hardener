//! Package manager abstraction layer.
//!
//! This module provides a unified interface for interacting with different
//! package managers across Linux distributions (APT, DNF, Pacman, Zypper).

use hardener_common::error::Result;
use serde::{
    Deserialize,
    Serialize
};

/// Represents a software package in the system.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Package {
    pub package_name:               String,
    pub package_version:            String,
    pub package_architecture:       String,
    pub package_is_security_update: bool,
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
