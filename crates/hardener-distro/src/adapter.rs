//! Distribution adapter trait and implementations.
//!
//! Provides distribution-specific behaviours for package management,
//! init systems, and other OS-level operations.

use crate::{Distribution, DistroFamily};

/// Distribution-specific adapter trait.
///
/// Each distribution family implements this trait to provide
/// family-specific functionality like package management.
pub trait DistributionAdapter: Send + Sync {
    /// Return the distribution information.
    fn distribution(&self) -> &Distribution;

    /// Returns the distribution family.
    fn family(&self) -> DistroFamily {
        self.distribution().distro_family
    }
}

#[cfg(test)]
mod tests;
