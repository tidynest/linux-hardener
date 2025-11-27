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
mod tests {
    use super::*;

    /// Mock adapter for testing.
    struct MockAdapter {
        distro: Distribution,
    }

    impl DistributionAdapter for MockAdapter {
        fn distribution(&self) -> &Distribution {
            &self.distro
        }
    }

    #[test]
    fn test_adapter_distribution() {
        let adapter = MockAdapter {
            distro: Distribution {
                distro_name: "TestOS".to_string(),
                distro_version: "1.0".to_string(),
                distro_family: DistroFamily::Debian,
                distro_codename: None,
            },
        };

        assert_eq!(adapter.distribution().distro_name, "TestOS");
        assert_eq!(adapter.distribution().distro_version, "1.0");
    }

    #[test]
    fn test_adapter_family() {
        let adapter = MockAdapter {
            distro: Distribution {
                distro_name: "TestOS".to_string(),
                distro_version: "1.0".to_string(),
                distro_family: DistroFamily::RedHat,
                distro_codename: None,
            },
        };

        assert_eq!(adapter.family(), DistroFamily::RedHat);
    }

    #[test]
    fn test_adapter_family_debian() {
        let adapter = MockAdapter {
            distro: Distribution {
                distro_name: "Ubuntu".to_string(),
                distro_version: "22.04".to_string(),
                distro_family: DistroFamily::Debian,
                distro_codename: Some("jammy".to_string()),
            },
        };

        assert_eq!(adapter.family(), DistroFamily::Debian);
    }

    #[test]
    fn test_adapter_family_arch() {
        let adapter = MockAdapter {
            distro: Distribution {
                distro_name: "Arch".to_string(),
                distro_version: "rolling".to_string(),
                distro_family: DistroFamily::Arch,
                distro_codename: None,
            },
        };

        assert_eq!(adapter.family(), DistroFamily::Arch);
    }

    #[test]
    fn test_adapter_family_suse() {
        let adapter = MockAdapter {
            distro: Distribution {
                distro_name: "openSUSE".to_string(),
                distro_version: "15.4".to_string(),
                distro_family: DistroFamily::Suse,
                distro_codename: None,
            },
        };

        assert_eq!(adapter.family(), DistroFamily::Suse);
    }
}
