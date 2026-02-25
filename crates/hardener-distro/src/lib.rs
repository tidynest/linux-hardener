//! Distribution detection and adaptation layer.
//!
//! Provides abstractions for working with different Linux distributions.

pub mod adapter;
pub mod package;

pub use adapter::DistributionAdapter;

use serde::{Deserialize, Serialize};

/// Major Linux distribution families.
///
/// Groups distributions by their package management and configuration approaches
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DistroFamily {
    /// Debian-based distributions (Debian, Ubuntu, Linux Mint, etc.).
    Debian,
    /// Red Hat-based distributions (RHEL, Fedora, CentOS, Rocky, etc.).
    RedHat,
    /// Arch-based distributions (Arch Linux, Manjaro, EndeavourOS, etc.).
    Arch,
    /// SUSE-based distributions (openSUSE, SLES, etc.).
    Suse,
}

/// Information about a detected Linux distribution.
///
/// Contains identifying information parsed from system files like `/etc/os-release`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Distribution {
    /// The distribution family this belongs to.
    pub distro_family: DistroFamily,
    /// Distribution name (e.g. "ubuntu", "fedora", "arch").
    pub distro_name: String,
    /// Distribution version (e.g., "22.04", "39", "rolling").
    pub distro_version: String,
    /// Optional codename (e.g., "jammy", "bookworm").
    pub distro_codename: Option<String>,
}

impl Distribution {
    /// Detects the current Linux distribution.
    ///
    /// Reads `/etc/os-release` to identify the distribution.
    ///
    /// # Errors
    /// Returns an error if the distribution cannot be detected.
    pub fn detect() -> hardener_common::error::Result<Self> {
        let os_release_data = Self::read_os_release()?;

        let distro_name = Self::extract_field(&os_release_data, "ID")?;
        let distro_version = Self::extract_field(&os_release_data, "VERSION_ID")
            .unwrap_or_else(|_| "rolling".to_string());
        let distro_codename = Self::extract_field(&os_release_data, "VERSION_CODENAME").ok();
        let distro_family = Self::map_to_family(&distro_name)?;

        Ok(Self {
            distro_family,
            distro_name,
            distro_version,
            distro_codename,
        })
    }

    /// Reads and parses the `/etc/os-release` file.
    fn read_os_release() -> hardener_common::error::Result<std::collections::HashMap<String, String>>
    {
        use std::fs;

        let content = fs::read_to_string("/etc/os-release")
            .map_err(hardener_common::error::HardeningError::System)?;

        let mut map = std::collections::HashMap::new();
        for line in content.lines() {
            if let Some((key, value)) = line.split_once("=") {
                // Remove quotes from value
                let clean_value = value.trim_matches('"');
                map.insert(key.to_string(), clean_value.to_string());
            }
        }

        Ok(map)
    }

    /// Extracts a field from the os-release data.
    fn extract_field(
        data: &std::collections::HashMap<String, String>,
        field_name: &str,
    ) -> hardener_common::error::Result<String> {
        data.get(field_name).cloned().ok_or_else(|| {
            hardener_common::error::HardeningError::Config(format!(
                "Missing os-release field '{}'",
                field_name
            ))
        })
    }

    /// Maps a distribution ID to its family.
    fn map_to_family(distro_id: &str) -> hardener_common::error::Result<DistroFamily> {
        match distro_id {
            // Debian family
            "debian" | "ubuntu" | "linuxmint" | "pop" | "elementary" => Ok(DistroFamily::Debian),

            // Red Hat family
            "rhel" | "fedora" | "centos" | "rocky" | "almalinux" | "ol" => Ok(DistroFamily::RedHat),

            // Arch family
            "arch" | "manjaro" | "endeavouros" | "garuda" => Ok(DistroFamily::Arch),

            // SUSE family
            "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" => Ok(DistroFamily::Suse),

            // Unknown distribution
            _ => Err(hardener_common::error::HardeningError::UnsupportedDistro(
                format!("Distribution '{}' is not supported", distro_id),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_detection() {
        let result = Distribution::detect();
        assert!(result.is_ok());

        let distro = result.unwrap();
        assert!(!distro.distro_name.is_empty());
        assert!(!distro.distro_version.is_empty());
    }
}

#[test]
fn test_family_mapping() {
    // Debian family
    assert_eq!(
        Distribution::map_to_family("ubuntu").unwrap(),
        DistroFamily::Debian
    );
    assert_eq!(
        Distribution::map_to_family("debian").unwrap(),
        DistroFamily::Debian
    );

    // Red Hat family
    assert_eq!(
        Distribution::map_to_family("fedora").unwrap(),
        DistroFamily::RedHat
    );
    assert_eq!(
        Distribution::map_to_family("rhel").unwrap(),
        DistroFamily::RedHat
    );

    // Arch family
    assert_eq!(
        Distribution::map_to_family("arch").unwrap(),
        DistroFamily::Arch
    );

    // SUSE family
    assert_eq!(
        Distribution::map_to_family("opensuse").unwrap(),
        DistroFamily::Suse
    );

    // Unknown should error
    assert!(Distribution::map_to_family("unknown").is_err());
}
