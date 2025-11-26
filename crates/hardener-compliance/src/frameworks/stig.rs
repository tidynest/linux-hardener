//! STIG (Security Technical Implementation Guide) control definitions
//!
//! Maps DISA STIG controls to plugin findings for Linux systems.
//! Based on RHEL 8/9 STIG.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns all STIG control definitions.
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // Kernel Hardening
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230280".to_string(),
            compliance_control_title:
                "RHEL must implement address space layout randomization (ASLR)".to_string(),
            compliance_section: Some("Kernel Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230281".to_string(),
            compliance_control_title: "RHEL must restrict exposed kernel pointer addresses"
                .to_string(),
            compliance_section: Some("Kernel Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230282".to_string(),
            compliance_control_title: "RHEL must restrict access to the kernel message buffer"
                .to_string(),
            compliance_section: Some("Kernel Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230283".to_string(),
            compliance_control_title: "RHEL must restrict the use of ptrace".to_string(),
            compliance_section: Some("Kernel Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230284".to_string(),
            compliance_control_title: "RHEL must disable core dumps for SUID programs".to_string(),
            compliance_section: Some("Kernel Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230288".to_string(),
            compliance_control_title: "RHEL must enable TCP syncookies".to_string(),
            compliance_section: Some("Network Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230289".to_string(),
            compliance_control_title: "RHEL must use reverse path filtering on all IPv4 interfaces"
                .to_string(),
            compliance_section: Some("Network Security".to_string()),
        },
        // ===========================================
        // SSH Server Configuration
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230296".to_string(),
            compliance_control_title: "RHEL must not permit direct root login via SSH".to_string(),
            compliance_section: Some("SSH Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230297".to_string(),
            compliance_control_title: "RHEL must not allow SSH with empty passwords".to_string(),
            compliance_section: Some("SSH Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230298".to_string(),
            compliance_control_title: "RHEL must disable X11 forwarding via SSH".to_string(),
            compliance_section: Some("SSH Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230299".to_string(),
            compliance_control_title: "RHEL must terminate idle SSH sessions".to_string(),
            compliance_section: Some("SSH Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230300".to_string(),
            compliance_control_title: "RHEL must limit SSH authentication attempts".to_string(),
            compliance_section: Some("SSH Configuration".to_string()),
        },
        // ===========================================
        // Audit System
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230386".to_string(),
            compliance_control_title: "RHEL must have the audit system installed and enabled"
                .to_string(),
            compliance_section: Some("Auditing".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230390".to_string(),
            compliance_control_title: "RHEL must audit privileged functions".to_string(),
            compliance_section: Some("Auditing".to_string()),
        },
        // ===========================================
        // Mandatory Access Control
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230223".to_string(),
            compliance_control_title: "RHEL must enable SELinux".to_string(),
            compliance_section: Some("Mandatory Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230224".to_string(),
            compliance_control_title: "RHEL must use SELinux targeted policy".to_string(),
            compliance_section: Some("Mandatory Access Control".to_string()),
        },
        // ===========================================
        // Password/PAM Configuration
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230356".to_string(),
            compliance_control_title: "RHEL must require passwords of at least 14 characters"
                .to_string(),
            compliance_section: Some("Authentication".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230357".to_string(),
            compliance_control_title: "RHEL must require password complexity".to_string(),
            compliance_section: Some("Authentication".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230358".to_string(),
            compliance_control_title: "RHEL must enforce password maximum lifetime".to_string(),
            compliance_section: Some("Authentication".to_string()),
        },
        // ===========================================
        // Firewall
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "V-230505".to_string(),
            compliance_control_title: "RHEL must have a host-based firewall enabled".to_string(),
            compliance_section: Some("Network Security".to_string()),
        },
    ]
}
