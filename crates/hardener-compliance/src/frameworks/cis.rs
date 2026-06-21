//! CIS Benchmark control definitions
//!
//! Maps CIS Benchmark controls to plugin findings for Linux systems.
//! Based on CIS Benchmark for Distribution Independent Linux v2.0.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns all control definitions for a given framework.
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // Section 1: Initial Setup
        // ===========================================

        // 1.5 Additional Process Hardening
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.5.1".to_string(),
            compliance_control_title: "Ensure address space layout randomisation (ASLR)"
                .to_string(),
            compliance_section: Some("Initial Setup".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.5.2".to_string(),
            compliance_control_title: "Ensure ptrace_scope is restricted".to_string(),
            compliance_section: Some("Initial Setup".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.5.3".to_string(),
            compliance_control_title: "Ensure core dumps are restricted".to_string(),
            compliance_section: Some("Initial Setup".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.5.4".to_string(),
            compliance_control_title: "Ensure kernel pointers are restricted".to_string(),
            compliance_section: Some("Initial Setup".to_string()),
        },
        // ===========================================
        // Section 3: Network Configuration
        // ===========================================

        // 3.2 Network Parameters (Host Only)
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.2.1".to_string(),
            compliance_control_title: "Ensure source routed packets are not accepted".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.2.2".to_string(),
            compliance_control_title: "Ensure ICMP redirects are not accepted".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.2.3".to_string(),
            compliance_control_title: "Ensure secure ICMP redirects are not accepted".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.2.4".to_string(),
            compliance_control_title: "Ensure suspicious packets are logged".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.2.7".to_string(),
            compliance_control_title: "Ensure reverse path filtering is enabled".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.2.8".to_string(),
            compliance_control_title: "Ensure TCP SYN cookies is enabled".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        // 3.4 Firewall Configuration
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.4.1.1".to_string(),
            compliance_control_title: "Ensure firewall is installed".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.4.1.2".to_string(),
            compliance_control_title: "Ensure firewall service is enabled and running".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        // ===========================================
        // Section 4: Logging and Auditing
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "4.1.1.1".to_string(),
            compliance_control_title: "Ensure auditd is installed".to_string(),
            compliance_section: Some("Logging and Auditing".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "4.1.1.2".to_string(),
            compliance_control_title: "Ensure auditd service is enabled and running".to_string(),
            compliance_section: Some("Logging and Auditing".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "4.1.2.1".to_string(),
            compliance_control_title: "Ensure audit log storage size is configured".to_string(),
            compliance_section: Some("Logging and Auditing".to_string()),
        },
        // ===========================================
        // Section 5: Access, Authentication and Authorisation
        // ===========================================

        // 5.1 Configure time-based job schedulers
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.1.8".to_string(),
            compliance_control_title: "Ensure cron is restricted to authorised users".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        // 5.2 SSH Server Configuration
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.1".to_string(),
            compliance_control_title: "Ensure permissions on /etc/ssh/sshd_config are configured"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.4".to_string(),
            compliance_control_title: "Ensure SSH Protocol is set to 2".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.6".to_string(),
            compliance_control_title: "Ensure SSH X11 forwarding is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.7".to_string(),
            compliance_control_title: "Ensure SSH MaxAuthTries is set to 4 or less".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.10".to_string(),
            compliance_control_title: "Ensure SSH root login is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.11".to_string(),
            compliance_control_title: "Ensure SSH PermitEmptyPasswords is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.13".to_string(),
            compliance_control_title: "Ensure SSH Idle Timeout Interval is configured".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.14".to_string(),
            compliance_control_title: "Ensure only strong Key Exchange algorithms are used"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.15".to_string(),
            compliance_control_title: "Ensure only strong Ciphers are used".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.16".to_string(),
            compliance_control_title: "Ensure only strong MAC algorithms are used".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        // 5.3 Configure PAM
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.1".to_string(),
            compliance_control_title: "Ensure password creation requirements are configured"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.2".to_string(),
            compliance_control_title: "Ensure lockout for failed password attempts is configured"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.3".to_string(),
            compliance_control_title: "Ensure password reuse is limited".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        // ===========================================
        // Section 6: System Maintenance
        // ===========================================

        // 6.1 System File Permissions
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "6.1.2".to_string(),
            compliance_control_title: "Ensure permissions on /etc/passwd are configured"
                .to_string(),
            compliance_section: Some("System Maintenance".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "6.1.3".to_string(),
            compliance_control_title: "Ensure permissions on /etc/shadow are configured"
                .to_string(),
            compliance_section: Some("System Maintenance".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "6.1.4".to_string(),
            compliance_control_title: "Ensure permissions on /etc/group are configured".to_string(),
            compliance_section: Some("System Maintenance".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "6.1.5".to_string(),
            compliance_control_title: "Ensure permissions on /etc/gshadow are configured"
                .to_string(),
            compliance_section: Some("System Maintenance".to_string()),
        },
        // 6.2 User and Group Settings (Services)
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.1.1".to_string(),
            compliance_control_title: "Ensure xinetd is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.2.2".to_string(),
            compliance_control_title: "Ensure X Window System is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.2.3".to_string(),
            compliance_control_title: "Ensure Avahi Server is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.2.4".to_string(),
            compliance_control_title: "Ensure CUPS is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        },
        // ===========================================
        // Mandatory Access Control
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.6.1.1".to_string(),
            compliance_control_title: "Ensure SELinux or AppArmor is installed".to_string(),
            compliance_section: Some("Mandatory Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.6.1.2".to_string(),
            compliance_control_title: "Ensure SELinux is not disabled in bootloader configuration"
                .to_string(),
            compliance_section: Some("Mandatory Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.6.1.3".to_string(),
            compliance_control_title: "Ensure SELinux policy is configured".to_string(),
            compliance_section: Some("Mandatory Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "1.6.1.4".to_string(),
            compliance_control_title: "Ensure the SELinux mode is enforcing or AppArmor is enabled"
                .to_string(),
            compliance_section: Some("Mandatory Access Control".to_string()),
        },
    ]
}
