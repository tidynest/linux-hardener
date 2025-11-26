//! PCI-DSS control definitions
//!
//! Maps PCI-DSS v4.0 requirements to plugin findings.
//! Focused on requirements relevant to Linux system hardening.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns all PCI-DSS control definitions.
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // Requirement 1: Network Security Controls
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "1.3.1".to_string(),
            compliance_control_title: "Inbound traffic is restricted to only authorised traffic".to_string(),
            compliance_section: Some("Network Security Controls".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "1.3.2".to_string(),
            compliance_control_title: "Outbound traffic is restricted to only authorised traffic".to_string(),
            compliance_section: Some("Network Security Controls".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "1.4.1".to_string(),
            compliance_control_title: "NSCs are implemented between trusted and untrusted networks".to_string(),
            compliance_section: Some("Network Security Controls".to_string()),
        },

        // ===========================================
        // Requirement 2: Secure Configurations
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "2.2.1".to_string(),
            compliance_control_title: "Configuration standards are developed and implemented".to_string(),
            compliance_section: Some("Secure Configurations".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "2.2.4".to_string(),
            compliance_control_title: "Only necessary services and protocols are enabled".to_string(),
            compliance_section: Some("Secure Configurations".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "2.2.5".to_string(),
            compliance_control_title: "Insecure services and protocols are notused".to_string(),
            compliance_section: Some("Secure Configurations".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "2.2.6".to_string(),
            compliance_control_title: "System security parameters are configured to prevent misuse".to_string(),
            compliance_section: Some("Secure Configurations".to_string()),
        },

        // ===========================================
        // Requirement 5: Protect from Malware
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "5.2.1".to_string(),
            compliance_control_title: "Anti-malware solution is deployed on all applicable systems".to_string(),
            compliance_section: Some("Protect from Malware".to_string()),
        },

        // ===========================================
        // Requirement 7: Restrict Access
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "7.2.1".to_string(),
            compliance_control_title: "Access control model is defined and includes granting appropriate access".to_string(),
            compliance_section: Some("Restrict Access".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "7.2.2".to_string(),
            compliance_control_title: "Access is assigned based on job classification and function".to_string(),
            compliance_section: Some("Restrict Access".to_string()),
        },

        // ===========================================
        // Requirement 8: Identify Users and Authenticate
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.2.1".to_string(),
            compliance_control_title: "All users are assigned a unique ID".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.2.2".to_string(),
            compliance_control_title: "Group and shared accounts are not used".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.3.1".to_string(),
            compliance_control_title: "Strong authentication for users and administrators".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.3.4".to_string(),
            compliance_control_title: "Invalid authentication attempts are limited".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.3.5".to_string(),
            compliance_control_title: "Passwords meet minimum complexity requirements".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.3.6".to_string(),
            compliance_control_title: "Passwords are changed at least every 90 days".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.3.9".to_string(),
            compliance_control_title: "Password history prevents reuse of last four passwords".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "8.6.1".to_string(),
            compliance_control_title: "Interactive login for system/application accounts is restricted".to_string(),
            compliance_section: Some("Identify and Authenticate".to_string()),
        },

        // ===========================================
        // Requirement 10: Log and Monitor Access
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "10.2.1".to_string(),
            compliance_control_title: "Audit logs are enabled and active".to_string(),
            compliance_section: Some("Log and Monitor".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "10.2.1.1".to_string(),
            compliance_control_title: "All individual user access to cardholder data is logged".to_string(),
            compliance_section: Some("Log and Monitor".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "10.2.1.2".to_string(),
            compliance_control_title: "All actions by privileged users are logged".to_string(),
            compliance_section: Some("Log and Monitor".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "10.2.1.5".to_string(),
            compliance_control_title: "All changes to authentication credentials are logged".to_string(),
            compliance_section: Some("Log and Monitor".to_string()),
        },
    ]
}
