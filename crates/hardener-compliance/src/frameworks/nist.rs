//! NIST 800-53 control definitions
//!
//! Maps NIST 800-53 Rev 5 security controls to plugin findings.
//! Focused on technical controls relevant to Linux system hardening.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns all NIST 800-53 control definitions.
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // AC - Access Control
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AC-3".to_string(),
            compliance_control_title: "Access Enforcement".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AC-6".to_string(),
            compliance_control_title: "Least Privilege".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AC-7".to_string(),
            compliance_control_title: "Unsuccessful Logon Attempts".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AC-8".to_string(),
            compliance_control_title: "System Use Notification".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AC-11".to_string(),
            compliance_control_title: "Device Lock".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AC-17".to_string(),
            compliance_control_title: "Remote Access".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        // ===========================================
        // AU - Audit and Accountability
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AU-2".to_string(),
            compliance_control_title: "Event Logging".to_string(),
            compliance_section: Some("Audit and Accountability".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AU-3".to_string(),
            compliance_control_title: "Content of Audit Records".to_string(),
            compliance_section: Some("Audit and Accountability".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AU-8".to_string(),
            compliance_control_title: "Time Stamps".to_string(),
            compliance_section: Some("Audit and Accountability".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "AU-12".to_string(),
            compliance_control_title: "Audit Record Generation".to_string(),
            compliance_section: Some("Audit and Accountability".to_string()),
        },
        // ===========================================
        // CM - Configuration Management
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "CM-6".to_string(),
            compliance_control_title: "Configuration Settings".to_string(),
            compliance_section: Some("Configuration Management".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "CM-7".to_string(),
            compliance_control_title: "Least Functionality".to_string(),
            compliance_section: Some("Configuration Management".to_string()),
        },
        // ===========================================
        // IA - Identification and Authentication
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "IA-2".to_string(),
            compliance_control_title: "Identification and Authentication (Organizational Users)"
                .to_string(),
            compliance_section: Some("Identification and Authentication".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "IA-5".to_string(),
            compliance_control_title: "Authenticator Management".to_string(),
            compliance_section: Some("Identification and Authentication".to_string()),
        },
        // ===========================================
        // SC - System and Communications Protection
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SC-5".to_string(),
            compliance_control_title: "Denial-of-Service Protection".to_string(),
            compliance_section: Some("System and Communications Protection".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SC-7".to_string(),
            compliance_control_title: "Boundary Protection".to_string(),
            compliance_section: Some("System and Communications Protection".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SC-10".to_string(),
            compliance_control_title: "Network Disconnect".to_string(),
            compliance_section: Some("System and Communications Protection".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SC-23".to_string(),
            compliance_control_title: "Session Authenticity".to_string(),
            compliance_section: Some("System and Communications Protection".to_string()),
        },
        // ===========================================
        // SI - System and Information Integrity
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SI-2".to_string(),
            compliance_control_title: "Flaw Remediation".to_string(),
            compliance_section: Some("System and Information Integrity".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SI-16".to_string(),
            compliance_control_title: "Memory Protection".to_string(),
            compliance_section: Some("System and Information Integrity".to_string()),
        },
    ]
}
