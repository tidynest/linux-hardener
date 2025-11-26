//! GDPR Article 32 control definitions
//!
//! Maps GDPR Article 32 (Security of Processing) requirements to plugin findings.
//! Focused on technical measures for data protection.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns all GDPR control definitions.
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // Article 32(1)(a) - Pseudonymisation and Encryption
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(a)".to_string(),
            compliance_control_title: "Pseudonymisation and encryption of personal data".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },

        // ===========================================
        // Article 32(1)(b) - Confidentiality, Integrity, Availability
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(b)-C".to_string(),
            compliance_control_title: "Ensure ongoing confidentiality of processing systems".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(b)-I".to_string(),
            compliance_control_title: "Ensure ongoing integrity of processing systems".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(b)-A".to_string(),
            compliance_control_title: "Ensure ongoing availability of processing systems".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(b)-R".to_string(),
            compliance_control_title: "Ensure resilience of processing systems".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },

        // ===========================================
        // Article 32(1)(c) - Restore Availability
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(c)".to_string(),
            compliance_control_title: "Ability to restore availability and access to personal data".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },

        // ===========================================
        // Article 32(1)(d) - Testing and Evaluation
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "Art.32(1)(d)".to_string(),
            compliance_control_title: "Process for regularly testing and evaluating security measures".to_string(),
            compliance_section: Some("Security of Processing".to_string()),
        },

        // ===========================================
        // Technical Measures (derived from Art. 32)
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "TM-AC".to_string(),
            compliance_control_title: "Access Control - Restrict access to personal data".to_string(),
            compliance_section: Some("Technical Measures".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "TM-AU".to_string(),
            compliance_control_title: "Audit Logging - Record access to personal data".to_string(),
            compliance_section: Some("Technical Measures".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "TM-NW".to_string(),
            compliance_control_title: "Network Security - Protect data in transit".to_string(),
            compliance_section: Some("Technical Measures".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "TM-AUTH".to_string(),
            compliance_control_title: "Authentication - Verify user identity".to_string(),
            compliance_section: Some("Technical Measures".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::GDPR,
            compliance_control_id: "TM-SH".to_string(),
            compliance_control_title: "System Hardening - Reduce attack surface".to_string(),
            compliance_section: Some("Technical Measures".to_string()),
        },
    ]
}
