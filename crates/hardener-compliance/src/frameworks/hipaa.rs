//! HIPAA Security Rule control definitions
//!
//! Maps HIPAA Security Rule technical safeguards to plugin findings.
//! Based on 45 CFR Part 164 Subpart C.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Returns all HIPAA control definitions.
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // 164.312(a) - Access Control
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(a)(1)".to_string(),
            compliance_control_title: "Implement technical policies for access to 
  ePHI".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(a)(2)(i)".to_string(),
            compliance_control_title: "Unique User Identification".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(a)(2)(ii)".to_string(),
            compliance_control_title: "Emergency Access Procedure".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(a)(2)(iii)".to_string(),
            compliance_control_title: "Automatic Logoff".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(a)(2)(iv)".to_string(),
            compliance_control_title: "Encryption and Decryption".to_string(),
            compliance_section: Some("Access Control".to_string()),
        },

        // ===========================================
        // 164.312(b) - Audit Controls
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(b)".to_string(),
            compliance_control_title: "Implement audit controls to record and examine 
  activity".to_string(),
            compliance_section: Some("Audit Controls".to_string()),
        },

        // ===========================================
        // 164.312(c) - Integrity
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(c)(1)".to_string(),
            compliance_control_title: "Implement policies to protect ePHI from improper 
  alteration".to_string(),
            compliance_section: Some("Integrity".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(c)(2)".to_string(),
            compliance_control_title: "Mechanism to authenticate ePHI".to_string(),
            compliance_section: Some("Integrity".to_string()),
        },

        // ===========================================
        // 164.312(d) - Person or Entity Authentication
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(d)".to_string(),
            compliance_control_title: "Implement procedures to verify person or entity 
  identity".to_string(),
            compliance_section: Some("Authentication".to_string()),
        },

        // ===========================================
        // 164.312(e) - Transmission Security
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(e)(1)".to_string(),
            compliance_control_title: "Implement technical security measures for ePHI 
  transmission".to_string(),
            compliance_section: Some("Transmission Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(e)(2)(i)".to_string(),
            compliance_control_title: "Integrity Controls for transmission".to_string(),
            compliance_section: Some("Transmission Security".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.312(e)(2)(ii)".to_string(),
            compliance_control_title: "Encryption for transmission".to_string(),
            compliance_section: Some("Transmission Security".to_string()),
        },

        // ===========================================
        // 164.308(a) - Administrative Safeguards (Technical aspects)
        // ===========================================
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.308(a)(5)(ii)(D)".to_string(),
            compliance_control_title: "Password Management".to_string(),
            compliance_section: Some("Administrative Safeguards".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::HIPAA,
            compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
            compliance_control_title: "Information System Activity Review".to_string(),
            compliance_section: Some("Administrative Safeguards".to_string()),
        },
    ]
}
