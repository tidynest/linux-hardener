//! ISO/IEC 27001:2022 Annex A control definitions.
//!
//! Catalogues the 93 Annex A controls of ISO/IEC 27001:2022, using the
//! official clause numbers (e.g. "5.1", "8.24") and the control titles from
//! ISO/IEC 27002:2022. Controls are grouped by the four themes via
//! `compliance_section`: Organizational (5.x), People (6.x), Physical (7.x),
//! and Technological (8.x).
//!
//! Plugin findings reference technological controls such as "8.24" (use of
//! cryptography), "8.5" (secure authentication), "8.20" (networks security),
//! "8.15" (logging), "8.9" (configuration management), and "8.3" (information
//! access restriction). Controls without an automated mapping are surfaced by
//! the report generator as `ManualReview` rather than `Pass`.

use hardener_common::types::{ComplianceFramework, ComplianceMapping};

/// Builds a single ISO/IEC 27001:2022 Annex A control mapping.
fn control(id: &str, title: &str, theme: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::ISO27001,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(theme.to_string()),
    }
}

/// Returns all ISO/IEC 27001:2022 Annex A control definitions (93 controls).
pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // ===========================================
        // Organizational controls (5.1 - 5.37)
        // ===========================================
        control("5.1", "Policies for information security", "Organizational"),
        control(
            "5.2",
            "Information security roles and responsibilities",
            "Organizational",
        ),
        control("5.3", "Segregation of duties", "Organizational"),
        control("5.4", "Management responsibilities", "Organizational"),
        control("5.5", "Contact with authorities", "Organizational"),
        control(
            "5.6",
            "Contact with special interest groups",
            "Organizational",
        ),
        control("5.7", "Threat intelligence", "Organizational"),
        control(
            "5.8",
            "Information security in project management",
            "Organizational",
        ),
        control(
            "5.9",
            "Inventory of information and other associated assets",
            "Organizational",
        ),
        control(
            "5.10",
            "Acceptable use of information and other associated assets",
            "Organizational",
        ),
        control("5.11", "Return of assets", "Organizational"),
        control("5.12", "Classification of information", "Organizational"),
        control("5.13", "Labelling of information", "Organizational"),
        control("5.14", "Information transfer", "Organizational"),
        control("5.15", "Access control", "Organizational"),
        control("5.16", "Identity management", "Organizational"),
        control("5.17", "Authentication information", "Organizational"),
        control("5.18", "Access rights", "Organizational"),
        control(
            "5.19",
            "Information security in supplier relationships",
            "Organizational",
        ),
        control(
            "5.20",
            "Addressing information security within supplier agreements",
            "Organizational",
        ),
        control(
            "5.21",
            "Managing information security in the ICT supply chain",
            "Organizational",
        ),
        control(
            "5.22",
            "Monitoring, review and change management of supplier services",
            "Organizational",
        ),
        control(
            "5.23",
            "Information security for use of cloud services",
            "Organizational",
        ),
        control(
            "5.24",
            "Information security incident management planning and preparation",
            "Organizational",
        ),
        control(
            "5.25",
            "Assessment and decision on information security events",
            "Organizational",
        ),
        control(
            "5.26",
            "Response to information security incidents",
            "Organizational",
        ),
        control(
            "5.27",
            "Learning from information security incidents",
            "Organizational",
        ),
        control("5.28", "Collection of evidence", "Organizational"),
        control(
            "5.29",
            "Information security during disruption",
            "Organizational",
        ),
        control(
            "5.30",
            "ICT readiness for business continuity",
            "Organizational",
        ),
        control(
            "5.31",
            "Legal, statutory, regulatory and contractual requirements",
            "Organizational",
        ),
        control("5.32", "Intellectual property rights", "Organizational"),
        control("5.33", "Protection of records", "Organizational"),
        control("5.34", "Privacy and protection of PII", "Organizational"),
        control(
            "5.35",
            "Independent review of information security",
            "Organizational",
        ),
        control(
            "5.36",
            "Compliance with policies, rules and standards for information security",
            "Organizational",
        ),
        control("5.37", "Documented operating procedures", "Organizational"),
        // ===========================================
        // People controls (6.1 - 6.8)
        // ===========================================
        control("6.1", "Screening", "People"),
        control("6.2", "Terms and conditions of employment", "People"),
        control(
            "6.3",
            "Information security awareness, education and training",
            "People",
        ),
        control("6.4", "Disciplinary process", "People"),
        control(
            "6.5",
            "Responsibilities after termination or change of employment",
            "People",
        ),
        control(
            "6.6",
            "Confidentiality or non-disclosure agreements",
            "People",
        ),
        control("6.7", "Remote working", "People"),
        control("6.8", "Information security event reporting", "People"),
        // ===========================================
        // Physical controls (7.1 - 7.14)
        // ===========================================
        control("7.1", "Physical security perimeters", "Physical"),
        control("7.2", "Physical entry", "Physical"),
        control("7.3", "Securing offices, rooms and facilities", "Physical"),
        control("7.4", "Physical security monitoring", "Physical"),
        control(
            "7.5",
            "Protecting against physical and environmental threats",
            "Physical",
        ),
        control("7.6", "Working in secure areas", "Physical"),
        control("7.7", "Clear desk and clear screen", "Physical"),
        control("7.8", "Equipment siting and protection", "Physical"),
        control("7.9", "Security of assets off-premises", "Physical"),
        control("7.10", "Storage media", "Physical"),
        control("7.11", "Supporting utilities", "Physical"),
        control("7.12", "Cabling security", "Physical"),
        control("7.13", "Equipment maintenance", "Physical"),
        control("7.14", "Secure disposal or re-use of equipment", "Physical"),
        // ===========================================
        // Technological controls (8.1 - 8.34)
        // ===========================================
        control("8.1", "User endpoint devices", "Technological"),
        control("8.2", "Privileged access rights", "Technological"),
        control("8.3", "Information access restriction", "Technological"),
        control("8.4", "Access to source code", "Technological"),
        control("8.5", "Secure authentication", "Technological"),
        control("8.6", "Capacity management", "Technological"),
        control("8.7", "Protection against malware", "Technological"),
        control(
            "8.8",
            "Management of technical vulnerabilities",
            "Technological",
        ),
        control("8.9", "Configuration management", "Technological"),
        control("8.10", "Information deletion", "Technological"),
        control("8.11", "Data masking", "Technological"),
        control("8.12", "Data leakage prevention", "Technological"),
        control("8.13", "Information backup", "Technological"),
        control(
            "8.14",
            "Redundancy of information processing facilities",
            "Technological",
        ),
        control("8.15", "Logging", "Technological"),
        control("8.16", "Monitoring activities", "Technological"),
        control("8.17", "Clock synchronization", "Technological"),
        control(
            "8.18",
            "Use of privileged utility programs",
            "Technological",
        ),
        control(
            "8.19",
            "Installation of software on operational systems",
            "Technological",
        ),
        control("8.20", "Networks security", "Technological"),
        control("8.21", "Security of network services", "Technological"),
        control("8.22", "Segregation of networks", "Technological"),
        control("8.23", "Web filtering", "Technological"),
        control("8.24", "Use of cryptography", "Technological"),
        control("8.25", "Secure development life cycle", "Technological"),
        control("8.26", "Application security requirements", "Technological"),
        control(
            "8.27",
            "Secure system architecture and engineering principles",
            "Technological",
        ),
        control("8.28", "Secure coding", "Technological"),
        control(
            "8.29",
            "Security testing in development and acceptance",
            "Technological",
        ),
        control("8.30", "Outsourced development", "Technological"),
        control(
            "8.31",
            "Separation of development, test and production environments",
            "Technological",
        ),
        control("8.32", "Change management", "Technological"),
        control("8.33", "Test information", "Technological"),
        control(
            "8.34",
            "Protection of information systems during audit testing",
            "Technological",
        ),
    ]
}

#[cfg(test)]
mod tests;
