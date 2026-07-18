use crate::types::{Finding, FindingCategory, PluginId, ScanResult, Severity};

/// Creates mock scan results for UI testing and development.
///
/// Returns a vector of ScanResult objects simulating what would come
/// from the actual plugin scanning system.
pub fn create_mock_scan_results() -> Vec<ScanResult> {
    vec![
        // Kernel plugin scan
        ScanResult {
            scan_plugin_id: PluginId::from("kernel-hardening"),
            scan_success:   true,
            scan_findings:  vec![
                Finding {
                    finding_id: "kernel-001".to_string(),
                    finding_category: FindingCategory::Kernel,
                    finding_severity: Severity::Critical,
                    finding_title: "ASLR not fully enabled".to_string(),
                    finding_description: "Address Space Layout Randomisation is not configured to maximum security level".to_string(),
                    finding_current_value: "1".to_string(),
                    finding_recommended_value: "2".to_string(),
                    finding_explanation: "ASLR randomises memory addresses to prevent exploitation. Level 2 provides full randomisation including heap and stack.".to_string(),
                    finding_impact: "Without full ASLR, attackers can more easily exploit memory corruption vulnerabilities.".to_string(),
                    finding_remediation_steps: vec![
                        "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf".to_string(),
                        "Run 'sudo sysctl -p' to apply changes".to_string(),
                    ],
                    finding_compliance: vec![],
                    finding_policy_exception: None,
                },
                Finding {
                    finding_id: "kernel-002".to_string(),
                    finding_category: FindingCategory::Kernel,
                    finding_severity: Severity::High,
                    finding_title: "Kernel pointers exposed".to_string(),
                    finding_description: "Kernel pointers are visible to unprivileged users".to_string(),
                    finding_current_value: "0".to_string(),
                    finding_recommended_value: "2".to_string(),
                    finding_explanation: "Hiding kernel pointers prevents information disclosure attacks.".to_string(),
                    finding_impact: "Exposed kernel pointers aid in kernel exploitation.".to_string(),
                    finding_remediation_steps: vec![
                        "Set kernel.kptr_restrict = 2".to_string(),
                    ],
                    finding_compliance: vec![],
                    finding_policy_exception: None,
                },
            ],
            scan_unchecked: vec![],
            scan_duration_us: 1250,
            scan_error: None,
        },
        // SSH plugin scan result
        ScanResult {
            scan_plugin_id: PluginId::from("ssh-hardening"),
            scan_success: true,
            scan_findings: vec![
                Finding {
                    finding_id: "ssh-001".to_string(),
                    finding_category:
                    FindingCategory::Authentication,
                    finding_severity: Severity::Critical,
                    finding_title: "Root login via SSH enabled".to_string(),
                    finding_description: "SSH configuration allows direct root login".to_string(),
                    finding_current_value: "yes".to_string(),
                    finding_recommended_value: "no".to_string(),
                    finding_explanation: "Disabling root SSH login forces users to authenticate as regular users first, providing better audit trails.".to_string(),
                    finding_impact: "Direct root access increases risk of brute-force attacks and provides no audit trail.".to_string(),
                    finding_remediation_steps: vec![
                        "Edit /etc/ssh/sshd_config".to_string(),
                        "Set PermitRootLogin no".to_string(),
                        "Restart SSH service: sudo systemctl restart sshd".to_string(),
                    ],
                    finding_compliance: vec![],
                    finding_policy_exception: None,
                },
            ],
            scan_unchecked: vec![],
            scan_duration_us: 890,
            scan_error: None,
        },
        // Firewall plugin scan result
        ScanResult {
            scan_plugin_id: PluginId::from("firewall-hardening"),
            scan_success: true,
            scan_findings: vec![
                Finding {
                    finding_id: "firewall-001".to_string(),
                    finding_category: FindingCategory::Network,
                    finding_severity: Severity::High,
                    finding_title: "Firewall not enabled".to_string(),
                    finding_description: "System firewall is not active".to_string(),
                    finding_current_value: "inactive".to_string(),
                    finding_recommended_value: "active".to_string(),
                    finding_explanation: "An active firewall blocks unauthorised network access.".to_string(),
                    finding_impact: "Without a firewall, all network services are exposed.".to_string(),
                    finding_remediation_steps: vec![
                        "Enable firewall: sudo ufw enable".to_string(),
                        "Configure default deny: sudo ufw default deny incoming".to_string(),
                    ],
                    finding_compliance: vec![],
                    finding_policy_exception: None,
                },
            ],
            scan_unchecked: vec![],
            scan_duration_us: 450,
            scan_error: None,
        },
    ]
}
