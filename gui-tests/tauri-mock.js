// =============================================================================
// TAURI IPC MOCK — Linux System Hardener GUI Tests
// =============================================================================
// Injected before WASM loads to simulate window.__TAURI__.core.invoke().
// Field names match Rust struct definitions exactly (serde snake_case).
//
// Error mode: add ?error_mode=scan|apply|all to URL to trigger errors.
// =============================================================================

(function () {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const errorMode = params.get('error_mode') || '';

  function shouldError(cmd) {
    if (errorMode === 'all') return true;
    if (errorMode === 'scan' && cmd === 'run_scan') return true;
    if (errorMode === 'apply' && (cmd === 'run_apply' || cmd === 'run_apply_dry_run')) return true;
    if (errorMode === 'checkpoint' && cmd === 'get_checkpoints') return true;
    return false;
  }

  // ---- State ----
  let scanHasRun = false;
  let remoteHosts = [
    { name: 'web-01', hostname: '192.168.1.10', user: 'admin', port: 22, key_file: '~/.ssh/id_ed25519', host_key_checking: true },
    { name: 'db-01', hostname: '10.0.0.5', user: 'root', port: 2222, key_file: null, host_key_checking: false },
  ];
  let remoteConnected = null; // { profile_name, host, user }

  // ---- Mock Data ----

  const SCAN_RESULTS = [
    {
      scan_plugin_id: 'kernel-hardening',
      scan_success: true,
      scan_findings: [
        {
          finding_id: 'kernel-001',
          finding_category: 'Kernel',
          finding_severity: 'Critical',
          finding_title: 'ASLR not fully enabled',
          finding_description: 'Address Space Layout Randomisation is not configured to maximum security level',
          finding_current_value: '1',
          finding_recommended_value: '2',
          finding_explanation: 'ASLR randomises memory addresses to prevent exploitation. Level 2 provides full randomisation including heap and stack.',
          finding_impact: 'Without full ASLR, attackers can more easily exploit memory corruption vulnerabilities.',
          finding_remediation_steps: [
            'Set kernel.randomize_va_space = 2 in /etc/sysctl.conf',
            "Run 'sudo sysctl -p' to apply changes",
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
        {
          finding_id: 'kernel-002',
          finding_category: 'Kernel',
          finding_severity: 'High',
          finding_title: 'Kernel pointers exposed',
          finding_description: 'Kernel pointers are visible to unprivileged users',
          finding_current_value: '0',
          finding_recommended_value: '2',
          finding_explanation: 'Hiding kernel pointers prevents information disclosure attacks.',
          finding_impact: 'Exposed kernel pointers aid in kernel exploitation.',
          finding_remediation_steps: ['Set kernel.kptr_restrict = 2'],
          finding_compliance: [],
          finding_policy_exception: null,
        },
      ],
      scan_duration_us: 1250,
      scan_error: null,
    },
    {
      scan_plugin_id: 'ssh-hardening',
      scan_success: true,
      scan_findings: [
        {
          finding_id: 'ssh-001',
          finding_category: 'Authentication',
          finding_severity: 'Critical',
          finding_title: 'Root login via SSH enabled',
          finding_description: 'SSH configuration allows direct root login',
          finding_current_value: 'yes',
          finding_recommended_value: 'no',
          finding_explanation: 'Disabling root SSH login forces users to authenticate as regular users first, providing better audit trails.',
          finding_impact: 'Direct root access increases risk of brute-force attacks and provides no audit trail.',
          finding_remediation_steps: [
            'Edit /etc/ssh/sshd_config',
            'Set PermitRootLogin no',
            'Restart SSH service: sudo systemctl restart sshd',
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
      ],
      scan_duration_us: 890,
      scan_error: null,
    },
    {
      scan_plugin_id: 'firewall-hardening',
      scan_success: true,
      scan_findings: [
        {
          finding_id: 'firewall-001',
          finding_category: 'Network',
          finding_severity: 'High',
          finding_title: 'Firewall not enabled',
          finding_description: 'System firewall is not active',
          finding_current_value: 'inactive',
          finding_recommended_value: 'active',
          finding_explanation: 'An active firewall blocks unauthorised network access.',
          finding_impact: 'Without a firewall, all network services are exposed.',
          finding_remediation_steps: [
            'Enable firewall: sudo ufw enable',
            'Configure default deny: sudo ufw default deny incoming',
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
      ],
      scan_duration_us: 450,
      scan_error: null,
    },
    {
      scan_plugin_id: 'pam-hardening',
      scan_success: true,
      scan_findings: [
        {
          finding_id: 'pam-001',
          finding_category: 'Authentication',
          finding_severity: 'Medium',
          finding_title: 'Password complexity not enforced',
          finding_description: 'PAM password quality module is not configured',
          finding_current_value: 'not configured',
          finding_recommended_value: 'minlen=12 ucredit=-1 dcredit=-1',
          finding_explanation: 'Strong password requirements reduce brute-force attack effectiveness.',
          finding_impact: 'Weak passwords can be easily guessed or cracked.',
          finding_remediation_steps: [
            'Install libpam-pwquality',
            'Configure /etc/security/pwquality.conf',
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
      ],
      scan_duration_us: 320,
      scan_error: null,
    },
    {
      scan_plugin_id: 'services-hardening',
      scan_success: true,
      scan_findings: [
        {
          finding_id: 'services-001',
          finding_category: 'Services',
          finding_severity: 'Medium',
          finding_title: 'Unnecessary services running',
          finding_description: 'avahi-daemon and cups are running but may not be required',
          finding_current_value: 'active',
          finding_recommended_value: 'disabled',
          finding_explanation: 'Minimising running services reduces the attack surface.',
          finding_impact: 'Each unnecessary service is a potential entry point for attackers.',
          finding_remediation_steps: [
            'Review service necessity',
            'Disable with: sudo systemctl disable --now <service>',
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
        {
          finding_id: 'services-002',
          finding_category: 'Services',
          finding_severity: 'Low',
          finding_title: 'Bluetooth service enabled',
          finding_description: 'bluetooth.service is active on a potentially headless system',
          finding_current_value: 'active',
          finding_recommended_value: 'disabled',
          finding_explanation: 'Bluetooth should be disabled on systems that do not require it.',
          finding_impact: 'Bluetooth can be used for proximity-based attacks.',
          finding_remediation_steps: [
            'Disable with: sudo systemctl disable --now bluetooth.service',
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
      ],
      scan_duration_us: 580,
      scan_error: null,
    },
    {
      scan_plugin_id: 'permissions-hardening',
      scan_success: true,
      scan_findings: [
        {
          finding_id: 'perms-001',
          finding_category: 'FileSystem',
          finding_severity: 'High',
          finding_title: 'World-writable files in /etc',
          finding_description: 'Configuration files with insecure permissions found',
          finding_current_value: '0666',
          finding_recommended_value: '0644',
          finding_explanation: 'World-writable config files can be modified by any user.',
          finding_impact: 'Attackers can modify system configuration to escalate privileges.',
          finding_remediation_steps: [
            'Run: sudo chmod 644 /etc/affected-file',
            'Audit all files in /etc for correct permissions',
          ],
          finding_compliance: [],
          finding_policy_exception: null,
        },
      ],
      scan_duration_us: 720,
      scan_error: null,
    },
  ];

  const APPLY_RESULTS = [
    {
      apply_plugin_id: 'kernel-hardening',
      apply_success: true,
      apply_changes: [
        {
          change_description: 'Set kernel.randomize_va_space = 2',
          change_type: 'KernelParameter',
          change_success: true,
          change_error: null,
        },
        {
          change_description: 'Set kernel.kptr_restrict = 2',
          change_type: 'KernelParameter',
          change_success: true,
          change_error: null,
        },
      ],
      apply_checkpoint_id: 'chk-20260223-001',
      apply_error: null,
    },
    {
      apply_plugin_id: 'ssh-hardening',
      apply_success: true,
      apply_changes: [
        {
          change_description: 'Set PermitRootLogin no in /etc/ssh/sshd_config',
          change_type: 'ConfigFile',
          change_success: true,
          change_error: null,
        },
      ],
      apply_checkpoint_id: 'chk-20260223-001',
      apply_error: null,
    },
  ];

  const DRY_RUN_RESULTS = [
    {
      validation_report_plugin_id: 'kernel-hardening',
      validation_report_is_valid: true,
      validation_report_issues: [],
      validation_report_estimated_changes: [
        'Set kernel.randomize_va_space = 2',
        'Set kernel.kptr_restrict = 2',
      ],
    },
    {
      validation_report_plugin_id: 'ssh-hardening',
      validation_report_is_valid: true,
      validation_report_issues: [],
      validation_report_estimated_changes: [
        'Set PermitRootLogin no in /etc/ssh/sshd_config',
        'Set MaxAuthTries 3 in /etc/ssh/sshd_config',
      ],
    },
    {
      validation_report_plugin_id: 'firewall-hardening',
      validation_report_is_valid: true,
      validation_report_issues: [
        {
          validation_issue_severity: 'Low',
          validation_issue_message: 'UFW not installed; nftables will be configured instead',
          validation_issue_config_key: null,
        },
      ],
      validation_report_estimated_changes: [
        'Enable nftables with default deny policy',
        'Allow established connections',
      ],
    },
  ];

  const CHECKPOINTS = [
    {
      checkpoint_id: 'chk-20260223-001',
      checkpoint_name: 'Pre-hardening checkpoint',
      checkpoint_created: '2026-02-23 10:30:00 UTC',
      checkpoint_user: 'root',
    },
    {
      checkpoint_id: 'chk-20260222-003',
      checkpoint_name: 'SSH hardening rollback point',
      checkpoint_created: '2026-02-22 15:45:00 UTC',
      checkpoint_user: 'root',
    },
    {
      checkpoint_id: 'chk-20260221-001',
      checkpoint_name: 'Initial system state',
      checkpoint_created: '2026-02-21 09:00:00 UTC',
      checkpoint_user: 'root',
    },
  ];

  function makeComplianceReport(framework, score, passing, failing, manualReview) {
    const total = passing + failing + manualReview;
    return {
      report_framework: framework,
      report_generated_at: new Date().toISOString(),
      report_controls: [
        {
          control_id: `${framework}-1.1`,
          control_title: 'Ensure filesystem integrity checking is configured',
          control_section: '1. Initial Setup',
          control_status: 'Pass',
          control_findings: [],
        },
        {
          control_id: `${framework}-5.2.1`,
          control_title: 'Ensure permissions on SSH config files',
          control_section: '5. Access Control',
          control_status: failing > 0 ? 'Fail' : 'Pass',
          control_findings: failing > 0 ? [SCAN_RESULTS[1].scan_findings[0]] : [],
        },
        {
          control_id: `${framework}-6.1`,
          control_title: 'System audit logging',
          control_section: '6. Logging and Auditing',
          control_status: manualReview > 0 ? 'ManualReview' : 'Pass',
          control_findings: [],
        },
      ],
      report_summary: {
        summary_total_controls: total,
        summary_passing: passing,
        summary_failing: failing,
        summary_manual_review: manualReview,
        summary_not_applicable: 0,
        summary_score_percentage: score,
      },
    };
  }

  const COMPLIANCE_REPORTS = {
    CIS: makeComplianceReport('CIS', 82.5, 33, 5, 2),
    STIG: makeComplianceReport('STIG', 71.0, 22, 8, 1),
    NIST: makeComplianceReport('NIST', 88.0, 44, 4, 2),
    PCIDSS: makeComplianceReport('PCIDSS', 55.0, 11, 7, 2),
    HIPAA: makeComplianceReport('HIPAA', 65.0, 13, 5, 2),
    GDPR: makeComplianceReport('GDPR', 78.0, 18, 4, 1),
  };

  const SCAN_HISTORY = [
    {
      session_id: 'session-001',
      started_at: '2026-02-23 10:30:00 UTC',
      status: 'completed',
      total_findings: 8,
      total_plugins: 6,
    },
    {
      session_id: 'session-002',
      started_at: '2026-02-22 15:45:00 UTC',
      status: 'completed',
      total_findings: 5,
      total_plugins: 4,
    },
    {
      session_id: 'session-003',
      started_at: '2026-02-21 09:00:00 UTC',
      status: 'failed',
      total_findings: 0,
      total_plugins: 2,
    },
  ];

  const PLUGINS = [
    { plugin_id: 'kernel-hardening', plugin_name: 'Kernel Hardening', plugin_description: 'Hardens kernel parameters via sysctl', plugin_category: 'Kernel', plugin_dependencies: [] },
    { plugin_id: 'ssh-hardening', plugin_name: 'SSH Hardening', plugin_description: 'Secures OpenSSH server configuration', plugin_category: 'Authentication', plugin_dependencies: [] },
    { plugin_id: 'firewall-hardening', plugin_name: 'Firewall Hardening', plugin_description: 'Configures host firewall rules', plugin_category: 'Network', plugin_dependencies: [] },
    { plugin_id: 'pam-hardening', plugin_name: 'PAM Hardening', plugin_description: 'Strengthens PAM authentication modules', plugin_category: 'Authentication', plugin_dependencies: [] },
    { plugin_id: 'services-hardening', plugin_name: 'Services Minimisation', plugin_description: 'Disables unnecessary system services', plugin_category: 'Services', plugin_dependencies: [] },
    { plugin_id: 'audit-hardening', plugin_name: 'Audit Hardening', plugin_description: 'Configures auditd rules for system auditing', plugin_category: 'Logging', plugin_dependencies: [] },
    { plugin_id: 'permissions-hardening', plugin_name: 'Permissions Hardening', plugin_description: 'Fixes insecure file and directory permissions', plugin_category: 'FileSystem', plugin_dependencies: [] },
    { plugin_id: 'mac-hardening', plugin_name: 'MAC Hardening', plugin_description: 'Enforces SELinux or AppArmor mandatory access controls', plugin_category: 'AccessControl', plugin_dependencies: [] },
  ];

  // ---- Command Handler ----

  async function handleInvoke(cmd, args) {
    // Simulate network latency
    await new Promise((r) => setTimeout(r, 150 + Math.random() * 200));

    if (shouldError(cmd)) {
      switch (cmd) {
        case 'run_scan':
          throw 'Scan failed: permission denied reading /proc/sys';
        case 'run_apply':
        case 'run_apply_dry_run':
          throw 'Authentication required: pkexec agent not available';
        case 'get_checkpoints':
          throw 'Failed to load checkpoints: database locked';
        default:
          throw `Mock error for command: ${cmd}`;
      }
    }

    switch (cmd) {
      case 'run_scan':
        scanHasRun = true;
        return SCAN_RESULTS;

      case 'run_scan_filtered': {
        scanHasRun = true;
        const ids = (args && args.plugin_ids) || [];
        if (ids.length === 0) return SCAN_RESULTS;
        return SCAN_RESULTS.filter((r) => ids.includes(r.scan_plugin_id));
      }

      case 'run_scan_with_options':
        scanHasRun = true;
        return SCAN_RESULTS;

      case 'get_latest_scan':
        return scanHasRun ? SCAN_RESULTS : null;

      case 'run_apply':
        return APPLY_RESULTS;

      case 'run_apply_dry_run':
        return DRY_RUN_RESULTS;

      case 'get_checkpoints':
        return CHECKPOINTS;

      case 'create_checkpoint':
        return 'chk-mock-' + Date.now();

      case 'delete_checkpoint':
        return true;

      case 'run_rollback':
        return {
          rollback_checkpoint_id: (args && args.checkpoint_id) || 'cp_mock_1234',
          rollback_checkpoint_name: 'kernel-hardening-pre-apply',
          rollback_success: true,
          rollback_files: [
            {
              restore_path: '/etc/sysctl.d/99-hardener.conf',
              restore_action: 'Removed',
              restore_success: true,
              restore_error: null,
            },
            {
              restore_path: '/proc/sys/kernel/kptr_restrict',
              restore_action: 'Restored',
              restore_success: true,
              restore_error: null,
            },
          ],
        };

      case 'generate_compliance_report': {
        const frameworks = (args && args.frameworks) || ['CIS'];
        return frameworks
          .map((f) => COMPLIANCE_REPORTS[f.toUpperCase()])
          .filter(Boolean);
      }

      case 'export_report':
        return ['Mock report content', 'txt'];

      case 'export_compliance_report':
        return '/home/user/Documents/compliance-report-20260224.txt';

      case 'get_scan_history':
        return SCAN_HISTORY;

      case 'get_scan_session':
        return SCAN_RESULTS;

      case 'list_plugins':
        return PLUGINS;

      case 'get_checkpoint_detail': {
        const cpId = (args && args.checkpointId) || 'unknown';
        const cp = CHECKPOINTS.find((c) => c.checkpoint_id === cpId) || CHECKPOINTS[0];
        return {
          checkpoint_id: cp.checkpoint_id,
          checkpoint_name: cp.checkpoint_name,
          checkpoint_created: cp.checkpoint_created,
          checkpoint_user: cp.checkpoint_user,
          file_count: 3,
          files: [
            { path: '/etc/sysctl.d/99-hardener.conf', permissions: '644', has_content: true },
            { path: '/etc/ssh/sshd_config', permissions: '600', has_content: true },
            { path: '/etc/security/pwquality.conf', permissions: '644', has_content: false },
          ],
        };
      }

      // ---- Remote Scanning Commands ----

      case 'list_remote_hosts':
        return remoteHosts;

      case 'save_remote_host': {
        const profile = args;
        const idx = remoteHosts.findIndex((h) => h.name === profile.name);
        if (idx >= 0) remoteHosts[idx] = profile;
        else remoteHosts.push(profile);
        return null;
      }

      case 'delete_remote_host': {
        const delName = args && args.name;
        remoteHosts = remoteHosts.filter((h) => h.name !== delName);
        if (remoteConnected && remoteConnected.profile_name === delName) remoteConnected = null;
        return null;
      }

      case 'connect_remote': {
        const connName = args && args.name;
        const host = remoteHosts.find((h) => h.name === connName);
        if (!host) return { Failed: { error: `Host "${connName}" not found` } };
        remoteConnected = { profile_name: host.name, host: host.hostname, user: host.user || 'root' };
        return { Connected: { host: host.hostname, user: host.user || 'root' } };
      }

      case 'disconnect_remote':
        remoteConnected = null;
        return null;

      case 'run_remote_scan':
        if (!remoteConnected) throw 'No active remote connection';
        return SCAN_RESULTS;

      default:
        throw `Unknown command: ${cmd}`;
    }
  }

  // ---- Install Mock ----

  window.__TAURI__ = {
    core: {
      invoke: handleInvoke,
    },
  };

  console.log('[tauri-mock] Tauri IPC mock installed (error_mode: ' + (errorMode || 'none') + ')');
})();
