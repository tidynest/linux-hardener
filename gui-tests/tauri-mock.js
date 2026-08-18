// =============================================================================
// TAURI IPC MOCK - Linux Hardener GUI Tests
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
  // Which apply outcome `run_apply` replies with. Selected the same way as
  // error_mode, per test, so the default stays the all-success path the
  // existing tests expect. `mixed` reaches the partial panel, which nothing
  // could reach before: with an all-success fixture the done panel is the only
  // one the interface can render.
  const applyMode = params.get('apply_mode') || '';
  // `?checkpoint_source=unreadable` makes get_checkpoints report that the
  // root-owned system database was skipped. The real condition needs a
  // root-owned file the desktop cannot read, which a browser fixture has no
  // way to produce, so the flag is set directly.
  const checkpointSource = params.get('checkpoint_source') || '';

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
  let schedulerConfig = {
    enabled: false,
    schedule: '0 0 2 * * *',
    plugins: [],
    min_severity: 'medium',
    notifications: {
      notify_min_severity: '',
      email: { enabled: false, recipients: [], from_address: '' },
      webhooks: { enabled: false, url: '', format: 'generic' },
    },
  };

  // ---- Mock Data ----

  // Field names match the Rust types exactly, and the frontend deserialises
  // this with serde, so a missing field fails the whole scan rather than the
  // one finding carrying it. `finding_exception` is an ExceptionOutcome, an
  // enum internally tagged on "state" with lowercase variant names, so the
  // "no exception configured" case is { state: 'notconfigured' } and not null.
  //
  // It replaced `finding_policy_exception: null`, and this file was not
  // updated with it: every finding then failed to deserialise, the Analysis
  // view showed "Scan failed: missing field `finding_exception`", and six
  // tests reported an empty findings table. Read as stale selectors, it was a
  // fixture a type change had left behind.
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
          finding_exception: { state: 'notconfigured' },
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
          finding_exception: { state: 'notconfigured' },
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
          // The one declined exception in the fixture. `ExceptionOutcome` is
          // internally tagged on "state", and the Declined variant is a
          // newtype, so `FindingExceptionDeclined`'s fields sit beside the tag
          // rather than under it. `DeclineReason` is tagged on "cause" in turn.
          //
          // Declined findings keep their real severity and stay in their
          // severity group, so this changes no count the suite asserts.
          finding_exception: {
            state: 'declined',
            exception_declined_reason: {
              cause: 'valuemismatch',
              documented: 'prohibit-password',
              observed: 'yes',
            },
            exception_reason: 'Break-glass access from the bastion',
          },
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
          finding_exception: { state: 'notconfigured' },
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
          // Deliberately keyless (finding_exception_key omitted, so it
          // deserialises to None): T-EXC-05 needs a real finding that offers
          // no accept/remove control at all.
          finding_exception: { state: 'notconfigured' },
        },
      ],
      scan_duration_us: 320,
      scan_error: null,
    },
    {
      scan_plugin_id: 'service-minimisation',
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
          // The one Applied exception in the fixture: T-EXC-04 needs a keyed,
          // already-accepted finding so the row offers Remove Exception rather
          // than Accept This Finding on first render.
          finding_exception: {
            state: 'applied',
            exception_allowed_value: 'active',
            exception_reason: 'Shared print server needs cups; approved by change management',
            exception_approved_by: 'ops-lead',
            exception_approved_date: '2026-06-01',
            exception_ticket: null,
            exception_expires: null,
            exception_is_expired: false,
          },
          finding_exception_key: 'unnecessary-services',
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
          // The one keyed-but-NotConfigured finding in the fixture: T-EXC-01,
          // T-EXC-02 and T-EXC-03 need a row that still offers Accept This
          // Finding so the modal and its submit path have something to drive.
          finding_exception: { state: 'notconfigured' },
          finding_exception_key: 'bluetooth-service',
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
          finding_exception: { state: 'notconfigured' },
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

  // The apply nobody has ever seen. Reached with `?apply_mode=mixed`.
  //
  // APPLY_RESULTS above is three changes, all successful, so
  // `applied_change_count()` and `apply_changes.len()` are both 3 and a test
  // written against it passes whether the renderer follows the counting rule
  // or ignores it. This fixture exists to make those two numbers differ, which
  // is the only way an assertion on them can fail.
  //
  // Shape reminders, all enforced by the Rust types:
  //   change_type: 'ConfigFile' | 'FirewallRule' | 'KernelParameter' |
  //                'Package' | 'Permissions' | 'Service' | 'Skipped' |
  //                'Checkpoint'
  //   'Skipped' and 'Checkpoint' are excluded from BOTH the applied and the
  //   failed totals; a plugin whose only entry is the checkpoint has hardened
  //   nothing.
  //   A failed change is change_success: false with a change_error. It counts
  //   as a manual step rather than a failure only when change_error matches a
  //   marker in MANUAL_ACTION_MARKERS (crates/hardener-ui/src/utils/mod.rs).
  //
  // Four areas, one per outcome the partial panel can classify, chosen so the
  // two totals diverge as widely as the type allows: seven entries, three of
  // them genuinely applied. A renderer reaching for `apply_changes.len()`
  // reports 7.
  const MIXED_APPLY_RESULTS = [
    {
      // Applied. The checkpoint entry is the sneaky one: it counts toward
      // neither total, so this area applied 2 of its 3 entries.
      apply_plugin_id: 'kernel-hardening',
      apply_success: true,
      apply_changes: [
        {
          change_description: 'Captured rollback checkpoint chk-20260808-002',
          change_type: 'Checkpoint',
          change_success: true,
          change_error: null,
        },
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
      apply_checkpoint_id: 'chk-20260808-002',
      apply_error: null,
    },
    {
      // Failed, and deliberately alongside a success: an area that did some
      // real work and still failed must report Failed, not Applied.
      apply_plugin_id: 'firewall-hardening',
      apply_success: false,
      apply_changes: [
        {
          change_description: 'Allow SSH to prevent lockout',
          change_type: 'FirewallRule',
          change_success: true,
          change_error: null,
        },
        {
          change_description: 'Enable nftables with default deny policy',
          change_type: 'FirewallRule',
          change_success: false,
          change_error: 'nft: Could not process rule: Operation not permitted',
        },
      ],
      apply_checkpoint_id: 'chk-20260808-002',
      apply_error: 'One rule could not be installed',
    },
    {
      // Skipped. Nothing applicable on this host, which is not a failure and
      // must not read as one.
      apply_plugin_id: 'mac-hardening',
      apply_success: true,
      apply_changes: [
        {
          change_description: 'No MAC system present (neither AppArmor nor SELinux)',
          change_type: 'Skipped',
          change_success: true,
          change_error: null,
        },
      ],
      apply_checkpoint_id: 'chk-20260808-002',
      apply_error: null,
    },
    {
      // ManualStep. A failed change whose error matches the sole entry in
      // MANUAL_ACTION_MARKERS exactly; any other text would classify as
      // Failed, which is the deliberate fallback direction.
      apply_plugin_id: 'pam-hardening',
      apply_success: false,
      apply_changes: [
        {
          change_description: 'Set faillock deny = 5',
          change_type: 'ConfigFile',
          change_success: false,
          change_error: 'inline pam.d override present',
        },
      ],
      apply_checkpoint_id: 'chk-20260808-002',
      apply_error: 'Manual action required',
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

  // The oldest entry is deliberately unverified. An all-verified fixture makes
  // the two states render identically as far as any assertion can tell, so no
  // test could distinguish "we checked and it passed" from "we never checked",
  // which is the ambiguity #157 is about.
  const CHECKPOINTS = [
    {
      checkpoint_id: 'chk-20260223-001',
      checkpoint_name: 'Pre-hardening checkpoint',
      checkpoint_created: '2026-02-23 10:30:00 UTC',
      checkpoint_user: 'root',
      checkpoint_verified: true,
    },
    {
      checkpoint_id: 'chk-20260222-003',
      checkpoint_name: 'SSH hardening rollback point',
      checkpoint_created: '2026-02-22 15:45:00 UTC',
      checkpoint_user: 'root',
      checkpoint_verified: true,
    },
    {
      checkpoint_id: 'chk-20260221-001',
      checkpoint_name: 'Initial system state',
      checkpoint_created: '2026-02-21 09:00:00 UTC',
      checkpoint_user: 'root',
      checkpoint_verified: false,
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

  // Two different strings name a framework across this boundary, and the
  // fixture has to hold both:
  //
  //   - the KEY is `ComplianceFramework::id()`, lowercase, which is what every
  //     one of the five call sites sends (`.map(|f| f.id().to_string())`);
  //   - `report_framework` is the serde VARIANT name, which is what the reply
  //     is deserialised back into the enum by. Sending an id there fails with
  //     "unknown variant `pci-dss`".
  //
  // They differ for exactly the three that are not a plain upper-casing:
  // pci-dss/PCIDSS, 800-171/NIST800171 and fedramp/FedRAMP. The table used to
  // be keyed on an upper-cased id, which cannot express that, so `PCIDSS` was
  // a key nothing could ever match: "pci-dss" upper-cases to "PCI-DSS".
  //
  // ISO 27001, SOC 2, NIST SP 800-171 and FedRAMP had no entry at all, having
  // joined ComplianceFramework::ALL without this file following. Between that
  // and the dead PCI-DSS key, selecting all ten frameworks produced five
  // reports and said nothing about the other five: the lookup drops a miss
  // with `.filter(Boolean)`, so a framework yielding no report is
  // indistinguishable from one nobody selected.
  const COMPLIANCE_REPORTS = {
    'cis': makeComplianceReport('CIS', 82.5, 33, 5, 2),
    'stig': makeComplianceReport('STIG', 71.0, 22, 8, 1),
    'nist': makeComplianceReport('NIST', 88.0, 44, 4, 2),
    'pci-dss': makeComplianceReport('PCIDSS', 55.0, 11, 7, 2),
    'hipaa': makeComplianceReport('HIPAA', 65.0, 13, 5, 2),
    'gdpr': makeComplianceReport('GDPR', 78.0, 18, 4, 1),
    'iso27001': makeComplianceReport('ISO27001', 74.0, 20, 6, 1),
    'soc2': makeComplianceReport('SOC2', 69.0, 16, 6, 2),
    '800-171': makeComplianceReport('NIST800171', 81.0, 27, 5, 1),
    'fedramp': makeComplianceReport('FedRAMP', 63.0, 19, 9, 2),
  };

  // `completed_at` is `Option<String>` on `ScanSessionInfo`, so omitting it
  // deserialises to None rather than failing, and the fixture validator passes
  // it deliberately: treating an Option as required would report a mock that
  // works. It carried `status: 'completed'` with no completion time, which is a
  // state the backend cannot produce, and `last_scanned_label` correctly read
  // it as never scanned. Both page subtitles therefore rendered "Not scanned
  // yet" above a score of 60/100 and eight findings, in all seven themes and
  // all 222 screenshots, and nothing failed because nothing asserted on them.
  //
  // The failed session keeps it null on purpose: that is the honest shape for a
  // scan that did not finish, and it keeps the None branch reachable.
  const SCAN_HISTORY = [
    {
      session_id: 'session-001',
      started_at: '2026-02-23 10:30:00 UTC',
      completed_at: '2026-02-23 10:30:42 UTC',
      status: 'completed',
      total_findings: 8,
      total_plugins: 6,
    },
    {
      session_id: 'session-002',
      started_at: '2026-02-22 15:45:00 UTC',
      completed_at: '2026-02-22 15:45:31 UTC',
      status: 'completed',
      total_findings: 5,
      total_plugins: 4,
    },
    {
      session_id: 'session-003',
      started_at: '2026-02-21 09:00:00 UTC',
      completed_at: null,
      status: 'failed',
      total_findings: 0,
      total_plugins: 2,
    },
  ];

  // Mirrors HostSessionInfo, keyed by the scheduler-db history key the host
  // expander sends (inventory name, or the canonical target for an ad-hoc
  // host). `started` is display-ready, `%Y-%m-%d %H:%M` local, because
  // `sessions_to_info` formats it backend-side and `checkpoint_time` splits on
  // the space to show the clock alone.
  //
  // Only `web-01` has rows. `db-01` deliberately has none, so the "No persisted
  // history for this host" branch stays reachable from a real answer rather
  // than from the mock refusing the command, which is what it used to be: the
  // mock had no case at all, `HostPanel` swallowed the rejection through
  // `.unwrap_or_default()`, and both hosts rendered the empty state whatever
  // the backend would have returned.
  //
  // `direction` is absent on the oldest row on purpose: the backend fetches one
  // extra session to compute it and has nothing older to compare the last one
  // against.
  const HOST_HISTORY = {
    'web-01': [
      { started: '2026-02-23 10:30', status: 'completed', total_findings: 8, critical: 0, high: 2, medium: 4, low: 2, info: 0, direction: 'worse' },
      { started: '2026-02-22 15:45', status: 'completed', total_findings: 5, critical: 0, high: 1, medium: 3, low: 1, info: 0, direction: 'better' },
      { started: '2026-02-21 09:00', status: 'completed', total_findings: 9, critical: 1, high: 2, medium: 4, low: 2, info: 0, direction: null },
    ],
    'db-01': [],
  };

  // Mirrors PluginMetadata exactly: plugin_category, plugin_description,
  // plugin_id, plugin_name, plugin_version. It carried a plugin_dependencies
  // the type does not have and lacked plugin_version, which serde requires, so
  // every list_plugins call failed with "missing field `plugin_version`" and
  // the Fleet Apply plugin selector rendered empty. The alert saying so sat on
  // the page while the tests around it reported selector problems.
  const PLUGINS = [
    { plugin_id: 'kernel-hardening', plugin_name: 'Kernel Hardening', plugin_description: 'Hardens kernel parameters via sysctl', plugin_category: 'Kernel', plugin_version: '1.0.0' },
    { plugin_id: 'ssh-hardening', plugin_name: 'SSH Hardening', plugin_description: 'Secures OpenSSH server configuration', plugin_category: 'Authentication', plugin_version: '1.0.0' },
    { plugin_id: 'firewall-hardening', plugin_name: 'Firewall Hardening', plugin_description: 'Configures host firewall rules', plugin_category: 'Network', plugin_version: '1.0.0' },
    { plugin_id: 'pam-hardening', plugin_name: 'PAM Hardening', plugin_description: 'Strengthens PAM authentication modules', plugin_category: 'Authentication', plugin_version: '1.0.0' },
    { plugin_id: 'service-minimisation', plugin_name: 'Services Minimisation', plugin_description: 'Disables unnecessary system services', plugin_category: 'Services', plugin_version: '1.0.0' },
    { plugin_id: 'audit-hardening', plugin_name: 'Audit Hardening', plugin_description: 'Configures auditd rules for system auditing', plugin_category: 'Audit', plugin_version: '1.0.0' },
    { plugin_id: 'permissions-hardening', plugin_name: 'Permissions Hardening', plugin_description: 'Fixes insecure file and directory permissions', plugin_category: 'FileSystem', plugin_version: '1.0.0' },
    { plugin_id: 'mac-hardening', plugin_name: 'MAC Hardening', plugin_description: 'Enforces SELinux or AppArmor mandatory access controls', plugin_category: 'MandatoryAccessControl', plugin_version: '1.0.0' },
  ];

  // ---- Command Handler ----

  async function handleInvoke(cmd, args) {
    // serde_wasm_bindgen serialises `json!({...})` args as a JS Map, not a plain
    // object (struct-derived args come through as objects). Normalise so the
    // handlers below can read args.field uniformly regardless of binding style.
    if (args instanceof Map) {
      const obj = {};
      args.forEach((v, k) => { obj[k] = v; });
      args = obj;
    }

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
        return applyMode === 'mixed' ? MIXED_APPLY_RESULTS : APPLY_RESULTS;

      case 'run_apply_dry_run':
        return DRY_RUN_RESULTS;

      case 'get_checkpoints':
        return {
          checkpoints: CHECKPOINTS,
          system_unreadable: checkpointSource === 'unreadable',
        };

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
          // The rollback modal's divergence section had no fixture, so it had
          // never rendered with data and nothing could have caught #143. Both
          // states are here, because they take different branches and are
          // coloured and labelled apart.
          //
          // The sentences are the real length the kernel probe emits, 200 to
          // 400 characters, and the subjects are the real shape: a sysctl key
          // and an absolute path, neither of which has a space to wrap at.
          // A shorter stand-in would make the row look fine at every width and
          // prove nothing, which is the whole reason this section shipped
          // unseen.
          rollback_divergences: [
            {
              divergence_plugin_id: 'kernel-hardening',
              divergence_subject: 'net.ipv4.conf.all.accept_source_route',
              divergence_state: 'Diverged',
              divergence_detail:
                'The running kernel holds 1 for this parameter and no surviving configuration file names it, so the rollback restored files and reloaded them without changing /proc/sys. The value stays as it is until the next reboot, at which point nothing will set it and the kernel default takes over.',
              divergence_expected:
                'a rollback restores files and reloads them and never writes /proc/sys, so a parameter no surviving file names keeps whatever the apply gave it until the next reboot',
            },
            {
              divergence_plugin_id: 'kernel-hardening',
              divergence_subject: '/usr/lib/sysctl.d/50-default.conf',
              divergence_state: 'Unverifiable',
              divergence_detail:
                'This configuration source could not be read, so the parameters it may name cannot be decided either way. Nothing here is a claim that the host disagrees with what was restored; it is a probe that could not answer, and the file is named so an operator can read it themselves.',
              divergence_expected: null,
            },
          ],
        };

      case 'generate_compliance_report': {
        const frameworks = (args && args.frameworks) || ['cis'];
        // Looked up by the id exactly as sent. Upper-casing it was what made
        // `pci-dss` unmatchable, and no single casing rule can reach both
        // `PCIDSS` and `FedRAMP` anyway.
        return frameworks
          .map((f) => COMPLIANCE_REPORTS[f])
          .filter(Boolean);
      }

      case 'export_report':
        return ['Mock report content', 'txt'];

      case 'export_compliance_report':
        return '/home/user/Documents/compliance-report-20260224.txt';

      case 'get_scan_history':
        return SCAN_HISTORY;

      case 'get_host_history': {
        const rows = HOST_HISTORY[args && args.host] || [];
        const cap = (args && args.limit) || rows.length;
        return rows.slice(0, cap);
      }

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

      // ---- Scheduler Commands ----

      case 'get_scheduler_config':
        return schedulerConfig;

      case 'save_scheduler_config': {
        const cfg = args && args.config;
        if (cfg) schedulerConfig = cfg;
        return '/home/user/.config/hardener/config.toml';
      }

      // ---- Policy Exception Commands ----
      // `WrittenException` is the CLI's own observed value coming back, not an
      // echo of anything the modal held, so this mock does not need the
      // finding's real section to answer correctly: nothing in the frontend
      // reads `written.section` or `written.key`, only `value`, `reason`,
      // `approved_by`, `ticket` and `expires`, which is why a fixed section
      // here is honest rather than a shortcut.
      case 'add_policy_exception': {
        const written = {
          section: 'services',
          key: args.exceptionKey,
          value: 'active',
          reason: args.reason,
          approved_by: args.approvedBy ?? null,
          ticket: args.ticket ?? null,
          expires: args.expires ?? null,
        };
        return written;
      }
      case 'remove_policy_exception':
        return null;

      case 'test_notification':
        return { success: true, message: 'Test notification sent successfully' };

      // ---- Fleet Commands ----
      // Field names match the Rust types exactly: FleetHostStatus::Ok serialises
      // as the string "Ok" and Failed(e) as {Failed: e}; ApplyStatus/RollbackStatus
      // are internally tagged on "state" (rename_all = lowercase).

      case 'run_fleet_scan': {
        const names = (args && args.hostNames) || [];
        const okTallies = { critical: 2, high: 3, medium: 2, low: 1, info: 0 };
        // FleetFrameworkPosture is { framework, summary, controls }. The
        // controls were missing, so every host carrying compliance failed to
        // deserialise with "missing field `controls`" and the whole scan was
        // discarded. db-01 scans with `compliance: []` and so had nothing to
        // fail on, which is why the failed-host path was the one that worked.
        const controls = (prefix) => [
          { control_id: `${prefix}-1.1`, control_title: 'Ensure filesystem integrity checking is configured', control_section: '1. Initial Setup', control_status: 'Pass' },
          { control_id: `${prefix}-5.2.1`, control_title: 'Ensure permissions on SSH config files', control_section: '5. Access and Authentication', control_status: 'Fail' },
        ];
        const compliance = [
          { framework: 'CIS', summary: { summary_total_controls: 40, summary_passing: 33, summary_failing: 5, summary_manual_review: 2, summary_not_applicable: 0, summary_score_percentage: 82.5 }, controls: controls('CIS') },
          { framework: 'STIG', summary: { summary_total_controls: 31, summary_passing: 22, summary_failing: 8, summary_manual_review: 1, summary_not_applicable: 0, summary_score_percentage: 71.0 }, controls: controls('STIG') },
        ];
        // A fleet-progress event per host, which is how the page knows the scan
        // finished: it counts completions against the hosts it expects and
        // stays on "Scanning..." until they match. FleetProgress is
        // { host, done, total, failed }.
        const targets = names.concat((args && args.adhoc) || []);
        targets.forEach((name, index) => {
          emit('fleet-progress', {
            host: name,
            done: index + 1,
            total: targets.length,
            failed: name === 'db-01',
          });
        });
        // db-01 exercises the failed-row path; everything else is a healthy host.
        return targets.map((name) =>
          name === 'db-01'
            ? { host_name: name, status: { Failed: 'SSH connection refused on port 2222' }, tallies: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, scan_results: [], compliance: [] }
            : { host_name: name, status: 'Ok', tallies: okTallies, scan_results: SCAN_RESULTS, compliance }
        );
      }

      case 'run_fleet_apply': {
        const hosts = (args && args.hosts) || [];
        const execute = !!(args && args.execute);
        return hosts.map((name) => ({
          name,
          target: name,
          status: execute
            ? { state: 'applied', ok: 2, failed: 0 }
            : { state: 'validated', plugins: 2, would_change: 5, failed: 0 },
        }));
      }

      case 'run_fleet_rollback': {
        const hosts = (args && args.hosts) || [];
        const execute = !!(args && args.execute);
        return hosts.map((name) => ({
          name,
          target: name,
          status: execute
            ? { state: 'rolledback', restored: 2, failed: 0 }
            : { state: 'previewed', checkpoints: 1 },
        }));
      }

      case 'validate_config':
        return {
          config_path: (args && args.path) || '/home/user/.config/linux-hardener/config.toml',
          config_is_valid: true,
          config_error: null,
          config_enabled_plugins: ['kernel', 'ssh', 'firewall', 'pam', 'services', 'audit', 'permissions', 'mac'],
          config_directive_count: 3,
          config_exception_count: 1,
        };

      case 'pick_config_file':
        return '/home/user/.config/linux-hardener/config.toml';

      default:
        throw `Unknown command: ${cmd}`;
    }
  }

  // ---- Install Mock ----

  // The frontend decides a Tauri runtime is present by `typeof window.__TAURI__
  // !== 'undefined'` and then uses whatever it needs from it. Defining only
  // `core` therefore claims a runtime this mock does not supply: the Hosts page
  // awaits `event.listen('fleet-progress')` before issuing its scan, and with
  // no `event` namespace that call could never succeed, so the scan sat at
  // "Scanning... 0 of 1 finished" for as long as the test waited. Nothing
  // reported an error, because the page treats live progress as best-effort.
  const listeners = new Map();

  function listen(name, handler) {
    const forName = listeners.get(name) || new Set();
    forName.add(handler);
    listeners.set(name, forName);
    return Promise.resolve(() => forName.delete(handler));
  }

  function emit(name, payload) {
    for (const handler of listeners.get(name) || []) {
      handler({ event: name, payload });
    }
  }

  window.__TAURI__ = {
    core: {
      invoke: handleInvoke,
    },
    event: {
      listen,
      emit: (name, payload) => Promise.resolve(emit(name, payload)),
    },
  };

  console.log('[tauri-mock] Tauri IPC mock installed (error_mode: ' + (errorMode || 'none') + ')');
})();
