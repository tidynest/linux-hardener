# Getting started

**Last Updated**: 2026-07-24

A task-oriented tour of the hardener for new users: scan a system, read the
findings, preview and apply hardening, roll it back, and produce a first
compliance report. Install the tool first ([installation guide](installation.md)),
then work through this page top to bottom.

Every command here is available in both the `hardener` CLI and the desktop
app; the CLI form is shown, with a desktop orientation at the end. The
complete flag-by-flag reference is [reference/cli.md](../reference/cli.md).

---

## 1. Run your first scan

Scanning is read-only and needs no root:

```bash
hardener scan
```

This runs all 8 security plugins (kernel, SSH, firewall, PAM, services,
permissions, audit, MAC) and prints each finding with a severity, the current
value, and the recommended value.

Useful variations:

```bash
hardener scan --severity high            # Only high and critical findings
hardener scan --plugin ssh --plugin pam  # Scan two plugins only
hardener --format json scan              # Machine-readable output
sudo hardener scan                       # Full results for root-only checks
```

Some checks (audit rules, service status) return partial results without
root; run with `sudo` when you want the complete picture.

## 2. Review the findings

Each finding shows:

- **Severity**: critical, high, medium, low, or info.
- **Current vs recommended value**: what the system has now and what the
  secure baseline expects.
- **Remediation steps**: what `apply` would change, or what to do manually
  where automatic changes are not safe.

If a finding is an accepted risk in your environment, do not just ignore it:
record a policy exception in the config file so the deviation carries a
reason, an approver, and an expiry date. See the
[configuration reference](../reference/configuration.md) for the exception
format, then use the scan modes to check your policy:

```bash
hardener scan --compliance    # Only violations without a valid exception
hardener scan --audit         # Ignore config entirely: the raw security truth
hardener scan --exit-code     # Exit 1 if findings exist (CI gate)
```

## 3. Preview changes with a dry-run

Before changing anything, see exactly what `apply` would do:

```bash
hardener apply --dry-run --all
```

The dry-run lists every change with its current and target value, modifies
nothing, creates no checkpoint, and needs no root. You can narrow it to one
plugin:

```bash
hardener apply --dry-run --plugin kernel
```

## 4. Apply hardening

When the preview looks right:

```bash
sudo hardener apply --all                # Everything
sudo hardener apply --plugin ssh         # One plugin at a time
```

Apply requires root. Before writing anything, each plugin captures a
checkpoint of the files it is about to change, so every change is reversible.
Plugins whose subsystem is absent (for example the MAC plugin on a host with
neither SELinux nor AppArmor) skip gracefully rather than failing.

## 5. Roll back if needed

Checkpoints make hardening safe to try. To undo:

```bash
hardener checkpoint list                 # Find the checkpoint ID
sudo hardener rollback <checkpoint-id>   # Restore the captured state
```

Rollback restores the exact file contents captured at apply time.

Rollback is reversible too: before it restores, a checkpoint of your current
state is saved automatically (named after the one you are restoring), so you can
undo the rollback itself from the checkpoint list. If that safety checkpoint
cannot be created, the rollback is refused rather than run.

## 6. Manage checkpoints

```bash
hardener checkpoint list                       # Newest 20 checkpoints (--limit N, or --all for every one)
sudo hardener checkpoint create "pre-change"   # Manual snapshot before your own edits
hardener checkpoint show <checkpoint-id>       # What a checkpoint contains
hardener checkpoint delete <checkpoint-id>     # Remove one you no longer need
```

Checkpoints are stored in a signed SQLite database:
`/var/lib/linux-hardener/checkpoints.db` when created as root,
`~/.local/share/linux-hardener/checkpoints.db` otherwise.

## 7. Generate your first compliance report

Reports assess the latest scan against security frameworks (CIS, STIG,
NIST 800-53, PCI-DSS, HIPAA, GDPR, ISO 27001, SOC 2, NIST 800-171, FedRAMP):

```bash
hardener report --interactive            # Wizard: pick scenario or framework
hardener report --framework cis          # One framework
hardener report --scenario server        # Preset bundle of frameworks
hardener report --framework cis --report-format json --output report.json
```

Controls the engine cannot automatically assess are reported as manual
review, never assumed compliant. RHEL 10 family hosts are assessed against
RHEL 10 STIG and CIS identifiers automatically; `--profile` overrides the
auto-detection.

## 8. Where to go next

- **Track history**: `hardener history list`, `hardener history trends --host <name>`,
  and `hardener history regressions` (a CI-friendly gate that exits 1 when a
  host got worse).
- **Schedule scans**: `sudo hardener systemd install` sets up a daily timer;
  `hardener daemon status` shows recent runs. Configuration lives in the
  `[scheduler]` config section
  ([configuration reference](../reference/configuration.md)).
- **Remote hosts**: `hardener --ssh user@host scan` scans over SSH;
  see the [SSH remote scanning guide](ssh-remote-scanning.md).
- **Fleets**: `hardener batch scan --all` and friends run against every host
  in the inventory concurrently; see [reference/cli.md](../reference/cli.md#batch).
- **Something broke?** See the [troubleshooting guide](troubleshooting.md).

---

## Desktop app orientation

The desktop app (`linux-hardener-desktop`) wraps the same engine:

1. Launch the app and click **Run Security Scan** on the Dashboard.
2. Review findings by severity on the **Analysis** page; click a finding for
   its detail panel.
3. On the **Hardening** page (Configure tab) pick a profile and plugins, click
   **Preview Changes**, then the Apply button (labelled "Apply N Changes"); a
   polkit dialog asks for your password (root work runs through `pkexec`, see
   the [desktop environment compatibility guide](desktop-environment-compatibility.md)).
4. Use the History tab on the Hardening page (it lists the checkpoints saved
   on every apply) to roll back if needed.

Seven pages in total, reached from the grouped left sidebar: Dashboard,
Analysis and Hardening (grouped Local); Hosts (the merged read-only
multi-host scan posture and remote scanning), Fleet Apply (apply and roll
back across hosts) and Scheduler (grouped Fleet); plus Settings (theme
picker and About), pinned below the groups. `Ctrl+1` to `Ctrl+5` jump to
Dashboard, Analysis, Hardening, Hosts and Scheduler (`Ctrl+4` reaches Hosts
via the retained `/remote` redirect); Fleet Apply and Settings have no
dedicated shortcut yet. `Alt+T` cycles themes, `F11` toggles fullscreen,
`Escape` closes panels.
