# SSH Remote Scanning User Guide

This guide explains how to use Linux System Hardener to scan and harden remote
Linux hosts via SSH without installing the tool on them.

## Overview

SSH remote scanning allows you to:

- **Scan** remote hosts for security issues
- **Apply** hardening configurations remotely
- **Rollback** changes using checkpoints
- **Generate** compliance reports from remote systems

All operations happen over SSH - the hardener tool runs locally and executes
commands on the remote host.

## Prerequisites

### Local Machine
- Linux System Hardener installed
- SSH client available

### Remote Host
- SSH server running (OpenSSH)
- Linux operating system
- Standard utilities: `cat`, `stat`, `test`, `systemctl`
- For apply/rollback: sudo or root access

### Authentication
- SSH key authentication (recommended)
- SSH agent for passphrase-protected keys
- Or password authentication (less secure)

## Quick Start

```bash
# Basic scan of a remote host
hardener --ssh user@hostname scan

# Scan with a specific SSH key
hardener --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_ed25519 scan

# Generate a compliance report from remote host
hardener --ssh root@server.example.com report --framework cis --report-format pdf

CLI Reference

SSH Connection Options

| FLAG               | DESCRIPTION                                        | DEFAULT |
|--------------------|----------------------------------------------------|---------|
| --ssh HOST         | Remote host to connect to (user@host or just host) |    -    |
|--------------------|----------------------------------------------------|---------|
| --port PORT        | SSH port number                                    |   22    |
|--------------------|----------------------------------------------------|---------|
| --ssh-key FILE     | Path to SSH private key                            |    -    |
|--------------------|----------------------------------------------------|---------| 
| --ssh-timeout SECS | Connection timeout in seconds                      |   30    |
|--------------------|----------------------------------------------------|---------|
| --ssh-no-verify    | Skip host key verification (insecure)              |  false  |
|--------------------|----------------------------------------------------|---------|

Host Format

The --ssh flag accepts these formats:

# With username
--ssh admin@server.example.com

# Without username (uses current user or SSH config)
--ssh server.example.com

# With IP address
--ssh root@192.168.1.100

Authentication Methods

SSH Agent (Recommended)

The most convenient method. Add your key to the agent:

# Start agent if needed
eval $(ssh-agent)

# Add your key
ssh-add ~/.ssh/id_ed25519

# Now scan without specifying key
hardener --ssh user@host scan

Key File

Specify the private key directly:

hardener --ssh user@host --ssh-key ~/.ssh/id_ed25519 scan

SSH Config Integration

The tool respects your ~/.ssh/config. If you have:

Host myserver
    HostName server.example.com
    User admin
    IdentityFile ~/.ssh/server_key
    Port 2222

You can simply use:

hardener --ssh myserver scan

Password Authentication

Warning: Password authentication is less secure. Use key-based authentication when
possible.

> **Not yet implemented.** The SSH executor currently uses the `openssh` crate with
> key-based and SSH agent authentication only. The `HARDENER_SSH_PASSWORD` environment
> variable is reserved for future use but has no effect at this time.

HARDENER_SSH_PASSWORD=secret hardener --ssh user@host scan

Common Use Cases

Scan a Single Host

# Full scan with all plugins
hardener --ssh root@webserver scan

# Scan specific plugins only (short names or full IDs work)
hardener --ssh root@webserver scan --plugin kernel --plugin ssh --plugin firewall

Generate Compliance Report

# CIS Benchmark report in PDF format
hardener --ssh root@server report --framework cis --report-format pdf --output server-cis.pdf

# NIST 800-53 report in JSON for automation
hardener --ssh root@server report --framework nist --report-format json --output report.json

# Multiple frameworks
hardener --ssh root@server report --framework cis,stig --report-format html

Apply Hardening Remotely

# Apply all recommended hardening
hardener --ssh root@server apply --all

# Apply specific plugins (short names work)
hardener --ssh root@server apply --plugin kernel --plugin ssh

# Dry-run to see what would change
hardener --ssh root@server apply --all --dry-run

The privilege gate probes the *executor* session (`id -u` / `sudo -n`), not the
local process, so `--ssh root@host apply` works when the remote session is
privileged even if you launched the CLI as an unprivileged local user.

Self-lockout guard: when apply runs as root over an SSH session, `PermitRootLogin`
is only tightened to `prohibit-password` (key-based root login still works, so the
session is not severed). The scan keeps recommending `no`, so a rescan honestly
reports the residual gap - reaching `no` is a deliberate console step.

Rollback Changes

# List available checkpoints
hardener --ssh root@server checkpoint list

# Rollback to a specific checkpoint
hardener --ssh root@server rollback abc123

Batch Scanning Multiple Hosts

The `hardener batch scan` command scans many hosts in a single run, connecting to
them concurrently and printing a per-host section (each under a coloured host
header) followed by a fleet rollup. This replaces the older shell-loop pattern
with bounded parallelism and CI-friendly exit codes. A `--output FILE` copy is
written colour-free (ANSI escapes stripped).

Host Inventory

Hosts are read from the inventory file:

~/.config/linux-hardener/hosts.toml

This file is shared with the desktop GUI: hosts you add through the GUI's host
list appear here, and entries you hand-edit appear in the GUI. You can also scan
ad-hoc hosts that are not in the inventory with the --ssh flag.

Selecting Hosts

# Scan every host in the inventory
hardener batch scan --all

# Scan named inventory hosts (comma-separated or repeated)
hardener batch scan --host web-01,db-02
hardener batch scan --host web-01 --host db-02

# Scan an ad-hoc host not in the inventory (repeatable)
hardener batch scan --ssh admin@10.0.0.5

# Ad-hoc host on a non-default SSH port (user@host:port)
hardener batch scan --ssh admin@10.0.0.5:2222

# Machine-readable output for automation (global --format flag)
hardener --format json batch scan --all

# Raise the parallelism (default is 8 concurrent hosts)
hardener batch scan --all --concurrency 16

The --all and --host flags are mutually exclusive. Output honours the global
--format (text or json) and --quiet flags.

Exit Codes

`batch scan` returns a tiered exit code so it can gate CI pipelines:

| CODE | MEANING                                                        |
|------|----------------------------------------------------------------|
|  0   | All selected hosts were reachable and had no findings          |
|  1   | All hosts reachable, but at least one host has findings         |
|  2   | At least one host errored/was unreachable, or a usage error    |
|      | (no hosts selected, unknown --host name)                       |

Planned Follow-ups

The current release covers concurrent fleet scanning with history persistence,
per-host trend tracking, regression alerts, a read-only desktop Fleet view with
CIS compliance-score columns, and a Fleet Apply page for applying/rolling back
hardening across saved hosts over SSH.

Desktop Fleet View

The desktop application includes a read-only **Fleet** page that lets you scan
multiple saved inventory hosts (and ad-hoc `user@host[:port]` targets) from the
GUI without using the CLI.

### What it does

- Select any number of saved inventory hosts from a multi-select list, and/or
  enter ad-hoc `user@host[:port]` targets that are not in the inventory
- Click **Scan selected** to scan them concurrently over SSH (bounded to 8 parallel
  connections, matching `hardener batch scan --concurrency 8`)
- Watch live per-host progress while the scan runs (a tick or cross appears as each
  host finishes), then review the completed table
- Each host row shows a CIS compliance score and a per-severity tally: critical /
  high / medium / low / info
- Expand any row to see that host's individual findings via the same `FindingsGrid`
  used on the single-host Remote page

### How it relates to the Remote page and CLI

| Surface | Scope | Mutates? | Ad-hoc targets? |
|---------|-------|----------|-----------------|
| Remote page (GUI) | One inventory host | No (scan only) | No |
| Fleet page (GUI) | Inventory + ad-hoc `user@host[:port]` | No (scan only) | Yes |
| Fleet Apply page (GUI) | Inventory + ad-hoc `user@host[:port]` | Yes (dry-run + confirm gate) | Yes |
| `hardener batch scan` (CLI) | Inventory + ad-hoc `--ssh` | No | Yes |
| `hardener batch apply` (CLI) | Inventory + ad-hoc `--ssh` | Yes (with `--execute`) | Yes |

The Fleet page reuses the single-host `scan_with_executor` helper internally,
the same plugin path that powers the Remote page and the CLI's `--ssh` scan.
The Fleet **Scan** page is read-only by structure: its scan context carries no
checkpoint manager or audit logger, so apply and rollback paths are unreachable
from it. Mutating fleet operations live on the separate Fleet **Apply** page.

Fleet scanning reads saved hosts from the shared inventory file:

~/.config/linux-hardener/hosts.toml

Hosts added via the Remote page's **Add Host** form appear in fleet selections
immediately. Ad-hoc hosts that are not in the inventory can be entered directly in
the Fleet page's ad-hoc target field (`user@host[:port]`); invalid targets (a
space or comma in the hostname, a leading dash) are rejected at entry.

### What remains CLI-only

- Fleet compliance assessment against an arbitrary framework
  (`hardener batch report --framework ...`); the GUI Fleet table surfaces only a
  CIS compliance score
- Machine-readable JSON, `--output FILE` export, and `--concurrency` tuning

Troubleshooting

Connection Refused

Error: Connection refused (os error 111)

Causes:
- SSH server not running on remote host
- Firewall blocking port 22
- Wrong port number

Solutions:
- Verify SSH is running: ssh user@host manually
- Check firewall rules on remote host
- Use --port if SSH runs on non-standard port

Permission Denied

Error: Permission denied (publickey,password)

Causes:
- Wrong username
- Key not authorized on remote
- Key not loaded in SSH agent

Solutions:
- Verify username: --ssh correctuser@host
- Add public key to remote ~/.ssh/authorized_keys
- Run ssh-add to load your key

Host Key Verification Failed

Error: Host key verification failed

Causes:
- First connection to this host
- Host key changed (potential security issue!)

Solutions:
- For new hosts: ssh user@host once to accept the key
- If key legitimately changed: remove old key from ~/.ssh/known_hosts
- For testing only: --ssh-no-verify (not recommended for production)

Command Not Found on Remote

Error: systemctl: command not found

Causes:
- Remote host missing required utilities
- PATH not set correctly for SSH session

Solutions:
- Install missing packages on remote host
- Ensure remote user has proper PATH

Timeout Issues

Error: Connection timed out

Causes:
- Network connectivity issues
- Host unreachable
- Firewall dropping packets

Solutions:
- Verify network connectivity: ping host
- Increase timeout: --ssh-timeout 60
- Check intermediate firewalls

Security Considerations

Always Use Key-Based Authentication

Password authentication is vulnerable to brute-force attacks. Use Ed25519 or RSA
keys:

# Generate a secure key
ssh-keygen -t ed25519 -C "hardener@$(hostname)"

Host Key Verification

Never use --ssh-no-verify in production. This flag disables host key checking,
making you vulnerable to man-in-the-middle attacks.

If you must use it for initial testing:
# Only for testing new infrastructure!
hardener --ssh root@newhost --ssh-no-verify scan

Sudo Configuration

For apply/rollback operations, the remote user needs sudo access. Configure
passwordless sudo for specific commands if desired:

# /etc/sudoers.d/hardener
admin ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/tee, /usr/sbin/sysctl

Audit Trail

All remote operations are logged locally. Check the audit log for a record of what
was changed:

hardener history list

Limitations

Current limitations of SSH remote scanning:

| Limitation                      | Description                                                  |
|---------------------------------|--------------------------------------------------------------|
| No jump host support            | Cannot use bastion/jump hosts (yet)                          |
| Local checkpoints               | Checkpoint data stored on local machine                      |

Parallel multi-host scanning is available via `hardener batch scan` (CLI) and
the desktop **Fleet** page, see *Batch Scanning Multiple Hosts* and
*Desktop Fleet View* above.

Future Enhancements

Planned for future releases:
- Jump host / bastion support
- Remote checkpoint storage option

**Last Updated**: 2026-07-19