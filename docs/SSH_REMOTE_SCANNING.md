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

Rollback Changes

# List available checkpoints
hardener --ssh root@server checkpoint list

# Rollback to a specific checkpoint
hardener --ssh root@server rollback abc123

Batch Scanning Multiple Hosts

The `hardener batch scan` command scans many hosts in a single run, connecting to
them concurrently and printing a per-host table followed by a fleet rollup. This
replaces the older shell-loop pattern with bounded parallelism and CI-friendly
exit codes.

Host Inventory

Hosts are read from the inventory file:

~/.config/linux-hardener/hosts.toml

This file is shared with the desktop GUI — hosts you add through the GUI's host
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

The current release covers concurrent fleet scanning. Scan-history persistence,
per-host trend tracking, regression alerts, and a desktop multi-host view are
planned for future releases and are not part of this release.

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

| Limitation           | Description                                    |
|----------------------|------------------------------------------------|
| No jump host support | Cannot use bastion/jump hosts (yet)            |
| Local checkpoints    | Checkpoint data stored on local machine        |
| No history/trends    | Batch scans are not yet persisted for trending |

Parallel multi-host scanning is available via `hardener batch scan` — see
*Batch Scanning Multiple Hosts* above.

Future Enhancements

Planned for future releases:
- Scan-history persistence and per-host trend tracking for batch scans
- Regression alerts and a desktop multi-host view
- Jump host / bastion support
- Remote checkpoint storage option

**Last Updated**: 2026-06-20