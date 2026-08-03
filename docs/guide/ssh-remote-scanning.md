# SSH Remote Scanning User Guide

This guide explains how to use Linux System Hardener to scan and harden remote
Linux hosts via SSH without installing the tool on them.

## Overview

SSH remote scanning allows you to:

- **Scan** remote hosts for security issues
- **Apply** hardening configurations remotely
- **Rollback** changes using checkpoints
- **Generate** compliance reports from remote systems

All four happen over SSH: the hardener tool runs locally and executes commands
on the remote host.

**`--ssh` is refused by the commands that cannot honour it**, exiting 2 before
any connection is opened and naming themselves in the message. Those are
`daemon`, `systemd`, `history`, `plugins` and the two checkpoint verbs that
address a row by id, `show` and `delete`; each acts on the machine you are
typing on. The daemon runs on this host and writes this host's database,
`systemd` manages this host's unit files, `history` reads this host's own scan
history, `plugins` lists what is compiled into the binary, and the checkpoint
database is this host's however many hosts it holds rows for. Every release up
to and including 1.5.1 accepted the flag on all of them, connected, said so
unless `--quiet` had silenced the line, and then acted on this host anyway. Use
`--host` to select a host within your history, and `hardener --ssh HOST scan` to
scan a remote.

## Prerequisites

### Local Machine
- Linux System Hardener installed
- SSH client available

### Remote Host
- SSH server running (OpenSSH)
- Linux operating system
- Standard utilities the executor itself runs: `cat`, `test`, `stat`, `find`,
  and `sudo tee` for writes. Plugins add their own, `systemctl` and `sysctl`
  among them.
- For apply/rollback: a root session, or a user whose `sudo -n true` succeeds

### Authentication
- SSH key authentication (recommended)
- SSH agent for passphrase-protected keys

Remote hosts authenticate with an SSH key or agent only. There is no password
code path anywhere in this tool, and the ssh layer it drives is invoked with
`BatchMode=yes` and no stdin, so a host that will only accept a password fails
at connect rather than prompting you for one.

## Quick Start

```bash
# Basic scan of a remote host
hardener --ssh user@hostname scan

# Scan with a specific SSH key
hardener --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_ed25519 scan

# Generate a compliance report from remote host
hardener --ssh root@server.example.com report --framework cis --report-format pdf
```

## CLI Reference

### SSH Connection Options

| FLAG               | DESCRIPTION                                        | DEFAULT |
|--------------------|----------------------------------------------------|---------|
| --ssh HOST         | Remote host to connect to (user@host or just host; no `:port` suffix here, use --port) |    -    |
| --port PORT        | SSH port number (always sent, overrides ssh config) |   22    |
| --ssh-key FILE     | Path to SSH private key                            |    -    |
| --ssh-timeout SECS | Connection timeout in seconds                      |   30    |
| --ssh-no-verify    | Skip host key verification (insecure)              |  false  |

### Host Format

The --ssh flag accepts these formats:

```bash
# With username
--ssh admin@server.example.com

# Without username (uses current user or SSH config)
--ssh server.example.com

# With IP address
--ssh root@192.168.1.100
```

## Authentication Methods

### SSH Agent (Recommended)

The most convenient method. Add your key to the agent:

```bash
# Start agent if needed
eval $(ssh-agent)

# Add your key
ssh-add ~/.ssh/id_ed25519

# Now scan without specifying key
hardener --ssh user@host scan
```

### Key File

Specify the private key directly:

```bash
hardener --ssh user@host --ssh-key ~/.ssh/id_ed25519 scan
```

Naming a key file makes it the only key offered: the flag is passed to ssh
together with `IdentitiesOnly=yes`, so an agent identity or an `IdentityFile`
from your `~/.ssh/config` is not tried as a fallback. Omit `--ssh-key` when you
want the agent and your config to decide.

### SSH Config Integration

The tool shells out to `ssh`, so your `~/.ssh/config` is read as usual. If you
have:

```
Host myserver
    HostName server.example.com
    User admin
    IdentityFile ~/.ssh/server_key
```

You can simply use:

```bash
hardener --ssh myserver scan
```

`HostName`, `User` and `IdentityFile` are honoured. **`Port` is not.** The
`--port` flag defaults to 22 and is always handed to ssh on the command line,
where it outranks the config file, so a host reached on another port needs the
port given explicitly every time:

```bash
hardener --ssh myserver --port 2222 scan
```

### Password Authentication

Not supported, and not merely unimplemented. `SshExecutor::connect` builds its
session from a key file, the agent, and your `~/.ssh/config` only, so there is
no password prompt and no environment variable that supplies one. Underneath,
the ssh master connection is launched with `BatchMode=yes` and its stdin closed,
which disables every interactive authentication method at the ssh layer itself.
A host that accepts passwords alone therefore fails at connect, immediately and
without a prompt, and stays unscannable until you authorise a key in its
`~/.ssh/authorized_keys`.

## Common Use Cases

### Scan a Single Host

```bash
# Full scan with all plugins
hardener --ssh root@webserver scan

# Scan specific plugins only (short names or full IDs work)
hardener --ssh root@webserver scan --plugin kernel --plugin ssh --plugin firewall
```

### Generate Compliance Report

```bash
# CIS Benchmark report in PDF format
hardener --ssh root@server report --framework cis --report-format pdf --output server-cis.pdf

# NIST 800-53 report in JSON for automation
hardener --ssh root@server report --framework nist --report-format json --output report.json

# Several frameworks at once: use a scenario preset, not a list.
# --framework takes exactly one id and rejects a comma-separated one.
# "server" is CIS + STIG.
hardener --ssh root@server report --scenario server --report-format html
```

`--report-format` accepts `text`, `json`, `csv`, `html` and `pdf`. A `pdf` run
writes to a file: give `--output`, or a timestamped name is generated for you.

### Apply Hardening Remotely

```bash
# Apply all recommended hardening
hardener --ssh root@server apply --all

# Apply specific plugins (short names work)
hardener --ssh root@server apply --plugin kernel --plugin ssh

# Dry-run to see what would change
hardener --ssh root@server apply --all --dry-run
```

The privilege gate probes the *executor* session (`id -u` / `sudo -n`), not the
local process, so `--ssh root@host apply` works when the remote session is
privileged even if you launched the CLI as an unprivileged local user.

Self-lockout guard: when apply runs as root over an SSH session, `PermitRootLogin`
is only tightened to `prohibit-password` (key-based root login still works, so the
session is not severed). The scan keeps recommending `no`, so a rescan honestly
reports the residual gap - reaching `no` is a deliberate console step.

### Rollback Changes

```bash
# List available checkpoints
hardener --ssh root@server checkpoint list

# Rollback to a specific checkpoint
hardener --ssh root@server rollback abc123
```

## Batch Scanning Multiple Hosts

The `hardener batch scan` command scans many hosts in a single run, connecting to
them concurrently and printing a per-host section (each under a coloured host
header) followed by a fleet rollup. This replaces the older shell-loop pattern
with bounded parallelism and CI-friendly exit codes. A `--output FILE` copy is
written colour-free (ANSI escapes stripped).

### Host Inventory

Hosts are read from the inventory file:

```
~/.config/linux-hardener/hosts.toml
```

This file is shared with the desktop GUI: hosts you add through the GUI's host
list appear here, and entries you hand-edit appear in the GUI. You can also scan
ad-hoc hosts that are not in the inventory with the --ssh flag.

### Selecting Hosts

```bash
# Scan every host in the inventory
hardener batch scan --all

# Scan named inventory hosts (comma-separated or repeated)
hardener batch scan --host web-01,db-02
hardener batch scan --host web-01 --host db-02

# Scan an ad-hoc host not in the inventory (repeatable)
hardener batch scan --ssh admin@10.0.0.5

# Ad-hoc host on a non-default SSH port (user@host:port)
hardener batch scan --ssh admin@10.0.0.5:2222

# Or give the whole run a port, for targets that name none of their own
hardener --port 2222 batch scan --ssh admin@10.0.0.5 --ssh admin@10.0.0.6

# Machine-readable output for automation (global --format flag)
hardener --format json batch scan --all

# Raise the parallelism (default is 8 concurrent hosts)
hardener batch scan --all --concurrency 16
```

The --all and --host flags are mutually exclusive. Output honours the global
--format (text or json) and --quiet flags.

### Exit Codes

`batch scan` returns a tiered exit code so it can gate CI pipelines:

| CODE | MEANING                                                        |
|------|----------------------------------------------------------------|
|  0   | All selected hosts were reachable and had no findings          |
|  1   | All hosts reachable, but at least one host has findings         |
|  2   | At least one host errored/was unreachable, or a usage error    |
|      | (no hosts selected, unknown --host name)                       |

### Planned Follow-ups

The current release covers concurrent fleet scanning with history persistence,
per-host trend tracking, regression alerts, a read-only desktop Hosts scan view with
compliance-score columns, and a Fleet Apply page for applying/rolling back
hardening across saved hosts over SSH.

## Desktop Hosts Screen

The desktop application's **Hosts** screen (under the Fleet group in the left
sidebar, routed at `/fleet`) lets you scan multiple saved inventory hosts (and
ad-hoc `user@host[:port]` targets) from the GUI without using the CLI. It
merged the former single-host Remote view with multi-host fleet scanning into
one screen; the old `/remote` route now just redirects here.

### What it does

- Select any number of saved inventory hosts from a multi-select list, and/or
  enter ad-hoc `user@host[:port]` targets that are not in the inventory
- Click **Scan Selected** to scan them concurrently over SSH (bounded to 8 parallel
  connections, matching `hardener batch scan --concurrency 8`)
- Watch live per-host progress while the scan runs (a tick or cross appears as each
  host finishes), then review the completed table
- Each host row shows a per-severity tally (critical / high / medium / low) and a
  compliance score strip, one cell per framework the scan carries posture for
- Expand any row to see that host's compliance detail and its findings, listed
  and grouped by severity, in a collapsible panel built into the row itself

### How it relates to the CLI

| Surface | Scope | Mutates? | Ad-hoc targets? |
|---------|-------|----------|-----------------|
| Hosts page (GUI) | Inventory + ad-hoc `user@host[:port]` (single or many) | No (scan only) | Yes |
| Fleet Apply page (GUI) | Inventory + ad-hoc `user@host[:port]` | Yes (dry-run + confirm gate) | Yes |
| `hardener batch scan` (CLI) | Inventory + ad-hoc `--ssh` | No | Yes |
| `hardener batch apply` (CLI) | Inventory + ad-hoc `--ssh` | Yes (with `--execute`) | Yes |

The Hosts screen reuses the single-host `scan_with_executor` helper internally,
the same plugin path that powers its single-host connect session and the CLI's
`--ssh` scan. The Hosts screen is read-only by structure: its scan context carries
no checkpoint manager or audit logger, so apply and rollback paths are unreachable
from it. Mutating fleet operations live on the separate Fleet **Apply** page.

Fleet scanning reads saved hosts from the shared inventory file:

```
~/.config/linux-hardener/hosts.toml
```

Hosts added via the Hosts screen's **Add Host** form appear in fleet selections
immediately. Ad-hoc hosts that are not in the inventory can be entered directly in
the Hosts screen's ad-hoc target field (`user@host[:port]`); invalid targets (a
space or comma in the hostname, a leading dash) are rejected at entry.

### What remains CLI-only

- Fleet compliance reports as standalone documents
  (`hardener batch report --framework ...`); the Hosts page shows compliance
  scores inline per host but does not generate a report file
- Machine-readable JSON, `--output FILE` export, and `--concurrency` tuning

## Troubleshooting

### Connection Refused

```
Error: Connection refused (os error 111)
```

Causes:
- SSH server not running on remote host
- Firewall blocking port 22
- Wrong port number

Solutions:
- Verify SSH is running: ssh user@host manually
- Check firewall rules on remote host
- Use --port if SSH runs on non-standard port

### Permission Denied

```
SSH connection failed: Failed to connect to server.example.com: ... Permission
denied (publickey,password) (no usable SSH key - load one with `ssh-add` or
configure a key file for this host)
```

The underlying ssh reason always reaches you; the key hint in brackets is
appended only when that reason names an authentication or agent failure, so a
refused connection, a timeout or an unresolvable name keeps its own wording and
never gets mislabelled as an auth problem.

Causes:
- Wrong username
- Key not authorized on remote
- Key not loaded in SSH agent
- The host offers passwords only, which this tool cannot use

Solutions:
- Verify username: --ssh correctuser@host
- Add public key to remote ~/.ssh/authorized_keys
- Run ssh-add to load your key
- Check `SSH_AUTH_SOCK` is set in the shell you launched from

### Host Key Verification Failed

```
Error: Host key verification failed
```

Causes:
- First connection to this host
- Host key changed (potential security issue!)

Solutions:
- For new hosts: ssh user@host once to accept the key
- If key legitimately changed: remove old key from ~/.ssh/known_hosts
- For testing only: --ssh-no-verify (not recommended for production)

### Command Not Found on Remote

```
Error: systemctl: command not found
```

Causes:
- Remote host missing required utilities
- PATH not set correctly for SSH session

Solutions:
- Install missing packages on remote host
- Ensure remote user has proper PATH

### Timeout Issues

```
Error: Connection timed out
```

Causes:
- Network connectivity issues
- Host unreachable
- Firewall dropping packets

Solutions:
- Verify network connectivity: ping host
- Increase timeout: --ssh-timeout 60
- Check intermediate firewalls

## Security Considerations

### Key-Based Authentication Is the Only Path

Password authentication is vulnerable to brute-force attacks, which is why this
tool never offers it and why the ssh layer beneath it is run with
`BatchMode=yes`: there is nothing to disable and no flag that re-enables it. Use
Ed25519 or RSA keys:

```bash
# Generate a secure key
ssh-keygen -t ed25519 -C "hardener@$(hostname)"
```

### Host Key Verification

Never use --ssh-no-verify in production. This flag disables host key checking,
making you vulnerable to man-in-the-middle attacks.

If you must use it for initial testing:

```bash
# Only for testing new infrastructure!
hardener --ssh root@newhost --ssh-no-verify scan
```

### Sudo Configuration

**Connect as root for apply and rollback.** That is what the examples above do,
and it is the only arrangement the tool exercises end to end.

A non-root remote user is gated on `sudo -n true` succeeding, and the gate fails
closed, so a command-limited `NOPASSWD` list that omits `true` refuses the whole
run before it starts. Passing the gate is also not enough on its own: of the
remote operations, only file writes are elevated, through `sudo tee`. Everything
else, `systemctl` and `sysctl` included, is run as the connecting user with no
`sudo` in front of it, so a plugin that changes unit or runtime state will not
take effect for a non-root session even once the gate is satisfied.

If you must use a non-root account, give it unrestricted passwordless sudo and
treat the result as unvalidated:

```
# /etc/sudoers.d/hardener
admin ALL=(ALL) NOPASSWD: ALL
```

### Audit Trail

Two separate records exist locally, and they answer different questions.

**What was changed** is the audit log, a hash-chained file of JSON lines written
by the local process: `/var/log/linux-hardener/audit.log` when run as root, and
`$XDG_DATA_HOME/linux-hardener/audit.log` (normally
`~/.local/share/linux-hardener/audit.log`) otherwise. There is no subcommand
that prints it; read it with ordinary tools:

```bash
sudo tail -n 20 /var/log/linux-hardener/audit.log
```

**What was found, and when** is the scan history database, which is what the
history subcommands read:

```bash
hardener history list
hardener history show <session-id>
```

## Limitations

Current limitations of SSH remote scanning:

| Limitation                      | Description                                                  |
|---------------------------------|--------------------------------------------------------------|
| No jump host support            | Cannot use bastion/jump hosts (yet)                          |
| No password authentication      | Key or agent only; a password-only host fails at connect     |
| ssh config `Port` ignored       | `--port` is always sent and outranks the config file          |
| Non-root sessions only half elevate | Only file writes go through `sudo`; other commands do not |
| Local checkpoints               | Checkpoint data stored on local machine. `list` and `rollback` are scoped to the host `--ssh` selects; `show` and `delete` address any row by id and refuse the flag |
| Scheduling is local only        | `daemon` and `systemd` refuse `--ssh`: a remote is scheduled by installing the tool on it, or by scheduling `--ssh HOST scan` here |
| Vendor-layer permissions        | On a layering host, scan reports permission findings apply cannot fix |

The last one needs explaining, because a run looks inconsistent with itself.
Where a remote host keeps its packaged configuration under `/usr/etc` (openSUSE,
and Fedora is moving the same way), a critical file can be absent from `/etc`
while the copy in force sits in the vendor layer. The scan assesses that copy and
reports a violating mode, naming the vendor file, but this tool never writes a
package-owned file, because the next package update on the remote host would
revert it. So `apply` makes no change for that path and `apply --dry-run`
previews none either, which is by design rather than a failure to connect or a
privilege problem. The finding carries an `install` command that copies the file
into `/etc` at the required mode, and it has to be run on the remote host; the
[troubleshooting guide](troubleshooting.md#scan-reports-a-permissions-finding-under-usretc-and-apply-changes-nothing) shows the
worked example.

Parallel multi-host scanning is available via `hardener batch scan` (CLI) and
the desktop **Hosts** screen, see *Batch Scanning Multiple Hosts* and
*Desktop Hosts Screen* above.

## Future Enhancements

Planned for future releases:
- Jump host / bastion support
- Remote checkpoint storage option

**Last Updated**: 2026-08-01
