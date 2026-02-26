# CLI Commands

Command reference for the `hardener` binary (`crates/hardener-cli/`).

**Binary locations:**
- Debug: `target/debug/hardener`
- Release: `target/release/hardener`

---

## Global Flags

These flags can be placed before or after any subcommand.

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `--format <FORMAT>` | Output format: `text`, `json`, `csv`, `html`, `pdf` | `text` |
| `-q`, `--quiet` | Suppress non-essential output | off |
| `-C`, `--config <FILE>` | Path to TOML configuration file | auto-detected |
| `--ssh <HOST>` | Remote host to scan via SSH (`user@host` or `host`) | local |
| `--port <PORT>` | SSH port (only with `--ssh`) | `22` |
| `--ssh-key <FILE>` | SSH private key file (only with `--ssh`) | SSH agent |
| `--ssh-timeout <SECONDS>` | SSH connection timeout (only with `--ssh`) | `30` |
| `--ssh-no-verify` | Skip SSH host key verification (insecure, only with `--ssh`) | off |
| `-h`, `--help` | Print help | |
| `-V`, `--version` | Print version | |

---

## Plugin Names

These names are used with `--plugin` in `scan` and `apply`:

| Name | Description |
|------|-------------|
| `kernel` | Sysctl hardening (ASLR, ptrace, symlink protection, network) |
| `ssh` | SSH daemon configuration |
| `firewall` | Firewall rules (nftables, firewalld, ufw backends) |
| `pam` | PAM password quality and aging policies |
| `services` | Unnecessary service minimisation |
| `permissions` | File and directory permission auditing |
| `audit` | Audit daemon (auditd) rule configuration |
| `mac` | Mandatory Access Control (SELinux, AppArmor) |

Short names (above) and full names (e.g. `kernel-hardening`, `ssh-hardening`) are both accepted.

---

## scan

Scan the system for security misconfigurations. Read-only — makes no changes.

```
hardener scan [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--plugin <NAME>` | Scan only this plugin (repeatable for multiple) | all plugins |
| `--audit` | Ignore config file, run a pure security assessment | off |
| `--compliance` | Only show findings that violate policy (no informational) | off |
| `--exit-code` | Exit with code 1 if any findings exist (for CI/CD pipelines) | off |
| `-s`, `--severity <LEVEL>` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` | `info` |

`--audit` and `--compliance` are mutually exclusive.

**Examples:**

```bash
hardener scan                                # Scan all plugins, show everything
hardener scan --plugin kernel --plugin ssh   # Scan only kernel and SSH
hardener scan --severity high                # Only show high and critical findings
hardener scan --audit                        # Ignore config, pure security check
hardener scan --exit-code                    # Return 1 if findings exist (CI use)
hardener --format json scan                  # JSON output for automation
hardener --ssh user@server scan              # Scan a remote host via SSH
```

---

## apply

Apply hardening changes to the system. Requires root (unless `--dry-run`).

Creates a checkpoint automatically before writing any changes, so all modifications can be rolled back.

```
sudo hardener apply [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-a`, `--all` | Apply all available plugins | |
| `-p`, `--plugin <NAME>` | Apply only this plugin (repeatable for multiple) | |
| `--dry-run` | Show what would change without writing anything (no root needed) | off |

Either `--all` or at least one `--plugin` is required. `--all` and `--plugin` are mutually exclusive.

**Examples:**

```bash
hardener apply --dry-run --all               # Preview all changes (no root needed)
hardener apply --dry-run --plugin pam        # Preview PAM changes only
sudo hardener apply --all                    # Apply everything (creates checkpoint first)
sudo hardener apply --plugin kernel          # Apply only kernel sysctl hardening
```

**Dry-run vs real apply:**
- `--dry-run` lists each change with its current and target value, then exits. No files are modified, no checkpoint is created, and root is not required.
- Without `--dry-run`, root is required. A checkpoint is created before any writes, and each plugin's changes are applied to the live system and persisted to config files.

---

## rollback

Restore the system to a previous checkpoint snapshot. Requires root.

```
sudo hardener rollback <CHECKPOINT_ID>
```

| Argument | Description |
|----------|-------------|
| `CHECKPOINT_ID` | ID of the checkpoint to restore (from `checkpoint list`) |

**Example:**

```bash
hardener checkpoint list                     # Find the checkpoint ID
sudo hardener rollback abc123                # Restore to that checkpoint
```

---

## checkpoint

Manage checkpoint snapshots.

### checkpoint list

List all stored checkpoints with their IDs, names, and timestamps.

```
hardener checkpoint list
```

### checkpoint create

Create a named checkpoint of the current system state.

```
hardener checkpoint create <NAME>
```

| Argument | Description |
|----------|-------------|
| `NAME` | Human-readable name for the checkpoint |

### checkpoint delete

Delete a checkpoint by its ID.

```
hardener checkpoint delete <CHECKPOINT_ID>
```

### checkpoint show

Display full details of a specific checkpoint.

```
hardener checkpoint show <CHECKPOINT_ID>
```

---

## plugins

List all available security plugins with their descriptions.

```
hardener plugins
```

No flags. Displays the 8 built-in plugins and their status.

---

## report

Generate compliance reports against security frameworks.

```
hardener report [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-s`, `--scenario <SCENARIO>` | Use case preset: `server`, `workstation`, `government`, `healthcare`, `financial`, `gdpr`, `all` | |
| `--framework <FRAMEWORK>` | Specific framework: `cis`, `stig`, `nist`, `pcidss`, `hipaa`, `gdpr` | |
| `--report-format <FORMAT>` | Report format: `text`, `json` | `text` |
| `-o`, `--output <FILE>` | Write to file instead of stdout | stdout |
| `-i`, `--interactive` | Launch interactive wizard to pick scenario/framework | off |

`--scenario` and `--framework` are mutually exclusive. Use `--scenario` for a preset that selects relevant frameworks for your environment, or `--framework` to target a single standard.

**Examples:**

```bash
hardener report --scenario server            # All frameworks relevant to servers
hardener report --framework cis              # CIS Benchmark report only
hardener report --interactive                # Step-by-step wizard
hardener report --scenario all --output report.json --report-format json
```

---

## daemon

Manage the scheduled scanning daemon.

### daemon start

Start the daemon process. Blocks until shutdown (Ctrl+C or signal).

```
sudo hardener daemon start
```

### daemon run-once

Run a single scan immediately, then exit. Does not start the daemon loop.

```
sudo hardener daemon run-once
```

### daemon status

Show daemon status and recent scan history.

```
hardener daemon status <LIMIT>
```

| Argument | Description |
|----------|-------------|
| `LIMIT` | Number of recent scan sessions to display |

---

## systemd

Generate, install, and manage systemd unit files for scheduled scanning.

### systemd generate

Generate timer and service unit files. Prints to stdout by default.

```
hardener systemd generate [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o`, `--output <DIR>` | Write files to a directory instead of stdout | stdout |
| `--binary <PATH>` | Path to the hardener binary | auto-detected |
| `-s`, `--schedule <EXPR>` | systemd calendar expression (e.g. `daily`, `*-*-* 02:00:00`) | `daily` |

### systemd install

Install unit files to systemd. Requires root for system-level install.

```
sudo hardener systemd install [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--user` | Install as user service instead of system service | system |
| `-s`, `--schedule <EXPR>` | systemd calendar expression | `daily` |

**System vs user install:** System install (`sudo`, no `--user`) runs as root and can apply all hardening changes. User install (`--user`, no sudo) runs under your user account, suitable for scan-only monitoring.

### systemd uninstall

Remove unit files from systemd.

```
sudo hardener systemd uninstall [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--user` | Remove user service instead of system service | system |

### systemd status

Show the current state of the systemd timer and service.

```
hardener systemd status [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--user` | Show user service status instead of system service | system |

---

## history

View and export past scan sessions.

### history list

List recent scan sessions.

```
hardener history list [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-l`, `--limit <N>` | Maximum number of sessions to show | `20` |
| `--host <HOST>` | Filter by host identifier | all hosts |
| `--status <STATUS>` | Filter by status: `running`, `completed`, `failed` | all |

### history show

Display full details of a specific scan session.

```
hardener history show <SESSION_ID>
```

| Argument | Description |
|----------|-------------|
| `SESSION_ID` | UUID of the session (from `history list`) |

### history export

Export a scan session to JSON.

```
hardener history export <SESSION_ID> [FLAGS]
```

| Argument / Flag | Description | Default |
|-----------------|-------------|---------|
| `SESSION_ID` | UUID of the session to export | |
| `-o`, `--output <FILE>` | Output file path | `session-<id>.json` |

**Last Updated**: 2026-02-26
