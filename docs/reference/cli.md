# CLI Commands

Command reference for the `hardener` binary (`crates/hardener-cli/`).

**Binary locations** (relative to the cargo target directory, `./target` by
default, or wherever `CARGO_TARGET_DIR`/`[build] target-dir` points):
- Debug: `debug/hardener`
- Release: `release/hardener`

---

## Global Flags

These flags can be placed before or after any subcommand.

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `--format <FORMAT>` | Output format: `text` or `json`. A value it cannot render is refused at the parse, exit 2. The rich formats belong to `report --report-format`, not to this flag. One exception: on `report` this flag governs only the command's own progress, because the report body is what `--report-format` selects | `text` |
| `-q`, `--quiet` | Suppress non-essential output | off |
| `-C`, `--config <FILE>` | Path to TOML configuration file | auto-detected |
| `--ssh <HOST>` | Remote host to act on via SSH (`user@host` or `host`). Accepted by the commands that reach a host, refused by the ones that do not: see below | local |
| `--port <PORT>` | SSH port for `--ssh`, and for any `batch` ad-hoc target that names no port of its own. **Only `batch` targets take a `:port` suffix**, and a valid one there outranks this flag; for every other command the whole `--ssh` value is the host, so `web-01:2200` is looked up as that hostname. Inventory hosts carry their own port and default to 22 without it | `22` |
| `--ssh-key <FILE>` | SSH private key file. Also the fallback for any `batch` host that names no key of its own | SSH agent |
| `--ssh-timeout <SECONDS>` | SSH connection timeout. Also applies to every `batch` connection | `30` |
| `--ssh-no-verify` | Skip SSH host key verification (insecure). With `batch` it reaches ad-hoc `--ssh` targets only; inventory hosts keep their own `host_key_checking` | off |
| `-h`, `--help` | Print help | |
| `-V`, `--version` | Print version | |

**Where `-C`, `--config` takes effect.** clap accepts it anywhere, but only the
commands that read a `config.toml` act on it: `scan`, `apply`, `report`, `batch
scan`, `batch report`, `batch apply`, `daemon`, `history`, and `systemd
generate`/`install`, which embed the path in the unit they write.

`daemon` and `history` read only the `[scheduler]` section, and they read it
from the named file when there is one. A single file carrying both a `[global]`
and a `[scheduler]` section is therefore honoured whole: before, `scan` took its
policy from the named file and then wrote its history to whichever database the
default search happened to find.

**That section does not merge**, and the named file is searched **first** rather
than instead: the first file that actually configures the scheduler wins whole.
A file with no `[scheduler]` section is not that file configuring it, so your
system or user config still decides. That matters because `systemd
generate`/`install` embed the `--config` path in the unit they write, so a timer
installed against a policy file would otherwise run its scheduled scan on the
compiled-in defaults, disabled and writing elsewhere, while your own config said
otherwise. A named path that is missing or will not parse is an error for these
verbs. It is not
everywhere: `batch scan`, `batch report` and `batch apply --dry-run`
deliberately keep their fallback to the compiled-in defaults, warning on stderr,
because they change no host.

Every other command accepts the flag, because clap declares it globally, and
does nothing with it: `rollback`, all five `checkpoint` verbs, `plugins`, and
`systemd uninstall`/`status` read no configuration at all. Two are worth naming
because they do read configuration and still ignore the flag, each evaluating
the host against the system and user configuration instead:

- `report --interactive`, which the wizard documents as deliberate: it loads the
  default sources so that it cannot score a host differently from
  `hardener report`. The same rule now covers the other two inputs to a score:
  the wizard scans through the executor the CLI built, so `--ssh` reaches it,
  and it resolves the compliance profile from the host it scanned rather than
  defaulting to `generic`. `--profile` overrides that resolution here exactly as
  it does for `hardener report`, and is parsed before the first prompt so that a
  name it cannot read is refused before five questions are answered. The
  resolved profile is printed before the reports are generated, whichever way it
  was arrived at.
- `batch rollback`, which reads no `config.toml` at all.

**Where `--ssh` takes effect, and where it is refused.** It is honoured by
`scan`, `apply`, `rollback`, `report` (including `--interactive`), `checkpoint
list` and `checkpoint create`, and by `batch`, whose own `--ssh` is the same
argument: `hardener --ssh web-01 batch scan` and `hardener batch scan --ssh
web-01` are one invocation naming one ad-hoc target.

Every other command **refuses it, exiting 2 before any connection is opened**,
and names itself in the refusal:

- `daemon start`, `run-once` and `status`, which run on this host, on this
  host's timer, and read and write this host's scheduler database. Scanning a
  remote is `hardener --ssh HOST scan`.
- `systemd generate`, `install`, `uninstall` and `status`, which write and
  manage this host's own unit files.
- `history list`, `trends`, `regressions`, `show` and `export`, which read this
  host's own scan history. A host **within** that history is selected with
  `--host`, which is a different question from which host to connect to.
- `checkpoint show` and `checkpoint delete`, which address one row of this
  host's checkpoint database by an id that names it whichever host it was
  captured from. Their two siblings do reach a host: `list` scopes its rows to
  the target's key, and `create` captures the target's files.
- `plugins`, which lists what is compiled into this binary and asks no host
  anything.

Every release up to and including 1.5.1 accepted the flag on all of those,
opened the connection, announced it unless `--quiet` had silenced that line,
and then acted on this host regardless. The flag's only effect there was that
an unreachable target stopped the command, so it could refuse work and never
redirect it.

`daemon` is separate again: it resolves the `[scheduler]` section through its own
path search rather than the loader, so the merge rules that apply to `[global]`
do not apply to it, and the first file found wins outright. `-C` is honoured:
naming a path replaces that search rather than adding to it (see
[configuration.md](configuration.md#scheduler)).

---

## Plugin Names

These names are used with `--plugin` in `scan` and `apply`:

| Name | Description |
|------|-------------|
| `kernel` | Sysctl hardening (ASLR, ptrace, symlink protection, network) |
| `ssh` | SSH daemon configuration |
| `firewall` | Firewall rules (nftables, firewalld, ufw backends) |
| `pam` | PAM password quality and aging policies |
| `service` | Unnecessary service minimisation |
| `permissions` | File and directory permission auditing |
| `audit` | Audit daemon (auditd) rule configuration |
| `mac` | Mandatory Access Control (SELinux, AppArmor) |

Short names (above) and full names (e.g. `kernel-hardening`, `ssh-hardening`) are
both accepted. A short name matches by prefix up to the first hyphen, so the
service plugin is `service`, not `services`: its full id is
`service-minimisation`.

> Every command rejects an unrecognised `--plugin` value with an error naming
> the valid ids, and exits non-zero. This applies to `scan`, `apply`,
> `batch apply` and `batch rollback` alike: a name that matches nothing is
> never dropped, so a typo cannot narrow the selection to nothing while the
> command still reports success.

---

## scan

Scan the system for security misconfigurations. Read-only: makes no changes.

```
hardener scan [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--plugin <NAME>` | Scan only this plugin (repeatable for multiple) | all config-enabled plugins |
| `--audit` | Ignore config file, run a pure security assessment | off |
| `--exit-code` | Exit with code 1 if any findings exist, or if any plugin's scan did not complete (for CI/CD pipelines) | off |
| `-s`, `--severity <LEVEL>` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` | `info` |
| `--timings` | Print a per-plugin timing table (slowest first) after the scan | off |

Plugins scan concurrently; `--timings` writes to stderr, so `--format json`
stdout stays machine-parseable.

**`scan` honours the configuration file.** Three things follow from that:

- A `directives` entry overrides the target value a check is measured against,
  so a check is judged against your policy rather than the shipped baseline.
- A finding covered by a valid policy exception is **annotated** with that
  exception rather than hidden. `scan` never removes a finding; it is
  `hardener report` that treats an annotated finding as satisfied for a
  compliance control, while still listing it as evidence.
- `[global] enabled_plugins` and `disabled_plugins` gate which plugins run.
  A plugin you asked for that the config disables is named in a
  `Skipped by config:` line rather than silently omitted, because silence
  there would read as a clean host. If the config disables **every** selected
  plugin, `scan` exits with an error instead of reporting an empty, clean-looking
  result.

`scan --audit` opts out of all of the above and measures against the unmodified
secure baseline.

**Unprivileged runs and unchecked checks:** some checks (root-only config
files such as `/etc/security/pwquality.conf` or `/etc/ssh/sshd_config`,
`auditctl -l`, `aa-status`, the active firewall ruleset) need root to read.
Running `scan` without root never reports these as failed or missing;
instead they are reported unchecked, distinct from a genuine finding.

Privilege is not the only reason a check goes unchecked: a plugin the
operator disabled, a path on a filesystem with no POSIX permission bits and
a probe that failed for its own reasons all land in the same list, and sudo
helps with none of them. Both the per-plugin list and the closing summary
therefore describe only what they can. Where every entry wants privilege they
read "N check(s) require root; run with sudo for a full scan"; where none
does, "N check(s) could not be verified"; and on a mixed run, "N check(s)
could not be verified, M of them for want of root; run with sudo for a fuller
scan". The reason beside each entry is always the authority.
`--format json` carries the same information as a per-plugin `unchecked`
array alongside `findings`, so automation can distinguish "no issue" from
"not checked". Run `sudo hardener scan` for a fully privileged scan with
zero unchecked checks (assuming every backend is reachable).

**Examples:**

```bash
hardener scan                                # Scan all plugins, show everything
hardener scan --plugin kernel --plugin ssh   # Scan only kernel and SSH
hardener scan --severity high                # Only show high and critical findings
hardener scan --audit                        # Ignore config, pure security check
hardener scan --exit-code                    # Return 1 on findings or an incomplete scan
hardener scan --timings                      # Show where scan time is spent
hardener --format json scan                  # JSON output for automation
hardener --ssh user@server scan              # Scan a remote host via SSH
```

---

## apply

Apply hardening changes to the system. Requires root or passwordless sudo on the
target session (unless `--dry-run`).

Creates a checkpoint automatically before writing any changes, so all modifications can be rolled back.

```
sudo hardener apply [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-a`, `--all` | Apply all available plugins | |
| `-p`, `--plugin <NAME>` | Apply only this plugin (repeatable for multiple) | |
| `--dry-run` | Show what would change without writing anything (no root needed) | off |

Either `--all` or at least one `--plugin` is required. `--all` and `--plugin` are
mutually exclusive. As with `scan`, a plugin the config disables is named in a
`Skipping (disabled):` line rather than dropped silently, and if the config
disables **every** selected plugin the command exits with an error instead of
reporting a clean run that hardened nothing.

**Examples:**

```bash
hardener apply --dry-run --all               # Preview all changes (no root needed)
hardener apply --dry-run --plugin pam        # Preview PAM changes only
sudo hardener apply --all                    # Apply everything (creates checkpoint first)
sudo hardener apply --plugin kernel          # Apply only kernel sysctl hardening
```

**Dry-run vs real apply:**
- `--dry-run` lists each pending change, with an "N already compliant" tail per plugin for settings that already meet policy, then exits. No files are modified, no checkpoint is created, and no privilege is required. **Neither category covers a finding apply cannot act on**, and there is one: on a distribution that keeps configuration under `/usr/etc`, a permission violation in the vendor copy is reported by `scan` and is deliberately absent from the dry run, because the vendor file is never written and so no change is pending. A clean dry run for `permissions` is therefore not the same as a clean `scan`.
- Without `--dry-run`, root or passwordless sudo is required on the target session (local, or the `--ssh` host). A checkpoint is created before any writes, and each plugin's changes are applied to the live system and persisted to config files. Apply is state-aware and idempotent: already-compliant settings are skipped rather than rewritten, unless the value is correct but the line's separator is not, which is repaired in place. The per-plugin summary counts only successful, non-skipped changes ("N change(s) applied"); a plugin that needed nothing reads "no changes needed", and failures are reported as "N failed".

---

## rollback

Restore the system to a previous checkpoint snapshot. Requires root or passwordless sudo on the target session (local, or the `--ssh` host). Rollback is reversible: before restoring, it captures the current state of the affected files as a new checkpoint (named after the one being restored), and fails closed (refuses, writing nothing) if that snapshot cannot be taken.

The symlink guard probes at the same privilege the restoring write uses, and
refuses any path it cannot determine an answer for rather than treating an
unreadable path as an ordinary file. The guard judges the final path component;
a regular file beneath a symlinked parent directory is restored without the
parent being resolved.

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

A checkpoint that records a protected system path (account databases, `/etc/ssh`,
`/etc/sudoers` and similar; see `UNDELETABLE_ROLLBACK_PATHS` in the source) as
absent is never trusted to mean the file should be deleted. If that path is
present on the host, rollback refuses to remove it, reports it as skipped, and
marks the run unsuccessful, leaving the file untouched; every other file in the
checkpoint still restores normally. A path that really is still absent restores
as a silent no-op, so a host that genuinely lacks an optional file is
unaffected.

**Restored files are reloaded.** Writing the bytes back is only half of a
rollback: until the services that read them re-read them, the machine keeps
running the configuration you just undid. Once the files are restored, every
plugin that owns one of the restored paths is asked to re-read it, and each
reload is listed in the output with what it did. Six plugins have something to
reload: `sshd` is restarted, kernel parameters go through `sysctl --system`,
the firewall backend re-reads its own configuration (`firewall-cmd --reload`,
`nft -f /etc/nftables.conf` or `ufw reload`, and never a start or an enable),
audit rules go through `augenrules --load`, systemd gets a `daemon-reload`, and
the MAC policy is put back with `setenforce` or `systemctl reload apparmor`.
`pam` and `permissions` reload nothing, because their changes take effect the
moment the file is written. A plugin with nothing to reload produces no line
rather than an empty one.

**Exit codes:** `0` = every file restored and every reload succeeded; `1` = the
rollback did not fully succeed, which now covers two distinct cases the message
tells apart. Either some files were not restored, or the files were restored
and a service refused to reload, in which case that service is still running
the previous configuration and needs attention even though the disk is correct.
A reload the host genuinely cannot perform is not counted as a failure: a
kernel audit configuration locked with `-e 2` is reported as restored but not
loaded until the next reboot, and exits `0`. The same holds for nftables on a
host that never had `/etc/nftables.conf` in the first place, which is every
Fedora and RHEL host (they ship `/etc/sysconfig/nftables.conf` instead): the
checkpoint records the path absent, the restore deletes the ruleset the apply
rendered there, and the reload is then skipped rather than asking `nft` to load
a file that is no longer present. That path is deliberately left deletable.
Protecting it would leave the rolled-back ruleset on disk with
`nftables.service` already enabled by the same apply, so the posture the
operator undid would come back at the next boot.

---

## checkpoint

Manage checkpoint snapshots.

### checkpoint list

List stored checkpoints newest first, with their IDs, names, host, and
timestamps. Capped at `--limit` rows by default; a dimmed footer discloses the
total when the list is capped.

**Only the current target's checkpoints are listed.** The rows are filtered to
the host key of the executor this invocation is using, so a plain run lists the
local host and `hardener --ssh user@server checkpoint list` lists that server's.
Checkpoints belonging to other hosts are never shown, which matches the rollback
rule that refuses to restore one host's state onto another.

```
hardener checkpoint list [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-l`, `--limit <N>` | Maximum number of checkpoints to show | `20` |
| `--all` | Show every checkpoint, ignoring the limit | off |

### checkpoint create

Create a named checkpoint. Requires root or passwordless sudo on the target
session.

```
sudo hardener checkpoint create <NAME>
```

| Argument | Description |
|----------|-------------|
| `NAME` | Human-readable name for the checkpoint |

This captures a **fixed list of configuration paths**, not the whole system:
`/etc/ssh/sshd_config`, `/etc/sysctl.conf`, `/etc/sysctl.d`, `/etc/pam.d`,
`/etc/security`, `/etc/audit/auditd.conf` and `/etc/audit/rules.d`
(`collect_config_paths` in `commands/checkpoint.rs`). A plugin's own pre-apply
checkpoint captures what that plugin is about to touch, which is not the same
set, so a manual checkpoint is a companion to an apply rather than a substitute
for the one `apply` takes.

### checkpoint delete

Delete a checkpoint by its ID.

```
hardener checkpoint delete <CHECKPOINT_ID>
```

**Not host-scoped, and it refuses `--ssh`.** The id is unique across every host
in the database, so it names one row on its own. This is deliberately unlike
`list`, which is scoped: an id copied out of `hardener --ssh web-01 checkpoint
list` is deleted by a plain `hardener checkpoint delete <id>`, which is also the
only way to clear the rows of a host that no longer answers.

A successful delete names the row it removed on stdout, as `checkpoint create`
names the one it made, so `--format json` yields `{"deleted": true,
"checkpoint_id": "..."}` rather than an empty stream. An id matching no
checkpoint is an error, exit 1: nothing was removed, so there is nothing to
report as removed.

### checkpoint show

Display full details of a specific checkpoint.

```
hardener checkpoint show <CHECKPOINT_ID>
```

**Not host-scoped, and it refuses `--ssh`, on the same rule as `checkpoint
delete`.**

### checkpoint repair

Report file rows that no checkpoint owns, and remove them on request.

```
hardener checkpoint repair [--execute]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--execute` | Remove the rows instead of only reporting them | off, report only |

A checkpoint is stored across two tables: one metadata row, and one file row per
captured file tagged with that checkpoint's id. A file row whose checkpoint is
gone can never be listed, restored or deleted, because `checkpoint delete`
refuses an id that matches no metadata row and is the only other statement that
removes from that table.

**A clean answer is the expected one.** The schema declares the foreign key and
the database is opened with enforcement on, so nothing acting through this tool
can strand a row. What this repairs is a database edited by something else:
`sqlite3` defaults that enforcement off, so deleting a checkpoint row by hand
leaves its file rows behind.

Reporting is the default because the run deletes from the state database,
matching `batch`, where a destructive run is asked for explicitly. Under
`--format json` the two runs are distinguishable by `executed` rather than by a
count that happens to be zero:

```
{"executed":false,"orphaned_checkpoints":1,"orphaned_rows":2,"removed_rows":null}
{"executed":true,"orphaned_checkpoints":1,"orphaned_rows":2,"removed_rows":2}
```

**Not host-scoped, and it refuses `--ssh`**: it mends this host's own checkpoint
database, which holds the rows of every host it has ever reached.

---

## plugins

List all available security plugins with their descriptions.

```
hardener plugins
```

No flags. Displays the 8 built-in plugins with their IDs, names, versions, and descriptions.

---

## report

Generate compliance reports against security frameworks.

```
hardener report [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-s`, `--scenario <SCENARIO>` | Use case preset: `server`, `workstation`, `government`, `healthcare`, `financial`, `gdpr`, `all` | `server` |
| `--framework <FRAMEWORK>` | Specific framework: `cis`, `stig`, `nist`, `pcidss`, `hipaa`, `gdpr`, `iso27001`, `soc2`, `800-171`, `fedramp` | |
| `--profile <PROFILE>` | Compliance ID profile: `generic`, `rhel10` | auto-detect |
| `--report-format <FORMAT>` | Report format: `text` (or `txt`), `json`, `csv`, `html`, `pdf`. This is the only flag that reaches the CSV, HTML and PDF formatters, none of which the global `--format` renders | `text` |
| `-o`, `--output <FILE>` | Write to file instead of stdout | stdout |
| `-i`, `--interactive` | Launch interactive wizard to pick scenario/framework. It prompts for `--scenario`, `--framework`, `--report-format` and `--output`, so those four are ignored beside it; `--profile` is honoured | off |

`--scenario` and `--framework` are mutually exclusive. Use `--scenario` for a preset that selects relevant frameworks for your environment, or `--framework` to target a single standard. With neither flag the report falls back to the `server` scenario (CIS plus STIG) and says so on stderr.

`--report-format` selects how the report is rendered and is separate from the
global `-f`, `--format`, which governs a command's own output. A value the
formatter does not know is refused rather than silently rendered as text. Two
notes on file handling: `--output` gains the format's extension when the path
you give has none (`report.json` from `--output report --report-format json`),
and a path whose extension **contradicts** `--report-format` is refused rather
than filled with the other document. `--report-format` defaults to `text`, so
`report --output report.json` used to write a human text report into a file
named `.json` and exit 0. Only an extension naming one of the five formats this
command renders (`.txt`, `.json`, `.csv`, `.htm`, `.html`, `.pdf`) counts as a
contradiction: a path is compared against the same closed list `history export`
uses, so a name that merely contains dots, such as `report.2026.08.03`, asks for
no document and is written as given. An extension naming something this command
does not render is written as given too, and nothing converts or compresses it:
`--output archive.tar.gz` under the default `text` puts a plain text report in a
file called `.tar.gz`. The list is closed on purpose, because
`Path::extension()` cannot tell a format from a date. `pdf` always writes a file, so without
`--output` it saves
`compliance-report-<timestamp>.pdf` in the working directory instead of printing
to stdout.

`--profile` selects which benchmark's control identifiers the report renders.
It auto-detects from the scanned system's `/etc/os-release` (read through the
scan executor, so a `--ssh` target resolves from its own os-release):
RHEL-family major 10 (RHEL/Rocky/Alma 10) selects `rhel10`: DISA RHEL 10
STIG V1R1 and CIS RHEL 10 Benchmark v1.0.1 identifiers; everything else uses
the `generic` baseline (RHEL 8 STIG identifiers, distribution-independent CIS
numbering). Canonical controls without a sourced counterpart in the selected
benchmark are omitted from the profiled report rather than guessed.

**Examples:**

```bash
hardener report --scenario server            # All frameworks relevant to servers
hardener report --framework cis              # CIS Benchmark report only
hardener report --framework stig --profile rhel10   # Force RHEL 10 STIG V1R1 IDs
hardener report --interactive                # Step-by-step wizard
hardener report --scenario all --output report.json --report-format json
```

---

## batch

Scan, assess, apply, or roll back hardening across multiple hosts concurrently.
All four subcommands share the same host-selection flags and accept the global
`--format text|json` flag. **There is no `--report-format` on `batch report`**,
so a fleet compliance report is text or JSON: the CSV, HTML and PDF formatters
are reachable only per host, through `hardener report --report-format`.
`apply` and `rollback` are **dry-run by default**; pass `--execute` to mutate
the remote hosts.

`batch scan`, `batch report` and `batch apply` honour the global `-C`,
`--config` flag, and without it they load the controller's own system and user
configuration, as a local `hardener scan` does. On the failure path they split
by whether the run writes:

- `batch apply --execute` **refuses**, exit `2`, when a `--config` path was
  named and will not load. It refuses before opening the first connection, so
  no host is touched. Falling back here would harden every host in the run from
  the compiled-in defaults, which enable every plugin and carry no directives
  and no exceptions, so the fleet would be written to against a policy nobody
  selected while the run still exited `0`.
- `batch scan`, `batch report` and `batch apply` without `--execute` keep the
  fallback: a config that will not load leaves the run on the compiled-in
  defaults with a warning on stderr. These verbs only read the hosts, so the
  worst outcome is a report against the wrong baseline, and the warning says so.

`batch rollback` reads no `config.toml` at all: it restores checkpoints and has
no directive, exception or plugin list to consult, so `--config` has no effect
on it.

> **Remote hosts are evaluated against the controller's configuration, not
> their own.** Directive overrides, policy exceptions and the plugin lists all
> come from the machine running `batch`, never from a file on the target. The
> policy belongs where the operator maintains it: a target supplying its own
> config could otherwise relax the very audit being run against it. This
> matches single-host `--ssh`, which has always evaluated a remote host against
> the local config file.

Host selection (common to all four subcommands):

| Flag | Description |
|------|-------------|
| `--all` | Target every host in the inventory (`~/.config/linux-hardener/hosts.toml`) |
| `--host <NAMES>` | Comma-separated inventory host names (repeatable) |
| `--ssh <user@host[:port]>` | Ad-hoc host not in the inventory (repeatable). Without a `:port` it takes the global `--port`, which defaults to 22 |

`--all` and `--host` are mutually exclusive.

An `--ssh` target that names a host already selected is dropped, and the
inventory entry wins. Two targets are the same host when their canonical
`user@host:port` matches, so `--ssh admin@web-01` and `--ssh admin@web-01:2222`
are two targets and both are scanned, as are `--ssh root@web-01` and `--ssh
admin@web-01`. An inventory entry's name is a nickname rather than an address,
so an `--ssh` target is compared against the inventory host's connection
details and not against what it is called. Hostnames are compared as written
and never resolved: `web-01`, `web-01.local` and the address behind them are
three targets.

This applies to `--ssh` targets alone. `--all` and `--host` are taken as given,
so two inventory entries pointing at one machine, or `--host web-01,web-01`,
still produce two hosts. Under `--execute` such a selection is then refused by
the checkpoint host-key check below, which names both inventory entries.

The history key is a *different* identity: an inventory host files its history
under its nickname and an ad-hoc target under `user@host:port`. Reaching one
machine both ways in separate runs therefore records two series for it, which
de-duplication cannot help with because only one form is present in each run.

The **checkpoint** host key is a third identity, and it is coarser than either.
It is `ssh://user@host:port`, and a target that named no user is filed under a
literal `root` whether or not that is the account ssh resolves it to. Two
consequences follow, and both are limitations rather than choices:

- `hardener --ssh web-01 apply` files its checkpoint under
  `ssh://root@web-01:22`, so `hardener --ssh admin@web-01 rollback <id>` is
  refused as belonging to a different host, though it is the same machine. Roll
  back with the same form of target you applied with.
- `--ssh web-01` and `--ssh root@web-01` are two targets everywhere else and one
  checkpoint host key. A fleet run that writes therefore **refuses** such a
  selection, exit `2`, before it connects to anything: their pre-apply
  checkpoints would land under one `(host key, name)` pair, the newest would
  win, and a later rollback could restore state the other target had already
  hardened while reporting success. The refusal names both hosts, by inventory
  name and canonical target, and says what to change. `batch scan` and `batch
  report` take no checkpoints and are not affected, nor is a dry run.

> **The refusal covers one invocation, not the underlying collision.** The
> newest checkpoint per key wins across the whole database rather than within a
> run, so reaching one machine as `--ssh web-01` in one run and as
> `--ssh root@web-01` in another files both under the same key with nothing to
> refuse them, and a later rollback of either can restore the state the other
> left behind. The single-host `apply` and `rollback` verbs do not pass through
> this check at all. **Until the key itself is corrected, reach a given machine
> by one and only one form of target.** Correcting it means resolving the
> effective remote user when the connection is made, which changes the key and
> orphans every checkpoint already filed under the old one, so it is deferred
> rather than done. `checkpoint list` conflates the same pair, for the same
> reason.

### batch scan

Scan selected hosts concurrently and print one clearly-headed section per
host (name, target, status and severity breakdown) followed by a fleet
summary. Headers and statuses are lightly coloured on a terminal; colour
disappears automatically when output is piped or `NO_COLOR` is set.

```
hardener batch scan (--all | --host a,b | --ssh user@host) [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--concurrency <N>` | Maximum hosts scanned in parallel | `8` |
| `--output <FILE>` | Write report to a file instead of stdout | stdout |

Tiered exit codes: `0` = no findings; `1` = findings present; `2` = one or more host errors.
Since `1` is returned even on a successful scan whenever findings exist, a
following `&&` in a shell chain will short-circuit; use `;` instead, or
inspect the `--output` file.

**Examples:**

```bash
hardener batch scan --all                               # Scan every inventory host
hardener batch scan --host web-01,db-02                # Scan two named hosts
hardener batch scan --ssh ops@10.0.0.5 --ssh ops@10.0.0.6  # Ad-hoc hosts
hardener --format json batch scan --all --output fleet.json
```

**Example output** (all four batch verbs share this per-host section shape):

```
==== web-01  admin@web-01.local:22 =====================================
  status:    ok
  findings:  38 total (7 crit, 13 high, 16 med, 2 low)
  unchecked: 3 check(s) require root; run with sudo for a full scan

==== db-02  admin@db-02.local:22 =======================================
  status:    FAILED
  error:     connection refused

---
2 host(s): 1 scanned, 1 failed; findings: 7 crit, 13 high, 16 med, 2 low (38 total)
```

### batch report

Assess selected hosts against a compliance framework and print one section per
host (header names the host, target and resolved compliance profile; one line
per framework with score and pass/fail/manual/NA control counts) plus a fleet
rollup of failing controls per framework.

```
hardener batch report (--all | --host a,b | --ssh user@host) [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--framework <FRAMEWORK>` | Single framework: `cis`, `stig`, `nist`, `pcidss`, `hipaa`, `gdpr`, `iso27001`, `soc2`, `800-171`, `fedramp` | |
| `--scenario <SCENARIO>` | Preset: `server`, `workstation`, `government`, `healthcare`, `financial`, `gdpr`, `all` | `server` |
| `--profile <PROFILE>` | Compliance ID profile: `generic`, `rhel10` | per-host auto-detect |
| `--concurrency <N>` | Maximum hosts assessed in parallel | `8` |
| `--output <FILE>` | Write report to a file instead of stdout | stdout |

`--framework` and `--scenario` are mutually exclusive.

Profiles resolve **per host** from each host's `/etc/os-release` (read over the
existing SSH session): a RHEL-10-family host is assessed against DISA RHEL 10
STIG V1R1 / CIS RHEL 10 v1.0.1 identifiers while the rest of the fleet keeps
the generic baseline, in the same run. JSON rows carry each host's resolved
`profile`. An explicit `--profile` forces one profile fleet-wide.

Tiered exit codes: `0` = all controls passing; `1` = any failing control; `2` = any host error.

**Examples:**

```bash
hardener batch report --all --framework cis
hardener batch report --host web-01,db-02 --scenario server
hardener --format json batch report --all --output posture.json
```

### batch apply

Apply hardening to selected hosts concurrently. **Dry-run unless `--execute` is given.**
Each host undergoes a privilege probe (`root` or `sudo -n true`) before any writes;
unprivileged hosts are isolated with a `Failed` result while the rest proceed.
Host-keyed checkpoints are created automatically on execute.

```
hardener batch apply (--all | --host a,b | --ssh user@host) [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--plugin <NAMES>` | Comma-separated plugins to apply (repeatable) | all plugins |
| `--execute` | Actually apply changes (without this, dry-run only) | dry-run |
| `--concurrency <N>` | Maximum hosts applied in parallel | `8` |
| `--output <FILE>` | Write report to a file instead of stdout | stdout |

Tiered exit codes: `0` = clean; `1` = apply or validation failure; `2` = connect, privilege, or usage error.
The usage errors refused before any connection are: no hosts selected, an
unknown `--host` name, a `--config` that will not load under `--execute`, and a
selection whose hosts share one checkpoint host key, and an `--output` path whose
extension contradicts `--format`. All four are judged before anything is
contacted, so a refused run costs no fleet work. A fleet report is text or JSON
only, so a path naming CSV, HTML or PDF contradicts it whichever way `--format`
is set.

**Examples:**

```bash
hardener batch apply --all                              # Dry-run all hosts
hardener batch apply --all --execute                   # Apply to all hosts
hardener batch apply --host web-01 --plugin ssh --execute
```

### batch rollback

Roll back selected hosts to their latest per-plugin checkpoint concurrently.
**Dry-run preview unless `--execute` is given.**

```
hardener batch rollback (--all | --host a,b | --ssh user@host) [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--plugin <NAMES>` | Comma-separated plugins to roll back (repeatable) | all plugins |
| `--execute` | Actually restore (without this, dry-run preview only) | dry-run |
| `--concurrency <N>` | Maximum hosts rolled back in parallel | `8` |
| `--output <FILE>` | Write report to a file instead of stdout | stdout |

Selection is by checkpoint **name**: for each selected plugin it takes the
newest checkpoint on that host called `<plugin-id>-pre-apply`, which is the name
`apply` captures under. A host with no such checkpoint is reported as having
nothing to do rather than as a failure. Name and recency are not the same thing
as the checkpoint a particular apply took, so this restores the last apply of
each plugin on each host, not a nominated run.

Tiered exit codes: `0` = every host restored or previewed cleanly, including
hosts with nothing to roll back; `1` = at least one checkpoint failed to
restore, or restored cleanly but whose plugin failed to reload; `2` = at
least one host-level error, which covers a failed connection, a host without
root or passwordless sudo, a checkpoint store that could not be read, and a
rollback task that did not finish. `2` also covers the selection refusals, which
happen before any connection: no hosts selected, an unknown `--host` name, and a
selection whose hosts would file their checkpoints under one host key.

**Examples:**

```bash
hardener batch rollback --all                           # Preview rollback for all hosts
hardener batch rollback --all --execute                # Restore all hosts
hardener batch rollback --host db-02 --plugin kernel --execute
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
hardener daemon status [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-l`, `--limit <N>` | Number of recent scan sessions to display | `10` |

---

## systemd

Generate, install, and manage systemd unit files for scheduled scanning.

All four verbs honour the global `-f`, `--format`. Under `--format json` each
prints one envelope on stdout instead of its human text: `generate` carries the
two units as `service` and `timer` objects, or the paths it wrote as
`generated`; `install` carries `installed` and `timer_enabled`; `uninstall`
carries `removed`, which is empty when there was nothing to remove, and
`timer_disabled`, which reports what `systemctl disable --now` returned. Expect
that to be `false` on a host where the timer was never enabled, since
`systemctl` fails for a unit that does not exist; it is worth reading only
alongside a non-empty `removed`, where it means the units are gone and the timer
may still be running. And `status`
carries `user_mode`, `exit_code`, `stdout` and `stderr`. `status` reports the
exit code rather than discarding it, because an inactive timer and a unit that
does not exist both make `systemctl` return non-zero and nothing else
distinguishes them without reading prose.

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

**The global `-C`, `--config` is written into the unit, not just used to
generate it.** Given `-C`, the service runs
`hardener --config <path> daemon run-once`; without it, plain
`hardener daemon run-once`, which resolves the config at each run through the
normal search order. Two consequences, both of the embedded path rather than of
the flag:

- **The path is embedded verbatim, and it reaches the scheduled run intact.**
  It is written as a quoted `ExecStart` word with any `%` escaped, so a path
  holding a space or a percent sign is delivered to the process as you typed it
  rather than being re-split or specifier-expanded by systemd. What is *not*
  done for you is resolving it: a relative `-C` produces a relative argument,
  which systemd resolves against the service's working directory (`/` for a
  system unit) rather than yours. Give `-C` an absolute path here.
- **The unit is pinned to that file for as long as it is installed.** A named
  path that is later moved, renamed or deleted does not fall back to the search
  order: the scheduled run exits non-zero every time, because the unit runs
  `daemon run-once`, and a `--config` that will not load is fatal for that verb.
  (It is not fatal everywhere; see the [global flags](#global-flags) for the
  three `batch` verbs that keep the fallback.) Regenerate or reinstall after
  moving the file.

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

`install` embeds the global `-C` on exactly the terms described under
[systemd generate](#systemd-generate). The units themselves are not identical,
because `generate` has no `--user` flag and always prints the system unit: under
`--user` the sandbox collapses to `NoNewPrivileges=true` alone and `WantedBy`
becomes `default.target`. That difference reaches the `-C` advice in one place.
A user unit's working directory is your home directory, not `/`, so a relative
`-C` resolves somewhere else again. Absolute either way.

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

### history trends

Show a per-host security timeline (per-severity counts and direction), oldest
scan first. Useful for spotting long-term improvement or drift.

```
hardener history trends --host <KEY> [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--host <KEY>` | Host identifier: inventory name or `user@host:port` for ad-hoc | (required) |
| `-l`, `--limit <N>` | Maximum number of scans to include | `20` |

**Example:**

```bash
hardener history trends --host web-01
hardener history trends --host ops@10.0.0.5:22 --limit 10
```

### history regressions

Compare each host's two newest completed scans. Reports any host whose latest
scan is worse than the previous one. Exits `1` when any regression is found,
`0` when all hosts are stable or improving, suitable as a CI gate.

```
hardener history regressions [FLAGS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--host <KEY>` | Limit check to a single host (default: every host in history) | all hosts |

**Examples:**

```bash
hardener history regressions                            # Check all hosts (CI gate)
hardener history regressions --host web-01
hardener --format json history regressions
```

### history export

Export a scan session to JSON.

```
hardener history export <SESSION_ID> [FLAGS]
```

| Argument / Flag | Description | Default |
|-----------------|-------------|---------|
| `SESSION_ID` | UUID of the session to export | |
| `-o`, `--output <FILE>` | Output file path. JSON is the only document this command produces, so a path ending in one of the report formats this tool renders elsewhere (`.csv`, `.htm`, `.html`, `.pdf`, `.txt`) is refused rather than filled with JSON. Any other path is written as given, including one with no extension and one whose name merely contains dots, such as `backups.2026.08.03` | `session-<first 8 chars of id>.json` |

**Last Updated**: 2026-08-04
