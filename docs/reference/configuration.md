# Configuration reference

**Last Updated**: 2026-08-01

Complete reference for the hardener's configuration files. Configuration
controls which plugins run, tightens directive targets beyond the built-in
baseline, and records policy exceptions with an audit trail. Configuration
annotates findings; it never hides them silently.

This document supersedes the archived design draft
`docs/plans/archive/CONFIG_DESIGN.md`, which described the config system
before it shipped.

There are three separate files:

| File | Purpose |
|------|---------|
| `config.toml` | Plugin behaviour, policy exceptions, and the `[scheduler]` section |
| `~/.config/linux-hardener/hosts.toml` | Saved remote-host inventory for `batch` and the desktop Hosts page |
| `packaging/assets/config.toml.example` (in the repository) | Annotated example installed by packages to `/etc/linux-hardener/config.toml` |

---

## File locations and precedence

`config.toml` is loaded from multiple sources. Later sources override earlier
ones:

1. Built-in defaults (all plugins enabled, no directives, no exceptions)
2. System config: `/etc/linux-hardener/config.toml`
3. User config: `~/.config/linux-hardener/config.toml`
4. CLI override: `hardener --config /path/to/config.toml`
5. Environment variables: `HARDENER_ENABLED_PLUGINS`, `HARDENER_DISABLED_PLUGINS`

Rules worth knowing:

- A missing system or user config is fine; a missing `--config` file is an
  error.
- When running as root (including via pkexec from the desktop app), the user
  config is **skipped** so that unprivileged per-user settings cannot influence
  root-level hardening. `ConfigLoader::load` tests the effective UID for this,
  so it holds for `sudo hardener ...` just as it does for the desktop app.
- `--config` is an addition to those sources rather than a replacement for them:
  the file named on the command line is merged on top of whatever the system and
  user files already contributed. It also reaches only the commands that pass it
  to the loader; `apply`, `report --interactive` and `batch rollback` accept the
  flag and do not act on it. See [cli.md](cli.md) for the full list.
- Directive and exception maps **merge** across sources (later keys override
  same-named earlier keys). The `[global]` plugin lists **replace** rather than
  merge: a non-empty list in a later source wins outright.
- A section's `enabled` key is taken from the **later source outright**, and
  `true` is its default value, so a later file that omits a section supplies
  `enabled = true` for it. A user config therefore restores a plugin the system
  config turned off through `[ssh] enabled = false`. To disable a plugin so that
  no later source can revive it, name it in `[global] disabled_plugins`, which
  merges by replacement only when the later source sets a non-empty list of its
  own.
- Size limits: a config file may be at most 1 MiB, with at most 500 `directives`
  and 200 exceptions per plugin section.

---

## [global]

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `enabled_plugins` | array of plugin IDs | `[]` | If non-empty, only the listed plugins run. Empty means all plugins are enabled. |
| `disabled_plugins` | array of plugin IDs | `[]` | Listed plugins never run. Takes precedence over `enabled_plugins`. |

Valid plugin IDs (full form):

```
audit-hardening      firewall-hardening   kernel-hardening   mac-hardening
pam-hardening        permissions-hardening service-minimisation ssh-hardening
```

```toml
[global]
disabled_plugins = ["mac-hardening"]
```

`hardener scan` names the plugins these lists kept it from running, and fails
with an explanation rather than reporting an empty, clean-looking scan when
the config disables every plugin selected (for example `scan --plugin ssh`
with `ssh-hardening` disabled).

---

## Plugin sections

Each plugin has its own TOML section. The section name is the short form; it
maps to the full plugin ID as follows:

| Section | Plugin ID |
|---------|-----------|
| `[ssh]` | `ssh-hardening` |
| `[kernel]` | `kernel-hardening` |
| `[firewall]` | `firewall-hardening` |
| `[pam]` | `pam-hardening` |
| `[audit]` | `audit-hardening` |
| `[mac]` | `mac-hardening` |
| `[permissions]` | `permissions-hardening` |
| `[services]` | `service-minimisation` |

Every section accepts the same three keys:

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `enabled` | bool | `true` | Set `false` to stop this plugin from running. Disabled anywhere is final within one merged config: `enabled = true` is the key's default value, so it can only ever turn a plugin off and never re-enable one `[global] disabled_plugins` has already refused, or one a non-empty `[global] enabled_plugins` omits. Across sources the key behaves differently; see the merge rule under File locations and precedence. |
| `directives` | table of string to string | `{}` | Overrides the target value for a built-in check, typically to something stricter than the baseline. Every directive is clamped tighten-only, in all four plugins that accept one. See below. |
| `exceptions` | table of exception entries | `{}` | Policy exceptions; see below. |

> **Removed: `custom_directives`.** Earlier releases accepted and validated a
> `custom_directives` table that no plugin ever read, so anything set there had
> no effect. It has been removed rather than implemented. A file that still
> names it loads unchanged, because the key is simply ignored, but the table
> can be deleted. If it holds a directive the plugin does support, move that
> entry into `directives`, where it will take effect.

`directives` and `exceptions`, together with `enabled` and the `[global]`
plugin lists, take effect for `scan`, `apply`, `report`, the scheduler daemon,
and all four `batch` subcommands, which evaluate remote hosts against the
controller's config. `scan --audit` ignores the config entirely and always
evaluates the unmodified secure baseline.

A plugin the config disables assesses nothing, so a compliance report lists
every control it covers as **Manual Review** rather than as passing. Disabling
a plugin therefore lowers a compliance score, which is the honest outcome: the
tool cannot vouch for a control it never evaluated.

Example, tightening SSH beyond the baseline:

```toml
[ssh]
enabled = true

[ssh.directives]
MaxAuthTries = "3"
ClientAliveInterval = "300"
ClientAliveCountMax = "2"
```

### Where `[ssh]`, `[kernel]` and `[pam]` write on layered distributions

Some distributions do not keep a setting in one file at one path, and `apply`
writes differently on each. Nothing in the config selects this; it follows from
what the host ships.

**Precedence runs in a different direction per format, so the numbers do too.**
This is the single most common way to misread the files this tool writes: a
`00-` fragment and a `99-` fragment are not an inconsistency, they are the same
intent expressed in two formats whose merge rules are opposites.

| Format | Which value wins | The file this tool writes |
|---|---|---|
| `sshd_config.d` | the **first** value obtained | `/etc/ssh/sshd_config.d/00-hardener.conf` |
| `sysctl.d` | the **last** file in lexical order | `/etc/sysctl.d/99-hardener.conf` |

**sshd fragments.** Fedora and RHEL ship `/etc/ssh/sshd_config.d/50-redhat.conf`
and openSUSE ships `40-suse-crypto-policies.conf`; sshd takes the **first** value
it obtains, so a fragment beats the main file. SSH hardening is therefore written
to `/etc/ssh/sshd_config.d/00-hardener.conf`, which sorts before what
distributions ship. The file carries a header marking it as managed, an empty
directive set removes it rather than leaving an empty file behind, and the
precedence is verified after writing by re-resolving the configuration rather
than assumed from the name.

**sysctl drop-ins.** `systemd-sysctl` merges `/etc/sysctl.d`, `/run/sysctl.d`,
`/usr/local/lib/sysctl.d` and `/usr/lib/sysctl.d`, sorts every file by name and
lets the lexicographically **last** name win, so kernel hardening is written to
`/etc/sysctl.d/99-hardener.conf` and is numbered the opposite way to the sshd
fragment for the same reason. A drop-in sorting before it therefore loses and is
not reported: Debian 13 ships `/usr/lib/sysctl.d/50-default.conf` with a looser
`rp_filter`, and this tool still wins at boot. `/etc/sysctl.conf` is not among
the files `systemd-sysctl` reads for itself; a distribution that still applies it
reaches it through an `/etc/sysctl.d/99-sysctl.conf` symlink, which is a file in
one of those directories and sorts after `99-hardener.conf`, so it does outrank
it. A file that sorts after this tool's, or one applied by a
unit ordered after `systemd-sysctl.service` (ufw is the only such case this tool
knows of, and it is named rather than inferred), is reported as a finding. That
reporting is read-only: this tool does not edit another package's configuration
file.

**Vendor configuration under `/usr/etc`.** openSUSE Leap 15.6+, Tumbleweed and
MicroOS reserve `/etc` for administrator overrides, and that override is
whole-file rather than per directive: once `/etc/login.defs` exists, every key
it omits stops applying. `scan` reads whichever copy is in force, and `apply`
copies the vendor file into `/etc` first and edits the managed directives into
that copy, so nothing the distribution set is lost. The vendor file itself is
never written.

An `/etc` file that already exists is the host's own, so `apply` edits the
directives it manages and does not import keys that file omits. Where those
omitted keys matter, `scan` reports them in a Medium finding naming each one.
Restoring them is a manual step by design: this tool cannot tell a key an
operator dropped on purpose from one an older release dropped for them.

`apply --dry-run` reports the same drift as a Medium validation issue, so the
preview an operator reads before applying does not describe a drifted host and
a clean one identically. It is an issue rather than an estimated change because
`apply` will not import the missing keys; Medium is advisory, so the dry run
still exits zero.

The masking is a property of the layering rather than of any one file, so every
layered file this plugin reads is checked and each has its own finding:

| File | Finding | What reverts to a built-in default |
|---|---|---|
| `/etc/login.defs` | `pam-login-defs-masked-keys` | shadow, including `ENCRYPT_METHOD` and `HOME_MODE` |
| `/etc/security/pwquality.conf` | `pam-pwquality-conf-masked-keys` | libpwquality, and with it `pwscore` and `pwmake` |
| `/etc/security/faillock.conf` | `pam-faillock-conf-masked-keys` | `pam_faillock` lockout behaviour |
| `/etc/security/pwhistory.conf` | `pam-pwhistory-conf-masked-keys` | `pam_pwhistory` reuse prevention |

### Directive value validation

All directive values are validated at load time, before any plugin sees them.
A config that fails validation is rejected with every invalid entry listed:

- No value may contain shell metacharacters (`;`, backtick, `$`, `(`, `)`,
  `{`, `}`, `|`, `&`), newlines, or NUL bytes.
- Kernel, SSH, firewall, and PAM values must match the expected format for
  their family (for example sysctl values must be integers, optionally
  space-separated).
- Permission modes may not set SUID/SGID/sticky bits, may not be
  world-writable, and may not be zero.

### Where a directive override is clamped to the baseline

Every `[pam]`, `[ssh]` and `[kernel]` directive is clamped so an override can
only tighten, in `scan`, `apply` and `apply --dry-run` alike. A `deny` limit
above the baseline is lowered back to it, a `remember` count below it is raised
back to it, a `minlen` below 14 is raised back to 14, a `PASS_MAX_DAYS` above 90
is lowered back to 90, `MaxAuthTries = "10"` yields 3, `X11Forwarding = "yes"`
yields `no`, and `kernel.kptr_restrict = "0"` yields 2.

`[permissions]` states the same rule differently, because a permission mode is
a bitmask rather than a value on a scale. `0640` and `0604` are neither
stricter nor looser than one another, they are different, so there is no
arithmetic comparison to make. An override is accepted when it sets no bit the
baseline does not already set, and refused otherwise: `/boot = "500"` is
honoured against a baseline of `0700`, and `/boot = "755"` is not, leaving the
baseline in force. A refused override is not reported; it simply has no effect.

The same test governs the two max-mask paths (`/etc/shadow` and
`/etc/gshadow`), where the configured value is the mask of permitted bits
rather than a mode. An override may narrow that mask and may not widen it,
which matters more than it looks: a widened mask would not chmod anything
wrong, it would make a world-readable `/etc/shadow` count as compliant and the
scan would then say nothing about it at all.

Validation additionally rules out values that are unsafe in themselves (the
list above), before any plugin sees them.

The clamp used to apply to `deny` and `remember` alone. Every other directive
in all three plugins was compared for equality, which has no direction, so any
value other than the baseline counted as a violation, stricter ones included. A
host expiring passwords every 30 days was reported as violating and then
written to 90, a host allowing two SSH authentication attempts was written up
to three, and a host forbidding `ptrace` outright was written back down to
admin-only: a hardening run leaving the host less secure than it found it, and
reporting success. Every directive in all three now carries a direction, and
apply writes the stricter of the target and what the host already holds rather
than skipping, so a file that also needs a duplicate or a stale separator
repaired still converges.

Two settings do not count downwards all the way. `maxrepeat = 0` switches the
consecutive-character check off rather than tightening it, and
`ClientAliveInterval 0` stops sshd probing an idle client at all, so for both
of them zero is the loosest value the setting has and is never treated as
compliant. `MaxAuthTries 0` and `ClientAliveCountMax 0`, by contrast, are the
strict end of their settings and are honoured as such.

Some settings are ordered rather than counted, because neither the number nor
the alphabet carries their strictness:

- `PermitRootLogin`: `no` is stricter than `forced-commands-only`, which is
  stricter than `prohibit-password`, which is stricter than `yes`.
  `without-password` is sshd's legacy spelling of `prohibit-password` and ranks
  with it, so a host using it is not rewritten for the sake of the name. Values
  are matched case-insensitively throughout, because sshd itself compares them
  that way.
- `net.ipv4.conf.*.rp_filter`: `1` is strict mode, `2` is loose mode and `0` is
  off, so the strongest value is the middle number. Treated as "larger is
  stricter" a host in loose mode would score compliant against a target of
  strict mode.
- `fs.suid_dumpable`: `0` refuses the dump, `2` writes one only root can read
  and `1` writes one from every setuid process, so the strongest value is the
  smallest and the weakest is in the middle.

Two kernel parameters have a value stronger than the baseline, and a host
already there keeps it: `kernel.yama.ptrace_scope = 3` forbids `ptrace`
entirely where the baseline restricts it to administrators, and
`net.ipv4.tcp_syncookies = 2` sends SYN cookies unconditionally rather than
under pressure.

To record a deliberate, approved deviation, an exception is the only route
that works: a loosening override is refused in every plugin and simply has no
effect. An exception carries a reason, an approver and an expiry, and the
report shows it instead of silently lowering the bar.

---

## Policy exceptions

An exception documents an intentional, approved deviation from the secure
baseline. `scan` still shows the finding, annotated with the exception it
matched; `hardener report` treats an annotated finding as satisfied, so it no
longer fails a compliance control. The text, HTML, PDF and JSON reports still
list that finding under its control as evidence, labelled `POLICY EXCEPTION`
instead of a severity, so a control passed by a documented deviation is never
presented as a clean pass. `apply --dry-run` lists an excepted setting
separately from the pending changes, so a preview whose only drift is excepted
is never rendered as nothing to do, and an exception cannot inflate the change
count either. Audit mode
(`scan --audit`) ignores the config, exceptions included.

```toml
[ssh.exceptions.PasswordAuthentication]
value = "yes"
allowed = true
reason = "Legacy application requires password auth on jump host"
approved_by = "Security Team"
approved_date = "2026-01-15"
ticket = "SEC-1234"
expires = "2026-07-15"
```

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `value` | string | yes | The deviating value being allowed. Must match the current system value. |
| `allowed` | bool | yes | Explicit acknowledgement; the exception is invalid unless `true`. |
| `reason` | string | yes | Human-readable justification. |
| `approved_by` | string | no | Who approved the exception. |
| `approved_date` | string | no | Approval date, ISO 8601 (`YYYY-MM-DD`). |
| `ticket` | string | no | Reference to the approval ticket or issue. |
| `expires` | string | no | Expiry date, ISO 8601 (`YYYY-MM-DD`). After this date the exception stops applying and the finding counts as a violation again. |

An exception is **valid** only while `allowed = true` and the `expires` date
(if set) has not passed. Expired exceptions are ignored, which means
exceptions age out rather than being forgotten forever.

### Where `value` is checked

On every path, `scan`, `report`, `apply` and `apply --dry-run`, for `[ssh]`,
`[kernel]`, `[pam]`, and `[permissions]`, the `value` field is compared
against the value found on the system. An exception whose `value` does not
match is ignored: the finding stays a live violation, still fails its
compliance controls, and `apply` hardens the setting instead of skipping it.
This stops a config from passing a control, or a setting from being left
unhardened, by documenting a deviation the host does not actually have.

The check is fail-closed by design: nothing is exempted merely because its
current value could not be established, except for one narrow carve-out
for `[pam]`, covered in full below. For `[ssh]` and `[kernel]`, an
unreadable value can never match an exception, so the setting is hardened
rather than silently skipped. `[pam]` behaves the same way for every value
except `"not set"`: an unreadable directive can still match that one,
because it renders identically to a genuinely absent one. For the `[pam]`
threshold directives, `deny` and `remember`, hardening can itself fail
rather than apply quietly: if an inline `pam.d` override is present,
`apply` refuses to auto-edit the authentication stack and reports the run
as failed instead of silently editing `faillock.conf` or `pwhistory.conf`
underneath it. Use `"not set"` to except a directive that is absent from
the file (that is the value `scan` reports for it) for `[ssh]` or `[pam]`.

`[permissions]` tells a missing path apart from one that exists but could
not be stat'd. A path missing from `/etc` is left alone by `apply`: no chmod
is attempted and nothing is recorded, the same treatment as an
already-compliant path. `scan` looks one layer further before concluding
there is nothing there. On a distribution that keeps its configuration under
`/usr/etc` and reserves `/etc` for administrator overrides, the vendor copy
is the file in force, so where `/etc` holds nothing and the vendor copy
violates the directive, `scan` reports a finding naming that path and its
mode. openSUSE is the measured case: no `/etc/sudoers`, a
`/usr/etc/sudoers` at 0444 against a required 0440. **The vendor file is
never written**, so the remediation offered is a copy into `/etc` at the
required mode rather than a chmod of the package-owned original, and `apply`
still changes nothing there. A path absent from both layers remains nothing
to report, and a vendor path whose existence or mode cannot be read is
reported as unchecked rather than as absence. That finding is keyed on the
`/etc` path, so an exception written for that path still annotates it, matched
against the mode of the vendor copy because that is the mode in force. Since
`apply` changes nothing there, `apply --dry-run` reports nothing there either:
it previews what `apply` would do, so a vendor violation reaches you through
`scan` and the compliance report rather than through the preview. A path
that exists but whose mode could not be verified is hardened anyway for the
seven critical paths with a single exact target mode (`/root`, `/boot`,
`/etc/ssh`, `/etc/sudoers`, `/etc/sudoers.d`, `/etc/passwd`, `/etc/group`):
`apply` chmods it to that baseline, or to an accepted `directives` override
for the path where one is set, regardless of the unknown starting mode -
the one exception being a filesystem positively confirmed unable to hold
POSIX permissions, where a skip is recorded instead of a chmod. Either way
the recorded change says so. The remaining two, `/etc/shadow` and
`/etc/gshadow`, only ever strip bits outside an allowed mask, a target that
cannot be computed without a verified mode, so `apply` skips them instead,
now recording the skip explicitly and logging a warning rather than doing
nothing silently. An exception can never match against an unverified mode,
for any of the nine paths. For `[permissions]`, write the mode in octal
with or without the leading zero (`644` and `0644` both match mode 0644);
`value = "not set"` can never match here, since the mode is always parsed
as octal.

For `[pam]`, an unreadable directive renders the same way as an absent one:
both display as `"not set"`. An exception written as `value = "not set"` is
therefore honoured whenever the directive could not be read, not only when
it is genuinely absent from the file, a narrow gap in the fail-closed rule
above. `[ssh]` does not share this gap: a read failure of `sshd_config`
never renders a directive as unset. `apply` reads the whole file in a
single pass and, if that read fails, the operation fails outright.
`apply --dry-run` does not fail outright on the same read failure: it
returns successfully with a Critical validation issue and zero estimated
changes, which the default text output currently renders as "0 change(s)
to apply" rather than surfacing the read failure (the issue is visible
only with `--format json`). Within a file that was read successfully,
`"not set"` means the directive is genuinely absent. Do not write
`value = "not set"` to mean "I do not know what this is": treat it as a
matchable value like any other, for both sections.

Outside exception matching, an unreadable file stops `[pam]`'s `apply`
before anything is written, as it does for `[ssh]`. They stop at different
points: `[ssh]` reads `sshd_config` itself and fails on that read, while
`[pam]` fails one step earlier, at the pre-apply checkpoint, which refuses
to record a file it was asked to protect but could not capture. Either way
the command reports an error for that plugin and rewrites nothing, so
`pwquality.conf`, `login.defs`, `faillock.conf` and `pwhistory.conf` are
all left alone, not only the one that could not be read.

A configuration file is only worth as much as the module that reads it.
`pwquality.conf`, `faillock.conf` and `pwhistory.conf` are each consumed by
exactly one PAM module (`pam_pwquality.so`, `pam_faillock.so`,
`pam_pwhistory.so`), and a host whose PAM stack never loads that module
enforces nothing the file says. `scan` reads the stack
(`/etc/pam.d/system-auth`, `password-auth` and the `common-*` file the
distribution uses) and reports every directive in an unread file as not
enforced rather than as compliant, so its compliance controls fail instead of
passing on evidence nothing consults. A stack this tool could not read, or a
distribution whose stack it does not recognise, is reported unchecked instead:
absence is only concluded from a file that was actually read.

`apply` still writes such a file, because the value is right the moment the
module is added, but it records the missing module as a failed change and the
run does not report success. `apply --dry-run` says the same thing as a High
issue, so the preview and the apply agree. Adding a module to `/etc/pam.d` is
not something this tool does: that step is yours. `/etc/login.defs` is
unaffected, because shadow-utils reads it directly with no module loaded.

The plugin also refuses per file, on its own, without relying on that
checkpoint: it declines to rewrite whichever file it could not read,
reports that one file as a failed change, and hardens the rest. No
`hardener` command reaches that fallback, because every command that
applies takes a checkpoint first and so stops at the capture above. It is
what protects an embedding of the plugin crate that runs `apply` with no
checkpoint manager configured.

For `[services]`, `[mac]`, `[audit]`, and `[firewall]` this comparison does
not apply on any path, including `apply`: the key itself names the deviating
item and there is no single system value to compare, so `value` is advisory
only; it is recorded in the audit trail but never matched.

Because it is never matched, `apply --dry-run` does not print it either. The
preview line for one of those four reads `left at 'unchanged'`, which claims
only that the run left the setting alone. Printing the advisory field there
would present text the operator wrote as a reading taken from the host, and it
would be wrong exactly when the declaration has gone stale. `[firewall]` says
`not applied` instead, because a rule that was never added is a different
statement from a state left as it was found.

The exception key is check-specific: an sshd directive name for `[ssh]`, a
sysctl name for `[kernel]`, a PAM directive name for `[pam]` (for example
`minlen`), an absolute path for `[permissions]` (for example `/etc/shadow`), a
service name for `[services]` (for example `cups`), an audit rule category for
`[audit]` (`time-change`, `identity`, `network-change`, `perm-mod`,
`privileged`, `delete`, `modules`), and `selinux-enforcing` /
`apparmor-enforce` for `[mac]`.

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `HARDENER_ENABLED_PLUGINS` | Comma-separated plugin IDs; overrides `[global] enabled_plugins`. Unknown IDs are rejected. |
| `HARDENER_DISABLED_PLUGINS` | Comma-separated plugin IDs; overrides `[global] disabled_plugins`. Unknown IDs are rejected. |
| `HARDENER_SMTP_PASSWORD` | SMTP password for scheduler email notifications (never stored in the config file). |
| `HARDENER_DECORATIONS` | Desktop window frame override. `0` hides the title bar and its min/max/close controls; any other value shows them. When unset, the frame is hidden automatically on tiling Wayland compositors (Hyprland, Sway, river, niri, Wayfire, labwc) and kept on floating desktops such as GNOME and KDE. |

```bash
HARDENER_DISABLED_PLUGINS=mac-hardening,firewall-hardening hardener scan
```

---

## [scheduler]

The `[scheduler]` section configures the scheduled scanning daemon
(`hardener daemon`) and the scan-history database used by `hardener history`
and `hardener batch`. It lives in the same `config.toml`, but is read
directly from the first file found (user config first, then system config)
rather than merged across sources.

Two rules from the top of this page do not reach it. `--config` is not consulted
(`load_scheduler_config` in the CLI's `commands/daemon.rs` searches the two
default paths itself), and the user config is **not** skipped under root here, so
a root daemon reads `~/.config/linux-hardener/config.toml` when that path exists
and resolves. Keep the scheduler settings in the system config on any host where
that distinction matters.

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `enabled` | bool | `false` | Must be `true` for `daemon start` to run. |
| `schedule` | string | `"0 0 2 * * *"` | Six-field cron expression (sec min hour dom mon dow). The default scans daily at 02:00. |
| `plugins` | array of strings | `[]` | Plugins to scan on schedule; empty means all. |
| `min_severity` | string | `"medium"` | Minimum severity recorded in scheduled scan results. |

### [scheduler.storage]

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `database_path` | path | `scheduler.db` under the data directory | SQLite database holding scan history (sessions, per-host results). |
| `json_output_dir` | path | `scans/` under the data directory | Directory for JSON scan exports. |
| `retention_count` | integer | `90` | Maximum scan sessions retained (0 = unlimited). |
| `retention_days` | integer | `0` | Retention period in days (0 = use `retention_count` instead). |

The data directory is `/var/lib/linux-hardener/` when running as root and
`~/.local/share/linux-hardener/` otherwise. Note this scan-history database is
separate from the checkpoint database (`checkpoints.db`).

### [scheduler.notifications]

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `notify_min_severity` | string | `""` | Minimum severity that triggers a notification. |
| `notify_mode` | string | `"findings"` | `findings` alerts when a scan has findings at or above the threshold; `regression` alerts only when a host got worse than its previous scan; `both` does both. |

Email (`[scheduler.notifications.email]`): `enabled` (default `false`),
`smtp_host`, `smtp_port` (default `587`), `smtp_tls` (default `true`),
`smtp_username`, `recipients` (array), `from_address`. The password comes from
`HARDENER_SMTP_PASSWORD`.

Webhooks (`[scheduler.notifications.webhooks]`): `enabled` (default `false`)
plus one `[[scheduler.notifications.webhooks.endpoints]]` block per endpoint
with `name`, `url`, `format` (`generic`, `slack`, or `discord`) and optional
`headers` (values support `${ENV_VAR}` expansion).

```toml
[scheduler]
enabled = true
schedule = "0 30 3 * * *"
min_severity = "high"

[scheduler.storage]
database_path = "/var/lib/linux-hardener/scheduler.db"
retention_days = 30

[scheduler.notifications]
notify_min_severity = "high"
notify_mode = "both"

[[scheduler.notifications.webhooks.endpoints]]
name = "ops-channel"
url = "https://hooks.slack.com/services/T000/B000/XXXX"
format = "slack"
```

---

## Host inventory: hosts.toml

The saved remote-host inventory lives at
`~/.config/linux-hardener/hosts.toml`. The CLI (`hardener batch`) and the
desktop app's Hosts page (under the Fleet group in the sidebar) read and write
the same file. A missing file is an empty inventory.

Each host is one `[[hosts]]` entry:

```toml
[[hosts]]
name = "web-01"
hostname = "web-01.example.com"
user = "admin"
port = 22
key_file = "/home/me/.ssh/id_ed25519"
host_key_checking = true
```

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `name` | string | required | Display name, used with `batch --host <name>` and as the history key. |
| `hostname` | string | required | Hostname or IP address. |
| `user` | string | current user | SSH username. |
| `port` | integer | `22` | SSH port. |
| `key_file` | string | SSH agent | Path to an SSH private key. |
| `host_key_checking` | bool | `true` | Verify the remote host key. Only disable for lab hosts. |

SSH authentication is key or agent based only; there is no password path.
