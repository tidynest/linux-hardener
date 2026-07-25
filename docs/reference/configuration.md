# Configuration reference

**Last Updated**: 2026-07-24

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
  root-level hardening.
- Directive and exception maps **merge** across sources (later keys override
  same-named earlier keys). The `[global]` plugin lists **replace** rather than
  merge: a non-empty list in a later source wins outright.
- Size limits: a config file may be at most 1 MiB, with at most 500 directives
  (`directives` and `custom_directives` counted together) and 200 exceptions per
  plugin section.

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

Every section accepts the same four keys:

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `enabled` | bool | `true` | Accepted and validated, but **not enforced**. To stop a plugin from running, list it in `[global] disabled_plugins`. |
| `directives` | table of string to string | `{}` | Overrides the target value for a built-in check, typically to something stricter than the baseline. Applied as given for `[kernel]`, `[ssh]` and `[permissions]`, so an override can also loosen a check; only the `[pam]` thresholds are clamped tighten-only. See below. |
| `custom_directives` | table of string to string | `{}` | Accepted and validated, but **not yet enforced** by any plugin. Reserved for checking directives beyond the built-in set. |
| `exceptions` | table of exception entries | `{}` | Policy exceptions; see below. |

`directives` and `exceptions`, together with the `[global]` plugin lists, take
effect for `scan` (both default and compliance modes) and for `apply`.
`scan --audit` ignores the config entirely and always evaluates the unmodified
secure baseline.

Example, tightening SSH beyond the baseline:

```toml
[ssh]
enabled = true

[ssh.directives]
MaxAuthTries = "3"

[ssh.custom_directives]
ClientAliveInterval = "300"
ClientAliveCountMax = "2"
```

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

### A directive override is not clamped to the baseline

For `[kernel]`, `[ssh]` and `[permissions]` an override replaces the target
value as given, for both `scan` and `apply`. Nothing checks that the new
target is at least as strict as the built-in baseline, so an override can
loosen a check as easily as tighten it: `MaxAuthTries = "10"` makes a host
running 10 compliant. Validation only rules out values that are unsafe in
themselves (the list above); it does not compare an override against the
baseline.

The exception is the `[pam]` threshold directives, `deny` and `remember`,
which are clamped so an override can only tighten: a `deny` limit above the
baseline is lowered back to it, and a `remember` count below the baseline is
raised back to it. Every other PAM directive is compared exactly and takes the
override as given, like the other sections.

To record a deliberate, approved deviation, prefer an exception over a
loosening override: an exception carries a reason, an approver and an expiry,
and the report shows it instead of silently lowering the bar.

---

## Policy exceptions

An exception documents an intentional, approved deviation from the secure
baseline. `scan` still shows the finding, annotated with the exception it
matched; `hardener report` treats an annotated finding as satisfied, so it no
longer fails a compliance control. The text, HTML, PDF and JSON reports still
list that finding under its control as evidence, labelled `POLICY EXCEPTION`
instead of a severity, so a control passed by a documented deviation is never
presented as a clean pass. Audit mode
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

On the `scan` and `report` paths, for `[ssh]`, `[kernel]`, `[pam]`, and
`[permissions]`, the `value` field is compared against the value found on the
system. An exception whose `value` does not match is ignored: the finding stays
a live violation and still fails its compliance controls. This stops a config
from passing a control by documenting a deviation the host does not actually
have. `apply` does not yet make this comparison, so it still skips a setting
carrying any valid exception. Use `"not set"` to
except a directive that is absent from the file (that is the value `scan`
reports for it), and for `[permissions]` write the mode in octal with or
without the leading zero (`644` and `0644` both match mode 0644).

For `[services]`, `[mac]`, and `[audit]` the key itself names the deviating
item and there is no single system value to compare, so `value` is advisory
only; it is recorded in the audit trail but not matched.

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
