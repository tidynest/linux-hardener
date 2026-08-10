# Configuration reference

**Last Updated**: 2026-08-10

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
  error. The one exception is the batch verbs that only read a fleet
  (`batch scan`, `batch report`, and `batch apply` without `--execute`), which
  warn on stderr and fall back to the compiled-in defaults. `batch apply
  --execute` refuses like the rest, because it writes.
- When running as root (including via pkexec from the desktop app), the user
  config is **skipped** so that unprivileged per-user settings cannot influence
  root-level hardening. `ConfigLoader::load` tests the effective UID for this,
  so it holds for `sudo hardener ...` just as it does for the desktop app.
- `--config` is an addition to those sources rather than a replacement for them:
  the file named on the command line is merged on top of whatever the system and
  user files already contributed. It also reaches only the commands that pass it
  to the loader; `report --interactive` and `batch rollback` accept the flag and
  do not act on it. See [cli.md](cli.md) for the full list.
- Directive and exception maps **merge** across sources (later keys override
  same-named earlier keys). The `[global]` plugin lists **replace** rather than
  merge: a non-empty list in a later source wins outright.
- A section's `enabled` key is decided by the **last source that states it**. A
  file that mentions a section without the key, for a directive or an exception,
  says nothing about whether the plugin runs, so an earlier `[ssh] enabled =
  false` stands. Only an explicit `enabled = true` in a later source revives it.
  This matters most for `--config`, which is typically partial and, since
  `apply` began honouring it, reaches the verb that writes: naming a section to
  tighten one directive no longer switches the plugin back on. `[global]
  disabled_plugins` remains the stronger statement, because it refuses a plugin
  whatever its own section says, and it merges by replacement only when the
  later source sets a non-empty list of its own.
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
| `enabled` | bool | `true` when no source states it | Set `false` to stop this plugin from running. Disabled anywhere is final within one merged config: it can only ever turn a plugin off and never re-enable one `[global] disabled_plugins` has already refused, or one a non-empty `[global] enabled_plugins` omits. Across sources, the last source that *states* the key decides it, and a section mentioned without it decides nothing; see the merge rule under File locations and precedence. |
| `directives` | table of string to string | `{}` | Overrides the target value for a built-in check, typically to something stricter than the baseline. Directives are clamped tighten-only: completely in `[kernel]`, `[ssh]`, `[pam]` and `[permissions]`, and in `[firewall]` on all four fields, `action` on its own terms and `port`, `source` and `protocol` against the direction the rule's action gives them. See below. |
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
the files `systemd-sysctl` reads for itself, and the earlier claim here that a
distribution reaches it through an `/etc/sysctl.d/99-sysctl.conf` symlink was
measured false on 2026-08-08: of arch, Debian 13 trixie, Fedora, RHEL and
openSUSE, none ships such a symlink and only Fedora ships `/etc/sysctl.conf` at
all. Fedora's copy assigns nothing: it is a comment block that directs the
reader to `/etc/sysctl.d/`, read 2026-08-08. **No tested distribution ships a
value in that file**, so the parameter named only there is one an operator
wrote by hand. What does read it is the procps `sysctl` binary, which
names those four directories plus `/etc/sysctl.conf` and reads the file **last**,
so an operator running `sysctl --system` by hand, or this tool's own rollback
reload, lets that file override `99-hardener.conf`. Nothing applies it at boot on
a systemd host, so a value that lives only there is lost at the next reboot; the
rollback divergence report says exactly that rather than claiming no file names
the parameter. That row is never marked `divergence_expected`, even though it
fires on every rollback of a host carrying such a file: the criterion is
whether the rollback leaves the host stronger or weaker than the configuration
it just restored, not how often the row appears, and this one leaves the host
weaker once the next reboot runs `systemd-sysctl`. Marking it expected would
teach an operator to skip the one row telling them their host is about to
silently lose a hardening setting.

> **Ceiling: `scan` does not report `/etc/sysctl.conf`.** The override above is
> reported only by the rollback divergence probe. The scan asks one question,
> whether a file beats `99-hardener.conf` *at boot*, and nothing at boot applies
> the legacy file, so the scan never reads it. A loosening value there therefore
> produces no finding and costs no compliance score, even though the next
> `sysctl --system` on that host applies it over this tool's drop-in. Run
> `sysctl -n <parameter>` after any manual reload to see what is actually in
> force.

A file that sorts after this tool's, or one applied by a
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

To record a deliberate, approved deviation, an exception is the route that
works everywhere: a loosening override is refused wherever it can be recognised
as one, and simply has no effect. An exception carries a reason, an approver and
an expiry, and the report shows it instead of silently lowering the bar.

**`[firewall]` clamps all four fields, and the direction is the rule's.** The
`action` field is clamped on its own terms, because its direction holds for any
rule: `accept` admits what `drop` and `reject` refuse, so a blocking rule cannot
be overridden into an accepting one. `source`, `protocol` and `port` have no
direction of their own, so each is judged against the action the rule ends up
carrying:

- On an **accepting** rule, a value that matches **more** is refused.
  `loopback.source = "0.0.0.0/0"`, `ssh.protocol = "any"` and
  `ssh.port = "1-65535"` are all loosenings and all ignored.
- On a **blocking** rule, a value that matches **less** is refused. Narrowing the
  catch-all drop, as in `drop_default.source = "10.0.0.0/8"`, stops everything
  outside that subnet from being dropped at all.

`action` is applied first, so tightening a rule and widening its match in the
same config works: on a rule you have just turned into a `drop`, a wider port is
a stricter ruleset.

A value of the **same width** as the baseline is admitted in either direction.
That is what keeps `ssh.port = "2222"` working, and it is a stated ceiling: a
source of the same prefix length but a different address, such as `loopback`
moving from `127.0.0.1/8` to `10.0.0.0/8`, is honoured. Refusing that needs CIDR
containment across both address families, which this plugin deliberately does
not implement. Anything the clamp cannot measure at all, including a source in
the other address family and a prefix longer than its family allows, is refused
rather than guessed at.

A refused directive is ignored and logged; the rule keeps its baseline value.
An exception is still the route that records a deviation as a decision.

**A port is applied as the number it is read as, not as it is written.** A
value is parsed and re-rendered before it reaches any backend, so `022` becomes
`22` and `+22` becomes `22`. This is not cosmetic: `nft` reads a leading zero as
octal, so an unnormalised `022` installed a rule for port 18. Only `port` is
treated this way; `source` and `protocol` reach the backend exactly as written.

**A port range is written with a dash**, as in `"80-443"`. That is the one form
the configuration layer accepts, and a range spelled any other way is refused
before any plugin sees it. Backends differ on this and the difference is handled
for you: nftables and firewalld take the dash as written, and ufw, which wants a
colon and rejects the dash outright, is given `80:443`.

**An apply refuses to install a firewall that admits nothing.** The input chain
carries `policy drop`, so the rules are the whole of what the host still admits.
Excepting every rule, or every accepting one, leaves a chain that drops even
loopback, and that is refused with an explanation rather than applied. Excepting
the SSH rule is refused too, but **only over a remote session**, because that is
the connection the apply is arriving on; from a console the same ruleset is
yours to ask for. A rule that survives while no longer accepting, which
`ssh.action = "drop"` produces, counts as not admitting: presence is not
admission.

**On the nftables backend the tool owns exactly one table, `inet
linux_hardener`.** It creates that table, replaces it outright on every apply so
a repeated apply cannot stack duplicate rules, and its `nft` load touches no
other table on the host: not `inet filter`, not Docker's, libvirt's or
`iptables-nft`'s. `inet filter` is the conventional default name rather than an
owned one, and most distributions ship a packaged ruleset using it, so deleting
it would destroy whatever the administrator put there.

**A separate ceiling once ran the other way; it is now closed.** The rendered
ruleset used to be written to `/etc/nftables.conf`, replacing the whole file.
On a distribution that ships a packaged ruleset there, Arch and Debian
included, that file is where the administrator's own `inet filter` table is
defined, so the write deleted their table from disk: it survived the apply in
the running kernel and was gone at the next boot, because the file that had
defined it no longer did. That was issue #98.

The plugin no longer writes over that file, or over whichever file
`nftables.service` actually loads on a given host: the boot path is probed
from the unit's own `ExecStart` rather than assumed, because Arch and Debian
load `/etc/nftables.conf`, Fedora and RHEL load
`/etc/sysconfig/nftables.conf`, and openSUSE loads
`/etc/nftables/rules/main.nft` through an inline `include` with no `-f`
argument to read it off, which is issue #52. The rendered ruleset is written
whole to a fragment this plugin owns outright,
`/etc/linux-hardener/nftables/50-linux-hardener.nft`, and persistence is
achieved by appending one line to the boot file instead of overwriting it:
`include "/etc/linux-hardener/nftables/*.nft"`. That include is a glob rather
than a literal path, because a rollback removes the fragment, and a literal
include naming an absent file is a parse error that would leave the host
unable to load a filtered ruleset at boot at all. A host whose boot path
cannot be determined has nothing written to it anywhere: the ruleset still
loads live, so the host is filtered now, and the operator is told
persistence was not achieved rather than left believing it was. An empty
`/etc/linux-hardener/nftables/` directory can still be left behind by a
rollback, because removing a file does not remove the directory that held
it, and the same is true of the boot file's own parent directory wherever
the apply had to create one, openSUSE's `/etc/nftables/rules` on a stock
host.

The consequence worth knowing before an apply: this tool's chain hooks `input`
with `policy drop`, and a `drop` verdict in any chain ends a packet's journey,
so an accept an administrator wrote in their own table no longer keeps a port
open. A port that must stay open is expressed as a directive to this tool, which
is what the directives above are for.

---

## Policy exceptions

An exception documents an intentional, approved deviation from the secure
baseline. What `scan` does with it depends on what happened to it: no
exception configured for a check is an ordinary live violation; one configured
and matching the host annotates the finding with it; one configured but
declined, either because its `value` no longer matches the host or because it
expired, leaves the finding live and gains a line naming why (see "Where
`value` is checked", below). `hardener report` treats only the annotated,
matching case as satisfied, so it no longer fails a compliance control. The
text, HTML, PDF and JSON reports still list that finding under its control as
evidence, labelled `POLICY EXCEPTION` instead of a severity, so a control
passed by a documented deviation is never presented as a clean pass. `apply
--dry-run` lists an excepted setting separately from the pending changes, so a
preview whose only drift is excepted is never rendered as nothing to do, and
an exception cannot inflate the change count either. Audit mode
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
(if set) has not passed. `allowed = false` is the operator explicitly
declining the exception, and that stays silent by design: nothing is
reported, because withholding an exception on purpose needs no comment. An
exception that expired, or whose `value` no longer matches the host, is
different: it is **declined** rather than merely ignored, the finding it
would have covered stays a live violation, and `scan` prints a line against
that finding naming which of the two happened. Age does not remove an
exception quietly; it turns the exception into evidence that something
drifted.

### Finding the key

An exception is keyed per check, and `scan` prints the key each finding takes
beneath the finding itself:

```
  * [HIGH] Bluetooth service is enabled
    Bluetooth increases the attack surface on a server
    accept as a documented deviation: [services.exceptions."bluetooth"]
```

The key is always quoted. `net.ipv4.ip_forward` and `/etc/ssh/sshd_config` are
not bare TOML keys, and a document built from an unquoted one parses as nested
tables rather than failing, so nothing would report the mistake. Quoting a key
that does not need it is still valid TOML.

**A finding's `finding_id` is not its exception key.** The id is derived from
the key, and every plugin's derivation loses information: `bluetooth` becomes
`service_bluetooth`, `net.ipv4.ip_forward` becomes `kernel_net_ipv4_ip_forward`,
`PermitRootLogin` becomes `ssh-permitrootlogin`, and `selinux-enforcing` becomes
`selinux-not-enforcing`, which shares no derivation at all. An id cannot be
turned back into a key, so use the line `scan` prints rather than the id from a
JSON report.

No line is printed for a finding that already rests on an exception, nor for
the few findings an exception cannot be about. A PAM directive whose module is
absent from the stack is reported as unenforced, but its value is already
correct and simply reaches nothing, so there is no deviating value for an
exception to document.

### Writing an exception without hand-editing the file

`hardener exception add <plugin-id> <key> --reason <text>` writes the same
`[<section>.exceptions.<key>]` table shown above, so this file need not be
edited by hand at all. `value` is not typed on the command line: the verb runs
its own scan of `<plugin-id>` and pins whatever value the finding matching
`<key>` reports right now, which is the host's actual current value rather than
one the operator might mistype or copy stale. `--approved-by`, `--ticket` and
`--expires` fill the matching optional fields; `approved_date` is not settable
this way; the file only gains that field if it was hand-written or edited
later. `hardener exception remove <plugin-id> <key>` deletes the table again,
and the parent tables above it too if that leaves them empty. Full flag
reference: [CLI: exception](cli.md#exception).

### Where `value` is checked

On every path, `scan`, `report`, `apply` and `apply --dry-run`, for `[ssh]`,
`[kernel]`, `[pam]`, and `[permissions]`, the `value` field is compared
against the value found on the system. An exception whose `value` does not
match is declined: the finding stays a live violation, still fails its
compliance controls, and `apply` hardens the setting instead of skipping it.
This stops a config from passing a control, or a setting from being left
unhardened, by documenting a deviation the host does not actually have.
`scan` reports the decline rather than staying quiet about it: the finding
keeps its real severity and gains a line naming the documented value against
the one actually observed, so a stale exception reads as a stale exception
rather than as one that simply never existed.

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
only; it is recorded in the audit trail but never matched. With no value to
mismatch, these four can only be declined for one reason, expiry, but an
expired exception here is reported exactly as a value mismatch is
elsewhere: the finding stays live and `scan` gains the same declined line,
naming the date the exception lapsed.

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
`privileged`, `delete`, `modules`), a baseline rule id for `[firewall]`
(`loopback`, `established`, `ssh`, `drop_default`), and `selinux-enforcing` /
`apparmor-enforce` for `[mac]`.

Some findings are about a subsystem rather than about a setting inside it, and
those take a key naming the subsystem state. A rule that was never applied is a
different statement from a firewall that was never enabled, so no rule id can
excuse the second:

| Key | Accepts a host where |
|---|---|
| `firewall-enabled` | no firewall is enforcing at all |
| `firewall-at-boot` | the firewall enforces now and is gone after a reboot |
| `mac-present` | neither SELinux nor AppArmor is installed |
| `auditd-present` | auditd is not installed |
| `auditd-at-boot` | auditd is installed and not started at boot |
| `auditd-running` | auditd is installed and currently stopped |

Each state takes its own key on purpose. Accepting a host with no firewall is a
different decision from accepting one whose firewall does not survive a
restart, and declaring one does not declare the other. The keys deliberately do
not carry the detected backend: an exception written on a host running ufw goes
on being honoured when the same policy reaches a host running firewalld.

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

One rule from the top of this page does not reach it: the user config is **not**
skipped under root here, so
a root daemon reads `~/.config/linux-hardener/config.toml` when that path exists
and resolves.

`--config` **is** consulted, and it joins the front of that search rather than
replacing it: the named file is looked at first, and the first file that
actually configures the scheduler wins whole. A named file with no
`[scheduler]` section is not that file configuring it, so your system or user
config still decides, which is what keeps a timer installed against a
policy-only file running on your real scheduler settings rather than the
compiled-in ones.

A **partial** `[scheduler]` table is allowed: every key in the table below, and
in the `storage` and `notifications` tables under it, has a default, so a
section naming only `enabled` is a valid section and the rest takes the defaults
listed here. The one exception is a webhook endpoint, where `name` and `url`
remain required, because neither has an answer worth guessing; `format` does
default.

A typo is the cost of this. Nothing rejects an unknown key, here or anywhere
else in the file, so `scheduel = "0 0 5 * * *"` is not an error and not a
setting: the daemon runs on the 02:00 default and no command says otherwise.
Check `hardener daemon status`, which prints the schedule it actually resolved.

What a partial table does **not** do is merge across files. The first file
carrying a `[scheduler]` section still wins whole, so a partial section in your
user config hides a complete one in the system config, and the keys it omits
come from these defaults rather than from the file it hid. Keep the scheduler
settings in the system config on any host where that distinction matters, and
keep them in one file.

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
with `name` and `url`, both **required**, plus `format` (`generic`, `slack`, or
`discord`; default `generic`) and optional `headers` (values support
`${ENV_VAR}` expansion).

The desktop offers a single webhook and writes it as one endpoint named
`desktop`. Saving from the desktop merges its form over the `[scheduler]`
section already in the file rather than replacing it, so every key the form does
not model, `[scheduler.storage]`, `notify_mode` and the SMTP settings included,
survives untouched. What the form does model it owns outright, and that includes
the endpoint list: it holds one webhook, so saving replaces the whole list with
that one, and clearing the URL removes it.

Ownership of the list reaches inside it. An endpoint the desktop writes carries
`name`, `url` and `format` and nothing else, so a hand-written `headers` table,
or a `name` you chose, is replaced on the first save from the GUI, even a save
that changed nothing about the webhook. That applies to a single hand-written
endpoint as much as to several. Configure webhooks by file on any host where a
webhook needs an authentication header.

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
