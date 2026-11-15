# Configuration reference

**Last Updated**: 2026-11-18

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
- A system or user config the process cannot **reach** is skipped like a missing
  one, but it says so. `Path::exists()` answers `false` both for a file nobody
  installed and for a file under a directory this process may not search, so the
  loader classifies the two apart and logs a warning naming the path and the
  error kind for the second. The case seen in practice is
  `/etc/linux-hardener` left at `0700 root:root`, which older versions did to
  themselves when saving the signing key: an unprivileged `scan` then resolved
  different configuration from a root `apply`, silently. Repair it with
  `chmod 755 /etc/linux-hardener`. An unreachable `--config` file is the same
  hard error as a missing one, since the operator named that file and applying a
  policy they did not write would be worse than stopping.
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

`[pam]` accepts a fourth key, `password_policy`, which chooses between the
benchmark rules and NIST SP 800-63B-4; see
[`[pam]` password policy](#pam-password-policy).

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
reader to `/etc/sysctl.d/`, read 2026-08-08. **None of those five ships a value
in that file**, so the parameter named only there is one an operator wrote by
hand. The claim is deliberately not written as "no tested distribution": Ubuntu
joined the matrix on 2026-08-07, the day before this reading, and was not among
the five put to the question. What does read it is the procps `sysctl` binary, which
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
- `[ssh.directives] AuthenticationMethods` accepts only
  `publickey,keyboard-interactive` and `publickey,keyboard-interactive:pam`,
  the second factor described under "`[ssh]`: a key, then the account
  password" below.

### Where a directive override is clamped to the baseline

The baseline is the plugins' built-in set of values. Every one of them, with
its comparison and where it came from, is listed in
[baseline-sources.md](baseline-sources.md). "Tighten" means stricter as the
code ranks it, and for one setting, `ClientAliveCountMax`, the code ranks the
value that switches the check off (`0`) as the strictest, so an override set to
it is accepted and written. That page lists it under
[A value that switches the check off](baseline-sources.md#a-value-that-switches-the-check-off).

Every `[pam]`, `[ssh]` and `[kernel]` directive is clamped so an override can
only tighten, in `scan`, `apply` and `apply --dry-run` alike. A `deny` limit
above the baseline is lowered back to it, a `remember` count below it is raised
back to it, a `minlen` below 14 is raised back to 14, a `PASS_MAX_DAYS` above 90
is lowered back to 90 (those two under the default password policy),
`MaxAuthTries = "10"` yields 3, `X11Forwarding = "yes"` yields `no`, and
`kernel.kptr_restrict = "0"` yields 2.

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

`PASS_MAX_DAYS` and faillock's `deny` go one step further, because for them
only a positive number is a working limit. `PASS_MAX_DAYS -1` switches expiry
off (login.defs(5) calls it the value that "disables the restriction"), `0`
expires every password as soon as it is set, `deny = 0` switches lockout off,
and a negative `deny` wraps to a very large number inside faillock (`-1`
becomes 65535). All of them rank as the
loosest value the setting has. A host carrying one is reported and given the
baseline by `apply`, and an override naming one loses the clamp rather than
being written as a tightening. Until #190 each of them ranked as the strictest
value instead, so a host with expiry or lockout switched off passed every
control the check maps to.

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

One SSH setting is judged together with another. `KbdInteractiveAuthentication`
is held to `no`, because sshd takes the account password through
keyboard-interactive wherever PAM is on and `PasswordAuthentication no` does not
close that. Unset counts as `yes`, which is sshd's own default. The setting is
left alone where no `AuthenticationMethods` list lets keyboard-interactive
finish a login on passwords alone, so `AuthenticationMethods
publickey,keyboard-interactive` with `KbdInteractiveAuthentication yes` is not a
finding, and `apply` neither writes over it nor keeps an older `no` of its own
in the way. sshd reads `ChallengeResponseAuthentication` and
`SkeyAuthentication` as the same option and keeps the first line it meets under
any of the three names. Scan follows that order, and where the main file uses
an older name `apply` rewrites that line. A host that asks for
keyboard-interactive with no key beside it, for a one-time code through PAM for
example, is still reported, since sshd_config cannot show what PAM asks for.
Record that with an exception under `[ssh.exceptions.KbdInteractiveAuthentication]`.
To ask for the account password after the key instead, see "`[ssh]`: a key,
then the account password" below, which switches keyboard-interactive on as
part of it.

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

### Password hashing in `[pam]`

`[pam]` judges how a new password is stored as well as how it is chosen.
Three directives cover it, and a host is held to only one of the two costs, the
one belonging to the algorithm its new passwords will use:

| Directive | Baseline | What it judges |
|---|---|---|
| `ENCRYPT_METHOD` | `YESCRYPT`, or `SHA512` where FIPS mode is on or the host cannot confirm yescrypt | The algorithm new passwords are hashed with, on every path that sets one |
| `YESCRYPT_COST_FACTOR` | `5` | The yescrypt cost, where new passwords are yescrypt |
| `SHA_CRYPT_MIN_ROUNDS` | `100000` | The SHA-512 rounds, where new passwords are SHA-512 |

**Two places decide the algorithm, and the PAM stack wins.** shadow's own
tools (`chpasswd -c`, `chgpasswd`, `gpasswd`, and `chpasswd` and `newusers`
outright on a shadow built without PAM, as RHEL 9's is) read `ENCRYPT_METHOD`
from `/etc/login.defs`. They compare it case-sensitively, so a lowercase
`yescrypt` is not a value they accept. `pam_unix`, which `passwd` uses, and
`chpasswd` and `newusers` too on a shadow built with PAM, reads the same key
only as a default and lets an algorithm named on its own `password` line
override it. The cost works the same way: `rounds=` on the `pam_unix` line
wins, then `YESCRYPT_COST_FACTOR` or `SHA_CRYPT_MAX_ROUNDS` from `login.defs`.
Linux-PAM before 1.6.0, which Ubuntu 24.04 and Debian 12 ship, never reads
`YESCRYPT_COST_FACTOR`.

The scan reads the `pam_unix` password lines of `common-password`,
`system-auth`, `password-auth`, `passwd`, `chpasswd` and `newusers`, each
where Linux-PAM looks for it: `/etc/pam.d` first, then `/usr/lib/pam.d`, where
openSUSE installs `common-password`, then `/usr/etc/pam.d`. It reports the
weakest of all these paths, and its finding says which path falls short and
names the file the host actually has. Where only `login.defs` is weak, as on a
stock Ubuntu 24.04 whose `common-password` already names `yescrypt`, the
finding says that `passwd` already gives yescrypt and only shadow's own tools
do not.

**`apply` writes `/etc/login.defs` and nothing else.** Where a `pam_unix` line
names a weaker algorithm, carries a `rounds=` below the target, or sits on a
Linux-PAM that ignores the cost factor, `apply` records a manual step naming
the file, and the run does not report success. `/etc/pam.d` is never edited,
for the reason given for `deny` and `remember`: a malformed stack edit can lock
everyone out. Make the change through the tool that manages the stack where
there is one (an authselect profile on Fedora and RHEL, pam-auth-update on
Debian and Ubuntu, pam-config on openSUSE, and on Gentoo, which this project
does not test, the `sha512` and `yescrypt` USE flags of `sys-auth/pambase`),
or its next run may undo a hand edit. On openSUSE the `/usr/etc/login.defs`
vendor copy is carried into `/etc` first, as for every other `login.defs`
directive.

**yescrypt only where the host can use it.** Before judging anything, the scan
asks the target, in one shell round trip that works over `--ssh` too, whether
`pam_unix.so`, the libcrypt it links against and shadow (through
`chpasswd --help`) were built with yescrypt, whether `pam_unix` reads
`YESCRYPT_COST_FACTOR`, and whether `/proc/sys/crypto/fips_enabled` is set.
The libcrypt is the one `pam_unix.so` names: `libcrypt.so.2` on Fedora, RHEL 9
and 10 and Arch, whose libxcrypt keeps `libcrypt.so.1` in an optional compat
package, and `libcrypt.so.1` on Debian, Ubuntu and openSUSE. The host is held
to yescrypt only when all three components say yes and FIPS mode is off;
otherwise the target is SHA-512 with 100000 rounds. This is not caution for
its own sake: every shadow release before 4.20.0 answers an `ENCRYPT_METHOD`
it was built without, or does not recognise, with DES, which keeps only the
first eight characters of a password, and RHEL 9 ships one (4.9) built without
yescrypt. That covers every supported family but openSUSE Tumbleweed, whose
shadow 4.20.3 falls back to SHA-512 instead. shadow 4.20.0 also stopped
accepting `DES` and `MD5` as values, so its own tools use SHA-512 for both, but
`pam_unix` still reads `MD5` as its `md5` default, so the scan still rates it
High. A host already on yescrypt is never moved down to SHA-512, in FIPS mode
or out of it.

**Overrides only tighten.** `[pam.directives] ENCRYPT_METHOD = "YESCRYPT"` is
how an operator chooses yescrypt on a host in FIPS mode, where FIPS 140 does
not approve it; it has no effect on a host that cannot confirm yescrypt.
`YESCRYPT_COST_FACTOR` can be raised to at most 11, the largest cost libxcrypt,
shadow and `pam_unix` all accept, and `SHA_CRYPT_MIN_ROUNDS` to at most
9999999, where `pam_unix` stops. A lower value is raised back to the baseline,
as for every other directive.

**A raised yescrypt cost is checked against the host's memory.** Each check of
a yescrypt password needs 2^(cost - 1) MiB: 16 MiB at the default of 5, 128 MiB
at 8 and 1 GiB at 11, the maximum. Every simultaneous check needs its own, and
a password the host cannot afford to check is rejected even when it is typed
correctly. A cost above 5 is therefore accepted only where ten simultaneous
checks fit in half of `MemTotal`, so cost `c` needs a `MemTotal` of at least
10 x 2^c MiB: 640 MiB for 6, 2.5 GiB for 8, 10 GiB for 10 and 20 GiB for 11.
`MemTotal` reads a little below the installed memory, so a machine sold as
20 GB does not reach 11. Ten is a safety margin rather than a measured load:
local checks run side by side (login, `su`, `sudo`, screen lockers), and where
sshd still takes a password or a keyboard-interactive answer through PAM, each
unauthenticated connection can start one, up to the ten at which sshd's default
`MaxStartups` begins refusing. This tool's SSH baseline turns both of those off,
so on a host it has hardened only a key holder reaches a password prompt.

The check is part of the plan the scan, `apply` and `apply --dry-run` share. A
cost the host cannot afford is refused once, and is never written to
`login.defs` or offered as a `rounds=` manual step: on a Linux-PAM older than
1.6.0 that line is what every user's password gets, so naming the refused cost
there would be the lockout the refusal prevents. The plan aims instead for the
largest cost the host can carry, and never for less than the default of 5, so
a refused override cannot leave a host weaker than no override would: that
cost is what `apply` writes and what any `rounds=` step names. Where
`/proc/meminfo` cannot be read, nothing above 5 can be shown to be safe, so the
plan holds the host to 5. The run then does not report success, and the dry
run shows the refusal as a High issue. A container's cgroup memory limit is not
read, so choose the cost by hand on a host whose real limit is lower than
`MemTotal`.

**A cost already in force that the host cannot carry is reported.** The cost
check only asks whether the cost is high enough, and `apply` never lowers one,
so a host where a cost was raised by hand (to the 1 GiB of cost 11, say) would
otherwise scan clean. `pam-yescrypt-cost-memory` reports the highest yescrypt
cost on any path, from `login.defs` or from `rounds=` on a `pam_unix` line, when
it is above 5 and above what the same measure allows. It is a Medium advisory
with no compliance mapping, `apply` leaves it to the operator, and
`[pam.exceptions.YESCRYPT_COST_FACTOR]` with that cost as its `value` accepts a
cost chosen on purpose for a host with few simultaneous logins. It says nothing
where `/proc/meminfo` cannot be read, and it does not look at the cost of
hashes already stored.

| Cost | Memory per check | Time per check |
|---|---|---|
| 5 (default) | 16 MiB | 21 ms |
| 6 | 32 MiB | 34 ms |
| 7 | 64 MiB | 76 ms |
| 8 | 128 MiB | 141 ms |
| 11 (maximum) | 1 GiB | 1.29 s |

Measured on 2026-11-15 with libxcrypt 4.4.36 on a 2.1 GHz Xeon virtual
machine, best of five runs (two at cost 11). SHA-512 took 3.5 ms at 5000
rounds and 54 ms at 100000, with no memory to speak of.

**Stored hashes are counted, never changed.** A stored hash keeps the
algorithm and cost it was made with until that password is set again, so
`pam-stored-password-hashes` counts the accounts whose hash uses a weaker
scheme than the one new passwords get, by scheme name only. `/etc/shadow` is
read inside the target's own shell, and only a scheme name per account leaves
it: no hash, salt or user name reaches this tool, its logs or its reports. The
count needs root and is reported unchecked without it. It takes no exception
and maps to no compliance control, because it changes every time a password is
set. The finding prints a command that lists the accounts on the host itself.

**Exceptions** take the directive name and the value the scan reports, so
`[pam.exceptions.ENCRYPT_METHOD]` with `value = "SHA512"` accepts a host kept
on SHA-512 on purpose, for example one whose hashes are copied to systems that
cannot verify yescrypt. The cost judged on that host is then SHA-512's.

A host held to a DISA STIG is the other case for that exception. The STIGs for
RHEL 8, 9 and 10 and Ubuntu 24.04 require SHA-512 with 100000 rounds, and the
RHEL 10 STIG requires it in `login.defs` and on the `pam_unix` lines and for
every stored hash. A fully compliant host also runs in FIPS mode, and FIPS mode
already holds it to SHA-512 here. A host configured to the STIG without FIPS
mode, a virtual machine or a container on a non-FIPS kernel for example, would
otherwise be moved to yescrypt, and the STIG scan run against it afterwards
would fail. The `--profile` that selects STIG identifiers in reports does not
reach the plugin, so record the exception on such hosts.

**Compliance.** The three directives map to NIST 800-53 IA-5(1)(d), NIST SP
800-171 3.5.7, FedRAMP IA-5(1)(d) and PCI DSS 4.0 8.3.2, beside the HIPAA,
GDPR, ISO/IEC 27001 8.5 and SOC 2 CC6.1 entries every PAM check carries.
IA-5(1)(d) is password storage in 800-53 Rev 5, the revision this project
cites; the ComplianceAsCode rules for the same settings cite IA-5(1)(c), which
is storage only in Rev 4. Rev 5 asks for "an approved salted key derivation
function". SP 800-63B names PBKDF2 (specified in SP 800-132) and Balloon as
examples, and neither yescrypt nor sha512crypt. A pass here therefore means
the strongest scheme the host's own password stack offers, and counting it
towards (d) is this project's judgement, not NIST's.

An `ENCRYPT_METHOD` finding for salted SHA-512 on a host held to yescrypt
carries no compliance mapping. A control fails on any live finding mapped to
it, whatever the finding's severity, and SHA-512 is the value the DISA STIGs
require for the same control, so the preference for yescrypt is this tool's
baseline, not a framework's. Such a host passes the controls; anything weaker
than SHA-512, or an algorithm that cannot be determined, fails them.

No STIG rule is mapped: every STIG rule for password storage requires SHA-512,
so a host this tool passes on yescrypt would fail it. No CIS control is mapped
either, because the hashing control of the benchmark the curated catalogue
follows could not be checked against the benchmark itself.

**Rollback** restores `/etc/login.defs`. A password set while the new settings
were in force keeps its new hash, algorithm and cost alike, which is never
weaker than before, but may be one an older system cannot verify if the hash is
copied there. A raised cost therefore outlives a rollback: an account whose
password was set at a cost the host cannot carry stays that way until the
password is set again with `passwd`. Rollback reports no divergence for this,
because the plugin's state is the file it restores.

### `[pam]` password policy

`[pam]` accepts one key the other sections do not, `password_policy`, which
chooses the set of password rules the PAM plugin enforces. Config validation
refuses the key in any other section, and a value it does not recognise stops
the configuration loading rather than falling back to a default.

```toml
[pam]
password_policy = "nist-800-63b"
```

| Value | What it enforces |
|---|---|
| `"benchmark"` (default) | The rules every earlier release enforced: `minlen` 14; one digit, one uppercase letter, one lowercase letter and one other character (`dcredit`, `ucredit`, `lcredit` and `ocredit` at `-1`); and a maximum password age of 90 days for new accounts. |
| `"nist-800-63b"` | NIST SP 800-63B-4: `minlen` 15; all four credits at `0`, so no character class is required and none shortens the minimum; `minclass` and `maxclassrepeat` at `0`, because either one at 4, as the CIS and STIG benchmarks set them, refuses every passphrase made of words; and `PASS_MAX_DAYS 99999`, so new accounts are not made to change their password on a schedule. |

Both policies keep the same `maxrepeat`, minimum password age, expiry warning,
lockout (`deny`) and history (`remember`) rules. Neither policy manages
libpwquality's dictionary check, `dictcheck`: its default is on, and a host
that sets `dictcheck = 0` keeps it. `maxsequence` is not managed either. Like
`maxrepeat` it bans a pattern rather than requiring a mixture. Measured on
2026-11-15, `maxsequence = 3` refused 2 of the 1,979 random passphrases of five
or seven EFF words that the rest of the NIST policy accepted, both for the
`rstu` in "overstuff".

**Why there are two.** The standards no longer agree. Section 3.1.1.2 of NIST
SP 800-63B-4 says verifiers "SHALL require passwords that are used as a
single-factor authentication mechanism to be a minimum of 15 characters",
"SHALL NOT impose other composition rules (e.g., requiring mixtures of
different character types)" and "SHALL NOT require subscribers to change
passwords periodically", forcing a change only on evidence that the password
has been compromised. The CIS and DISA STIG benchmarks still require character
classes and a maximum age, and PCI DSS v4.0.1 asks for a digit and a letter
(8.3.6) and, where the password is the only factor, for a change at least every
90 days or for the account's security posture to be analysed dynamically
instead (8.3.9). No host meets both sides. The default stays `benchmark`, so an
upgrade changes nothing on a host whose configuration did not ask for a
change; choose `nist-800-63b` where those frameworks do not apply, or where an
auditor accepts the deviation.

The NIST policy covers the length, composition and rotation rules of SP
800-63B-4. It does not cover the blocklist the same section requires ("SHALL
compare the prospective secret against a blocklist that contains known commonly
used, expected, or compromised passwords"), because no PAM module this tool
manages has one; see "What no setting here can enforce" below. A host on this
policy therefore meets SP 800-63B-4 only once a blocklist is in place by other
means.

**What the report says about the choice.** A control the chosen policy
deliberately does not meet is reported as failing, never as passing. Under
`nist-800-63b`, a host that requires no character class, or forces no expiry,
gets one Info finding per dropped rule, `pam-<directive>-policy-departure`. It
carries the CIS, DISA STIG and PCI DSS controls the benchmark check maps to,
because those texts still require the rule, so those controls read Fail and the
finding under them names the policy. It does not carry the NIST SP 800-53, NIST
SP 800-171 or FedRAMP controls. SP 800-53 Rev 5 IA-5(1) has no password
lifetime item, leaves composition rules to the organisation in item (h), and
says "Enforced composition rules provide marginal security benefits while
decreasing usability"; SP 800-171 r3 requirement 03.05.07 says the same; and
FedRAMP's Rev 5 baselines add that password policies "shall not enforce special
character or minimum password rotation requirements". Following SP 800-63B-4
therefore fails none of them. The HIPAA, GDPR, ISO/IEC 27001 and SOC 2 controls
ask that a password policy is followed rather than which one, so the departure
does not fail them either. `apply` never acts on a departure finding.

The SP 800-171 judgement follows Revision 3, the revision this tool labels its
800-171 framework with, although the control ID it reports keeps the Revision 2
number, 3.5.7. An assessment under Revision 2, which CMMC Level 2 uses, reads
3.5.7 as "Enforce a minimum password complexity and change of characters when
new passwords are created", with the complexity left to the organisation to
define. Under such an assessment, record how the 15-character minimum meets it,
or choose `benchmark`.

A value that is set and meets neither rule, such as `PASS_MAX_DAYS 0` (every
password expires at once), `PASS_MAX_DAYS 120` or a positive credit (which lets
a password be shorter than the minimum), is one ordinary finding instead,
carrying every control the check maps to at the benchmark's severity. A value
that is not set is one Low finding asking for it to be written down. Unset, a
credit is libpwquality's `0` and the maximum age is login.defs(5)'s `-1`, which
already behave as the policy asks, so that finding carries the CIS, DISA STIG
and PCI DSS controls a departure would, and the four policy-agnostic ones, but
no NIST SP 800-53, NIST SP 800-171 or FedRAMP control. `apply` rewrites either
kind to the policy's value, after which only the departure remains.

Where an auditor accepts a departure, record it as an ordinary policy exception
under the directive's own name, documenting the host's value, and the control
then lists the documented deviation instead of failing:

```toml
[pam.exceptions.PASS_MAX_DAYS]
value = "99999"
allowed = true
reason = "MFA on every login, so PCI DSS 8.3.9 does not apply"
```

An exception is keyed by directive, not by framework, so it lists the deviation
under every control the departure carries: the CIS and DISA STIG controls as
well as PCI DSS, whatever its `reason` names. There is no way to accept a
departure for one framework alone; where another framework's control must keep
failing, leave the departure unexcepted.

**Exit codes and notifications.** A host that follows the NIST policy always
carries its departure findings, as Info, even when every one of them is
excepted, because an excepted finding is still listed. `hardener scan
--exit-code` exits 1 whenever any finding is left after the `--severity` filter,
whose default is `info`, so a CI gate on such a host should run `hardener scan
--exit-code --severity low`. A scheduled scan that notifies at the Info
threshold notifies on every run for the same reason.

**What `apply` does under `nist-800-63b`.** It writes `minlen = 15`, writes each
credit as `0` (over a `-1` an earlier apply wrote, too), writes `minclass = 0`
and `maxclassrepeat = 0`, and writes `PASS_MAX_DAYS 99999`. A host already at
`PASS_MAX_DAYS -1`, which is shadow's own "never expires", is left alone. Every
write that relaxes a rule the host had names the policy in its change line, and
`apply --dry-run` shows the same note beside each pending change, so a
relaxation never appears as an anonymous edit. A write that repairs a value
rather than relaxing it, such as `PASS_MAX_DAYS 0` becoming 99999, carries no
such note. A negative `minclass` or `maxclassrepeat` is off to libpwquality
just as `0` is, because it tests only for a `maxclassrepeat` above 0 and for
fewer classes than `minclass`, so the scan does not report one; `apply` spells
it `0`, which changes nothing, and labels nothing. The checkpoint is taken first as always, so `rollback` restores the
files the apply changed. It cannot reach accounts created between the apply and
the rollback: they keep the maximum age they were created with (99999). Check
them with `sudo chage -l <user>` and set the age you want with `sudo chage -M
<days> <user>`.

**Overrides follow the selected policy's direction.** An override is still
clamped tighten-only, but on the selected policy's own scale. Under
`nist-800-63b` nothing is stricter than `0` for a credit, `minclass` or
`maxclassrepeat`, so an override such as `dcredit = "-1"` has no effect; the dry
run reports that as a Low issue and the scan log says so too. To require a
character class, choose `benchmark`. `PASS_MAX_DAYS = "-1"` is honoured under
`nist-800-63b`, because it means no expiry at all. A longer minimum is honoured
under either policy, because it tightens: `minlen = "24"` under
`[pam.directives]` asks for passphrase-length passwords.

**Where the policy takes effect.** The pwquality rows take effect only where the
PAM stack loads `pam_pwquality.so`. Where the scan does not find it, it reports
the module as not loaded against each directive, and `apply` still writes
`pwquality.conf` but reports the PAM run as not fully successful, because the
step that remains, adding the module to the stack, is the operator's. Some
distributions do not load it by default; Arch's `pambase` `system-auth` did
not, as far as the archived copy shows. The scan looks for it in `system-auth`,
`password-auth` and `common-password`, and does not follow which of those files
a given program actually uses. That can matter on Arch: in the archived
`shadow` 4.13 package (2023, before Arch moved to shadow 4.14; the current file
may differ), `/etc/pam.d/passwd` holds its own `pam_unix.so` line and does not
include `system-auth`, so a `pam_pwquality.so` line added to `system-auth`
would satisfy the scan while `passwd` never runs it, and one added to
`/etc/pam.d/passwd` would work while the scan reports it as not loaded. Check
with `grep -n include /etc/pam.d/passwd`.

Gentoo's `pambase` loads pam_passwdqc rather than pam_pwquality by default: its
`passwdqc` USE flag is on by default and cannot be combined with `pwquality`.
On such a host the pwquality rows report the module as not loaded, and neither
policy changes which passwords are accepted; passwdqc takes its settings from
`/etc/security/passwdqc.conf` (passwdqc.conf(5)). Gentoo is not among the
distributions this tool is tested on.

Arguments written on the `pam_pwquality.so` line itself, such as `minclass=4`
or `dcredit=-1`,
override `pwquality.conf` (pam_pwquality(8)), and this tool does not read them
yet, so a host that sets composition rules there still refuses passphrases
while the scan reports the policy as met. Neither does it read the drop-ins in
`/etc/security/pwquality.conf.d/`; libpwquality reads those before
`pwquality.conf`, so the explicit lines `apply` writes there win over them.

**Existing accounts keep their ageing.** `/etc/login.defs` supplies ageing to
accounts created after it changes. Accounts that already exist keep the maximum
age recorded for them in `/etc/shadow`, under either policy, and this tool does
not change it. Read it with `sudo chage -l <user>`; `sudo chage -M -1 <user>`
removes the forced change from one account (chage(1): "-1 as MAX_DAYS will
remove checking a password's validity").

**What no setting here can enforce.** pam_pwquality, the module this tool
manages, judges one string at a time. It cannot tell a passphrase of truly
random words from a phrase someone made up, and it has no notion of a word
count, so the 15-character minimum makes room for long passphrases without
being able to require them. Choosing the words at random, with dice or a
generator over a published list, is what makes a passphrase strong. A different
module, pam_passwdqc, can go further, and this tool does not manage it:
passwdqc.conf(5) offers `passphrase=N`, "The number of words required for a
passphrase", and `random=N,only`, whose `only` modifier "can be used to
disallow user-chosen passwords". A password is then accepted only if it
contains the passphrase passwdqc generated and offered ("Any passphrase that
contains the offered randomly-generated string will be allowed"), sized at 24
to 136 bits. passwdqc builds it from its own list of 4,096 words, each with a
random capital, joined by random digits and symbols, so passwdqc 2.0.3's
`pwqgen random=85` offers five words and `random=91` six.

libpwquality's dictionary check is not a breach list either: it never compares
a password with passwords leaked elsewhere, and it accepted `password password
password` under these settings. It errs the other way too: on Ubuntu 24.04
(libpwquality 1.4.5, cracklib 2.9.6), measured on 2026-11-15, it refused
between 1 and 2 in every 100 random passphrases of four to seven words from
the EFF long list as "too simplistic/systematic". Picking another phrase is the
remedy. Under `benchmark` the same test accepted none of them, for want of a
digit. Spaces are accepted and count towards the length. libpwquality counts
bytes rather than characters, so a character outside ASCII counts as more than
one, and pam_unix refuses a new password longer than 512 bytes.

### `[ssh]`: a key, then the account password

By default the SSH plugin turns password login off and relies on the key
alone. A key is a file on the client, so whoever copies it can log in. One
directive asks for a second step after the key, the account password, and it
is off unless your own config sets it:

```toml
[ssh.directives]
AuthenticationMethods = "publickey,keyboard-interactive"
```

`publickey,keyboard-interactive:pam` is accepted as well and behaves the same,
since PAM is keyboard-interactive's only device on Linux. Any other value is
refused when the config loads. `publickey,password` in particular would need
`PasswordAuthentication yes`, which the baseline holds at `no`, so `sshd -t`
would reject the result.

With it set, the plugin manages three settings together and writes them to its
own drop-in, `/etc/ssh/sshd_config.d/00-hardener.conf`, which sshd reads before
the files the six validated distributions ship (Arch switches
keyboard-interactive off in `99-archlinux.conf`, and a value in the main file
would lose to it):

| Setting | Value | Why |
|---|---|---|
| `AuthenticationMethods` | the value above | The key first. sshd offers the password prompt only after the key succeeds, so nobody without the key can guess at the password or run up its failure count. |
| `KbdInteractiveAuthentication` | `yes` | The method that carries the prompt. It is a second factor here, so the usual `no` does not apply. |
| `UsePAM` | `yes` | PAM asks the question. `UsePAM no` passes `sshd -t` and then refuses every login after the key. |

`PasswordAuthentication` stays at `no`. A host whose own drop-in already asks
for at least as much, `publickey,publickey,keyboard-interactive` for example,
keeps its list, and only the two companion settings are written.

The drop-in wins only where the main file's `Include` of `sshd_config.d` sits
above its global lines, which is where the six validated distributions put it.
Gentoo puts it at the foot of `/etc/ssh/sshd_config`, so a line in the main file
is read before every drop-in, this one included. A normal apply there writes
`KbdInteractiveAuthentication no` in place of the commented default, above that
`Include`, so with the second factor on, the apply switches that line to `yes`
as well and says so, and switches it back to `no` when you turn the second
factor off. A `UsePAM no` or an `AuthenticationMethods` line of your own above
the `Include` is left alone, and the apply refuses the second factor naming it.

`scan` reports a host that does not enforce this as
`ssh-authenticationmethods` (High), naming what is in force instead, and maps
it to NIST SP 800-53 IA-2(1) and IA-2(2). Those two controls are not declared
as covered, because a host that never opted in would otherwise pass them on
the strength of a check that did not run. `apply --dry-run` lists the three
settings it will write.

**What `apply` checks before it writes.** `sshd -t` checks only the global
lists, and only whether the methods they name are switched on, so it cannot
see most of the ways this change locks people out. `apply` stages the
candidate and reads it the way sshd will run it (`sshd -T`), globally and then
for each account, before anything is written. It stages the same apply without
the second factor beside it and compares the two, so an account that loses its
way in to the rest of the hardening (password login switched off, say) is not
blamed on the second factor. If a check fails, the second factor is left out,
the rest of the SSH hardening still goes ahead, and the run ends unsuccessful
with the reason:

1. Globally, the candidate has to ask for the key and then the password, with
   `KbdInteractiveAuthentication yes` and `UsePAM yes` in force. The fragment is
   read before every file the distributions ship, but not before a line above
   the main file's `Include`, which sshd reads first, nor before a drop-in whose
   name sorts ahead of `00-hardener.conf`. A `UsePAM no` there passes `sshd -t`
   and then turns every login away after the key. A main file that does not
   include `sshd_config.d` at all never reads the fragment, and is refused
   saying so.
2. The PAM service sshd uses has to reach `pam_unix` (or `pam_sss`), following
   `include`, `substack` and `@include` through `/etc/pam.d`, then
   `/usr/lib/pam.d` and `/usr/etc/pam.d`. That service is `sshd` unless
   `PAMServiceName` (OpenSSH 10.0 and later) names another, globally or in a
   `Match` block, and each one in use is checked. It shows the stack can ask
   for the account password, not that nothing else answers first.
3. Nothing may let accounts in without a key file the account check below can
   read: `AuthorizedKeysCommand` (LDAP, opkssh and the like), user certificates
   under `TrustedUserCAKeys`, trusted hosts under `HostbasedAuthentication`, or
   Kerberos tickets under `GSSAPIAuthentication` where `/etc/krb5.keytab`
   exists. The check cannot see who logs in that way, and the policy turns
   every one of them away unless they also hold a key and a password, so the
   apply refuses until an exception names those settings (see below). Fedora
   and Rocky switch `GSSAPIAuthentication` on in `50-redhat.conf`; without a
   keytab nobody can log in with a ticket, so there it is only a note.
4. Over `--ssh`, the account the apply connected as has to keep a way in on its
   key alone, if it has one today, because this tool's remote mode cannot answer
   a prompt. Root under `PermitRootLogin prohibit-password` never passes a
   keyboard-interactive step (sshd refuses root every method but `publickey`,
   `hostbased` and `gssapi-with-mic` there), so a remote root apply needs the
   `Match` block below. Otherwise run the first apply from a session on the host
   itself.
5. Every account that logs in over SSH has to keep a way in. That is every
   account with a key file sshd reads (one `AuthorizedKeysFile` names), whatever
   its login shell: sshd lets a `nologin` or `false` account authenticate, which
   is how SFTP-only and tunnel-only accounts work, and the password step locks
   them out like any other. It is also every account with a usable password
   that the apply without the second factor would still let in on that password
   alone, which happens wherever an exception keeps `PasswordAuthentication yes`.
   Each account is read with `sshd -T -C user=...,host=...,addr=...` from two
   addresses: the session's client address over `--ssh` or `127.0.0.1` locally,
   and `203.0.113.254`, a documentation address (RFC 5737) no real `Match`
   block names, so an exemption scoped to loopback or to the controller cannot
   hide a lockout for logins from anywhere else. Every list naming a method
   that is switched off for the account (a `Match` block setting
   `KbdInteractiveAuthentication no`, for example) is dropped, as sshd drops
   it. What is left has to let the account in from both addresses on its key
   alone, or on its key and a password `pam_unix` will accept. A locked (`!`),
   disabled (`*`) or empty hash does not count, and root's password counts only
   under `PermitRootLogin yes`, which this tool never writes. The account an
   apply over `--ssh` runs as needs only the session's address: the `Match`
   block below keeps it to that address on purpose, so losing the others is a
   note rather than a refusal.
6. No login may finish on a password alone where the apply without the second
   factor would not let it. Switching keyboard-interactive on for every
   connection wakes a `Match` list that names it without a key in front, such
   as `AuthenticationMethods publickey keyboard-interactive` (two lists, one of
   them the password alone), which sshd had been dropping. The apply refuses
   any such block it finds in the files, whichever addresses or users it
   matches, and any probe above that meets one.

When it goes ahead, the run names every account that will now be asked for its
password after the key. Anything that logs in as one of them with a key alone,
a backup job, git, rsync or Ansible, stops working unless a `Match` block keeps
it on its key.

To accept losing SSH access for the accounts the fifth check names, write an
exception whose `value` lists exactly those accounts, sorted and
comma-separated, as the refusal prints them. A new account in that list makes
it stop matching:

```toml
[ssh.exceptions."second-factor-lockout"]
value = "deploy,git"
allowed = true
reason = "Key-only service accounts; CI now deploys from the console host"
approved_by = "Security Team"
```

To accept that the third check cannot see who logs in through
`AuthorizedKeysCommand`, `TrustedUserCAKeys`, `HostbasedAuthentication` or
`GSSAPIAuthentication`, name the settings in force, in the same form, for
example `value = "GSSAPIAuthentication,TrustedUserCAKeys"`:

```toml
[ssh.exceptions."second-factor-unlisted-keys"]
value = "TrustedUserCAKeys"
allowed = true
reason = "Certificates are issued to administrators, who all have passwords"
approved_by = "Security Team"
```

**Keeping an automation key on its key alone.** A `Match` block overrides the
global list for the connections it matches, whichever file it sits in: sshd
reads the configuration a second time for each connection with only the
matching `Match` blocks active, and lays what they set over the global values.
To keep this tool's remote mode, or a CI deploy key, working from one address,
add a block of your own:

```
# /etc/ssh/sshd_config.d/50-automation.conf
Match User root Address 192.0.2.10
    AuthenticationMethods publickey
    PermitRootLogin prohibit-password
```

The `PermitRootLogin` line matters wherever the hardener also runs on the host
itself. A local apply sets `PermitRootLogin no`, and a `Match` block that
changes only `AuthenticationMethods` does not let root back in. Set inside the
block, `prohibit-password` lets root in on its key from that one address while
every other address stays at `no`.

Narrow it as far as you can: one account, one address, and ideally a key
restricted with `from=` and `restrict` in `authorized_keys`. Use an address
that does not move, a VPN or a jump host rather than a laptop's changing one.
That identity no longer has a second factor, which is the trade being made.
Check the result with `sshd -T -C user=root,host=192.0.2.10,addr=192.0.2.10 |
grep -E 'authenticationmethods|permitrootlogin'` before restarting sshd.

**A second factor of your own inside a `Match` block.** This plugin holds the
global `KbdInteractiveAuthentication` at `no` whenever the opt-in is off, and
it reads the global scope only. A `Match` block of your own that asks some
users for `AuthenticationMethods publickey,keyboard-interactive` therefore has
to set `KbdInteractiveAuthentication yes` inside the same block. Without it
sshd drops the list as naming a switched-off method and turns those users away
at login with "no authentication methods enabled", and `sshd -t` passes,
because it checks the global lists only. Check each such user with
`sshd -T -C user=...,host=...,addr=...` before restarting sshd.

The reverse holds once the opt-in is on, because it switches
keyboard-interactive on for every connection. A `Match` list that names
`keyboard-interactive` without `publickey` in front of it, or a `Match` block
with `AuthenticationMethods any`, then lets the password alone finish a login,
and the apply refuses the second factor naming the block (check 6 above). Put
`publickey` first in that list, or set `KbdInteractiveAuthentication no` inside
the block.

**Turning it off again.** Remove the directive and run `apply`: the three
settings leave the fragment, and `KbdInteractiveAuthentication` falls back to
the plugin's usual `no`. Rolling back the checkpoint of the apply that added
them does the same.

**Other things that change.** With a password step, PAM's authentication
stack now runs for SSH logins: `pam_faillock` counts wrong passwords typed after
the key, and pam_unix checks the password hash on every such login, so the cost
the hash was made with is paid each time someone logs in over SSH. Password
ageing is not new. Under `UsePAM yes`, sshd already runs PAM's account check
after every login, a key-only one included, and an aged password forces a
change there: on a terminal sshd runs `passwd`, and without one the login ends
with "Password change required but no TTY available". With the password step,
the change is asked for inside the prompt instead. sshd's `MaxAuthTries` (3
here) counts each wrong password; before OpenSSH 10.6 every key the client
offers and the server rejects counts too, so a client offering several keys can
run out of tries before it reaches the password. Pin the key with
`IdentityFile` and `IdentitiesOnly yes` in `~/.ssh/config`.

**What the checks do not see.** Accounts that `/etc/passwd` does not list, such
as directory (SSSD or LDAP) accounts keeping their keys in their home
directory; a `Match` block that exempts an account from an address other than
the two the checks log in from, which the lockout check counts as locked out
(and a local apply cannot tell apart from a lost account, so it needs the
exception); `GSSAPIAuthentication` or `HostbasedAuthentication` switched on
inside a `Match` block only, and a Kerberos keytab kept somewhere other than
`/etc/krb5.keytab`; an `AuthorizedKeysFile` set inside a `Match` block (the
global one is read); an `Include` of the drop-in directory from inside another
included file; and which PAM module answers first where the stack reaches more
than one. The checks run `sshd -T` and read `/etc/shadow`, which only root can
do, and the remote executor elevates file writes alone, so a remote apply needs
a root session.

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
`minlen`, or `ENCRYPT_METHOD` for the hashing algorithm), an absolute path for
`[permissions]` (for example `/etc/shadow`), a service name for `[services]`
(for example `cups`), an audit rule category for
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

Two keys accept an outcome rather than a finding: `second-factor-lockout`,
whose value lists the accounts an opted-in SSH second factor would leave with
no way in, and `second-factor-unlisted-keys`, whose value names the
`AuthorizedKeysCommand`, `TrustedUserCAKeys`, `HostbasedAuthentication` or
`GSSAPIAuthentication` setting whose logins the lockout check cannot see. No finding carries either, so `hardener exception
add` cannot pin them; write them by hand as shown under "`[ssh]`: a key, then
the account password".

---

## [compliance]

Declares compliance controls that do not apply to this system, so they leave
the score's denominator instead of counting against it.

**This is not the same mechanism as a policy exception**, and the difference is
what keeps it safe. An exception documents a finding the engine raised. An
exclusion covers a control the engine cannot assess at all: ISO 27001 Annex A
is a published catalogue of 93 controls, most of them about policy, personnel,
suppliers and physical premises, and a configuration scanner can never answer
those. On a cloud host with no premises they are not unmeasured, they do not
apply.

```toml
[compliance.not_applicable.iso27001."7.1"]
reason = "No physical premises; all infrastructure is cloud-hosted"
approved_by = "eric"
approved_date = "2026-08-18"
ticket = "SEC-412"
review_by = "2027-08-18"
hosts = ["web-01", "web-02"]
```

| Key | Meaning | Default |
|-----|---------|---------|
| `reason` | Why the control does not apply. An exclusion raises the score, so an unexplained one raises it for no stated cause | required |
| `approved_by` | Who approved it | none |
| `approved_date` | When it was approved (ISO 8601) | written by the verb |
| `ticket` | Approval ticket or issue reference | none |
| `review_by` | When it must be re-examined (ISO 8601) | twelve months from `approved_date` |
| `hosts` | Hosts it covers. Matched case-insensitively against a saved profile's name, its hostname, its `user@host:port` target, or that target with the port dropped (`user@host`) | empty, meaning every host |

The framework key accepts any spelling `--framework` accepts, so `iso27001`,
`ISO27001` and `iso-27001` are one key, as are `nist800171` and `nist-800-171`.
A key naming no framework the tool knows is inert, per "It never applied" below,
and **is warned about at config load** as of 2026-08-19:

```
WARN [compliance.not_applicable.iso270001] names no known framework, so every
     exclusion under it applies to nothing. Accepted: cis, hipaa, iso27001, ...
```

Nothing said so before that, and the silence was the whole problem. Being inert
is the safe direction, so the report the typo produces is the report the
operator would have got without writing the exclusion at all: identical to the
one they wrote it to change, with nothing in it pointing at the spelling.

Prefer `hardener scope exclude` over hand-editing. The verb validates before it
writes and records the declaration in the audit log; **a hand-edited entry is
honoured but produces no audit record**, because nothing runs to write one.

### An exclusion can never hide a failure

The report generator decides a control's status in a fixed order: a live
finding first, then a check that could not run, then a control the engine
assessed, and only then exclusions. So an exclusion can convert a Manual Review
and nothing else. Declaring a failing control not applicable does not change
its Fail, and declaring an assessed control not applicable does not change its
Pass.

The same ordering supplies the change trigger most frameworks actually ask for.
When a plugin gains the ability to assess an excluded control, the engine's
answer supersedes the declaration on the next scan, without waiting for
`review_by`.

### Two ways an exclusion stops applying

**It expires.** `review_by`, or twelve months from `approved_date` when absent.

**It never applied.** An entry with no parseable `review_by` and no parseable
`approved_date` is invalid rather than permanent, and so is one naming a
framework the tool does not know. Both fail closed: the control returns to
counting against the score. An expired or invalid exclusion returns a control
to Manual Review, never to Pass.

### The interval comes from the framework owner

Twelve months for every framework. Four publish an interval bearing on a scope
determination: PCI DSS Req 12.5.2, FedRAMP CA-2, SOC 2's Type II observation
period, and 32 CFR 170.22's annual affirmation for NIST 800-171. The other six
publish none and name a change trigger instead, so twelve months there is this
project's default rather than a framework requirement.

**PCI DSS service providers must set six months by hand** under Req 12.5.2.1.
The tool cannot know whether an operator is a service provider, so it does not
guess.

### It reaches the fleet

`batch report` and the desktop fleet view both evaluate every remote host
against the controller's config, not the host's own, so an exclusion written
here applies fleet-wide unless `hosts` narrows it. That is deliberate and
predates this section: policy belongs where the operator maintains it, and a
target that supplied its own could otherwise weaken the audit reporting on
itself.

Each host is matched against `hosts` individually, so a narrowed exclusion
raises the score of the hosts it names and no others. The controller's own
local report is not a host in that sense: it honours an exclusion with an empty
`hosts` list and never one that names hosts, so narrowing an exclusion cannot
quietly raise the score of the machine you wrote it on.

### It has no effect for eight of the ten frameworks

Only CIS and ISO 27001 ship a curated catalogue. Every other framework's
catalogue is derived from what the engine can already assess, so it lists no
control an exclusion could apply to. `hardener scope exclude` still writes and
audits such a declaration, and warns that it cannot take effect.

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

A root scan opens and writes whatever database this key names, so the file a
root run takes its `[scheduler]` section from decides that. Keep such a file
owned by root, with `database_path` unset or in a directory only root can
write, as the default is. Two things can put a file that you, the desktop user,
can write in that position: the desktop's deep scan passes the config chosen in
the app to the root CLI, and a root run that keeps your `HOME` or
`XDG_CONFIG_HOME` (such as `sudo -E`) reads this section from your own
`~/.config/linux-hardener/config.toml`, as described above. On 1.9.1 and
earlier this matters more, because their bundled SQLite can return stale
process memory from a planted database and `-wal` pair (RUSTSEC-2026-0459). See
[SECURITY.md](../../SECURITY.md#rustsec-2026-0459-bundled-sqlite---fixed-after-191)
for what to do until you upgrade.

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

**A channel switched on with nowhere to send is refused at the save** as of
2026-08-19, for webhooks with no URL and for email with no recipient. Until
then it was accepted in silence at both ends: an endpoint with no URL is not
written at all, so the file ended up with `enabled = true` beside an empty
list, the desktop reported `Saved to <path>`, and the daemon's per-endpoint
warning sits inside a loop over that empty list and so warned about nothing.
The daemon now also says so once when webhooks are enabled and the list is
empty, which is the case a hand-edited file reaches. **`smtp_host` is not part
of this check**: the desktop has no field for it, so email switched on with a
recipient and a from-address still reaches a daemon that refuses it when the
host is missing, and that refusal is logged rather than shown.

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

SSH authentication is key or agent based only; there is no password path. A
host that asks for a password or a second factor is reachable from the CLI over
a connection you opened yourself (`--ssh-control-path`), and not from `batch`,
which opens its own; see the
[SSH remote guide](../guide/ssh-remote-scanning.md#hosts-that-ask-for-a-second-factor).
