# Where the default values come from

**Last Updated**: 2026-11-15

linux-hardener judges every host against a set of built-in values, called the
baseline. This page lists each of them and answers three questions about it:
what the value is, where it came from, and what the main hardening guides ask
for on the same setting. It was written in answer to
[issue #189](https://github.com/tidynest/linux-hardener/issues/189), which
asked which guide the defaults follow.

**The short answer is that they follow no single guide.** The baseline is the
project's own set of values. Most of them were chosen when the project started,
in November 2025, and nothing in the repository records which guide each one
came from. Where a source is recorded, this page quotes it. Where none is, the
row says so plainly, and the next column shows what the guides ask for, so you
can see where the value sits among them.

This page is held to the code. `scripts/validate/validate_baseline_sources.py`
reads the baseline tables in the plugins, and `validate_all.py`, which the pull
request checklist in CONTRIBUTING.md asks for, fails when a default, a
comparison or a severity changes without its row here, when a check is added
or removed without one, and when a plugin gains a table of values the script
does not read yet. CI does not run it. What the guides say cannot be checked
that way, so every guide is quoted with its version and the date it was read,
listed under [Sources](#sources).

---

## Contents

- [How the values were chosen](#how-the-values-were-chosen)
- [How the baseline fits with the rest of the tool](#how-the-baseline-fits-with-the-rest-of-the-tool)
- [Where a Pass and the control disagree](#where-a-pass-and-the-control-disagree)
- [How to read the tables](#how-to-read-the-tables)
- [Kernel parameters](#kernel-parameters)
- [SSH server](#ssh-server)
- [PAM and password ageing](#pam-and-password-ageing)
- [Services](#services)
- [Firewall](#firewall)
- [Audit rules](#audit-rules)
- [File permissions](#file-permissions)
- [Mandatory access control](#mandatory-access-control)
- [Proposing a change](#proposing-a-change)
- [Sources](#sources)

---

## How the values were chosen

The first tables were written in the project's first week: the kernel and SSH
tables on 2025-11-20, the firewall rules on 2025-11-21, the PAM and services
tables on 2025-11-22, and the audit rules and the first five file-permission
paths on 2025-11-23. The README of the first commit described a working
catalogue, `.claude/SECURITY_CONTROLS.md`, holding "All kernel parameters with
secure values", "SSH, PAM, audit rules" and "Compliance framework mappings".
That file was never committed, so the reasoning behind those first values
cannot be recovered from the repository. None of the original tables cites a
source for a value. The audit rules and the permissions table each carry a
one-line comment, quoted below, that names CIS without a version or a section.

Later additions are better recorded:

- The SSH algorithm allow-lists were added on 2026-06-20 in commit `7b0d6b58`,
  with a comment naming 'OpenSSH 10 defaults and Mozilla "Modern" SSH
  guidance' as the source. Checked against both, that was only partly right,
  and the comment now says what the lists actually follow; see
  [SSH algorithm allow-lists](#ssh-algorithm-allow-lists).
- The ICMP redirect and martian-logging parameters were added on 2026-07-01 in
  commit `5a13797a`, whose subject says they are there "for CIS 3.2.2-3.2.4".
- The faillock `deny` and pwhistory `remember` checks were added the same day
  in commit `0fdfaa82`, "for CIS 5.3.2/5.3.3".
- `xinetd` joined the services list the same day in commit `cb8b9f19`, "for
  CIS 2.1.1".
- `/etc/passwd`, `/etc/group`, `/etc/shadow` and `/etc/gshadow` joined the
  permissions table the same day in commit `001f6d1b`, "for CIS 6.1.2-6.1.5".
  Its message gives the reason for the two comparisons: the shadow files use a
  mask "so a stricter mode (0000 on RHEL) is compliant and apply never loosens
  perms", and the other two are exact 0644.
- On 2026-09-02 commit `87351654` added the audit backlog settings, scoped the
  busy perm-mod and delete rules to logged-in users and dropped their 32-bit
  copies, after measuring lost events on a build host; see
  [Audit rules](#audit-rules).
- The audit rules carry a comment saying they are "based on CIS Benchmark and
  NIS2 compliance requirements", and the permissions table one saying "Based on
  CIS Benchmark and security best practices". Neither names a version or a
  section. NIS2, the EU directive, is not one of the ten frameworks the reports
  cover.

Compliance mappings were first wired into all eight plugins on 2025-11-26, in
commit `6596a550`, a few days after the first values. From 2026-06-20, in
commit `61fc9fa0`, they were re-sourced from the rule references in
ComplianceAsCode, the project that writes the SCAP Security Guide content
OpenSCAP scans with. A mapping says which control a check relates to. It does
not say where the check's number came from, and in several places the control
asks for a different number, or for more than the check measures, as
[a later section](#where-a-pass-and-the-control-disagree) shows.

Severities have no recorded rationale anywhere. They are the project's
judgement.

### Closest matches among the guides

Some values match one guide edition exactly, although nothing records that
they were taken from it. These are matches, not sources:

- **Password length and reuse.** `minlen` 14 and `remember` 5 are the values of
  the CIS Benchmarks for Red Hat Enterprise Linux 7 (v3.1.1) and 8 (v1.0.1 and
  v2.0.0), as ComplianceAsCode encodes them. The RHEL 7 edition also accepts
  one character from each class, the four credit settings, in place of
  `minclass` 4, and its expiry control is titled "Ensure password expiration is
  365 days or less", word for word the title in the code. Later editions moved
  on: CIS RHEL 8 v4.0.0 and RHEL 10 v1.0.1 ask for `remember` 24.
- **Password expiry.** `PASS_MAX_DAYS` 90 matches no CIS edition read, all of
  which say 365. The only guide read that says 90 is PCI DSS 8.3.9, and only for
  a password that is the single factor.
- **SSH algorithms.** The key-exchange list is ssh-audit's "Hardened OpenSSH
  Server v9.9" policy without `diffie-hellman-group-exchange-sha256` and the
  older spelling of the sntrup method, and the MAC list holds the same three
  methods as that policy. The cipher list is the authenticated-encryption part
  of it.

### Choosing a value from now on

There is no written rule yet for choosing between guides where they disagree.
Until there is one, a change is decided on the evidence its proposal brings;
[Proposing a change](#proposing-a-change) lists what that evidence is.

What *is* written down, and enforced in code, is how a value is compared rather
than which value is chosen:

- **Every comparison has a direction**, so a host that is already stricter than
  the baseline is neither reported nor loosened
  (`crates/hardener-plugins/src/strictness.rs`). File permissions are one
  exception, described [below](#file-permissions). The other is at the bottom
  of the scale: for three settings, faillock `deny`, `PASS_MAX_DAYS` and
  `ClientAliveCountMax`, the value that switches the check off counts as the
  strictest of all; see
  [A value that switches the check off](#a-value-that-switches-the-check-off).
- **A `directives` override can only tighten a value**, as the code ranks it.
  One that would loosen it is ignored. For those three settings, an override
  that switches the check off is taken as a tightening and written to the
  host.
- **SSH algorithm lists are cut down to what the host's own OpenSSH supports**,
  so `sshd` is never handed a name it cannot parse, and `sshd -t` checks the
  result before it is installed.
- **Two guards stop a remote apply from cutting off its own connection.**
  `PermitRootLogin` is written as `prohibit-password` rather than `no` when the
  apply arrives over a root SSH session, and the firewall refuses a ruleset with
  no SSH accept rule when the apply arrives over SSH.

---

## How the baseline fits with the rest of the tool

**The values are the same on every distribution.** The plugins do not depend on
the distribution-detection crate, so nothing on this page changes with the
distribution. What does change is where a value is written and whether it can
be: openSUSE keeps its vendor files under `/usr/etc`, Arch builds shadow without
a minimum password age, and the cracklib dictionary sits in a different place on
Debian. The tables note these where they matter.

**A compliance profile changes identifiers, never values.** `--profile`, and the
RHEL 10 profile chosen automatically on RHEL 10 family hosts, translate the
control identifiers a report prints. A report that names DISA RHEL 10 STIG
identifiers still judges the host by the values on this page. Those
identifiers were taken from the RHEL 10 STIG V1R1. V1R3, dated 30 September
2026, is current: it still has every identifier the profile uses, but its
password lifetime rule, `RHEL-10-600100`, now asks for 180 days where the title
in the code still says 60.

**A Pass means the host meets this page's value.** A control passes when a
plugin assesses it and finds nothing wrong, and "wrong" means weaker than the
value in the tables below. Where a control's own text asks for a different
number, the Pass is still judged against the baseline. That cuts both ways:

- Where the baseline is **stricter** than the control, a host that meets the
  control can still fail it in the report. The RHEL 8 STIG's password lifetime
  rule, `RHEL-08-020200`, asks for 180 days at most, and the baseline asks for
  90, so a host at 120 days fails that STIG control in the report.
- Where the baseline is **weaker** than the control, or the control asks for
  more than the check measures, a host passes a control it does not meet. The
  cases found so far are listed in the next section, with two more kinds: a
  host that has switched a check off, and a control that asks for one exact
  value the baseline goes past.

**Directives tighten, exceptions loosen, scope excludes.**

- `[<plugin>.directives]` changes a target, but only towards stricter, as the
  code ranks it. The [configuration reference](configuration.md) has the rule
  for each plugin, and
  [A value that switches the check off](#a-value-that-switches-the-check-off)
  the three settings where the code's ranking is wrong.
- `[<plugin>.exceptions]` is how a host records a deliberately weaker value. It
  does not change the baseline. The finding stays, labelled with the reason, and
  the compliance report counts the control as satisfied while listing the
  finding as evidence.
- `hardener scope exclude` marks a control as not applicable to a host. It never
  changes a value, and it cannot turn a failure into a pass.
- `hardener scan --audit` ignores the configuration entirely and measures the
  host against the baseline exactly as listed here.
- A plugin disabled in the configuration assesses nothing, so every control it
  covers shows as Manual Review.

---

## Where a Pass and the control disagree

A report can show **Pass** for a host that does not do what a control's own
text asks. There are four ways this happens, and each has a table below:

- The control asks for a stricter value than the baseline.
- The control asks for something the check does not measure.
- The host has switched the check off, with a value the code counts as the
  strictest of all.
- The control asks for one exact value and the baseline goes past it, so a
  DISA or OpenSCAP check of the same control reports a finding where this tool
  reports a Pass.

These are the cases found so far. Expect more: nobody has yet compared every
mapped control with its full text.

Each row names the check, the control identifier the plugin maps it to, and
the identifier the same control gets under the RHEL 10 profile. The "What the
control asks" column says under which profile the gap shows. The STIG values
were read in the RHEL 8 STIG V2R9 and the RHEL 10 STIG V1R3, the CIS values in
ComplianceAsCode's encodings of the CIS Benchmarks, and the PCI DSS ones in its
transcription of PCI DSS v4.0.1; see [Sources](#sources).

**Which CIS text a row rests on.** The tool's own CIS identifiers follow the
CIS Distribution Independent Linux numbering, whose text was not read here.
Where a row says "under the RHEL 10 profile", the gap was read in
ComplianceAsCode's encoding of CIS RHEL 10 v1.0.1. Its encoding of the older
CIS RHEL 8 v2.0.0 asks the same under numbers of its own: 6.1.3 to 6.1.6 for
the four account files, 1.6.1.5 for the SELinux mode and 4.1.2.1 for the audit
log size. Only the last shares its number and its title with the tool's own
identifier, so only the audit row says "under both profiles" for a CIS control.

### The control asks for a stricter value

<!-- baseline-table: weaker-pass -->

| Check | Control the plugin maps | Under the RHEL 10 profile | What the control asks | What the baseline accepts |
|---|---|---|---|---|
| `minlen` | STIG `RHEL-08-020230` | STIG `RHEL-10-600220` | A minimum length of 15 characters, under both profiles | `14` or more |
| `deny` | STIG `RHEL-08-020011` | STIG `RHEL-10-600410` | Lock the account after 3 failed attempts, under both profiles | `5` or fewer |
| `Ciphers` | STIG `RHEL-08-010291` | STIG `RHEL-10-300040` | Ciphers limited to aes256-gcm, aes256-ctr, aes128-gcm and aes128-ctr, set through the system's FIPS crypto policy, under both profiles | allows `chacha20-poly1305@openssh.com` |
| `MACs` | STIG `RHEL-08-010290` | STIG `RHEL-10-300060` | MACs limited to hmac-sha2-512-etm, hmac-sha2-256-etm, hmac-sha2-512 and hmac-sha2-256, set through the FIPS crypto policy, under both profiles | allows `umac-128-etm@openssh.com` |
| `remember` | CIS `5.3.3` | CIS `5.3.2.3.1` | Under the RHEL 10 profile, remember at least 24 previous passwords. The title under the default profile names no number | `5` or more |
| `/etc/shadow` | CIS `6.1.3` | CIS `7.1.5` | Under the RHEL 10 profile, mode 0000, from the ComplianceAsCode rule its CIS RHEL 10 v1.0.1 encoding uses. The same rule gives Debian, Ubuntu and SUSE 0640 | no bits beyond `0640` |
| `/etc/gshadow` | CIS `6.1.5` | CIS `7.1.7` | As for `/etc/shadow` | no bits beyond `0640` |

The STIG checks for ciphers and MACs read the system crypto policy, while the
plugin writes `sshd_config`, so those two rows compare different mechanisms as
well as different lists.

### The control asks for more than the check measures

<!-- baseline-table: unmeasured-pass -->

| Check | Control the plugin maps | Under the RHEL 10 profile | What the control asks | What the check measures |
|---|---|---|---|---|
| `deny` | CIS `5.3.2` | CIS `5.3.2.1.2` | Under the RHEL 10 profile, a faillock unlock time of 900 seconds. The profile maps the `deny` check to this control as well as to 5.3.2.1.1 | `deny` only. `unlock_time` is never read |
| `X11Forwarding` | CIS `5.2.6` | CIS `5.1.8` | Under the RHEL 10 profile, `DisableForwarding yes`, which also turns off agent, TCP and StreamLocal forwarding. The title under the default profile asks for X11 only | `X11Forwarding` only |
| `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` | CIS `6.1.2`, `6.1.4`, `6.1.3`, `6.1.5` | CIS `7.1.1`, `7.1.3`, `7.1.5`, `7.1.7` | Under the RHEL 10 profile, the owner and group as well as the mode, in ComplianceAsCode's CIS RHEL 10 v1.0.1 encoding: owner root and group root. The same rules give `/etc/shadow` the shadow group on Debian, Ubuntu and SUSE | The mode only. The owner and group in the code's table are never read |
| `rules` | CIS `4.1.2.1` | CIS `6.3.2.1` | `max_log_file` set in `auditd.conf`, under both profiles. The tool's own title for 4.1.2.1 is "Ensure audit log storage size is configured", and ComplianceAsCode encodes CIS RHEL 10 6.3.2.1 and CIS RHEL 8 v2.0.0 4.1.2.1 with the same rule, at 8 MB and 6 MB | That some loaded rule contains each category's name. `auditd.conf` is never read, and the rule text is not compared; see [Audit rules](#audit-rules) |
| `selinux-not-enforcing` | CIS `1.6.1.4` | CIS `1.3.1.5` | Under the RHEL 10 profile, `SELINUX=enforcing` in `/etc/selinux/config`, so the host boots enforcing, as ComplianceAsCode's `selinux_state` rule checks it for CIS RHEL 10 v1.0.1 | The running mode only, through `getenforce`. Apply runs `setenforce 1`, which a reboot undoes, so the control passes until the next boot |
| `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE` | CIS `5.4.1.1`, `5.4.1.2`, `5.4.1.3` | CIS `5.4.1.1`, `5.4.1.2`, `5.4.1.3` | Under the RHEL 10 profile, the same limits on every existing account in `/etc/shadow`, not only the defaults `login.defs` gives new accounts | `/etc/login.defs` only |
| `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE` | NIST `IA-5(1)(d)`, FedRAMP `IA-5(1)(d)` | unchanged, since the profile only translates STIG and CIS | In SP 800-53 Rev 5, IA-5(1)(d) is "Store passwords using an approved salted key derivation function", and no item of IA-5(1) covers password lifetime. The label comes from ComplianceAsCode's references for its ageing rules, which still cite IA-5(1)(d) | Password ageing in `login.defs`. Nothing checks how passwords are stored |
| `minlen`, `dcredit`, `ucredit`, `lcredit` | PCI DSS `8.2.3` | unchanged, since the profile only translates STIG and CIS | In PCI DSS v4.0.1, 8.2.3 is "Additional requirement for service providers only: Service providers with remote access to customer premises use unique authentication factors for each customer premises". Password complexity is 8.3.6 | Password length and character classes |
| `deny` | PCI DSS `8.1.6` | unchanged, since the profile only translates STIG and CIS | PCI DSS v4.0.1 has no 8.1.6. Locking out after repeated failures is 8.3.4, which allows at most 10 attempts | `deny` in `faillock.conf` |
| `PASS_MAX_DAYS`, `PASS_WARN_AGE` | PCI DSS `8.2.4` | unchanged, since the profile only translates STIG and CIS | In PCI DSS v4.0.1, 8.2.4 is "Addition, deletion, and modification of user IDs, authentication factors, and other identifier objects are managed". A limited password lifetime is 8.3.9, and only where the password is the single factor | Password ageing in `login.defs`. Nothing checks how user IDs are managed |

The same `rules` finding is the only evidence for every other control the
audit plugin maps to its rules, among them NIST `AU-12(c)` and PCI DSS
`10.2.7`, so they pass on the same category-name test.

The three PCI DSS numbers are those of an older edition. They come from
ComplianceAsCode's `pcidss` rule references (`Req-8.2.3`, `Req-8.1.6` and
`Req-8.2.4`). ComplianceAsCode's PCI-DSS v3.2.1 profile for RHEL 8 was built on
those references, with 7 characters, 6 attempts and 90 days, and the titles in
the code, such as "Change user passwords/passphrases at least once every 90
days", fit those requirements rather than the v4.0.1 ones. The code says it
uses v4.0 numbers, and `SECURITY.md` says the reports map to PCI-DSS v4.0, so a
PCI DSS report prints these three as Passes against requirements that, in the
current edition, are about something else.

The SELinux check also maps the Oracle Linux 8 STIG rule `OL08-00-010170`,
which is not listed because its text was not read. Its RHEL 8 counterpart,
`RHEL-08-010170`, checks the running mode with `getenforce`, as the plugin
does, and sets the boot setting only in its fix.

### A value that switches the check off

Each of these settings is compared *at most*, so the code ranks 0, and every
negative number, as the strictest values the setting can hold. For these three,
that end of the scale switches the check off. A host set that way passes, and a
`directives` override set that way is written to the host as a tightening.

<!-- baseline-table: switched-off-pass -->

| Check | Control the plugin maps | Under the RHEL 10 profile | What the control asks | What the check accepts |
|---|---|---|---|---|
| `deny` | STIG `RHEL-08-020011`, CIS `5.3.2` | STIG `RHEL-10-600410`, CIS `5.3.2.1.1` | A lockout after repeated failures. The STIG's check text says 3 or fewer "(but not "0")", and `pam_faillock` locks an account only when `deny` is not 0 | `0`, ranked stricter than `5`, so lockout is off and the host passes |
| `PASS_MAX_DAYS` | STIG `RHEL-08-020200`, CIS `5.4.1.1` | STIG `RHEL-10-600100`, CIS `5.4.1.1` | A maximum password lifetime: 180 days in the STIG, 365 in the CIS encoding. `login.defs(5)` says -1 "disables the restriction". The STIG's check text flags only a value above 180 or a missing line, so it would miss -1 too | `-1`, ranked stricter than `90`, so passwords never expire and the host passes |
| `ClientAliveCountMax` | CIS `5.2.13`, HIPAA `164.312(a)(2)(iii)`, NIST `AC-17(a)` | CIS `5.1.7` | An idle timeout that ends the session. `sshd_config(5)`: "Setting a zero ClientAliveCountMax disables connection termination" | `0`, ranked stricter than `2`, so an idle session is never cut and the host passes |

The code's own comment on `ClientAliveCountMax` reads "Zero disconnects on the
first one, which is the strict end rather than a disable", which the OpenSSH
manual contradicts. `ClientAliveInterval` and `maxrepeat` already rank 0 as the
weakest value, through *at most, not 0*. A fix for the two PAM rows is being
prepared with [#190](https://github.com/tidynest/linux-hardener/issues/190);
the SSH row has none yet.

### The control asks for an exact value the baseline goes past

<!-- baseline-table: exact-value-pass -->

| Check | Control the plugin maps | Under the RHEL 10 profile | What the control asks | What the baseline accepts |
|---|---|---|---|---|
| `kernel.kptr_restrict` | STIG `RHEL-08-040283` | STIG `RHEL-10-701060` | Exactly 1, under both profiles: "If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding" | `2` or more |
| `kernel.yama.ptrace_scope` | STIG `RHEL-08-040282` | STIG `RHEL-10-701140` | Exactly 1, under both profiles: the RHEL 8 check text says "is not set to "1"", and the RHEL 10 one "is not equal to "1"" | `2` or more |

Here the baseline is stricter than the control, and the tool's STIG report
says Pass for a host at 2, while the STIG's own check, and an OpenSCAP scan
that follows it, report a finding for the same host. The ComplianceAsCode rule
behind CIS RHEL 10 1.5.7 sets `ptrace_scope` to 1 as well, and lists 1, 2 or 3
only for Ubuntu 24.04; how its check compares the value was not read.

Each row in these four tables is a decision for whoever changes it: raise the
baseline to the control's value, measure what the check leaves out, fix the
comparison, or stop mapping the check to that control. Each is a change to
propose as described [below](#proposing-a-change). Until then, README lists
this under its known limitations.

---

## How to read the tables

- **Default** is the value the plugin compares the host against and, where it
  changes anything, writes. The audit rules are the exception: apply writes the
  rule text shown, but scan compares only the category name, as
  [Audit rules](#audit-rules) explains.
- **Comparison** is the direction in which a value counts as stricter.
  - *at least*: larger is stricter.
  - *at most*: smaller is stricter, all the way down, so 0 and negative
    numbers count as the strictest values. Where one of those switches the
    setting off, that is wrong; see
    [A value that switches the check off](#a-value-that-switches-the-check-off).
  - *at most, not 0*: smaller is stricter, but 0 switches the check off, so it
    counts as the weakest value of all.
  - *ranked*: a fixed order, weakest first, for settings whose strictness the
    number or word does not carry. `rp_filter` is the clearest case: 2 (loose
    mode) is weaker than 1 (strict mode).
- **Severity** is how a failing host is scored.
- **Where the value comes from** is what the code or its history records. "No
  source recorded" means exactly that.
- **What the guides say** gives the same setting in the guides under
  [Sources](#sources), with the identifier of the rule that says it. A guide
  missing from a row was either not checked for that setting or has no rule for
  it. These are the guides' values, not the tool's.

Short names used in the tables:

- **STIG** is the DISA RHEL 8 STIG V2R9, unless a `RHEL-09-` identifier shows
  the RHEL 9 STIG V2R10 was the one read. The canonical STIG identifiers the
  plugins emit are the RHEL 8 ones.
- **CIS RHEL 10** is the CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1, as
  ComplianceAsCode encodes it. The tool's own CIS identifiers follow the older
  CIS Distribution Independent Linux numbering, so they differ from the ones
  quoted here unless the RHEL 10 profile is active. **CIS RHEL 7** and **CIS
  RHEL 8** name older editions, also as ComplianceAsCode encodes them, with the
  version given in the row.
- **KSPP** is the Kernel Self Protection Project's recommended settings.
- **800-63B-4** is NIST Special Publication 800-63B-4.
- **PCI DSS** is PCI DSS v4.0.1, as ComplianceAsCode transcribes it.

---

## Kernel parameters

The kernel plugin writes each value to `/proc/sys` and to
`/etc/sysctl.d/99-hardener.conf`, keeping the host's own value wherever it is
already stricter. The table in the code is `KERNEL_PARAMS` in
`crates/hardener-plugins/src/kernel/mod.rs`.

<!-- baseline-table: kernel -->

| Setting | Default | Comparison | Severity | Where the value comes from | What the guides say |
|---|---|---|---|---|---|
| `kernel.randomize_va_space` | `2` | at least | High | No source recorded (2025-11) | STIG RHEL-08-010430: 2. KSPP: 2. |
| `kernel.kptr_restrict` | `2` | at least | Medium | No source recorded (2025-11) | STIG RHEL-08-040283: exactly 1, so a STIG check reports 2 as a finding. KSPP: 2, or 1 "if root absolutely needs values from /proc". The baseline matches KSPP and is stricter than the STIG. |
| `kernel.dmesg_restrict` | `1` | at least | Medium | No source recorded (2025-11) | STIG RHEL-08-010375: 1. KSPP: 1. |
| `kernel.yama.ptrace_scope` | `2` | at least | High | No source recorded (2025-11) | STIG RHEL-08-040282: exactly 1, so a STIG check reports 2 as a finding. KSPP: 3, or 1 where ptrace is needed. The ComplianceAsCode rule behind CIS RHEL 10 1.5.7 sets 1, and accepts 1, 2 or 3 on Ubuntu 24.04. The baseline sits between the STIG and KSPP, and a host at 3 is left at 3. |
| `fs.suid_dumpable` | `0` | ranked, weakest first: `1`, `2`, `0` | Medium | No source recorded (2025-11) | KSPP: 0. CIS RHEL 10 1.5.4 has a control for it. |
| `fs.protected_hardlinks` | `1` | at least | Medium | No source recorded (2025-11) | STIG RHEL-08-010374: 1. KSPP: 1. |
| `fs.protected_symlinks` | `1` | at least | Medium | No source recorded (2025-11) | STIG RHEL-08-010373: 1. KSPP: 1. |
| `net.ipv4.conf.all.rp_filter` | `1` | ranked, weakest first: `0`, `2`, `1` | High | No source recorded (2025-11) | STIG RHEL-08-040285: 1. CIS RHEL 10 3.3.1.12: enabled. KSPP has no network settings. |
| `net.ipv4.conf.default.rp_filter` | `1` | ranked, weakest first: `0`, `2`, `1` | High | No source recorded (2025-11) | STIG RHEL-08-040287: 1. |
| `net.ipv4.tcp_syncookies` | `1` | at least | High | No source recorded (2025-11) | RHEL 9 STIG RHEL-09-253010 requires them. CIS RHEL 10 3.3.1.18: enabled. |
| `net.ipv4.conf.all.accept_source_route` | `0` | at most | Medium | No source recorded (2025-11) | RHEL 9 STIG RHEL-09-253020: 0. CIS RHEL 10 3.3.1.14: disabled. |
| `net.ipv4.conf.default.accept_source_route` | `0` | at most | Medium | No source recorded (2025-11) | RHEL 9 STIG RHEL-09-253045: 0. |
| `net.ipv4.conf.all.accept_redirects` | `0` | at most | Medium | Commit `5a13797a` (2026-07-01), "for CIS 3.2.2-3.2.4" | STIG RHEL-08-040279: 0. CIS RHEL 10 3.3.1.8: disabled. |
| `net.ipv4.conf.default.accept_redirects` | `0` | at most | Medium | Commit `5a13797a` (2026-07-01), "for CIS 3.2.2-3.2.4" | STIG RHEL-08-040209: 0. |
| `net.ipv4.conf.all.secure_redirects` | `0` | at most | Medium | Commit `5a13797a` (2026-07-01), "for CIS 3.2.2-3.2.4" | CIS RHEL 10 3.3.1.10: disabled. |
| `net.ipv4.conf.default.secure_redirects` | `0` | at most | Medium | Commit `5a13797a` (2026-07-01), "for CIS 3.2.2-3.2.4" | As for the `all` row. |
| `net.ipv4.conf.all.log_martians` | `1` | at least | Low | Commit `5a13797a` (2026-07-01), "for CIS 3.2.2-3.2.4" | RHEL 9 STIG RHEL-09-253025 requires it. CIS RHEL 10 3.3.1.16: enabled. |
| `net.ipv4.conf.default.log_martians` | `1` | at least | Low | Commit `5a13797a` (2026-07-01), "for CIS 3.2.2-3.2.4" | RHEL 9 STIG RHEL-09-253030 requires it. |

Not in the baseline: the IPv6 counterparts of the redirect and source-routing
settings, which the RHEL 9 STIG covers (RHEL-09-254015, RHEL-09-254020,
RHEL-09-254035 and RHEL-09-254040), and the KSPP settings this plugin does not
manage, among them `kernel.unprivileged_bpf_disabled`,
`kernel.kexec_load_disabled`, `kernel.perf_event_paranoid`,
`fs.protected_fifos` and `fs.protected_regular`.

---

## SSH server

The SSH plugin writes the main `sshd_config`, or a drop-in where the main file
cannot win, and checks the candidate with `sshd -t` before anything is
committed. The tables in the code are `SSH_DIRECTIVES` and
`SSH_CRYPTO_DIRECTIVES` in `crates/hardener-plugins/src/ssh/mod.rs`.

**Before you apply, make sure a key login works.** `PasswordAuthentication no`
and `KbdInteractiveAuthentication no` are applied without checking that any
account has a working key, so a host reached only by password stops accepting
new logins.

<!-- baseline-table: ssh -->

| Setting | Default | Comparison | Severity | Where the value comes from | What the guides say |
|---|---|---|---|---|---|
| `PermitRootLogin` | `no` | ranked, weakest first: `yes`, `prohibit-password`, `without-password`, `forced-commands-only`, `no` | Critical | No source recorded (2025-11) | STIG RHEL-08-010550: no. CIS RHEL 10 5.1.20 has a control for it. Mozilla Modern: No. `prohibit-password` and `without-password` are two spellings of one rank. Over a root SSH session the apply writes `prohibit-password`, and the next scan still reports the gap. |
| `PasswordAuthentication` | `no` | ranked, weakest first: `yes`, `no` | Critical | No source recorded (2025-11) | Mozilla Modern: public-key logins only, through `AuthenticationMethods publickey`. |
| `KbdInteractiveAuthentication` | `no` | ranked, weakest first: `yes`, `no` | Critical | Added 2026-11-13 for issue #186, so a password cannot log in through keyboard-interactive once `PasswordAuthentication` is off. Left alone where `AuthenticationMethods` only lets keyboard-interactive act as a second factor | No rule names it in the RHEL 8, 9 or 10 STIGs or the CIS RHEL 10 encoding read here. Mozilla Modern allows public-key logins only, through `AuthenticationMethods publickey`; Mozilla's multi-factor configuration turns it on as a second factor after a key, through `AuthenticationMethods publickey,keyboard-interactive:pam`. |
| `PermitEmptyPasswords` | `no` | ranked, weakest first: `yes`, `no` | Critical | No source recorded (2025-11) | STIG RHEL-08-020330: no. CIS RHEL 10 5.1.19 has a control for it. |
| `MaxAuthTries` | `3` | at most | Medium | No source recorded (2025-11) | CIS RHEL 10 5.1.16: 4, and the CIS title in the code reads "4 or less". The baseline is stricter. |
| `X11Forwarding` | `no` | ranked, weakest first: `yes`, `no` | Medium | No source recorded (2025-11) | STIG RHEL-08-040340: no. CIS RHEL 10 5.1.8 asks for `DisableForwarding`, which covers all forwarding, and the RHEL 10 profile maps this check to it, so that Pass rests on X11 alone. |
| `ClientAliveInterval` | `300` | at most, not 0 | Low | No source recorded (2025-11) | STIG RHEL-08-010201: 600. CIS RHEL 10 5.1.7 leaves the value to site policy, according to ComplianceAsCode's notes, and its encoding uses 5 minutes. The baseline is stricter than the STIG. |
| `ClientAliveCountMax` | `2` | at most | Low | No source recorded (2025-11) | STIG RHEL-08-010200: 1, which is stricter than the baseline. The plugin maps no STIG control to this setting, so no STIG Pass rests on it. ComplianceAsCode's encoding of CIS RHEL 10 5.1.7 also uses 1, while its notes say the benchmark is flexible about the values. `sshd_config(5)`: 0 "disables connection termination", which the *at most* comparison counts as stricter than 2; see [A value that switches the check off](#a-value-that-switches-the-check-off). |

### SSH algorithm allow-lists

These are allow-lists, not fixed values. The value written is the list below
intersected with what `ssh -Q` says the host supports, in the order shown. If
the host supports none of them, the directive is left alone rather than given a
value `sshd` cannot parse.

<!-- baseline-table: ssh-crypto -->

| Directive | Allow-list, in preference order | Severity | Where the value comes from | What the guides say |
|---|---|---|---|---|
| `KexAlgorithms` | `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, `curve25519-sha256`, `curve25519-sha256@libssh.org`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512` | High | Commit `7b0d6b58` (2026-06-20). Closest published list, though none is recorded: ssh-audit's Hardened OpenSSH Server v9.9 policy, less `diffie-hellman-group-exchange-sha256` and the `@openssh.com` spelling of sntrup | ssh-audit's v9.9 policy: the same methods plus those two, with sntrup ahead of mlkem. OpenSSH 10.0 server default: the same two post-quantum hybrids and curve25519, then the NIST curves ecdh-sha2-nistp256, -nistp384 and -nistp521, which the baseline leaves out. OpenSSH 10.0 moved the finite-field diffie-hellman groups to the client side only; the baseline keeps group16 and group18 as a fallback for hosts that lack the newer methods. ssh-audit's Hardened OpenSSH Server v10.4 policy: the two hybrids alone. Mozilla Modern, written for OpenSSH 6.7: curve25519, the NIST curves and diffie-hellman-group-exchange-sha256, with no post-quantum method. |
| `Ciphers` | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` | High | Commit `7b0d6b58` (2026-06-20). Authenticated encryption only | OpenSSH 10.0 default, ssh-audit's v10.4 policy and Mozilla Modern all add the AES-CTR modes. STIG RHEL-08-010291 allows aes256-gcm, aes256-ctr, aes128-gcm and aes128-ctr only, so not ChaCha20. |
| `MACs` | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `umac-128-etm@openssh.com` | Medium | Commit `7b0d6b58` (2026-06-20). Encrypt-then-MAC only | Identical to ssh-audit's v10.4 policy, and the same three as its v9.9 policy in another order. The OpenSSH 10.0 default also allows umac-64, the non-ETM forms and hmac-sha1. Mozilla Modern adds the non-ETM SHA-2 and UMAC forms. STIG RHEL-08-010290 allows the two SHA-2 ETM forms and the two non-ETM SHA-2 forms, so not UMAC. |

The comment above these lists in the code named 'OpenSSH 10 defaults and
Mozilla "Modern" SSH guidance' as their source until 2026-11-15. Neither
matches. The lists are closest to ssh-audit's Hardened OpenSSH Server v9.9
policy, whose key exchange keeps curve25519 and two finite-field groups as
fallbacks, as this one does; ssh-audit's policies for OpenSSH 10 drop them.
Nothing records that the lists were taken from it, and the order points the
other way: the baseline puts mlkem ahead of sntrup and orders its MACs as
ssh-audit's OpenSSH 10 policies do, where v9.9 has both the other way round. So
this is a match, not a source. A host held to the RHEL STIGs cannot meet their
cipher and MAC rules with these lists as they stand.

---

## PAM and password ageing

Two open issues are discussing values in this section:
[#190](https://github.com/tidynest/linux-hardener/issues/190) asks about
password expiry and long passphrases, and
[#191](https://github.com/tidynest/linux-hardener/issues/191) about how
passwords are hashed, which the baseline does not cover today. The rows below
describe the code as it stands, not the outcome of either discussion.

The `pwquality.conf` values take effect only when `pam_pwquality` is in the PAM
stack, and the `faillock.conf` and `pwhistory.conf` values only when their
modules are. Where a module is missing, the plugin reports the setting as not
enforced rather than writing a value nothing reads. The same goes for
`PASS_MIN_DAYS` on Arch, whose shadow build has no minimum password age. The
table in the code is `PAM_DIRECTIVES` in
`crates/hardener-plugins/src/pam/mod.rs`.

<!-- baseline-table: pam -->

| Setting | Default | Comparison | Severity | Where the value comes from | What the guides say |
|---|---|---|---|---|---|
| `minlen` | `14` | at least | High | No source recorded (2025-11-22) | CIS RHEL 10 5.3.2.2.2: 14, as in CIS RHEL 7 v3.1.1 5.4.1 and CIS RHEL 8 v1.0.1 and v2.0.0. STIG RHEL-08-020230: 15. 800-63B-4: at least 15 where the password is the only factor, and at least 8 where it is one of several. PCI DSS 8.3.6: 12. |
| `dcredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020130: -1, at least one digit. CIS RHEL 10 5.3.2.2.3 asks for complexity through `minclass`, encoded as 4. CIS RHEL 7 v3.1.1 5.4.1 gives one character of each class, the four credit settings, as the other way to meet it. PCI DSS 8.3.6: digits and letters. 800-63B-4: verifiers "SHALL NOT impose other composition rules". |
| `ucredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020110: -1, at least one capital. Otherwise as for `dcredit`. |
| `lcredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020120: -1, at least one lower-case letter. Otherwise as for `dcredit`. |
| `ocredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020280: -1, at least one special character. Otherwise as for `dcredit`. |
| `maxrepeat` | `3` | at most, not 0 | Low | No source recorded (2025-11-22) | STIG RHEL-08-020150: 3. CIS RHEL 10 5.3.2.2.4 has a control for it. |
| `PASS_MAX_DAYS` | `90` | at most | Medium | No source recorded (2025-11-22) | `login.defs(5)`: -1 disables the restriction, which the *at most* comparison counts as stricter than 90; see [A value that switches the check off](#a-value-that-switches-the-check-off). STIG RHEL-08-020200: 180 in V2R9; the title in the code still reads 60 days. CIS RHEL 10 5.4.1.1: 365, as in every CIS edition read. The NIST and FedRAMP label in the code, IA-5(1)(d), comes from ComplianceAsCode's references, but in SP 800-53 Rev 5 that item is about storing passwords, and no item of IA-5(1) covers password lifetime. PCI DSS 8.3.9: 90, only where the password is the single factor, and dynamic risk analysis is allowed instead. 800-63B-4: verifiers "SHALL NOT require subscribers to change passwords periodically", and must force a change on evidence of compromise. |
| `PASS_MIN_DAYS` | `1` | at least | Low | No source recorded (2025-11-22) | STIG RHEL-08-020190: 1. CIS RHEL 10 5.4.1.2: 1. Not enforceable on Arch. |
| `PASS_WARN_AGE` | `7` | at least | Low | No source recorded (2025-11-22) | CIS RHEL 10 5.4.1.3: 7. |
| `deny` | `5` | at most | High | Commit `0fdfaa82` (2026-07-01), "for CIS 5.3.2/5.3.3" | CIS RHEL 10 5.3.2.1.1: 5. STIG RHEL-08-020011: 3, "but not 0", since 0 turns lockout off, which the *at most* comparison counts as stricter than 5; see [A value that switches the check off](#a-value-that-switches-the-check-off). PCI DSS 8.3.4: lock out after no more than 10 attempts. 800-63B-4: no more than 100 consecutive failures. A lower `deny` locks accounts sooner, which is also a way to lock out a legitimate user. |
| `remember` | `5` | at least | Medium | Commit `0fdfaa82` (2026-07-01), "for CIS 5.3.2/5.3.3" | CIS RHEL 10 5.3.2.3.1: 24, as in CIS RHEL 8 v4.0.0. CIS RHEL 7 v3.1.1 5.4.4 and CIS RHEL 8 v1.0.1 and v2.0.0: 5. The RHEL 8 STIG V2R9 and RHEL 9 STIG V2R10 have no password reuse rule. |

---

## Services

The services plugin stops, disables and masks each of these where it is
installed. The code describes the list as services "commonly enabled by default
but not required for typical server operations", and that is the assumption to
check before applying it: a desktop that prints or uses Bluetooth loses both.
The first four entries date from 2025-11-22 with no recorded source, and
`xinetd` joined on 2026-07-01. The table in the code is
`UNNECESSARY_SERVICES` in `crates/hardener-plugins/src/services/mod.rs`.

<!-- baseline-table: services -->

| Service | Severity | Where the value comes from | What the guides say |
|---|---|---|---|
| `bluetooth` | High | No source recorded (2025-11-22) | CIS RHEL 10 3.1.3: not in use. |
| `cups` | Medium | No source recorded (2025-11-22) | CIS RHEL 10 2.1.10: print server services not in use. |
| `avahi-daemon` | Medium | No source recorded (2025-11-22) | CIS RHEL 10 2.1.2: not in use. |
| `ModemManager` | Low | No source recorded (2025-11-22). It carries no compliance mapping | No control for it in the CIS RHEL 10 encoding or the RHEL 8 and RHEL 9 STIGs read here. |
| `xinetd` | Medium | Commit `cb8b9f19` (2026-07-01), "for CIS 2.1.1" | Mapped to CIS 2.1.1 in the older numbering. CIS RHEL 10 v1.0.1 has no xinetd control, so the RHEL 10 profile drops it. |

---

## Firewall

The firewall plugin installs these four rules on an input chain whose policy is
drop, through nftables, firewalld or ufw. The same four rules, with the same
values, arrived on 2025-11-21 with no recorded source, and none of the guides
quoted on this page was compared with them. The rules are built by
`get_baseline_rules` in `crates/hardener-plugins/src/firewall/mod.rs`.

<!-- baseline-table: firewall -->

| Rule | Action | Protocol | Port | Source address | Where the value comes from | Notes |
|---|---|---|---|---|---|---|
| `loopback` | `accept` | `all` | `any` | `127.0.0.1/8` | No source recorded (2025-11-21) | Local traffic. |
| `established` | `accept` | `all` | `any` | `any` | No source recorded (2025-11-21) | Existing connections, including the session an apply runs over. |
| `ssh` | `accept` | `tcp` | `22` | `any` | No source recorded (2025-11-21). Its description in the code is "Allow SSH to prevent lockout" | **The port is fixed at 22.** The plugin does not read the port `sshd` listens on, so a host whose `sshd` listens elsewhere stops accepting new SSH logins after apply unless `[firewall.directives]` sets `ssh.port`. |
| `drop_default` | `drop` | `all` | `any` | `any` | No source recorded (2025-11-21) | Everything else inbound. |

---

## Audit rules

The audit plugin writes these rules to `/etc/audit/rules.d/hardening.rules`
and leaves `auditd.conf` alone. The code says they are "based on CIS Benchmark
and NIS2 compliance requirements" without naming a version or section. The
`-F auid>=1000 -F auid!=unset` filter on the busy families is described in the
code as the CIS scope: it keeps daemons out of the log while every event a
logged-in user causes still lands. The table in the code is `AUDIT_RULES` in
`crates/hardener-plugins/src/audit/mod.rs`.

**Scan does not compare the rule text.** It reads the loaded rules with
`auditctl -l` and counts a category as present when any loaded line contains the
category's name. One rule keyed `identity` therefore satisfies all five identity
rules below, and any line that contains `delete`, such as one watching the
`delete_module` system call, satisfies the deletion rule. Apply writes every
rule exactly as shown. So the Rule column is what apply writes, not what a scan
compares, and a host can pass every audit rule with far less auditing than the
table lists. The compliance controls that rest on this finding are listed
under [Where a Pass and the control disagree](#where-a-pass-and-the-control-disagree).

The file opens with `-b 65536` and `--backlog_wait_time 0`. That is a project
decision with a measurement behind it: on a 16-core build host on 2026-09-02,
auditd's stock backlog of 8192 stayed full and lost over 564,000 events. The
larger queue absorbs bursts, and the zero wait makes an overflow drop events
rather than stall every process that writes one. The same commit, `87351654`,
scoped the perm-mod and delete rules to logged-in users and dropped their
32-bit copies; the 32-bit time-change rule stays.

<!-- baseline-table: audit -->

| Category | Rule | Severity | Where the value comes from |
|---|---|---|---|
| `time-change` | `-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `time-change` | `-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `time-change` | `-a always,exit -F arch=b64 -S clock_settime -k time-change` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `time-change` | `-w /etc/localtime -p wa -k time-change` | Medium | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `identity` | `-w /etc/passwd -p wa -k identity` | Critical | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `identity` | `-w /etc/shadow -p wa -k identity` | Critical | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `identity` | `-w /etc/group -p wa -k identity` | Critical | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `identity` | `-w /etc/gshadow -p wa -k identity` | Critical | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `identity` | `-w /etc/security/opasswd -p wa -k identity` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `network-change` | `-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change` | Medium | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `network-change` | `-w /etc/hosts -p wa -k network-change` | Medium | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `network-change` | `-w /etc/network/ -p wa -k network-change` | Medium | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `perm-mod` | `-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm-mod` | Medium | Code comment: CIS and NIS2 (2025-11-23); scoped to `auid>=1000` on 2026-09-02 in `87351654` |
| `perm-mod` | `-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=unset -k perm-mod` | Medium | Code comment: CIS and NIS2 (2025-11-23); scoped to `auid>=1000` on 2026-09-02 in `87351654` |
| `perm-mod` | `-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -F auid>=1000 -F auid!=unset -k perm-mod` | Medium | Code comment: CIS and NIS2 (2025-11-23); scoped to `auid>=1000` on 2026-09-02 in `87351654` |
| `privileged` | `-w /usr/bin/sudo -p x -k privileged` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `privileged` | `-w /usr/bin/su -p x -k privileged` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `privileged` | `-w /usr/bin/passwd -p wa -k privileged` | Medium | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `delete` | `-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete` | Medium | Code comment: CIS and NIS2 (2025-11-23); scoped to `auid>=1000` on 2026-09-02 in `87351654` |
| `modules` | `-w /sbin/insmod -p x -k modules` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `modules` | `-w /sbin/rmmod -p x -k modules` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |
| `modules` | `-w /sbin/modprobe -p x -k modules` | High | Code comment: CIS and NIS2, no section named (2025-11-23) |

One rule does less than its description in the code says. The `passwd` rule is
described as monitoring execution, but `-p wa` records writes and attribute
changes to the file, not its use: in `auditctl(8)`, `x` is execute, `w` is write
and `a` is attribute change.

---

## File permissions

The permissions plugin checks the mode of each path and nothing else.
**Ownership is not checked**, although the table in the code carries an owner
and a group for every path, and the CIS controls the account files map to ask
for both; see [Where a Pass and the control disagree](#where-a-pass-and-the-control-disagree).
The code says the modes are "Based on CIS Benchmark and security best
practices", with no section named. The first five paths date from 2025-11-23,
and the four account files from 2026-07-01. The table in the code is
`CRITICAL_PERMISSIONS` in `crates/hardener-plugins/src/permissions/mod.rs`.

There are two comparisons:

- *no bits beyond* is a mask: the path passes if it sets no permission bit
  outside the mode shown, so a stricter mode passes, and apply only ever removes
  bits. `/etc/shadow` at `0000`, the Red Hat default, and at `0640`, the Debian
  default, both pass.
- *exact* means any other mode is reported, **a stricter one included**, and
  apply sets the mode shown. On these seven paths that can loosen a host: an
  `/etc/ssh` at `0700` is reported and set to `0755`. This is the one place the
  never-loosen rule does not hold. Commit `001f6d1b` says `/etc/passwd` and
  `/etc/group` are exact 0644 without saying why, and nothing says why the
  first five paths are exact. For files ordinary programs read, such as
  `/etc/passwd`, a narrower mode could break them, so exact may be deliberate
  there, and it is harder to explain for `/root` or `/etc/sudoers`. A
  `directives` override with the stricter mode keeps the host where it is, and
  rollback restores the earlier mode.

<!-- baseline-table: permissions -->

| Path | Mode | Comparison | Severity | Where the value comes from | Notes |
|---|---|---|---|---|---|
| `/root` | `0700` | exact | High | Code comment: CIS and best practice, no section named | |
| `/boot` | `0700` | exact | High | Code comment: CIS and best practice, no section named | |
| `/etc/ssh` | `0755` | exact | High | Code comment: CIS and best practice, no section named | |
| `/etc/sudoers` | `0440` | exact | Critical | Code comment: CIS and best practice, no section named | |
| `/etc/sudoers.d` | `0750` | exact | Critical | Code comment: CIS and best practice, no section named | |
| `/etc/passwd` | `0644` | exact | High | Commit `001f6d1b` (2026-07-01), "for CIS 6.1.2-6.1.5" | CIS RHEL 10 7.1.1 asks for the mode, 0644 in ComplianceAsCode's encoding, and for the owner and group. |
| `/etc/group` | `0644` | exact | High | Commit `001f6d1b` (2026-07-01), "for CIS 6.1.2-6.1.5" | CIS RHEL 10 7.1.3 asks for the mode, owner and group. |
| `/etc/shadow` | `0640` | no bits beyond | Critical | Commit `001f6d1b` (2026-07-01), "for CIS 6.1.2-6.1.5", which chose a mask so 0000 on RHEL passes | CIS RHEL 10 7.1.5 asks for 0000 on Red Hat family systems, in ComplianceAsCode's encoding, and for the owner and group. |
| `/etc/gshadow` | `0640` | no bits beyond | Critical | Commit `001f6d1b` (2026-07-01), "for CIS 6.1.2-6.1.5", which chose a mask so 0000 on RHEL passes | CIS RHEL 10 7.1.7: as for `/etc/shadow`. |

On openSUSE, where a path exists only under `/usr/etc`, the plugin reports the
vendor copy and prints the command that copies it into `/etc`, but never writes
the package-owned file itself.

---

## Mandatory access control

The MAC plugin has one target and no table: **SELinux in enforcing mode**, where
SELinux is present. Scan reads only the running mode, through `getenforce`.
Apply switches it on with `setenforce 1`, which lasts until the next boot; the
finding tells you to set `SELINUX=enforcing` in `/etc/selinux/config` to make it
permanent. Apply never writes that file; it only checkpoints it, and rollback
reads it back to decide which mode to restore. CIS RHEL 10 1.3.1.5,
as ComplianceAsCode checks it, asks for that boot setting rather than the
running mode, so a host that is enforcing only until its next reboot passes it;
see [Where a Pass and the control disagree](#where-a-pass-and-the-control-disagree).
On a host whose files are not correctly labelled, enforcing mode can stop
services from starting, so check the audit log for denials after applying.

AppArmor is reported, not changed: profiles left in complain mode, no profiles
loaded, or no MAC system at all each produce a finding with the steps to take by
hand. Severities in the code are High for SELinux not enforcing and for
AppArmor with no profiles, and Medium for profiles in complain mode and for no
MAC system.

---

## Proposing a change

Proposals are welcome, and this page is the place to start: find the row, and
the columns tell you what the code does today and what is already known about
it. Then open an issue with the **Propose a baseline change** form, or a plain
issue, and include:

1. **The setting**, spelled as in the tables, with its current default and the
   value you propose. For a setting the tables do not hold yet, say so.
2. **The source.** The guide, its version, and the rule or section that asks
   for your value, with a link. A primary source (the benchmark, the standard,
   the upstream project) carries more weight than an article about it.
3. **What it changes on each validated distribution:** Arch, Debian, Ubuntu,
   Fedora, RHEL or Rocky, and openSUSE. Whether each one ships the setting,
   where it lives, and whether a vendor layer gets in the way.
4. **What could break.** Who could be locked out, what could stop working, and
   whether `hardener rollback` puts it right.
5. **What it does to compliance reports:** which mapped controls would move
   between Pass and Fail.
6. **Whether it should be the default for everyone**, or a stricter value people
   choose for themselves. For a setting already in the kernel, SSH, PAM,
   file-permission or firewall tables, a stricter value needs no change at all:
   `directives` sets it today. That does not cover switching a check off: the
   three settings where the code counts that as stricter are a defect, listed
   [above](#a-value-that-switches-the-check-off). The SSH algorithm lists, the services list, the
   audit rules, the SELinux target and any setting not in the tables cannot be
   changed through the configuration, so those need a change to the code. A
   deliberately looser value is recorded as an exception, which keeps it
   visible in every report.

There is no written rule yet for choosing between guides that disagree, so say
why your value is better than the others the row lists, not only which guide
asks for it.

A change that lands updates its row here in the same commit, since
`validate_all.py` fails otherwise, and says in the CHANGELOG what it does to a
host that was already hardened.

---

## Sources

Every guide quoted on this page, with the version read. All were read on
2026-11-15. Each link names the commit or tag that was read, so it shows the
same text later. ComplianceAsCode replaces its copies of the DISA files with
every release, and its `master` was at commit `033b1b8` that day.

- **DISA Red Hat Enterprise Linux 8 STIG, Version 2, Release 9**, benchmark date
  30 September 2026. DISA's XCCDF file as redistributed by ComplianceAsCode:
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/shared/references/disa-stig-rhel8-v2r9-xccdf-manual.xml>
- **DISA Red Hat Enterprise Linux 8 STIG, Version 2, Release 8**, benchmark date
  1 July 2026, the release before, for the 60-day password lifetime, at
  ComplianceAsCode tag `v0.1.82`:
  <https://github.com/ComplianceAsCode/content/blob/v0.1.82/shared/references/disa-stig-rhel8-v2r8-xccdf-manual.xml>
- **DISA Red Hat Enterprise Linux 9 STIG, Version 2, Release 10**, benchmark
  date 30 September 2026, from the same place:
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/shared/references/disa-stig-rhel9-v2r10-xccdf-manual.xml>
- **DISA Red Hat Enterprise Linux 10 STIG, Version 1, Release 3**, benchmark
  date 30 September 2026, for the RHEL 10 profile's identifiers:
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/shared/references/disa-stig-rhel10-v1r3-xccdf-manual.xml>
- **CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1**, as ComplianceAsCode
  encodes it. The benchmark itself needs a CIS account and was not read.
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/products/rhel10/controls/cis_rhel10.yml>
- **Older CIS editions**, as ComplianceAsCode encoded them: Red Hat Enterprise
  Linux 7 v3.1.1 at tag `v0.1.66`, Red Hat Enterprise Linux 8 v1.0.1 at tag
  `v0.1.62` and v2.0.0 at tag `v0.1.66`, and Red Hat Enterprise Linux 8 v4.0.0
  at commit `033b1b8`:
  <https://github.com/ComplianceAsCode/content/blob/v0.1.66/controls/cis_rhel7.yml>,
  <https://github.com/ComplianceAsCode/content/blob/v0.1.62/controls/cis_rhel8.yml>,
  <https://github.com/ComplianceAsCode/content/blob/v0.1.66/controls/cis_rhel8.yml>,
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/products/rhel8/controls/cis_rhel8.yml>
- **ComplianceAsCode rules behind the controls a Pass can fall short of**:
  `file_permissions_etc_shadow`, `file_permissions_etc_gshadow`,
  `file_owner_etc_shadow`, `file_groupowner_etc_shadow`,
  `sshd_disable_forwarding`, `selinux_state`,
  `auditd_data_retention_max_log_file` and
  `accounts_password_set_max_life_existing`, under
  <https://github.com/ComplianceAsCode/content/tree/033b1b8672802ffa6bd555c373e2c73c32d25f5d/linux_os/guide>
- **ComplianceAsCode rule `sysctl_kernel_yama_ptrace_scope`**, for the value
  behind the ptrace controls:
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/linux_os/guide/system/permissions/restrictions/sysctl_kernel_yama_ptrace_scope/rule.yml>
- **ComplianceAsCode's PCI DSS references**: the `pcidss` entries of the rules
  `accounts_password_pam_minlen`, `accounts_passwords_pam_faillock_deny`,
  `accounts_maximum_age_login_defs` and `accounts_password_warn_age_login_defs`
  under
  <https://github.com/ComplianceAsCode/content/tree/033b1b8672802ffa6bd555c373e2c73c32d25f5d/linux_os/guide/system/accounts>,
  and the PCI-DSS v3.2.1 profile for RHEL 8 built on them, at tag `v0.1.66`:
  <https://github.com/ComplianceAsCode/content/blob/v0.1.66/products/rhel8/profiles/pci-dss.profile>
- **NIST SP 800-53 Rev 5, release 5.2.0**, the OSCAL catalogue, last modified
  22 October 2026, for the wording of IA-5(1)(d):
  <https://github.com/usnistgov/oscal-content/blob/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>
- **NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and
  Authenticator Management**, which supersedes SP 800-63B. NIST's HTML edition,
  rendered 26 August 2025:
  <https://github.com/usnistgov/800-63-4/blob/4f2487bb81adecdc84ccaac6920bf0b500b379ae/sp800-63b.html>
- **PCI DSS v4.0.1**, requirements 8.2.3, 8.2.4, 8.3.4, 8.3.6 and 8.3.9, as
  ComplianceAsCode transcribes them:
  <https://github.com/ComplianceAsCode/content/blob/033b1b8672802ffa6bd555c373e2c73c32d25f5d/controls/pcidss_4.yml>
- **Kernel Self Protection Project, Recommended Settings**:
  <https://github.com/KSPP/kspp.github.io/blob/04b2a2c36113730382a58eb46ee1f23adecaff41/Recommended_Settings.md>
- **OpenSSH 10.0p1 default algorithms**, `myproposal.h` at tag `V_10_0_P1`:
  <https://github.com/openssh/openssh-portable/blob/V_10_0_P1/myproposal.h>
- **sshd_config(5)** at tag `V_10_0_P1`, for what a zero `ClientAliveCountMax`
  does:
  <https://github.com/openssh/openssh-portable/blob/V_10_0_P1/sshd_config.5>
- **login.defs(5)**, the `PASS_MAX_DAYS` entry, from the shadow project:
  <https://github.com/shadow-maint/shadow/blob/9d7c2241f59489994ea8a72b47c5e006edd0e61b/man/login.defs.d/PASS_MAX_DAYS.xml>
- **pam_faillock**, whose source locks an account only when `deny` is not 0
  (`if (opts->deny && failures >= opts->deny)`):
  <https://github.com/linux-pam/linux-pam/blob/ad0801a88028397ff31b6e88f9e1fbc8614150ea/modules/pam_faillock/pam_faillock.c>
- **ssh-audit built-in policies**, "Hardened OpenSSH Server v9.9 (version 1)"
  and "Hardened OpenSSH Server v10.4 (version 1)":
  <https://github.com/jtesta/ssh-audit/blob/5c67dd2e431914e24c17ea7bff597c4965b9710c/src/ssh_audit/builtin_policies.py>
- **Mozilla Security Guidelines, OpenSSH**, the "Modern (OpenSSH 6.7+)" and
  "Multi-Factor Authentication" configurations:
  <https://github.com/mozilla/infosec.mozilla.org/blob/92fca1d1b7414113c064ed4c5d8ff7d0441d8dd7/docs/guidelines/openssh.md>
- **auditctl(8)**, from the audit userspace project:
  <https://github.com/linux-audit/audit-userspace/blob/2bfaae30ed11035d03a43b1f3abe3dc822b06b26/docs/auditctl.8>

Guides move. The DISA STIGs are revised every quarter, and the RHEL 8 password
lifetime rule changed from 60 to 180 days in the release quoted here. When a
guide quoted on this page publishes a new release, the rows that quote it need
reading again, and nothing automated will notice.
