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
reads the baseline tables in the plugins and fails the documentation gate when
a default, a comparison or a severity changes without its row here, and when a
check is added or removed without one. What the guides say cannot be checked
that way, so every guide is quoted with its version and the date it was read,
listed under [Sources](#sources).

---

## Contents

- [How the values were chosen](#how-the-values-were-chosen)
- [How the baseline fits with the rest of the tool](#how-the-baseline-fits-with-the-rest-of-the-tool)
- [Where a Pass is weaker than the control](#where-a-pass-is-weaker-than-the-control)
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

The kernel, SSH, PAM and services tables were written between 2025-11-20 and
2025-11-22, in the project's first week. The README of the first commit pointed
to a working catalogue of hardening parameters, `.claude/SECURITY_CONTROLS.md`,
but that file was never committed, so the reasoning behind those first values
cannot be recovered from the repository. None of the original tables cites a
source.

Later additions are better recorded:

- The ICMP redirect and martian-logging parameters were added on 2026-07-01 in
  commit `5a13797a`, whose subject says they are there "for CIS 3.2.2-3.2.4".
- The faillock `deny` and pwhistory `remember` checks were added the same day
  in commit `0fdfaa82`, "for CIS 5.3.2/5.3.3".
- The SSH algorithm allow-lists were added on 2026-06-20 in commit `7b0d6b58`,
  with a comment naming "OpenSSH 10 defaults and Mozilla Modern SSH guidance"
  as the source. Checked against both, that was only partly right, and the
  comment now says what the lists actually follow; see
  [SSH algorithm allow-lists](#ssh-algorithm-allow-lists).
- The audit rules carry a comment saying they are "based on CIS Benchmark and
  NIS2 compliance requirements", and the permissions table one saying "Based on
  CIS Benchmark and security best practices". Neither names a version or a
  section. NIS2, the EU directive, is not one of the ten frameworks the reports
  cover.

The compliance mappings came later still. From 2026-06-20 each check was tagged
with control identifiers taken from the rule references in ComplianceAsCode,
the project that writes the SCAP Security Guide content OpenSCAP scans with. A
mapping says which control a check relates to. It does not say where the
check's number came from, and in several places the control asks for a
different number, as [a later section](#where-a-pass-is-weaker-than-the-control)
shows.

Severities have no recorded rationale anywhere. They are the project's
judgement.

What *is* written down, and enforced in code, is how a value is compared rather
than which value is chosen:

- **Every comparison has a direction**, so a host that is already stricter than
  the baseline is neither reported nor loosened
  (`crates/hardener-plugins/src/strictness.rs`). File permissions are the one
  exception, described [below](#file-permissions).
- **A `directives` override can only tighten a value.** One that would loosen it
  is ignored.
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
identifiers still judges the host by the values on this page.

**A Pass means the host meets this page's value.** A control passes when a
plugin assesses it and finds nothing wrong, and "wrong" means weaker than the
value in the tables below. Where a control's own text asks for a different
number, the Pass is still judged against the baseline. That cuts both ways:

- Where the baseline is **stricter** than the control, a host that meets the
  control can still fail it in the report. The RHEL 8 STIG's password lifetime
  rule, `RHEL-08-020200`, asks for 180 days at most, and the baseline asks for
  90, so a host at 120 days fails that STIG control in the report.
- Where the baseline is **weaker** than the control, a host passes a control it
  does not meet. The cases known today are listed in the next section.

**Directives tighten, exceptions loosen, scope excludes.**

- `[<plugin>.directives]` changes a target, but only towards stricter. The
  [configuration reference](configuration.md) has the rule for each plugin.
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

## Where a Pass is weaker than the control

These are the controls, known today, where a report can show **Pass** for a host
that does not meet the number in the control's own text. In every case the host
does meet the baseline. The STIG values were read in the RHEL 8 STIG V2R9, and
the CIS values in ComplianceAsCode's encoding of the CIS RHEL 10 Benchmark
v1.0.1; see [Sources](#sources).

<!-- baseline-table: weaker-pass -->

| Control, as the report prints it | What the control asks | Setting | Baseline |
|---|---|---|---|
| STIG `RHEL-08-020230`, or `RHEL-10-600220` under the RHEL 10 profile | A minimum length of 15 characters | `minlen` | `14` |
| STIG `RHEL-08-020011`, or `RHEL-10-600410` under the RHEL 10 profile | Lock the account after 3 failed attempts | `deny` | `5` |
| STIG `RHEL-08-010291`, or `RHEL-10-300040` under the RHEL 10 profile | Ciphers limited to aes256-gcm, aes256-ctr, aes128-gcm and aes128-ctr, set through the system's FIPS crypto policy | `Ciphers` | allows `chacha20-poly1305@openssh.com` |
| STIG `RHEL-08-010290`, or `RHEL-10-300060` under the RHEL 10 profile | MACs limited to hmac-sha2-512-etm, hmac-sha2-256-etm, hmac-sha2-512 and hmac-sha2-256, set through the FIPS crypto policy | `MACs` | allows `umac-128-etm@openssh.com` |
| CIS `5.3.2.3.1`, under the RHEL 10 profile only | Remember at least 24 previous passwords | `remember` | `5` |
| CIS `5.3.2.1.2`, under the RHEL 10 profile only | A faillock unlock time of 900 seconds. The plugin never reads unlock_time: the profile maps the `deny` check to this control as well, so the control passes on `deny` alone | `deny` | `5` |

The STIG checks for ciphers and MACs read the system crypto policy, while the
plugin writes `sshd_config`, so those two rows compare different mechanisms as
well as different lists.

Each row is a decision for whoever changes it: raise the baseline to the
control's value, or stop mapping the check to that control. Either is a change
to propose as described [below](#proposing-a-change). Until then, README lists
this under its known limitations.

---

## How to read the tables

- **Default** is the value the plugin compares the host against and, where it
  changes anything, writes.
- **Comparison** is the direction in which a value counts as stricter.
  - *at least*: larger is stricter.
  - *at most*: smaller is stricter.
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
  quoted here unless the RHEL 10 profile is active.
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
| `kernel.kptr_restrict` | `2` | at least | Medium | No source recorded (2025-11) | STIG RHEL-08-040283: 1. KSPP: 2, or 1 "if root absolutely needs values from /proc". The baseline matches KSPP and is stricter than the STIG. |
| `kernel.dmesg_restrict` | `1` | at least | Medium | No source recorded (2025-11) | STIG RHEL-08-010375: 1. KSPP: 1. |
| `kernel.yama.ptrace_scope` | `2` | at least | High | No source recorded (2025-11) | STIG RHEL-08-040282: 1. KSPP: 3, or 1 where ptrace is needed. The ComplianceAsCode rule behind CIS RHEL 10 1.5.7 sets 1, and accepts 1, 2 or 3 on Ubuntu 24.04. The baseline sits between the STIG and KSPP, and a host at 3 is left at 3. |
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
| `KbdInteractiveAuthentication` | `no` | ranked, weakest first: `yes`, `no` | Critical | Added 2026-11-13 for issue #186, so a password cannot log in through keyboard-interactive once `PasswordAuthentication` is off | Left alone where `AuthenticationMethods` only lets keyboard-interactive act as a second factor. |
| `PermitEmptyPasswords` | `no` | ranked, weakest first: `yes`, `no` | Critical | No source recorded (2025-11) | STIG RHEL-08-020330: no. CIS RHEL 10 5.1.19 has a control for it. |
| `MaxAuthTries` | `3` | at most | Medium | No source recorded (2025-11) | CIS RHEL 10 5.1.16: 4, and the CIS title in the code reads "4 or less". The baseline is stricter. |
| `X11Forwarding` | `no` | ranked, weakest first: `yes`, `no` | Medium | No source recorded (2025-11) | STIG RHEL-08-040340: no. CIS RHEL 10 5.1.8 asks for `DisableForwarding`, and the RHEL 10 profile maps this check to it. |
| `ClientAliveInterval` | `300` | at most, not 0 | Low | No source recorded (2025-11) | STIG RHEL-08-010201: 600. CIS RHEL 10 5.1.7 leaves the value to site policy, according to ComplianceAsCode's notes, and its encoding uses 5 minutes. The baseline is stricter than the STIG. |
| `ClientAliveCountMax` | `2` | at most | Low | No source recorded (2025-11) | STIG RHEL-08-010200: 1, which is stricter than the baseline. The plugin maps no STIG control to this setting, so no STIG Pass rests on it. |

### SSH algorithm allow-lists

These are allow-lists, not fixed values. The value written is the list below
intersected with what `ssh -Q` says the host supports, in the order shown. If
the host supports none of them, the directive is left alone rather than given a
value `sshd` cannot parse.

<!-- baseline-table: ssh-crypto -->

| Directive | Allow-list, in preference order | Severity | Where the value comes from | What the guides say |
|---|---|---|---|---|
| `KexAlgorithms` | `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, `curve25519-sha256`, `curve25519-sha256@libssh.org`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512` | High | Commit `7b0d6b58` (2026-06-20). Follows no single published list; see below | OpenSSH 10.0 server default: the same two post-quantum hybrids and curve25519, then the NIST curves ecdh-sha2-nistp256, -nistp384 and -nistp521, which the baseline leaves out. OpenSSH 10.0 moved the finite-field diffie-hellman groups to the client side only; the baseline keeps group16 and group18 as a fallback for hosts that lack the newer methods. ssh-audit's Hardened OpenSSH Server v10.4 policy: the two hybrids alone. Mozilla Modern, written for OpenSSH 6.7: curve25519, the NIST curves and diffie-hellman-group-exchange-sha256, with no post-quantum method. |
| `Ciphers` | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` | High | Commit `7b0d6b58` (2026-06-20). Authenticated encryption only | OpenSSH 10.0 default, ssh-audit's v10.4 policy and Mozilla Modern all add the AES-CTR modes. STIG RHEL-08-010291 allows aes256-gcm, aes256-ctr, aes128-gcm and aes128-ctr only, so not ChaCha20. |
| `MACs` | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `umac-128-etm@openssh.com` | Medium | Commit `7b0d6b58` (2026-06-20). Encrypt-then-MAC only | Identical to ssh-audit's v10.4 policy. The OpenSSH 10.0 default also allows umac-64, the non-ETM forms and hmac-sha1. Mozilla Modern adds the non-ETM SHA-2 and UMAC forms. STIG RHEL-08-010290 allows the two SHA-2 ETM forms and the two non-ETM SHA-2 forms, so not UMAC. |

The comment above these lists in the code named "OpenSSH 10 defaults and
Mozilla Modern SSH guidance" as their source until 2026-11-15. Neither matches:
the lists are closest to ssh-audit's hardened policy, with curve25519 and two
finite-field groups kept as fallbacks. A host held to the RHEL STIGs cannot meet
their cipher and MAC rules with these lists as they stand.

---

## PAM and password ageing

Two open issues are discussing values in this section:
[#190](https://github.com/tidynest/linux-hardener/issues/190) asks about
password expiry and composition rules, and
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
| `minlen` | `14` | at least | High | No source recorded (2025-11-22) | CIS RHEL 10 5.3.2.2.2: 14. STIG RHEL-08-020230: 15. 800-63B-4: at least 15 where the password is the only factor, and at least 8 where it is one of several. PCI DSS 8.3.6: 12. |
| `dcredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020130: -1, at least one digit. CIS RHEL 10 5.3.2.2.3 asks for complexity through `minclass`, encoded as 4. PCI DSS 8.3.6: digits and letters. 800-63B-4: verifiers "SHALL NOT impose other composition rules". |
| `ucredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020110: -1, at least one capital. Otherwise as for `dcredit`. |
| `lcredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020120: -1, at least one lower-case letter. Otherwise as for `dcredit`. |
| `ocredit` | `-1` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020280: -1, at least one special character. Otherwise as for `dcredit`. |
| `maxrepeat` | `3` | at most, not 0 | Low | No source recorded (2025-11-22) | STIG RHEL-08-020150: 3. CIS RHEL 10 5.3.2.2.4 has a control for it. |
| `PASS_MAX_DAYS` | `90` | at most | Medium | No source recorded (2025-11-22) | STIG RHEL-08-020200: 180 in V2R9; the title in the code still reads 60 days. CIS RHEL 10 5.4.1.1: 365. PCI DSS 8.3.9: 90, only where the password is the single factor, and dynamic risk analysis is allowed instead. 800-63B-4: verifiers "SHALL NOT require subscribers to change passwords periodically", and must force a change on evidence of compromise. |
| `PASS_MIN_DAYS` | `1` | at least | Low | No source recorded (2025-11-22) | STIG RHEL-08-020190: 1. CIS RHEL 10 5.4.1.2: 1. Not enforceable on Arch. |
| `PASS_WARN_AGE` | `7` | at least | Low | No source recorded (2025-11-22) | CIS RHEL 10 5.4.1.3: 7. |
| `deny` | `5` | at most | High | Commit `0fdfaa82` (2026-07-01), "for CIS 5.3.2/5.3.3" | CIS RHEL 10 5.3.2.1.1: 5. STIG RHEL-08-020011: 3. PCI DSS 8.3.4: lock out after no more than 10 attempts. 800-63B-4: no more than 100 consecutive failures. A lower `deny` locks accounts sooner, which is also a way to lock out a legitimate user. |
| `remember` | `5` | at least | Medium | Commit `0fdfaa82` (2026-07-01), "for CIS 5.3.2/5.3.3" | CIS RHEL 10 5.3.2.3.1: 24. The RHEL 8 STIG V2R9 and RHEL 9 STIG V2R10 have no password reuse rule. |

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
drop, through nftables, firewalld or ufw. No source is recorded for them. The
rules are built by `get_baseline_rules` in
`crates/hardener-plugins/src/firewall/mod.rs`.

<!-- baseline-table: firewall -->

| Rule | Action | Protocol | Port | Source address | Notes |
|---|---|---|---|---|---|
| `loopback` | `accept` | `all` | `any` | `127.0.0.1/8` | Local traffic. |
| `established` | `accept` | `all` | `any` | `any` | Existing connections, including the session an apply runs over. |
| `ssh` | `accept` | `tcp` | `22` | `any` | **The port is fixed at 22.** The plugin does not read the port `sshd` listens on, so a host whose `sshd` listens elsewhere stops accepting new SSH logins after apply unless `[firewall.directives]` sets `ssh.port`. |
| `drop_default` | `drop` | `all` | `any` | `any` | Everything else inbound. |

---

## Audit rules

The audit plugin writes these rules to `/etc/audit/rules.d/hardening.rules`
and leaves `auditd.conf` alone. The code says they are "based on CIS Benchmark
and NIS2 compliance requirements" without naming a version or section. The
`-F auid>=1000 -F auid!=unset` filter on the busy families is described in the
code as the CIS scope: it keeps daemons out of the log while every event a
logged-in user causes still lands. The table in the code is `AUDIT_RULES` in
`crates/hardener-plugins/src/audit/mod.rs`.

The file opens with `-b 65536` and `--backlog_wait_time 0`. That is a project
decision with a measurement behind it: on a 16-core build host on 2026-09-02,
auditd's stock backlog of 8192 stayed full and lost over 564,000 events. The
larger queue absorbs bursts, and the zero wait makes an overflow drop events
rather than stall every process that writes one.

<!-- baseline-table: audit -->

| Category | Rule | Severity |
|---|---|---|
| `time-change` | `-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change` | High |
| `time-change` | `-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change` | High |
| `time-change` | `-a always,exit -F arch=b64 -S clock_settime -k time-change` | High |
| `time-change` | `-w /etc/localtime -p wa -k time-change` | Medium |
| `identity` | `-w /etc/passwd -p wa -k identity` | Critical |
| `identity` | `-w /etc/shadow -p wa -k identity` | Critical |
| `identity` | `-w /etc/group -p wa -k identity` | Critical |
| `identity` | `-w /etc/gshadow -p wa -k identity` | Critical |
| `identity` | `-w /etc/security/opasswd -p wa -k identity` | High |
| `network-change` | `-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change` | Medium |
| `network-change` | `-w /etc/hosts -p wa -k network-change` | Medium |
| `network-change` | `-w /etc/network/ -p wa -k network-change` | Medium |
| `perm-mod` | `-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm-mod` | Medium |
| `perm-mod` | `-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=unset -k perm-mod` | Medium |
| `perm-mod` | `-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -F auid>=1000 -F auid!=unset -k perm-mod` | Medium |
| `privileged` | `-w /usr/bin/sudo -p x -k privileged` | High |
| `privileged` | `-w /usr/bin/su -p x -k privileged` | High |
| `privileged` | `-w /usr/bin/passwd -p wa -k privileged` | Medium |
| `delete` | `-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete` | Medium |
| `modules` | `-w /sbin/insmod -p x -k modules` | High |
| `modules` | `-w /sbin/rmmod -p x -k modules` | High |
| `modules` | `-w /sbin/modprobe -p x -k modules` | High |

One rule does less than its description in the code says. The `passwd` rule is
described as monitoring execution, but `-p wa` records writes and attribute
changes to the file, not its use: in `auditctl(8)`, `x` is execute, `w` is write
and `a` is attribute change.

---

## File permissions

The permissions plugin checks the mode of each path and nothing else.
**Ownership is not checked**, although the table in the code carries an owner
and a group for every path. The code says the modes are "Based on CIS Benchmark
and security best practices", with no section named. The table in the code is
`CRITICAL_PERMISSIONS` in `crates/hardener-plugins/src/permissions/mod.rs`.

There are two comparisons:

- *no bits beyond* is a mask: the path passes if it sets no permission bit
  outside the mode shown, so a stricter mode passes, and apply only ever removes
  bits. `/etc/shadow` at `0000`, the Red Hat default, and at `0640`, the Debian
  default, both pass.
- *exact* means any other mode is reported, **a stricter one included**, and
  apply sets the mode shown. On these seven paths that can loosen a host: an
  `/etc/ssh` at `0700` is reported and set to `0755`. This is the one place the
  never-loosen rule does not hold. The code does not say why these paths are
  exact. For files ordinary programs read, such as `/etc/passwd`, a narrower
  mode could break them, so exact may be deliberate there, and it is harder to
  explain for `/root` or `/etc/sudoers`. A `directives` override with the
  stricter mode keeps the host where it is, and rollback restores the earlier
  mode.

<!-- baseline-table: permissions -->

| Path | Mode | Comparison | Severity | Where the value comes from | Notes |
|---|---|---|---|---|---|
| `/root` | `0700` | exact | High | Code comment: CIS and best practice, no section named | |
| `/boot` | `0700` | exact | High | Code comment: CIS and best practice, no section named | |
| `/etc/ssh` | `0755` | exact | High | Code comment: CIS and best practice, no section named | |
| `/etc/sudoers` | `0440` | exact | Critical | Code comment: CIS and best practice, no section named | |
| `/etc/sudoers.d` | `0750` | exact | Critical | Code comment: CIS and best practice, no section named | |
| `/etc/passwd` | `0644` | exact | High | Code comment: CIS and best practice, no section named | CIS RHEL 10 7.1.1 has a control for its access. |
| `/etc/group` | `0644` | exact | High | Code comment: CIS and best practice, no section named | CIS RHEL 10 7.1.3 has a control for its access. |
| `/etc/shadow` | `0640` | no bits beyond | Critical | Code comment: CIS and best practice, no section named | CIS RHEL 10 7.1.5 has a control for its access. |
| `/etc/gshadow` | `0640` | no bits beyond | Critical | Code comment: CIS and best practice, no section named | CIS RHEL 10 7.1.7 has a control for its access. |

On openSUSE, where a path exists only under `/usr/etc`, the plugin reports the
vendor copy and prints the command that copies it into `/etc`, but never writes
the package-owned file itself.

---

## Mandatory access control

The MAC plugin has one target and no table: **SELinux in enforcing mode**, where
SELinux is present. Apply switches it on with `setenforce 1`, which lasts until
the next boot; the finding tells you to set `SELINUX=enforcing` in
`/etc/selinux/config` to make it permanent. CIS RHEL 10 1.3.1.5 asks for the
same. On a host whose files are not correctly labelled, enforcing mode can stop
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
   value you propose.
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
   choose for themselves. A stricter value needs no change at all:
   `directives` sets it today. A deliberately looser value is recorded as an
   exception, which keeps it visible in every report.

A change that lands updates its row here in the same commit, since the
documentation gate fails otherwise, and says in the CHANGELOG what it does to a
host that was already hardened.

---

## Sources

Every guide quoted on this page, with the version read. All were read on
2026-11-15.

- **DISA Red Hat Enterprise Linux 8 STIG, Version 2, Release 9**, benchmark date
  30 September 2026. DISA's XCCDF file as redistributed by ComplianceAsCode:
  <https://github.com/ComplianceAsCode/content/blob/master/shared/references/disa-stig-rhel8-v2r9-xccdf-manual.xml>
- **DISA Red Hat Enterprise Linux 8 STIG, Version 2, Release 8**, benchmark date
  1 July 2026, the release before, for the 60-day password lifetime, at
  ComplianceAsCode tag `v0.1.82`:
  <https://github.com/ComplianceAsCode/content/blob/v0.1.82/shared/references/disa-stig-rhel8-v2r8-xccdf-manual.xml>
- **DISA Red Hat Enterprise Linux 9 STIG, Version 2, Release 10**, benchmark
  date 30 September 2026, from the same place:
  <https://github.com/ComplianceAsCode/content/blob/master/shared/references/disa-stig-rhel9-v2r10-xccdf-manual.xml>
- **CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1**, as ComplianceAsCode
  encodes it. The benchmark itself needs a CIS account and was not read.
  <https://github.com/ComplianceAsCode/content/blob/master/products/rhel10/controls/cis_rhel10.yml>
- **ComplianceAsCode rule `sysctl_kernel_yama_ptrace_scope`**, for the value
  behind the ptrace controls:
  <https://github.com/ComplianceAsCode/content/blob/master/linux_os/guide/system/permissions/restrictions/sysctl_kernel_yama_ptrace_scope/rule.yml>
- **NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and
  Authenticator Management**, which supersedes SP 800-63B. NIST's HTML edition,
  rendered 26 August 2025:
  <https://github.com/usnistgov/800-63-4/blob/nist-pages/sp800-63b.html>
- **PCI DSS v4.0.1**, requirements 8.3.4, 8.3.6 and 8.3.9, as ComplianceAsCode
  transcribes them:
  <https://github.com/ComplianceAsCode/content/blob/master/controls/pcidss_4.yml>
- **Kernel Self Protection Project, Recommended Settings**:
  <https://github.com/KSPP/kspp.github.io/blob/main/Recommended_Settings.md>
- **OpenSSH 10.0p1 default algorithms**, `myproposal.h` at tag `V_10_0_P1`:
  <https://github.com/openssh/openssh-portable/blob/V_10_0_P1/myproposal.h>
- **ssh-audit built-in policies**, "Hardened OpenSSH Server v10.4 (version 1)":
  <https://github.com/jtesta/ssh-audit/blob/master/src/ssh_audit/builtin_policies.py>
- **Mozilla Security Guidelines, OpenSSH**, the "Modern (OpenSSH 6.7+)"
  configuration:
  <https://github.com/mozilla/infosec.mozilla.org/blob/master/docs/guidelines/openssh.md>
- **auditctl(8)**, from the audit userspace project:
  <https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8>

Guides move. The DISA STIGs are revised every quarter, and the RHEL 8 password
lifetime rule changed from 60 to 180 days in the release quoted here. When a
guide quoted on this page publishes a new release, the rows that quote it need
reading again, and nothing automated will notice.
