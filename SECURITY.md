# Security Policy

## Supported Versions

The current release is **1.8.2**. Only the current release series receives
security fixes; there are no backports, so upgrade rather than pin.

| Version           | Supported          | Notes                                                 |
| ----------------- | ------------------ | ----------------------------------------------------- |
| 1.8.x             | :white_check_mark: | Current release series                                |
| 1.7.x and earlier | :x:                | End of life; upgrade                                  |
| 1.4.x and earlier | :x:                | Also affected by GHSA-x4xp-32mf-xwjh, fixed in 1.5.0 |

There are no backported patches. GHSA-x4xp-32mf-xwjh applies to every release up
to and including 1.4.0 and was fixed in 1.5.0, so any installation still on 1.4.x
or older carries a High-severity data-loss defect. **Upgrade rather than pin.**

### Fixes not yet in a release

The `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) opens with a `Security`
heading, and entries under it describe defects present in the newest release.
Read it before deploying: at the time of writing it carries firewall findings
affecting every release up to and including 1.5.1, each with the command an
operator can run to check whether their own host is affected. A fix that is on
`main` but not yet tagged protects nobody who installed from a package.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Reporting Process

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Use GitHub's private vulnerability reporting, which is enabled on this
   repository: **[Report a vulnerability](https://github.com/tidynest/linux-hardener/security/advisories/new)**.
   This is the preferred channel, because it opens a private advisory thread
   with the maintainer and becomes the published advisory once fixed.
3. If you would rather not use GitHub, email your findings to:
   **tidynest@proton.me**.
4. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Affected version (`hardener --version`)
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### What to Expect

1. Acknowledgement of your report
2. Assessment of severity and impact
3. Development of a fix
4. Coordinated disclosure (if applicable)
5. Credit in release notes (unless you prefer anonymity)

## Security Considerations

### Privilege Model

Linux Hardener operates with a split privilege model:

- **Scanning**: Can run as regular user for most checks
- **Applying Changes**: Requires root privileges
- **Rollback**: Requires root privileges

### Threat Model

This tool is designed to harden systems against common attack vectors, but is **not** designed to protect against:

- Kernel-level rootkits (if already compromised)
- Physical access attacks
- Supply chain attacks on this tool itself
- Vulnerabilities in the underlying operating system

### Security Features

1. **Checkpoint System**
   - All changes are reversible via checkpoints
   - Checkpoints use Ed25519 cryptographic signatures
   - Tamper-evident hash chain for audit logs

2. **Input Validation**
   - All user inputs are validated before processing
   - Path traversal attacks are prevented
   - Configuration values are sanitised

3. **Least Privilege**
   - Scanning runs unprivileged and reports what it could not read rather than
     escalating in order to read it
   - Only `apply` and `rollback` require root, and the desktop application holds
     none of its own: it escalates per invocation through `pkexec`, and the
     privileged process is the short-lived CLI child rather than the GUI
   - Individual operations request only necessary permissions

4. **Audit Logging**
   - All operations are logged
   - A SHA-256 hash chain makes a modified or reordered entry **detectable**. It
     prevents nothing: an attacker who can write the file can still write it,
     and what the chain gives you is that the edit does not verify afterwards
   - `verify_integrity` walks from a 32-zero-byte genesis and stops at
     end-of-file, holding no expected length and no anchor outside the file, so
     **a prefix of a valid chain is itself a valid chain and truncation of the
     tail is not detected**. Measured 2026-08-18: deleting the last of three
     entries left it returning `true`; deleting the first returned `false`,
     because the survivor no longer links to the genesis. An operator who needs
     the record of what the tool last did has to protect the file
   - When not running as root the log is written to
     `~/.local/share/linux-hardener/audit.log`, **where the same user the
     entries describe can rewrite the chain from genesis**. The root path
     (`/var/log/linux-hardener/audit.log`, 0700 directory) is the one with a
     privilege boundary under it
   - Both ceilings, and the evidence behind them, are in
     [evidence-ledger.md](docs/reference/evidence-ledger.md)

### Known Limitations

The limitations below are the ones that are known. The separate question of what
has never been **measured** is answered in
[what this release does not prove](docs/reference/what-is-not-proven.md), which
ships with the release and names, for each capability, the reading that does not
exist: the plugins whose applies no independent oracle reads back, the
distributions accepted by name and never run, and the fleet test file that
reports four passes having asserted nothing. Read it alongside this section
before deploying to a host that matters.

1. **Race Conditions**: Configuration file locking is implemented for `sshd_config` via an exclusive advisory `flock` held across the full read-modify-write cycle. Other configuration files do not currently use advisory locking.

2. **Symbolic Links**: The permissions plugin uses `O_NOFOLLOW` with `fchmod` on local targets to prevent TOCTOU symlink substitution. Backup creation refuses to follow or overwrite symlinks at the destination. Remote execution paths fall back to the executor's `chmod` command and do not carry this guarantee.

3. **External Dependencies**: System utilities (`sysctl`, `systemctl`, etc.) are resolved via a trusted binary path allowlist (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`) rather than the ambient `PATH`, preventing PATH-substitution attacks (CWE-426). The binaries themselves must still be trusted.

4. **Distribution Detection**: Relies on `/etc/os-release` which could be spoofed on a compromised system.

5. **Findings the Tool Will Not Remediate**: `hardener scan` can report a finding, up to Critical severity, that `apply` will never act on. Where a distribution layers its configuration (openSUSE keeps packaged files under `/usr/etc` and reserves `/etc` for overrides; Fedora is moving the same way) and a critical path is absent from `/etc`, the permissions plugin assesses the vendor copy and reports a violating mode there. It never writes that file: the file is package-owned, so a package update would revert the change, and `/etc` is where a deviation belongs. `apply` therefore makes no change for such a path and `apply --dry-run` previews nothing about it, so `scan` is the only command that surfaces it. The finding carries the `install` command that copies the file into `/etc` at the required mode, and an operator has to run it; the control keeps reporting `Fail` until they do. Measured case: `/usr/etc/sudoers` at mode 0444 where 0440 is required, which leaves the sudo policy readable by every account on the host.

6. **Compliance Coverage**: All 10 frameworks (CIS, STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR, ISO 27001:2022, SOC 2, NIST 800-171, FedRAMP) emit real Pass/Fail results via plugin-declared per-control coverage. Controls not covered by any plugin are reported as `ManualReview`. Do not treat a `ManualReview` result as compliant.

### SSH Remote Scanning Security

The SSH remote scanning feature (`--ssh` flag) has these security considerations:

1. **Host Key Verification**: By default, strict host key checking is enforced. The `--ssh-no-verify` flag disables this but should only be used for testing.

2. **Credential Handling**: SSH connections use key-based authentication only (via the `openssh` crate, which drives the system `ssh` client). Keys held in a running `ssh-agent` are honoured. Password authentication is not implemented.

3. **Privilege Escalation**: Apply/rollback operations on remote hosts require sudo access. Configure passwordless sudo for specific commands if needed.

4. **Network Exposure**: SSH connections should use secure networks. Consider using VPNs or jump hosts for production environments.

### Scheduler Notification Credentials

The scheduled scanning daemon supports email notifications via SMTP:

1. **SMTP Password**: Read from the `HARDENER_SMTP_PASSWORD` environment variable at runtime. This value is never written to disk or logged. Set it in your systemd unit environment or shell session before starting the daemon.

2. **Webhook URLs**: Webhook endpoints (Slack, Discord, generic) are stored in `config.toml`. Ensure appropriate file permissions on the config file if webhook URLs contain secrets.

### Desktop Application Privilege Escalation

The Tauri desktop application uses `pkexec` (polkit) for operations that require root privileges:

1. **Apply/Rollback**: When the user triggers apply or rollback from the GUI, the app invokes the hardener CLI binary via `pkexec`, prompting for authentication through the desktop polkit agent.

2. **No Persistent Root**: The GUI process itself never runs as root. Privilege escalation is scoped to the specific CLI invocation and drops back to user-level immediately after completion.

3. **Polkit Agent Requirement**: A polkit authentication agent must be running in the desktop session (GNOME, KDE, Hyprland, etc. all provide one).

4. **Per-Command Capability ACLs**: Every application IPC command is declared in `src-tauri/build.rs` (`tauri_build::AppManifest`), which autogenerates an `allow-*`/`deny-*` permission pair per command and enables Tauri's runtime ACL check for application commands. The main-window capability (`src-tauri/capabilities/default.json`) grants each of the 32 commands explicitly, grouped by risk tier; a command whose permission is removed is rejected by the ACL layer before argument deserialisation or handler dispatch. This layers beneath the existing IPC input validation, `PrivilegedOpGuard` rate limiting, and pkexec boundary rather than replacing any of them.

## Secure Development Practices

The project follows these security practices:

- All dependencies are regularly audited: `cargo audit` runs in GitHub CI (`.github/workflows/ci.yml`), `cargo deny check` runs from the release checklist, and `deny.toml` pins the licence/advisory policy. GitLab is a push mirror carrying no pipeline of its own, so GitHub is the only place CI catches anything. Nothing in this repository blocks a push, so CI is where an advisory is caught rather than before it
- Code is reviewed before merging
- No use of `unsafe` Rust without justification
- Error handling avoids information disclosure
- Sensitive data is not logged
- All IPC inputs are validated (length limits, control character rejection, allowlist-based plugin IDs) with 48 dedicated tests
- Signing keys are encrypted at rest using AES-256-GCM with HKDF-SHA256 derived from the machine identity and a frozen salt. The salt is a key-derivation input rather than a label, so changing it makes every existing signing key undecryptable and every signature already written unverifiable; it is named `KEY_DERIVATION_SALT` and pinned by a known-answer test whose expected bytes are computed independently from RFC 5869 rather than recorded from this implementation
- System binaries are resolved via a trusted path allowlist, not the ambient `PATH` environment variable
- Privileged IPC operations are rate-limited (5-second cooldown) with mutual exclusion to prevent concurrent privilege escalation attempts
- Error messages are sanitised before reaching the frontend to avoid leaking internal filesystem paths (CWE-209)
- HTML report output escapes all dynamic fields to prevent XSS
- File writes use atomic tempfile-and-rename to prevent partial write exposure
- Advisory exclusive file locking is held across read-modify-write cycles on files where concurrent modification is a risk

## Security Hardening This Tool Provides

### Kernel Hardening
- ASLR enforcement
- ptrace restrictions
- dmesg restrictions
- Core dump restrictions
- Module loading restrictions

### Network Hardening
- SSH configuration security
- Firewall rule management
- IP forwarding controls
- ICMP restrictions

### Authentication Hardening
- PAM configuration
- Password policies
- Login attempt limits
- Account lockout

### System Hardening
- Service minimisation
- File permission auditing
- Mandatory Access Control (SELinux/AppArmor)
- Audit daemon configuration

## Compliance Standards

This tool maps findings to:

- CIS Benchmark for Distribution Independent Linux v2.0 (benchmark levels are not modelled, so a report cannot be scoped to Level 1 or Level 2)
- DISA STIG (where applicable)
- NIST 800-53 security controls
- PCI-DSS v4.0 requirements
- HIPAA technical safeguards
- GDPR Article 32 (security of processing)
- ISO 27001:2022 Annex A controls
- SOC 2 Trust Services Criteria
- NIST SP 800-171 (protection of Controlled Unclassified Information)
- FedRAMP Moderate baseline

## Published Advisories for This Project

### GHSA-x4xp-32mf-xwjh - Rollback could delete account files on a remote host (High)

Published 2026-07-27. Affects **all versions up to and including 1.4.0**; fixed
in **1.5.0**, with no backport.

Over SSH, the metadata probe ran `stat ... || echo 'NOTFOUND'`, so a host whose
`stat` output this tool could not parse reported every path as missing.
Checkpoint capture records a missing path with permissions `0`, and rollback
removes any path recorded that way, so `apply` followed by `rollback` on such a
host deleted `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` and
`/etc/sudoers`. Hosts with a working `stat` were unaffected.

The probe now confirms absence with `test -e` and reports a path it cannot read
as an error, which capture propagates, so the operation stops rather than
recording a file as absent. Separately, rollback now refuses to delete a
protected system path that a checkpoint records as absent while the file is
present on the host, which covers checkpoints written before the fix: those rows
were already stored and the probe fix does not rewrite them.

**If you hold checkpoints taken by 1.4.0 or earlier against a remote host,
upgrading is necessary but not sufficient on its own to make those stored rows
correct; the refusal above is what protects a rollback that reads one.**

## Known Security Advisories

The entries below concern **dependencies**, not this project's own code. For
advisories against this project, see the section above.

### RUSTSEC-2023-0071 (rsa crate) - False Positive

Dependabot/cargo-audit may report a vulnerability in the `rsa` crate (Marvin Attack timing sidechannel). This is a **false positive** for this project because:

- The `rsa` crate is pulled in by `sqlx-mysql` as an optional dependency
- This project uses SQLite only (`default-features = false` with only `sqlite` feature)
- The `rsa` crate appears in Cargo.lock metadata but is **not compiled or used**
- Verification: `cargo tree -p rsa` shows "nothing to print"

The advisory can be safely dismissed as it does not affect this project's security posture.

### RUSTSEC-2026-0173 (proc-macro-error2) - Unmaintained, Accepted

`proc-macro-error2` (a fork of the also-unmaintained `proc-macro-error`, RUSTSEC-2024-0370) is unmaintained upstream with **no safe upgrade available**. It is pulled in purely transitively through the Leptos macro stack (`leptos_macro` / `leptos_router` / `rstml`) used by `hardener-ui`, and there is no first-party usage and no drop-in replacement short of removing Leptos. It is a compile-time proc-macro with no runtime attack surface. Accepted and ignored in `deny.toml`.

The complete set of accepted advisories (unmaintained GTK3 and `idna` transitive crates, etc.) is enumerated with per-ID justifications in `deny.toml`, the authoritative source of truth for advisory policy.

## Contact

For security concerns: [private vulnerability report](https://github.com/tidynest/linux-hardener/security/advisories/new)
(preferred), or **tidynest@proton.me**

For general issues: [GitHub Issues](https://github.com/tidynest/linux-hardener/issues)

**Last Updated**: 2026-08-31
