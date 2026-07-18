# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :x:                |
| 1.0.x   | :x:                |
| 0.3.x   | :x:                |
| 0.2.x   | :x:                |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Reporting Process

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email your findings to: **tidynest@proton.me**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
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

Linux System Hardener operates with a split privilege model:

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
   - Privileges are dropped as soon as possible
   - Individual operations request only necessary permissions

4. **Audit Logging**
   - All operations are logged
   - Hash chain prevents log tampering
   - Logs can be verified for integrity

### Known Limitations

1. **Race Conditions**: Configuration file locking is implemented for `sshd_config` via an exclusive advisory `flock` held across the full read-modify-write cycle. Other configuration files do not currently use advisory locking.

2. **Symbolic Links**: The permissions plugin uses `O_NOFOLLOW` with `fchmod` on local targets to prevent TOCTOU symlink substitution. Backup creation refuses to follow or overwrite symlinks at the destination. Remote execution paths fall back to the executor's `chmod` command and do not carry this guarantee.

3. **External Dependencies**: System utilities (`sysctl`, `systemctl`, etc.) are resolved via a trusted binary path allowlist (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`) rather than the ambient `PATH`, preventing PATH-substitution attacks (CWE-426). The binaries themselves must still be trusted.

4. **Distribution Detection**: Relies on `/etc/os-release` which could be spoofed on a compromised system.

5. **Compliance Coverage**: All 7 frameworks (CIS, STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR, ISO 27001:2022) emit real Pass/Fail results via plugin-declared per-control coverage. Controls not covered by any plugin are reported as `ManualReview`. Do not treat a `ManualReview` result as compliant.

### SSH Remote Scanning Security

The SSH remote scanning feature (`--ssh` flag) has these security considerations:

1. **Host Key Verification**: By default, strict host key checking is enforced. The `--ssh-no-verify` flag disables this but should only be used for testing.

2. **Credential Handling**: SSH connections use key-based authentication only (via the `openssh` crate). SSH agent forwarding is supported. Password authentication is not implemented.

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

4. **Per-Command Capability ACLs**: Every application IPC command is declared in `src-tauri/build.rs` (`tauri_build::AppManifest`), which autogenerates an `allow-*`/`deny-*` permission pair per command and enables Tauri's runtime ACL check for application commands. The main-window capability (`src-tauri/capabilities/default.json`) grants each of the 29 commands explicitly, grouped by risk tier; a command whose permission is removed is rejected by the ACL layer before argument deserialisation or handler dispatch. This layers beneath the existing IPC input validation, `PrivilegedOpGuard` rate limiting, and pkexec boundary rather than replacing any of them.

## Secure Development Practices

The project follows these security practices:

- All dependencies are regularly audited (`cargo audit` and `cargo-deny`; a global pre-push gate blocks advisories, and `deny.toml` pins the licence/advisory policy)
- Code is reviewed before merging
- No use of `unsafe` Rust without justification
- Error handling avoids information disclosure
- Sensitive data is not logged
- All IPC inputs are validated (length limits, control character rejection, allowlist-based plugin IDs) with 47 dedicated tests
- Signing keys are encrypted at rest using AES-256-GCM with HKDF-SHA256 derived from the machine identity
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

- CIS Benchmarks (Level 1 and Level 2)
- DISA STIG (where applicable)
- NIST 800-53 security controls
- PCI-DSS v4.0 requirements
- HIPAA technical safeguards
- GDPR Article 32 (security of processing)
- ISO 27001:2022 Annex A controls

## Known Security Advisories

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

For security concerns: **tidynest@proton.me**

For general issues: [GitHub Issues](https://github.com/tidynest/linux-system-hardener/issues)

**Last Updated**: 2026-07-18
