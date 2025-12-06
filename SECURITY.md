# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |

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

1. **Race Conditions**: The tool does not currently lock configuration files during modification. Concurrent edits could cause conflicts.

2. **Symbolic Links**: The tool follows symbolic links, which could potentially be exploited in certain scenarios.

3. **External Dependencies**: The tool relies on system utilities (`sysctl`, `systemctl`, etc.) which must be trusted.

4. **Distribution Detection**: Relies on `/etc/os-release` which could be spoofed on a compromised system.

### SSH Remote Scanning Security

The SSH remote scanning feature (`--ssh` flag) has these security considerations:

1. **Host Key Verification**: By default, strict host key checking is enforced. The `--ssh-no-verify` flag disables this but should only be used for testing.

2. **Credential Handling**: SSH keys are recommended over passwords. Passwords can be passed via `HARDENER_SSH_PASSWORD` environment variable (hidden from CLI history).

3. **Privilege Escalation**: Apply/rollback operations on remote hosts require sudo access. Configure passwordless sudo for specific commands if needed.

4. **Network Exposure**: SSH connections should use secure networks. Consider using VPNs or jump hosts for production environments.

## Secure Development Practices

The project follows these security practices:

- All dependencies are regularly audited (`cargo audit`)
- Code is reviewed before merging
- No use of `unsafe` Rust without justification
- Error handling avoids information disclosure
- Sensitive data is not logged

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

## Known Security Advisories

### RUSTSEC-2023-0071 (rsa crate) - False Positive

Dependabot/cargo-audit may report a vulnerability in the `rsa` crate (Marvin Attack timing sidechannel). This is a **false positive** for this project because:

- The `rsa` crate is pulled in by `sqlx-mysql` as an optional dependency
- This project uses SQLite only (`default-features = false` with only `sqlite` feature)
- The `rsa` crate appears in Cargo.lock metadata but is **not compiled or used**
- Verification: `cargo tree -p rsa` shows "nothing to print"

The advisory can be safely dismissed as it does not affect this project's security posture.

## Contact

For security concerns: **tidynest@proton.me**

For general issues: [GitHub Issues](https://github.com/tidynest/linux-system-hardener/issues)

**Last Updated**: 2025-12-03
