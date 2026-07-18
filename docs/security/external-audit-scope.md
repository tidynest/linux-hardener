# External Security Audit: Scope & Preparation

**Status:** prepared 2026-07-17, awaiting vendor selection and budget decision
(issue #19). Internal remediation is complete (53/53 findings resolved, see
`archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`), which is precisely the right time to buy outside
eyes.

---

## Threat model (what the audit must assume)

1. **Local unprivileged attacker → root via the hardener.** The tool's whole
   purpose is privileged mutation of system state; any parsing, IPC, or
   signing weakness is a privilege-escalation primitive.
2. **Compromised remote host → controller.** Batch/fleet operation connects
   outward over SSH; a malicious or compromised target must not be able to
   corrupt the controller's state, inject into its terminal/UI, or pivot
   through checkpoint/rollback data it influences.

## In scope

- **The privilege boundary:** pkexec/polkit policy
  (`packaging/assets/com.tidynest.linux-hardener.policy`), Tauri IPC surface (28 commands,
  `src-tauri/src/commands.rs`, `PrivilegedOpGuard`), CLI-as-root paths
  (`apply`, `rollback`, `checkpoint`).
- **SSH executor and batch paths:** remote command construction and quoting
  (`hardener-core/src/executor/ssh.rs`), host-key handling and the
  fail-closed privilege probe, per-host isolation in `batch`/fleet flows,
  checkpoint capture/restore over the executor (cross-host refusal logic).
- **Checkpoint & audit-log integrity:** Ed25519 signing, AES-256-GCM key at
  `/etc/linux-hardener/signing.key` (root 0400), SQLite WAL databases under
  `/var/lib/linux-hardener/`, the hash-chain audit log
  (`/var/log/linux-hardener/audit.log`); tamper-evidence claims should be
  attacked directly.
- **Parser attack surface:** config TOML loading order, `sshd_config` and
  PAM file editing (including `sshd -t` pre-write validation), os-release
  parsing, compliance report generation from untrusted finding content.

## Out of scope

- Leptos UI rendering/styling, documentation, packaging cosmetics.
- Third-party dependency audits beyond what `cargo audit`/`cargo deny`
  already gate (the accepted-warning list is documented).

## Vendor shortlist (Rust + systems-security capable)

Trail of Bits · X41 D-Sec · Radically Open Security · Cure53 ·
Include Security. For an open-source security tool, also apply to
OSTIF / Sovereign Tech Fund-style programmes that sponsor audits for
security-relevant OSS, a credible funding route given the tool's nature.

## Handover pack (assemble at engagement start)

- Repo access (public), `SECURITY.md`, `archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`
- `docs/architecture/architecture.md` + `docs/reference/data-flow.md`
- This scope document (threat model above)
- Runbooks: `docs/guide/installation.md`, `docs/contributing/testing.md`, container fixtures
  (`scripts/containers/create-container.sh <distro>`, `scripts/containers/boot-ssh-test-container.sh`)

## Logistics decisions (owner: maintainer)

- Budget band and timeline: TBD.
- Disclosure: findings land as private GitHub Security Advisories first,
  get fixed, then publish; maintainer triages.
- After the audit: file each finding (private advisory if exploitable),
  fix, add an "external audit" section to `archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`, record
  the audit and outcome in `SECURITY.md` and the README.
