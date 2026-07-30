# External Security Audit: Scope & Preparation

**Status:** prepared 2026-07-17, awaiting vendor selection and budget decision
(issue #19). Internal remediation is complete (53/53 findings resolved, see
`archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`), which is precisely the right time to buy outside
eyes.

**Last Updated**: 2026-07-30

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
  (`packaging/assets/com.tidynest.linux-hardener.policy`), Tauri IPC surface (30 commands,
  `src-tauri/src/commands.rs`, `PrivilegedOpGuard`), CLI-as-root paths
  (`apply`, `rollback`, `checkpoint`).
- **SSH executor and batch paths:** remote command construction and quoting
  (`crates/hardener-core/src/executor/ssh.rs`), host-key handling and the
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
- **Layered host configuration (`/etc` and `/usr/etc`):**
  `crates/hardener-common/src/vendor_config.rs` decides which copy of a
  configuration file is in force, and the ssh, pam and permissions plugins all
  route through it. Two properties are load bearing and should be attacked
  directly: that `/usr/etc` is consulted only on an absence positively
  confirmed at `/etc`, because answering with the vendor copy for an `/etc`
  file that merely could not be read describes a configuration the host does
  not obey, and that no write path ever touches `/usr/etc`.
- **Silent false negatives, as a class.** A check the tool cannot make must be
  reported as unchecked and never as a clean result, and several of the fixes
  in the Unreleased section of `CHANGELOG.md` have exactly this shape. The most
  recent instance, closed on 2026-07-30: the permissions plugin read `/etc`
  alone, so on openSUSE, where `/etc/sudoers` does not exist and
  `/usr/etc/sudoers` sits at 0444 against a required 0440, `scan` reported
  neither a finding nor an unchecked check and a Critical severity check passed
  on evidence nobody had collected. `scan` now
  reports that mode as a finding keyed on the `/etc` path, with a copy into
  `/etc` as the remediation; `apply` and `apply --dry-run` deliberately stay
  silent, because the tool will not write the vendor layer. Auditors should
  treat every remaining silence as a claim to be tested: the report's unchecked
  list is part of the security surface, not a footnote to it.

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
- Verification harnesses: `scripts/test/full-test-suite.sh` and
  `scripts/test/differential-suite.sh`, the latter judging every checked setting
  by asking its real consumer (`sshd -T`, `chage -l`, `stat -c %a`) rather than
  this project's own parser, driven across the five container distributions by
  `scripts/test/run-cross-distro-tests.sh --differential`

## Logistics decisions (owner: maintainer)

- Budget band and timeline: TBD.
- Disclosure: findings land as private GitHub Security Advisories first,
  get fixed, then publish; maintainer triages.
- After the audit: file each finding (private advisory if exploitable),
  fix, add an "external audit" section to `archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`, record
  the audit and outcome in `SECURITY.md` and the README.
