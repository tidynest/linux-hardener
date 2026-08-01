# External Security Audit: Scope & Preparation

**Status:** prepared 2026-07-17, awaiting vendor selection and budget decision
(issue #19). Internal remediation is complete (53/53 findings resolved, see
`docs/security/archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`), which is precisely the right time to buy outside
eyes.

**Last Updated**: 2026-08-01

---

## Codebase shape (for sizing the engagement)

A Cargo workspace of ten library and binary crates under `crates/`, plus the
Tauri desktop backend at `src-tauri/` (package `linux-hardener-desktop`):

| Crate | Relevance to this audit |
|-------|-------------------------|
| `hardener-types` | Shared types, compiled for the backend and for WASM |
| `hardener-common` | Executor abstraction, binary-path allowlist, vendor-layer resolution |
| `hardener-core` | Plugin infrastructure, `LocalExecutor` and `SshExecutor`, config loading |
| `hardener-distro` | `/etc/os-release` parsing and family detection |
| `hardener-plugins` | The eight hardening plugins; every write to the host originates here |
| `hardener-state` | Checkpoints, Ed25519 signing, the hash-chain audit log, SQLite |
| `hardener-compliance` | Report generation from finding content |
| `hardener-scheduler` | The scheduled-scan daemon, its own database, and notifications |
| `hardener-cli` | The `hardener` binary, including every root path |
| `hardener-ui` | Leptos WASM frontend; out of scope, see below |

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
  attacked directly. **Start here.** The one advisory published against this
  project so far, GHSA-x4xp-32mf-xwjh (High, fixed in 1.5.0), lived exactly at
  this junction: a remote `stat` whose output the tool could not parse was
  folded into "the path does not exist", capture stored that as permissions `0`,
  and rollback removes any path recorded that way, so `apply` then `rollback`
  deleted `/etc/passwd`, `/etc/shadow` and three other account files. The lesson
  generalises past the one probe: a sentinel value that stands for more than one
  outcome is the recurring shape of the serious defects found here, and the
  checkpoint schema still encodes "absent" as a mode of zero.
- **Parser attack surface:** config TOML loading order, `sshd_config` and
  PAM file editing (including `sshd -t` pre-write validation), os-release
  parsing, compliance report generation from untrusted finding content.
- **The scheduled-scan daemon (`crates/hardener-scheduler`).** It is the only
  component that runs unattended, and it is the only one that handles a secret
  belonging to somebody else. Four properties are worth attacking: the SMTP
  password is read from `HARDENER_SMTP_PASSWORD` at runtime
  (`notification/email.rs`) and must never reach disk, the journal or a report;
  the webhook URL validator (`notification/webhook.rs`, `validate_webhook_url`)
  is the SSRF boundary and closed one internal finding already (SAM-010), so its
  private-address and loopback rejection should be probed rather than read;
  `scheduler.db` is a second SQLite database, distinct from the checkpoint store
  and written by batch and scheduled scans, so it carries its own integrity
  question; and the shipped systemd unit
  (`packaging/systemd/linux-hardener.service`) runs `hardener daemon run-once`
  with `ProtectSystem=strict` and an explicit `ReadWritePaths` list, which is a
  confinement claim that should be tested rather than trusted.
- **Layered host configuration (`/etc` and `/usr/etc`):**
  `crates/hardener-common/src/vendor_config.rs` decides which copy of a
  configuration file is in force, and the ssh, pam and permissions plugins all
  route through it. Two properties are load bearing and should be attacked
  directly: that `/usr/etc` is consulted only on an absence positively
  confirmed at `/etc`, because answering with the vendor copy for an `/etc`
  file that merely could not be read describes a configuration the host does
  not obey, and that no write path ever touches `/usr/etc`.
- **Silent false negatives, as a class.** A check the tool cannot make must be
  reported as unchecked and never as a clean result, and most of the fixes in
  the Unreleased section of `CHANGELOG.md` have exactly this shape. That section
  is the single most useful document an auditor can read before starting,
  because each entry names a place where this tool reported an answer nobody had
  collected. Two worked examples:

  - **The tool reported a firewall it had not enabled.** `apply --plugin
    firewall-hardening` treated `systemctl is-active ufw` printing `active` as
    proof that ufw was enforcing. Debian ships `ENABLED=no` and a oneshot unit
    that reports active having loaded no rules, so the check passed on a host
    with no firewall, and the subsequent `ufw allow` calls succeeded because
    they write ufw's own files rather than the kernel's tables. Measured on the
    test containers: identical binary, identical run, Arch ended with a 392-line
    ruleset and `-P INPUT DROP` while Debian ended with an empty filter table
    and a default-ACCEPT policy. Every shipped release up to and including 1.5.1
    is affected.
  - **A Critical control passed on a file nobody looked at.** The permissions
    plugin read `/etc` alone, so on openSUSE, where `/etc/sudoers` does not
    exist and `/usr/etc/sudoers` sits at 0444 against a required 0440, `scan`
    reported neither a finding nor an unchecked check. `scan` now reports that
    mode as a finding keyed on the `/etc` path, with a copy into `/etc` as the
    remediation; `apply` and `apply --dry-run` deliberately stay silent, because
    the tool will not write the vendor layer.

  Auditors should treat every remaining silence as a claim to be tested: the
  report's unchecked list is part of the security surface, not a footnote to it.
  The generalisable question, which both examples above answer badly, is whether
  the thing being consulted is the thing that actually decides the outcome.

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

- Repo access (public), `SECURITY.md`, `docs/security/archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`
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
  get fixed, then publish; maintainer triages. Private vulnerability reporting
  is already enabled on the repository and has been exercised once, on
  GHSA-x4xp-32mf-xwjh, so the route is proven rather than theoretical.
- After the audit: file each finding (private advisory if exploitable),
  fix, add an "external audit" section to `docs/security/archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`, record
  the audit and outcome in `SECURITY.md` and the README.
